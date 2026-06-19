package triage

import (
	"regexp"
	"testing"
)

func TestScannerDefaults(t *testing.T) {
	// A default scanner matches the package-level Classify behavior.
	s := NewScanner()
	in := []byte("AKIAIOSFODNN7EXAMPLE")
	got := s.Classify(in)
	want := Classify(in, 0)
	if len(got.Secrets) != 1 || got.Secrets[0].Rule != "AWS Access Key" {
		t.Fatalf("default scanner = %+v, want one AWS finding", got.Secrets)
	}
	if got.Entropy != want.Entropy {
		t.Errorf("entropy %v != Classify %v", got.Entropy, want.Entropy)
	}
}

func TestScannerWithMinEntropy(t *testing.T) {
	token := []byte("gB7x9K2pQ4rT6yU8wA1zC3vN5mL0jH")
	if NewScanner().Classify(token).HighEntropy {
		t.Errorf("default (threshold 0) should not flag high-entropy")
	}
	if !NewScanner(WithMinEntropy(4.0)).Classify(token).HighEntropy {
		t.Errorf("WithMinEntropy(4.0) should flag high-entropy token")
	}
}

func TestScannerAllowlist(t *testing.T) {
	s := NewScanner(WithAllowlist("AKIAIOSFODNN7EXAMPLE"))
	if f := s.DetectSecrets([]byte("AKIAIOSFODNN7EXAMPLE")); len(f) != 0 {
		t.Errorf("allowlisted key still reported: %+v", f)
	}
	// A non-allowlisted key of the same rule still fires.
	if f := s.DetectSecrets([]byte("AKIA1234567890ABCDEF")); len(f) != 1 {
		t.Errorf("non-allowlisted key = %+v, want 1 finding", f)
	}
}

func TestScannerWithoutRules(t *testing.T) {
	s := NewScanner(WithoutRules("AWS Access Key"))
	if f := s.DetectSecrets([]byte("AKIAIOSFODNN7EXAMPLE")); len(f) != 0 {
		t.Errorf("disabled rule still fired: %+v", f)
	}
	// Other rules remain active.
	if f := s.DetectSecrets([]byte("glpat-" + repeat("a", 20))); len(f) != 1 {
		t.Errorf("GitLab rule = %+v, want 1 finding", f)
	}
}

func TestScannerWithExtraRules(t *testing.T) {
	acme := Rule{
		Name:     "Acme Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bacme_[a-z0-9]{8}\b`),
	}
	s := NewScanner(WithExtraRules(acme))
	f := s.DetectSecrets([]byte("acme_abcd1234"))
	if len(f) != 1 || f[0].Rule != "Acme Key" {
		t.Fatalf("custom rule = %+v, want one Acme Key finding", f)
	}
	// Built-ins still present alongside the custom rule.
	if f := s.DetectSecrets([]byte("AKIAIOSFODNN7EXAMPLE")); len(f) != 1 {
		t.Errorf("built-in AWS rule lost after WithExtraRules: %+v", f)
	}
}

func TestScannerWithRulesReplaces(t *testing.T) {
	only := Rule{Name: "Only", Severity: SeverityLow, Pattern: regexp.MustCompile(`\bzzz[0-9]{9}\b`)}
	s := NewScanner(WithRules(only))
	// The built-ins are gone.
	if f := s.DetectSecrets([]byte("AKIAIOSFODNN7EXAMPLE")); len(f) != 0 {
		t.Errorf("WithRules should replace built-ins, got %+v", f)
	}
	if f := s.DetectSecrets([]byte("zzz123456789")); len(f) != 1 {
		t.Errorf("replacement rule = %+v, want 1 finding", f)
	}
}

func TestScannerRedactMask(t *testing.T) {
	s := NewScanner(WithRedactMask([]byte("XXX")))
	if got := string(s.Redact([]byte("k=AKIAIOSFODNN7EXAMPLE"))); got != "k=XXX" {
		t.Errorf("Scanner.Redact = %q, want %q", got, "k=XXX")
	}
}

func TestScannerNilPatternIsSkipped(t *testing.T) {
	// A custom rule with a nil Pattern must be skipped, not panic.
	s := NewScanner(WithExtraRules(Rule{Name: "Broken", Severity: SeverityLow}))
	f := s.DetectSecrets([]byte("AKIAIOSFODNN7EXAMPLE"))
	if len(f) != 1 || f[0].Rule != "AWS Access Key" {
		t.Errorf("nil-pattern rule disrupted scanning: %+v", f)
	}
}

func TestDefaultRulesIsACopy(t *testing.T) {
	a := DefaultRules()
	n := len(a)
	a = append(a, Rule{Name: "x"})
	_ = a
	if len(DefaultRules()) != n {
		t.Errorf("appending to DefaultRules() result mutated the package defaults")
	}
}
