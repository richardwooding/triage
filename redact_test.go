package triage

import (
	"bytes"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no secret", "the quick brown fox", "the quick brown fox"},
		{"aws in context", "key=AKIAIOSFODNN7EXAMPLE end", "key=[REDACTED] end"},
		{
			"two secrets",
			"a AKIAIOSFODNN7EXAMPLE b AKIA1234567890ABCDEF c",
			"a [REDACTED] b [REDACTED] c",
		},
		{"only secret", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(Redact([]byte(tt.in))); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactDoesNotModifyInput(t *testing.T) {
	in := []byte("token=AKIAIOSFODNN7EXAMPLE")
	orig := append([]byte(nil), in...)
	out := Redact(in)
	if !bytes.Equal(in, orig) {
		t.Errorf("Redact modified its input: %q", in)
	}
	// Result must be a distinct backing array even when nothing matched.
	clean := []byte("nothing here")
	if got := Redact(clean); &got[0] == &clean[0] {
		t.Errorf("Redact returned an aliased slice")
	}
	_ = out
}

func TestRedactNoLeakedSecret(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	out := Redact([]byte("prefix " + secret + " suffix"))
	if bytes.Contains(out, []byte(secret)) {
		t.Errorf("Redact leaked the secret: %q", out)
	}
}

func TestRedactWith(t *testing.T) {
	out := RedactWith([]byte("k=AKIAIOSFODNN7EXAMPLE"), []byte("***"))
	if got, want := string(out), "k=***"; got != want {
		t.Errorf("RedactWith = %q, want %q", got, want)
	}
}

func TestRedactOverlappingMatches(t *testing.T) {
	// A generic key=value assignment whose value is itself an AWS key triggers
	// two overlapping rules; the region must be masked exactly once.
	in := []byte(`api_key="AKIAIOSFODNN7EXAMPLE"`)
	out := string(Redact(in))
	if bytes.Count([]byte(out), []byte("[REDACTED]")) != 1 {
		t.Errorf("Redact(%q) = %q, want a single mask", in, out)
	}
	if bytes.Contains([]byte(out), []byte("AKIA")) {
		t.Errorf("Redact(%q) = %q, leaked key material", in, out)
	}
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		"", "AKIAIOSFODNN7EXAMPLE", "key=AKIAIOSFODNN7EXAMPLE val",
		"the quick brown fox", "-----BEGIN RSA PRIVATE KEY-----",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Redaction must be idempotent: the mask is itself secret-free, so
		// redacting an already-redacted string changes nothing.
		once := Redact(data)
		twice := Redact(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("Redact not idempotent for %q: %q vs %q", data, once, twice)
		}
	})
}
