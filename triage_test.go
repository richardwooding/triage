package triage

import (
	"math"
	"testing"
)

func TestEntropy(t *testing.T) {
	tests := []struct {
		name string
		data string
		want float64
		tol  float64
	}{
		{"empty", "", 0, 0},
		{"single byte repeated", "aaaaaaaa", 0, 0.0001},
		{"two equiprobable symbols", "abababab", 1.0, 0.0001},
		{"four equiprobable symbols", "abcdabcd", 2.0, 0.0001},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Entropy([]byte(tt.data))
			if math.Abs(got-tt.want) > tt.tol {
				t.Errorf("Entropy(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}

	// 256 distinct bytes should approach the maximum of 8 bits/byte.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if got := Entropy(all); math.Abs(got-8.0) > 0.0001 {
		t.Errorf("Entropy(all 256 bytes) = %v, want 8", got)
	}
}

func TestClassifyCategory(t *testing.T) {
	tests := []struct {
		in   string
		want Category
	}{
		{"https://example.com/path?q=1", CategoryURL},
		{"s3://bucket/key", CategoryURL},
		{"user.name@example.co.uk", CategoryEmail},
		{"10.0.0.5", CategoryIPv4},
		{"255.255.255.0", CategoryIPv4},
		{"2001:db8::1", CategoryIPv6},
		{"550e8400-e29b-41d4-a716-446655440000", CategoryUUID},
		{`C:\Windows\System32\drivers`, CategoryPathWindows},
		{"/usr/local/bin/txtr", CategoryPathUnix},
		{"api.github.com", CategoryDomain},
		{"deadbeefcafebabe1234", CategoryHex},
		{"TWFuIGlzIGRpc3Rpbmd1aXNoZWQ=", CategoryBase64},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			cat, ok := classifyCategory([]byte(tt.in))
			if !ok {
				t.Fatalf("classifyCategory(%q) returned no category, want %q", tt.in, tt.want)
			}
			if cat != tt.want {
				t.Errorf("classifyCategory(%q) = %q, want %q", tt.in, cat, tt.want)
			}
		})
	}
}

func TestClassifyCategoryNegatives(t *testing.T) {
	// Plain prose and short tokens should not be classified.
	for _, in := range []string{"hello world", "a short string", "not/a path", "999.999.999.999"} {
		if cat, ok := classifyCategory([]byte(in)); ok {
			t.Errorf("classifyCategory(%q) = %q, want no match", in, cat)
		}
	}
}

func TestDetectSecrets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		rule string
	}{
		{"aws", "AKIAIOSFODNN7EXAMPLE", "AWS Access Key"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----", "PEM Private Key"},
		{"github", "ghp_" + repeat("a", 36), "GitHub Token"},
		{"slack", "xoxb-123456789012-abcdefghijkl", "Slack Token"},
		{"stripe", "sk_live_" + repeat("A", 20), "Stripe Key"},
		{"gitlab", "glpat-" + repeat("a", 20), "GitLab Personal Access Token"},
		{"npm", "npm_" + repeat("A", 36), "npm Access Token"},
		{"anthropic", "sk-ant-api03-" + repeat("a", 32), "Anthropic API Key"},
		{"openai-classic", "sk-" + repeat("A", 48), "OpenAI API Key"},
		{"openai-proj", "sk-proj-" + repeat("a", 20), "OpenAI API Key"},
		{"sendgrid", "SG." + repeat("a", 22) + "." + repeat("b", 43), "SendGrid API Key"},
		{"telegram", "123456789:" + repeat("a", 35), "Telegram Bot Token"},
		{"telegram-64bit", "12345678901234:" + repeat("a", 35), "Telegram Bot Token"},
		{"twilio", "SK" + repeat("a", 32), "Twilio API Key"},
		{"twilio-upper", "SK" + repeat("A", 32), "Twilio API Key"},
		{"square-eaaa", "EAAA" + repeat("a", 60), "Square Access Token"},
		{"square-sq0", "sq0atp-" + repeat("a", 22), "Square Access Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectSecrets([]byte(tt.in))
			if len(findings) == 0 {
				t.Fatalf("detectSecrets(%q) found nothing, want rule %q", tt.in, tt.rule)
			}
			found := false
			for _, f := range findings {
				if f.Rule == tt.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("detectSecrets(%q) = %+v, want rule %q", tt.in, findings, tt.rule)
			}
		})
	}
}

func TestDetectSecretsOffsets(t *testing.T) {
	// The reported offsets must delimit the match exactly.
	in := []byte("prefix AKIAIOSFODNN7EXAMPLE suffix")
	findings := detectSecrets(in)
	if len(findings) != 1 {
		t.Fatalf("detectSecrets = %d findings, want 1", len(findings))
	}
	f := findings[0]
	if got := string(in[f.Start:f.End]); got != f.Match {
		t.Errorf("in[%d:%d] = %q, want Match %q", f.Start, f.End, got, f.Match)
	}
	if f.Start != 7 {
		t.Errorf("Start = %d, want 7", f.Start)
	}
}

func TestDetectSecretsMultipleMatches(t *testing.T) {
	// Two distinct secrets of the same rule must both be reported.
	in := []byte("AKIAIOSFODNN7EXAMPLE and AKIA1234567890ABCDEF")
	findings := detectSecrets(in)
	var aws int
	for _, f := range findings {
		if f.Rule == "AWS Access Key" {
			aws++
			if string(in[f.Start:f.End]) != f.Match {
				t.Errorf("offset mismatch for %q", f.Match)
			}
		}
	}
	if aws != 2 {
		t.Errorf("found %d AWS keys, want 2", aws)
	}
}

func TestDetectSecretsNoFalsePositives(t *testing.T) {
	for _, in := range []string{
		"hello world", "the quick brown fox", "AKIA-too-short",
		// Classic OpenAI keys are exactly 48 chars after sk-; a shorter sk-
		// token must not match (the {48} anchor guards against loose matches).
		"sk-" + repeat("a", 30),
	} {
		if findings := detectSecrets([]byte(in)); len(findings) != 0 {
			t.Errorf("detectSecrets(%q) = %+v, want none", in, findings)
		}
	}
}

func TestAnthropicNotMatchedAsOpenAI(t *testing.T) {
	// An Anthropic key must be reported once, by the Anthropic rule only — the
	// OpenAI sk- pattern must not also fire on it.
	in := []byte("sk-ant-api03-" + repeat("a", 40))
	rules := map[string]int{}
	for _, f := range detectSecrets(in) {
		rules[f.Rule]++
	}
	if rules["OpenAI API Key"] != 0 {
		t.Errorf("Anthropic key matched OpenAI rule: %+v", rules)
	}
	if rules["Anthropic API Key"] != 1 {
		t.Errorf("Anthropic key matched Anthropic rule %d times, want 1", rules["Anthropic API Key"])
	}
}

func TestClassifyHighEntropy(t *testing.T) {
	// A long random-looking token above threshold is high-entropy.
	token := "gB7x9K2pQ4rT6yU8wA1zC3vN5mL0jH" // mixed-case alnum, no spaces
	r := Classify([]byte(token), 4.0)
	if !r.HighEntropy {
		t.Errorf("Classify(%q).HighEntropy = false (entropy=%v), want true", token, r.Entropy)
	}
	if !r.Interesting() {
		t.Errorf("Classify(%q).Interesting() = false, want true", token)
	}

	// Prose with spaces must not be high-entropy regardless of threshold.
	prose := "the quick brown fox jumps over the lazy dog"
	if Classify([]byte(prose), 0.5).HighEntropy {
		t.Errorf("Classify(prose).HighEntropy = true, want false")
	}

	// Disabled threshold (0) never flags high-entropy.
	if Classify([]byte(token), 0).HighEntropy {
		t.Errorf("Classify with minEntropy=0 flagged high-entropy, want false")
	}
}

// TestDogfoodRegressions covers false positives found by running triage over a
// real-world corpus (system binaries, firmware, APKs/DEX).
func TestDogfoodRegressions(t *testing.T) {
	t.Run("prose is not a generic secret", func(t *testing.T) {
		// Found in /usr/bin/ssh: prose with "password " + word matched the old
		// generic rule because it allowed a bare space as the separator.
		prose := "Password authentication is disabled to avoid man-in-the-middle attacks."
		if f := detectSecrets([]byte(prose)); len(f) != 0 {
			t.Errorf("detectSecrets(prose) = %+v, want none", f)
		}
		// A real assignment must still match.
		if f := detectSecrets([]byte("password=hunter2hunter2")); len(f) == 0 {
			t.Errorf("detectSecrets(real assignment) found nothing, want a match")
		}
		if f := detectSecrets([]byte(`api_key: "AKIAabcdef0123456789"`)); len(f) == 0 {
			t.Errorf("detectSecrets(api_key assignment) found nothing, want a match")
		}
	})

	t.Run("mixed-case identifiers are not domains", func(t *testing.T) {
		// Found in DEX string tables: mangled identifiers matched the domain TLD.
		for _, junk := range []string{"qY.Ze", "TE.An", "Tr.Ir", "T0.OTB.Oq"} {
			if cat, ok := classifyCategory([]byte(junk)); ok && cat == CategoryDomain {
				t.Errorf("classifyCategory(%q) = Domain, want not-a-domain", junk)
			}
		}
		// Real lowercase domains still classify.
		for _, d := range []string{"api.github.com", "example.co.uk", "downloads.openwrt.org"} {
			if cat, ok := classifyCategory([]byte(d)); !ok || cat != CategoryDomain {
				t.Errorf("classifyCategory(%q) = (%q,%v), want Domain", d, cat, ok)
			}
		}
	})

	t.Run("structural content is not high-entropy", func(t *testing.T) {
		// Found in /usr/bin/ssh: long build paths flooded HIGH-ENT output.
		path := "/AppleInternal/Library/BuildRoots/4~CNqOugDnhI02cZCCCbihSM9XQTugjRCpEt/Library"
		if r := Classify([]byte(path), 4.5); r.HighEntropy {
			t.Errorf("Classify(path).HighEntropy = true, want false (entropy=%.2f)", r.Entropy)
		}
		// An opaque base64-shaped blob of similar entropy should still flag.
		blob := "z8PxKAjRS9di0bBYU17OsoETJW4xQpL9mNvCdEf="
		if r := Classify([]byte(blob), 4.5); !r.HighEntropy {
			t.Errorf("Classify(base64 blob).HighEntropy = false, want true (entropy=%.2f)", r.Entropy)
		}
	})
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"", "https://example.com", "AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN RSA PRIVATE KEY-----", "10.0.0.5", "2001:db8::1",
		"deadbeef", "C:\\Windows", "/usr/bin", "user@example.com",
	}
	for _, s := range seeds {
		f.Add([]byte(s), 4.5)
	}
	f.Fuzz(func(t *testing.T, data []byte, minEntropy float64) {
		// Must never panic and must return a sane entropy value.
		r := Classify(data, minEntropy)
		if r.Entropy < 0 || r.Entropy > 8.0001 {
			t.Errorf("entropy out of range: %v for %q", r.Entropy, data)
		}
	})
}
