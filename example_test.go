package triage_test

import (
	"fmt"
	"regexp"

	"github.com/richardwooding/triage"
)

func ExampleEntropy() {
	fmt.Printf("%.2f\n", triage.Entropy([]byte("hello")))
	// Output: 1.92
}

func ExampleClassify() {
	res := triage.Classify([]byte("AKIAIOSFODNN7EXAMPLE"), 4.5)
	fmt.Printf("entropy=%.2f category=%q\n", res.Entropy, res.Category)
	for _, s := range res.Secrets {
		fmt.Printf("[%s] %s: %s\n", s.Severity, s.Rule, s.Match)
	}
	// Output:
	// entropy=3.68 category="Base64"
	// [HIGH] AWS Access Key: AKIAIOSFODNN7EXAMPLE
}

func ExampleRedact() {
	fmt.Println(string(triage.Redact([]byte("aws_key = AKIAIOSFODNN7EXAMPLE"))))
	// Output: aws_key = [REDACTED]
}

// A Scanner adds custom rules and an allowlist on top of the built-in
// detectors. Here a project-specific "Acme Key" rule is added and the AWS
// documentation key is allowlisted so it is not reported.
func ExampleScanner() {
	s := triage.NewScanner(
		triage.WithExtraRules(triage.Rule{
			Name:     "Acme Key",
			Severity: triage.SeverityHigh,
			Pattern:  regexp.MustCompile(`\bacme_[a-z0-9]{8}\b`),
		}),
		triage.WithAllowlist("AKIAIOSFODNN7EXAMPLE"),
	)
	res := s.Classify([]byte("acme_abcd1234 and AKIAIOSFODNN7EXAMPLE"))
	for _, f := range res.Secrets {
		fmt.Printf("%s: %s\n", f.Rule, f.Match)
	}
	// Output: Acme Key: acme_abcd1234
}
