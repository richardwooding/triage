package triage

import "regexp"

// Severity classifies how serious a secret finding is.
type Severity string

// Severity levels for secret findings.
const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// SecretFinding describes a single secret detected inside a string.
type SecretFinding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Match    string   `json:"match"`
	// Start and End are the byte offsets of the match within the scanned
	// string: str[Start:End] == Match. End is exclusive. They make it possible
	// to highlight or redact the exact span (see [Redact]).
	Start int `json:"start"`
	End   int `json:"end"`
}

// secretRule is a precompiled detector for one class of secret.
//
// All patterns are compiled once at package initialization (never per-string),
// mirroring the CompilePatterns discipline in internal/extractor/filter.go.
// Go's regexp engine (RE2) guarantees linear-time matching, so these patterns
// are inherently free of catastrophic-backtracking (ReDoS) risk.
type secretRule struct {
	name     string
	severity Severity
	re       *regexp.Regexp
	// minEntropy, when > 0, gates the rule: a candidate match whose Shannon
	// entropy is below this threshold is rejected as a likely false positive.
	minEntropy float64
}

// secretRules is the ordered set of secret detectors applied to every string
// in triage mode. Patterns are intentionally anchored on recognizable prefixes
// to keep false positives low.
var secretRules = []secretRule{
	{
		name:     "AWS Access Key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`),
	},
	{
		name:     "PEM Private Key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
	},
	{
		name:     "GitHub Token",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bgh[posru]_[A-Za-z0-9]{36,}\b`),
	},
	{
		name:     "Slack Token",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	},
	{
		name:     "Google API Key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		name:     "Stripe Key",
		severity: SeverityHigh,
		re:       regexp.MustCompile(`\b[sprk]k_(?:test|live)_[A-Za-z0-9]{16,}\b`),
	},
	{
		name:     "JSON Web Token",
		severity: SeverityMedium,
		re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
	},
	{
		name:     "Generic Secret",
		severity: SeverityMedium,
		// key-like name, an actual assignment operator (: or =, optionally
		// quoted/spaced), then a sufficiently long value. Requiring : or =
		// avoids matching prose such as "password authentication is ...".
		re:         regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+=_\-]{12,}`),
		minEntropy: 3.5,
	},
}
