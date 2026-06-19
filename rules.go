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

// Rule is a precompiled detector for one class of secret. Callers can supply
// custom rules to a [Scanner] via [WithRules] or [WithExtraRules].
//
// Patterns should be compiled once (e.g. with [regexp.MustCompile]) and reused,
// never recompiled per string. Go's regexp engine (RE2) guarantees linear-time
// matching, so patterns are inherently free of catastrophic-backtracking
// (ReDoS) risk.
type Rule struct {
	// Name identifies the rule in a [SecretFinding] and is the key used by
	// [WithoutRules] to disable it.
	Name string
	// Severity is reported on every finding the rule produces.
	Severity Severity
	// Pattern is the compiled detector. Required.
	Pattern *regexp.Regexp
	// MinEntropy, when > 0, gates the rule: a candidate match whose Shannon
	// entropy is below this threshold is rejected as a likely false positive.
	MinEntropy float64
}

// DefaultRules returns a fresh copy of the built-in secret detectors, suitable
// for passing to [WithRules] as a base to extend or trim. The patterns are
// shared (they are immutable and safe for concurrent use); only the slice is
// copied, so appending to the result never affects the package defaults.
func DefaultRules() []Rule {
	out := make([]Rule, len(defaultRules))
	copy(out, defaultRules)
	return out
}

// defaultRules is the ordered set of secret detectors applied by default.
// Patterns are intentionally anchored on recognizable prefixes to keep false
// positives low.
var defaultRules = []Rule{
	{
		Name:     "AWS Access Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`),
	},
	{
		Name:     "PEM Private Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
	},
	{
		Name:     "GitHub Token",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bgh[posru]_[A-Za-z0-9]{36,}\b`),
	},
	{
		Name:     "Slack Token",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	},
	{
		Name:     "Google API Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		Name:     "Stripe Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\b[sprk]k_(?:test|live)_[A-Za-z0-9]{16,}\b`),
	},
	{
		Name:     "GitLab Personal Access Token",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
	},
	{
		Name:     "npm Access Token",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	},
	{
		Name:     "Anthropic API Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{32,}\b`),
	},
	{
		Name:     "OpenAI API Key",
		Severity: SeverityHigh,
		// Newer project/service-account keys (sk-proj-/sk-svcacct-, which may
		// contain - and _) and the classic sk- + 48-alphanumeric format. The
		// classic alternative requires alphanumerics only, so it cannot match
		// an Anthropic sk-ant- key (the hyphen after "ant" breaks the run);
		// fixing its length at 48 keeps false positives low.
		Pattern: regexp.MustCompile(`\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b`),
	},
	{
		Name:     "SendGrid API Key",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`),
	},
	{
		Name:     "Telegram Bot Token",
		Severity: SeverityHigh,
		// IDs are 64-bit integers and grow past 10 digits over time; allow up
		// to 20 so newer tokens are not missed.
		Pattern: regexp.MustCompile(`\b\d{8,20}:[A-Za-z0-9_\-]{35}\b`),
	},
	{
		Name:     "Twilio API Key",
		Severity: SeverityHigh,
		// 32 hex chars; usually lowercase but allow uppercase too (configs,
		// env vars, logs sometimes upper-case them).
		Pattern: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
	},
	{
		Name:     "Square Access Token",
		Severity: SeverityHigh,
		Pattern:  regexp.MustCompile(`\bEAAA[A-Za-z0-9_\-]{60,}\b|\bsq0[a-z]{3}-[A-Za-z0-9_\-]{22,}\b`),
	},
	{
		Name:     "JSON Web Token",
		Severity: SeverityMedium,
		Pattern:  regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
	},
	{
		Name:     "Generic Secret",
		Severity: SeverityMedium,
		// key-like name, an actual assignment operator (: or =, optionally
		// quoted/spaced), then a sufficiently long value. Requiring : or =
		// avoids matching prose such as "password authentication is ...".
		Pattern:    regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+=_\-]{12,}`),
		MinEntropy: 3.5,
	},
}
