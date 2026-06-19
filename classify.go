package triage

import (
	"bytes"
	"net"
	"regexp"
)

// Category is a human-readable classification of a string's content.
type Category string

// Classification categories.
const (
	CategoryURL         Category = "URL"
	CategoryEmail       Category = "Email"
	CategoryIPv4        Category = "IPv4"
	CategoryIPv6        Category = "IPv6"
	CategoryUUID        Category = "UUID"
	CategoryPathWindows Category = "WinPath"
	CategoryPathUnix    Category = "UnixPath"
	CategoryDomain      Category = "Domain"
	CategoryHex         Category = "Hex"
	CategoryBase64      Category = "Base64"
)

// Result holds the triage analysis of a single string.
type Result struct {
	// Entropy is the Shannon entropy (bits/byte) of the trimmed string.
	Entropy float64
	// HighEntropy is true when Entropy meets the configured threshold and the
	// string looks like an opaque token rather than natural-language text.
	HighEntropy bool
	// Category is the content classification (first match wins by priority);
	// the empty string when nothing matched.
	Category Category
	// Secrets holds any detected secrets/credentials.
	Secrets []SecretFinding
}

// Interesting reports whether the result is worth surfacing in --secrets mode:
// it contains a detected secret or qualifies as a high-entropy blob.
func (r Result) Interesting() bool {
	return len(r.Secrets) > 0 || r.HighEntropy
}

// Anchored category patterns. RE2 guarantees linear-time evaluation.
var (
	reURL      = regexp.MustCompile(`^(?:https?|ftps?|ssh|file|s3|git)://[^\s]+$`)
	reEmail    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	reUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rePathWin  = regexp.MustCompile(`^[A-Za-z]:\\[^\x00\r\n]*$`)
	rePathUnix = regexp.MustCompile(`^/(?:[^/\x00\s]+/)+[^/\x00\s]*$`)
	// TLD restricted to lowercase letters: embedded real domains are virtually
	// always lowercase, whereas mixed-case junk (e.g. DEX identifiers like
	// "TE.An", "qY.Ze") would otherwise match and flood domain classification.
	reDomain     = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$`)
	reHex        = regexp.MustCompile(`^(?:[0-9a-f]{16,}|[0-9A-F]{16,})$`)
	reBase64     = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
	reNumericIsh = regexp.MustCompile(`^[0-9a-fA-F.:%]+$`)
)

// Classify analyzes a string and returns its entropy, content category, and any
// detected secrets, using the built-in secret rules. minEntropy is the
// threshold (bits/byte) above which an opaque token is flagged as high-entropy;
// pass 0 to disable that flag.
//
// For custom rules, an allowlist, or a fixed entropy threshold, build a
// [Scanner] with [NewScanner] and call [Scanner.Classify].
func Classify(str []byte, minEntropy float64) Result {
	return classify(str, defaultRules, minEntropy, nil)
}

// classify is the shared implementation behind [Classify] and
// [Scanner.Classify].
func classify(str []byte, rules []Rule, minEntropy float64, allow map[string]struct{}) Result {
	trimmed := bytes.TrimSpace(str)

	r := Result{Entropy: Entropy(trimmed)}

	cat, hasCat := classifyCategory(trimmed)
	if hasCat {
		r.Category = cat
	}

	r.Secrets = detectSecretsWith(str, rules, allow)

	// High-entropy flags opaque blobs. Suppress it for recognized structural
	// content (URLs, paths, domains, IPs, ...) which is rarely secret material;
	// keep it when uncategorized or when the bytes are an opaque Hex/Base64 blob
	// (the shapes key material typically takes).
	if minEntropy > 0 && r.Entropy >= minEntropy && isTokenLike(trimmed) {
		if !hasCat || cat == CategoryHex || cat == CategoryBase64 {
			r.HighEntropy = true
		}
	}

	return r
}

// classifyCategory returns the highest-priority category matching the string.
func classifyCategory(b []byte) (Category, bool) {
	switch {
	case reURL.Match(b):
		return CategoryURL, true
	case reEmail.Match(b):
		return CategoryEmail, true
	}

	// IP addresses: use net.ParseIP for correctness, gated by a cheap pre-check.
	if reNumericIsh.Match(b) && (bytes.IndexByte(b, '.') >= 0 || bytes.IndexByte(b, ':') >= 0) {
		if ip := net.ParseIP(string(b)); ip != nil {
			if ip.To4() != nil {
				return CategoryIPv4, true
			}
			return CategoryIPv6, true
		}
	}

	switch {
	case reUUID.Match(b):
		return CategoryUUID, true
	case rePathWin.Match(b):
		return CategoryPathWindows, true
	case rePathUnix.Match(b):
		return CategoryPathUnix, true
	case reDomain.Match(b):
		return CategoryDomain, true
	case reHex.Match(b) && len(b)%2 == 0:
		return CategoryHex, true
	case reBase64.Match(b):
		return CategoryBase64, true
	}

	return "", false
}

// minSecretLen is a lower bound on the length of any string that could contain
// a secret: the shortest detector (Slack token) needs ~14 bytes, so strings
// below this threshold are skipped without running the (relatively expensive)
// regex scan. Short strings dominate real binaries, so this is a meaningful win.
const minSecretLen = 12

// detectSecrets runs the built-in secret rules against the string. It is a
// convenience wrapper over [detectSecretsWith] with no allowlist.
func detectSecrets(str []byte) []SecretFinding {
	return detectSecretsWith(str, defaultRules, nil)
}

// detectSecretsWith runs the given secret rules against the string, reporting
// every non-overlapping match (not just the first) and applying entropy gating
// where configured. Matches present in allow (an exact-match set, may be nil)
// are suppressed. Findings are ordered by rule, then by position.
func detectSecretsWith(str []byte, rules []Rule, allow map[string]struct{}) []SecretFinding {
	if len(str) < minSecretLen {
		return nil
	}

	var findings []SecretFinding
	for _, rule := range rules {
		if rule.Pattern == nil {
			continue
		}
		for _, loc := range rule.Pattern.FindAllIndex(str, -1) {
			match := str[loc[0]:loc[1]]
			if rule.MinEntropy > 0 && Entropy(match) < rule.MinEntropy {
				continue
			}
			if allow != nil {
				if _, ok := allow[string(match)]; ok {
					continue
				}
			}
			findings = append(findings, SecretFinding{
				Rule:     rule.Name,
				Severity: rule.Severity,
				Match:    string(match),
				Start:    loc[0],
				End:      loc[1],
			})
		}
	}
	return findings
}

// isTokenLike reports whether b looks like an opaque token: long enough and
// free of whitespace/control characters (which would indicate prose).
func isTokenLike(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	for _, c := range b {
		if c <= ' ' {
			return false
		}
	}
	return true
}
