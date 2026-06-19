package triage

// Scanner performs triage analysis with a configurable set of secret rules, a
// fixed entropy threshold, an allowlist of known-benign values, and a redaction
// mask. Create one with [NewScanner]; the zero value is not usable.
//
// After construction a Scanner is read-only and safe for concurrent use. For
// one-off analysis with the built-in rules, the package-level [Classify] and
// [Redact] functions are simpler.
type Scanner struct {
	rules      []Rule
	minEntropy float64
	allow      map[string]struct{}
	mask       []byte
}

// Option configures a [Scanner]. Options are applied in order, so later options
// observe the effects of earlier ones (e.g. [WithoutRules] after [WithRules]).
type Option func(*Scanner)

// NewScanner returns a Scanner configured by opts. With no options it uses the
// built-in rules ([DefaultRules]), a disabled high-entropy threshold (0), no
// allowlist, and [DefaultRedactMask].
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{
		rules: DefaultRules(),
		mask:  []byte(DefaultRedactMask),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// WithMinEntropy sets the threshold (bits/byte) above which an opaque token is
// flagged as high-entropy by [Scanner.Classify]. Pass 0 to disable the flag.
func WithMinEntropy(threshold float64) Option {
	return func(s *Scanner) { s.minEntropy = threshold }
}

// WithRules replaces the scanner's rule set entirely. Pass [DefaultRules] as a
// base if you want to extend rather than replace the built-ins.
func WithRules(rules ...Rule) Option {
	return func(s *Scanner) { s.rules = rules }
}

// WithExtraRules appends custom rules to the scanner's current rule set.
func WithExtraRules(rules ...Rule) Option {
	return func(s *Scanner) { s.rules = append(s.rules, rules...) }
}

// WithoutRules removes any rules whose [Rule.Name] matches one of names. Use it
// to disable specific built-ins, e.g. WithoutRules("Generic Secret").
func WithoutRules(names ...string) Option {
	drop := make(map[string]struct{}, len(names))
	for _, n := range names {
		drop[n] = struct{}{}
	}
	return func(s *Scanner) {
		kept := make([]Rule, 0, len(s.rules))
		for _, r := range s.rules {
			if _, ok := drop[r.Name]; !ok {
				kept = append(kept, r)
			}
		}
		s.rules = kept
	}
}

// WithAllowlist suppresses findings whose matched text exactly equals one of
// values. It is the way to silence known-benign tokens such as the documentation
// keys (e.g. "AKIAIOSFODNN7EXAMPLE"). Repeated calls accumulate.
func WithAllowlist(values ...string) Option {
	return func(s *Scanner) {
		if s.allow == nil {
			s.allow = make(map[string]struct{}, len(values))
		}
		for _, v := range values {
			s.allow[v] = struct{}{}
		}
	}
}

// WithRedactMask sets the replacement written over each secret by
// [Scanner.Redact]. The slice is used as-is; do not mutate it afterwards.
func WithRedactMask(mask []byte) Option {
	return func(s *Scanner) { s.mask = mask }
}

// Classify analyzes str using the scanner's rules, allowlist, and entropy
// threshold. See [Classify] for the meaning of each [Result] field.
func (s *Scanner) Classify(str []byte) Result {
	return classify(str, s.rules, s.minEntropy, s.allow)
}

// DetectSecrets returns the secrets found in str using the scanner's rules and
// allowlist, without computing entropy or category.
func (s *Scanner) DetectSecrets(str []byte) []SecretFinding {
	return detectSecretsWith(str, s.rules, s.allow)
}

// Redact returns a copy of str with every detected secret replaced by the
// scanner's mask. The input is never modified. See [Redact] for details.
func (s *Scanner) Redact(str []byte) []byte {
	return redactSpans(str, s.DetectSecrets(str), s.mask)
}
