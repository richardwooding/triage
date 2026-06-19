# triage

[![CI](https://github.com/richardwooding/triage/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/triage/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/triage.svg)](https://pkg.go.dev/github.com/richardwooding/triage)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/triage)](https://goreportcard.com/report/github.com/richardwooding/triage)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Lightweight, **dependency-free** security analysis of byte strings for Go: Shannon entropy
scoring, content classification, and secret/credential detection. Point it at any string and
it tells you whether it looks like a URL, an IP, a file path, an opaque high-entropy blob, or
a leaked credential.

Extracted from [`txtr`](https://github.com/richardwooding/txtr), where it powers the
`--triage`/`--secrets` modes for firmware and malware analysis.

## Install

```bash
go get github.com/richardwooding/triage
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/richardwooding/triage"
)

func main() {
	res := triage.Classify([]byte("AKIAIOSFODNN7EXAMPLE"), 4.5)

	fmt.Printf("entropy: %.2f\n", res.Entropy)        // entropy: 3.68
	fmt.Printf("category: %q\n", res.Category)        // category: "Base64"
	for _, s := range res.Secrets {
		fmt.Printf("[%s] %s: %s\n", s.Severity, s.Rule, s.Match)
		// [HIGH] AWS Access Key: AKIAIOSFODNN7EXAMPLE
	}
	fmt.Println(res.Interesting())                    // true
}
```

`Classify` takes the bytes to analyze and a `minEntropy` threshold (bits/byte) above which an
opaque token is flagged as high-entropy. Pass `0` to disable high-entropy flagging.

Each `SecretFinding` carries the byte offsets of the match (`Start`/`End`, where
`str[Start:End] == Match`), so you can highlight or redact the exact span.

The raw entropy function is exported too:

```go
triage.Entropy([]byte("hello"))   // 1.92
```

## Redaction

Use `Redact` to scrub secrets out of text (logs, crash dumps, anything you're
about to store or forward) before it leaves your process:

```go
clean := triage.Redact([]byte(`db: "AKIAIOSFODNN7EXAMPLE"`))
// db: "[REDACTED]"
```

`Redact` never modifies its input and returns a new slice. `RedactWith` lets you
supply a custom mask. Overlapping matches are merged so each region is masked
exactly once, and the fixed mask avoids leaking the original secret's length.

## Custom rules and allowlists

`Classify` and `Redact` use the built-in rules. For custom detectors, an
allowlist of known-benign values, or a fixed entropy threshold, build a
`Scanner`:

```go
s := triage.NewScanner(
	triage.WithExtraRules(triage.Rule{
		Name:     "Acme Key",
		Severity: triage.SeverityHigh,
		Pattern:  regexp.MustCompile(`\bacme_[a-z0-9]{8}\b`),
	}),
	triage.WithAllowlist("AKIAIOSFODNN7EXAMPLE"), // suppress the docs key
	triage.WithMinEntropy(4.5),
)

res := s.Classify([]byte("acme_abcd1234"))
clean := s.Redact([]byte("acme_abcd1234"))
```

Options compose in order:

| Option | Effect |
| --- | --- |
| `WithMinEntropy(f)` | High-entropy threshold for `Scanner.Classify` |
| `WithRules(...)` | Replace the rule set entirely (use `DefaultRules()` as a base) |
| `WithExtraRules(...)` | Append custom rules to the built-ins |
| `WithoutRules(names...)` | Disable specific built-ins by name |
| `WithAllowlist(values...)` | Suppress findings whose match equals a listed value |
| `WithRedactMask(mask)` | Replacement used by `Scanner.Redact` |

A `Scanner` is read-only and safe for concurrent use after construction.

## What it detects

**Content categories** (first match wins, structural classification):

| Category | Example |
| --- | --- |
| `URL` | `https://example.com/path` |
| `Email` | `user@example.com` |
| `IPv4` / `IPv6` | `10.0.0.5`, `2001:db8::1` (validated via `net.ParseIP`) |
| `Domain` | `api.github.com` |
| `WinPath` / `UnixPath` | `C:\Windows\System32`, `/usr/bin/txtr` |
| `Hex` / `Base64` | `deadbeefcafebabe`, `TWFuIGlz...` |
| `UUID` | `550e8400-e29b-41d4-a716-446655440000` |

**Secret rules** (precompiled, with optional entropy gating):

AWS access keys, PEM private keys, GitHub tokens, Slack tokens, Stripe keys, Google API keys,
GitLab personal access tokens, npm access tokens, Anthropic & OpenAI API keys, SendGrid API
keys, Telegram bot tokens, Twilio API keys, Square access tokens, JSON Web Tokens, and generic
`key=value` secret assignments.

**High-entropy blobs**: long opaque tokens above the entropy threshold that don't classify as
benign structural content (so file paths and cipher lists don't get flagged, but base64/hex
key material does).

## Design

- **Zero dependencies** — standard library only.
- **ReDoS-safe** — all patterns use Go's `regexp` (RE2), which guarantees linear-time matching;
  patterns are compiled once at package init, never per call.
- **Low false positives** — IPs are validated with `net.ParseIP`; the generic secret rule
  requires an actual `:`/`=` assignment (not prose); domains require a lowercase TLD; high
  entropy is suppressed for recognized structural content.
- **Fast** — strings shorter than the shortest possible secret skip the secret scan; entropy is
  a single O(n) pass.

## License

MIT — see [LICENSE](LICENSE).
