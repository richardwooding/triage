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
	fmt.Printf("categories: %v\n", res.Categories)    // categories: []
	for _, s := range res.Secrets {
		fmt.Printf("[%s] %s: %s\n", s.Severity, s.Rule, s.Match)
		// [HIGH] AWS Access Key: AKIAIOSFODNN7EXAMPLE
	}
	fmt.Println(res.Interesting())                    // true
}
```

`Classify` takes the bytes to analyze and a `minEntropy` threshold (bits/byte) above which an
opaque token is flagged as high-entropy. Pass `0` to disable high-entropy flagging.

The raw entropy function is exported too:

```go
triage.Entropy([]byte("hello"))   // 1.92
```

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
JSON Web Tokens, and generic `key=value` secret assignments.

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
