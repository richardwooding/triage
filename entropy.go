// Package triage provides lightweight security analysis of byte strings:
// Shannon entropy scoring, content classification (URL, email, IPv4/IPv6,
// domain, file path, hex, base64, UUID), and secret/credential detection
// (AWS keys, PEM private keys, GitHub/Slack/Stripe tokens, Google API keys,
// JWTs, and generic key=value assignments).
//
// It depends only on the standard library, making it easy to embed in
// scanners, CI secret gates, log scrubbers, and forensics tooling. The entry
// point is [Classify]; [Entropy] is exposed separately for reuse.
package triage

import "math"

// Entropy returns the Shannon entropy of data in bits per byte, a value in the
// range [0, 8]. Higher values indicate more randomness: natural-language text
// typically scores ~4.0-4.5, base64-encoded data ~6, and cryptographic key
// material approaches 8.
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
