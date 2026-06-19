package triage

import "sort"

// DefaultRedactMask is the replacement written over each detected secret by
// [Redact]. A fixed token (rather than length-preserving asterisks) avoids
// leaking the original secret's length.
const DefaultRedactMask = "[REDACTED]"

// Redact returns a copy of str with every detected secret replaced by
// [DefaultRedactMask]. It is intended for scrubbing logs, crash dumps, and
// other text before it is stored or forwarded. The input is never modified.
//
// Detection uses the same rules as [Classify]; bytes that are not part of a
// secret are preserved verbatim. Overlapping matches are merged so each
// region is masked exactly once.
func Redact(str []byte) []byte {
	return RedactWith(str, []byte(DefaultRedactMask))
}

// RedactWith behaves like [Redact] but replaces each detected secret with the
// supplied mask instead of [DefaultRedactMask].
func RedactWith(str, mask []byte) []byte {
	findings := detectSecrets(str)
	if len(findings) == 0 {
		// Always return a distinct slice so callers may mutate the result
		// without affecting the input.
		return append([]byte(nil), str...)
	}

	// Different rules can match the same or overlapping regions; merge the
	// spans into a sorted, non-overlapping set so each region is masked once.
	type span struct{ start, end int }
	spans := make([]span, len(findings))
	for i, f := range findings {
		spans[i] = span{f.Start, f.End}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})

	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		merged = append(merged, s)
	}

	out := make([]byte, 0, len(str))
	cursor := 0
	for _, s := range merged {
		out = append(out, str[cursor:s.start]...)
		out = append(out, mask...)
		cursor = s.end
	}
	out = append(out, str[cursor:]...)
	return out
}
