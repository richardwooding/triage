package triage

import "testing"

// benchmarkInputs covers the distinct code paths through Classify: plain text
// (no match), a content category, and a detected secret.
var benchmarkInputs = []struct {
	name string
	data []byte
}{
	{"PlainText", []byte("the quick brown fox jumps over the lazy dog")},
	{"URL", []byte("https://www.example.com/path/to/resource?q=1&r=2")},
	{"IPv4", []byte("192.168.100.200")},
	{"Base64", []byte("TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcw==")},
	{"SecretAWS", []byte("AKIAIOSFODNN7EXAMPLE")},
	{"SecretPEM", []byte("-----BEGIN RSA PRIVATE KEY-----")},
	{"HighEntropy", []byte("gB7x9K2pQ4rT6yU8wA1zC3vN5mL0jH4dF6sX8wQ")},
}

// BenchmarkEntropy measures Shannon-entropy throughput across input sizes.
func BenchmarkEntropy(b *testing.B) {
	sizes := []int{16, 256, 4096}
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i * 7) // deterministic spread across the byte space
		}
		b.Run(formatSize(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Entropy(data)
			}
		})
	}
}

// BenchmarkClassify measures full per-string triage cost (entropy +
// classification + all secret rules) for each input type.
func BenchmarkClassify(b *testing.B) {
	for _, tc := range benchmarkInputs {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Classify(tc.data, 4.5)
			}
		})
	}
}

// BenchmarkDetectSecrets isolates the secret-rule scan (all rules applied).
func BenchmarkDetectSecrets(b *testing.B) {
	for _, tc := range benchmarkInputs {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = detectSecrets(tc.data)
			}
		})
	}
}

func formatSize(size int) string {
	switch size {
	case 16:
		return "16B"
	case 256:
		return "256B"
	case 4096:
		return "4KB"
	default:
		return "custom"
	}
}
