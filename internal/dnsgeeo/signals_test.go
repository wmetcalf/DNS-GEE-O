package dnsgeeo

import (
	"testing"
)

func TestDecomposeSuffixes(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"foo.bar.github.io", []string{"bar.github.io", "github.io", "io"}},
		{"example.com", []string{"com"}},
		{"a.b.c.d.com", []string{"b.c.d.com", "c.d.com", "d.com", "com"}},
		{"com", nil},
		{"", nil},
	}
	for _, tt := range tests {
		got := decomposeSuffixes(tt.domain)
		if len(got) != len(tt.want) {
			t.Errorf("decomposeSuffixes(%q) = %v, want %v", tt.domain, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("decomposeSuffixes(%q)[%d] = %q, want %q", tt.domain, i, got[i], tt.want[i])
			}
		}
	}
}

func TestExtractTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "com"},
		{"foo.bar.xyz", "xyz"},
		{"test.co.uk", "uk"},
		{"com", "com"},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractTLD(tt.domain)
		if got != tt.want {
			t.Errorf("extractTLD(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
