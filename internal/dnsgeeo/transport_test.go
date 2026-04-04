package dnsgeeo

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUDPTransportExchange(t *testing.T) {
	transport := &UDPTransport{Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.RecursionDesired = true

	resp, err := transport.Exchange(context.Background(), msg, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("UDPTransport.Exchange failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
	}
}

func TestResolveDoHURL(t *testing.T) {
	tests := []struct {
		server  string
		want    string
		wantErr bool
	}{
		{"8.8.8.8:53", "https://dns.google/dns-query", false},
		{"8.8.4.4:53", "https://dns.google/dns-query", false},
		{"9.9.9.9:53", "https://dns.quad9.net/dns-query", false},
		{"https://custom.example.com/dns-query", "https://custom.example.com/dns-query", false},
		{"1.2.3.4:53", "", true},
	}
	for _, tt := range tests {
		got, err := ResolveDoHURL(tt.server)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ResolveDoHURL(%q) expected error, got %q", tt.server, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveDoHURL(%q) unexpected error: %v", tt.server, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ResolveDoHURL(%q) = %q, want %q", tt.server, got, tt.want)
		}
	}
}

func TestWireFormatPreservesQuad9BlockedFlags(t *testing.T) {
	// Simulate a Quad9 blocked response: NXDOMAIN with RA=false
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("malicious.example.com"), dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.RecursionAvailable = false
	msg.Response = true

	// Pack to wire format (what DoH sends over HTTPS)
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Unpack from wire format (what DoH receives back)
	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// The exact flags CheckMaliciousDomain inspects
	if unpacked.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode not preserved: got %d, want %d", unpacked.Rcode, dns.RcodeNameError)
	}
	if unpacked.RecursionAvailable {
		t.Error("RecursionAvailable should be false after round-trip")
	}

	// Verify detection logic would return true
	isMalicious := unpacked.Rcode == dns.RcodeNameError && !unpacked.RecursionAvailable
	if !isMalicious {
		t.Error("detection logic should identify this as malicious")
	}
}

func TestWireFormatPreservesNonBlockedFlags(t *testing.T) {
	// Simulate a normal NXDOMAIN (not blocked): RA=true
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("nonexistent.example.com"), dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.RecursionAvailable = true
	msg.Response = true

	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if unpacked.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode not preserved: got %d, want %d", unpacked.Rcode, dns.RcodeNameError)
	}
	if !unpacked.RecursionAvailable {
		t.Error("RecursionAvailable should be true after round-trip")
	}

	// Detection logic should NOT flag this as malicious
	isMalicious := unpacked.Rcode == dns.RcodeNameError && !unpacked.RecursionAvailable
	if isMalicious {
		t.Error("detection logic should NOT identify this as malicious")
	}
}
