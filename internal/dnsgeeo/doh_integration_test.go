//go:build integration

package dnsgeeo

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQuad9DoHMatchesUDP(t *testing.T) {
	// isitblocked.org is Quad9's official test domain that is always blocked
	domain := "isitblocked.org"

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	// Query via UDP
	udpTransport := &UDPTransport{Timeout: 5 * time.Second}
	udpResp, err := udpTransport.Exchange(context.Background(), msg, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("UDP query failed: %v", err)
	}

	// Query via DoH
	dohTransport := NewDoHTransport()
	dohResp, err := dohTransport.Exchange(context.Background(), msg, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("DoH query failed: %v", err)
	}

	// Both should have NXDOMAIN
	if udpResp.Rcode != dns.RcodeNameError {
		t.Errorf("UDP: expected NXDOMAIN, got rcode %d", udpResp.Rcode)
	}
	if dohResp.Rcode != dns.RcodeNameError {
		t.Errorf("DoH: expected NXDOMAIN, got rcode %d", dohResp.Rcode)
	}

	// Both should have RA=false (Quad9 blocked signature)
	if udpResp.RecursionAvailable {
		t.Error("UDP: expected RecursionAvailable=false for blocked domain")
	}
	if dohResp.RecursionAvailable {
		t.Error("DoH: expected RecursionAvailable=false for blocked domain")
	}

	// Both should match on Rcode
	if udpResp.Rcode != dohResp.Rcode {
		t.Errorf("Rcode mismatch: UDP=%d, DoH=%d", udpResp.Rcode, dohResp.Rcode)
	}

	// Both should match on RA flag
	if udpResp.RecursionAvailable != dohResp.RecursionAvailable {
		t.Errorf("RA mismatch: UDP=%v, DoH=%v", udpResp.RecursionAvailable, dohResp.RecursionAvailable)
	}

	// Detection logic should return true for both
	udpMalicious := udpResp.Rcode == dns.RcodeNameError && !udpResp.RecursionAvailable
	dohMalicious := dohResp.Rcode == dns.RcodeNameError && !dohResp.RecursionAvailable

	if !udpMalicious {
		t.Error("UDP: detection logic should identify isitblocked.org as malicious")
	}
	if !dohMalicious {
		t.Error("DoH: detection logic should identify isitblocked.org as malicious")
	}
}

func TestQuad9DoHSafeDomain(t *testing.T) {
	domain := "example.com"

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	// Query via UDP
	udpTransport := &UDPTransport{Timeout: 5 * time.Second}
	udpResp, err := udpTransport.Exchange(context.Background(), msg, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("UDP query failed: %v", err)
	}

	// Query via DoH
	dohTransport := NewDoHTransport()
	dohResp, err := dohTransport.Exchange(context.Background(), msg, "9.9.9.9:53")
	if err != nil {
		t.Fatalf("DoH query failed: %v", err)
	}

	// Both should succeed
	if udpResp.Rcode != dns.RcodeSuccess {
		t.Errorf("UDP: expected success, got rcode %d", udpResp.Rcode)
	}
	if dohResp.Rcode != dns.RcodeSuccess {
		t.Errorf("DoH: expected success, got rcode %d", dohResp.Rcode)
	}

	// Detection logic should return false for both
	udpMalicious := udpResp.Rcode == dns.RcodeNameError && !udpResp.RecursionAvailable
	dohMalicious := dohResp.Rcode == dns.RcodeNameError && !dohResp.RecursionAvailable

	if udpMalicious {
		t.Error("UDP: example.com should not be flagged as malicious")
	}
	if dohMalicious {
		t.Error("DoH: example.com should not be flagged as malicious")
	}
}
