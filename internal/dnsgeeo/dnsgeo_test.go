package dnsgeeo

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockTransport returns a pre-built dns.Msg for testing.
type mockTransport struct {
	response *dns.Msg
	err      error
}

func (m *mockTransport) Exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	return m.response, m.err
}

func TestCheckMaliciousDomainWithTransport_Blocked(t *testing.T) {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.RecursionAvailable = false
	resp.Response = true

	transport := &mockTransport{response: resp}

	result := CheckMaliciousDomain(context.Background(), "evil.example.com", 2*time.Second, transport)
	if !result {
		t.Error("expected malicious=true for blocked response")
	}
}

func TestCheckMaliciousDomainWithTransport_NotBlocked(t *testing.T) {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.RecursionAvailable = true
	resp.Response = true

	transport := &mockTransport{response: resp}

	result := CheckMaliciousDomain(context.Background(), "safe.example.com", 2*time.Second, transport)
	if result {
		t.Error("expected malicious=false for safe response")
	}
}

func TestCheckMaliciousDomainWithTransport_NXDOMAINWithRA(t *testing.T) {
	// Regular NXDOMAIN (not Quad9 blocked) — RA is true
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeNameError
	resp.RecursionAvailable = true
	resp.Response = true

	transport := &mockTransport{response: resp}

	result := CheckMaliciousDomain(context.Background(), "nonexistent.example.com", 2*time.Second, transport)
	if result {
		t.Error("expected malicious=false for normal NXDOMAIN with RA=true")
	}
}

func TestCheckMaliciousDomainWithTransport_Error(t *testing.T) {
	transport := &mockTransport{err: fmt.Errorf("network error")}

	result := CheckMaliciousDomain(context.Background(), "test.example.com", 2*time.Second, transport)
	if result {
		t.Error("expected malicious=false when transport returns error")
	}
}

// mockTransportFunc allows using a function as a DNSTransport.
type mockTransportFunc struct {
	fn func(msg *dns.Msg, server string) (*dns.Msg, error)
}

func (m *mockTransportFunc) Exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	return m.fn(msg, server)
}

func TestRRResolverDoH_DirectA(t *testing.T) {
	// Mock transport that returns a direct A record
	resp := new(dns.Msg)
	resp.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	resp.Response = true
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
	}

	transport := &mockTransport{response: resp}
	resolver := NewRRResolver([]string{"8.8.8.8:53"})
	resolver.Transport = transport

	ips, server, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr failed: %v", err)
	}
	if server == "" {
		t.Error("expected non-empty server")
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP")
	}
	if ips[0].IP.String() != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %s", ips[0].IP.String())
	}
}

func TestRRResolverDoH_CNAMEFollowing(t *testing.T) {
	callCount := 0
	transport := &mockTransportFunc{fn: func(msg *dns.Msg, server string) (*dns.Msg, error) {
		callCount++
		resp := new(dns.Msg)
		resp.SetReply(msg)
		qname := msg.Question[0].Name

		if qname == "alias.example.com." {
			resp.Answer = []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "real.example.com.",
				},
			}
		} else if qname == "real.example.com." {
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "real.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("1.2.3.4"),
				},
			}
		}
		return resp, nil
	}}

	resolver := NewRRResolver([]string{"8.8.8.8:53"})
	resolver.Transport = transport

	ips, _, err := resolver.LookupIPAddr(context.Background(), "alias.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP after CNAME following")
	}
	if ips[0].IP.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ips[0].IP.String())
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 transport calls (CNAME + A), got %d", callCount)
	}
}

func TestRRResolverDoH_CNAMELoopProtection(t *testing.T) {
	transport := &mockTransportFunc{fn: func(msg *dns.Msg, server string) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "loop.example.com.",
			},
		}
		return resp, nil
	}}

	resolver := NewRRResolver([]string{"8.8.8.8:53"})
	resolver.Transport = transport

	_, _, err := resolver.LookupIPAddr(context.Background(), "loop.example.com")
	if err == nil {
		t.Error("expected error for CNAME loop, got nil")
	}
}
