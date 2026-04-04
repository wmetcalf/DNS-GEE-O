package dnsgeeo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSTransport abstracts DNS message exchange over different protocols.
type DNSTransport interface {
	Exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error)
}

// UDPTransport sends DNS queries over UDP using miekg/dns.
type UDPTransport struct {
	Timeout time.Duration
}

func (t *UDPTransport) Exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := &dns.Client{Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	return resp, err
}

// dohServerMap maps well-known DNS server IPs to their DoH endpoint URLs.
var dohServerMap = map[string]string{
	"8.8.8.8:53": "https://dns.google/dns-query",
	"8.8.4.4:53": "https://dns.google/dns-query",
	"9.9.9.9:53": "https://dns.quad9.net/dns-query",
}

// ResolveDoHURL maps a server address to a DoH URL.
// If the server starts with "https://", it is returned as-is.
// Known IPs are mapped via dohServerMap.
// Unknown servers return an error.
func ResolveDoHURL(server string) (string, error) {
	if strings.HasPrefix(server, "https://") {
		return server, nil
	}
	if url, ok := dohServerMap[server]; ok {
		return url, nil
	}
	host := strings.TrimSuffix(server, ":53")
	return "", fmt.Errorf("--doh: no DoH endpoint known for server %s; use an https:// URL in --dns instead", host)
}

// DoHTransport sends DNS queries over HTTPS using RFC 8484 wire format.
type DoHTransport struct {
	Client *http.Client
}

func (t *DoHTransport) Exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	url, err := ResolveDoHURL(server)
	if err != nil {
		return nil, err
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: failed to pack DNS message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("doh: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: server returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("doh: failed to read response body: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh: failed to unpack DNS response: %w", err)
	}

	return response, nil
}

// NewDoHTransport creates a DoHTransport with a shared HTTP client.
func NewDoHTransport() *DoHTransport {
	return &DoHTransport{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
