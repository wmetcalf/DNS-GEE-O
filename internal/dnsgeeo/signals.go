package dnsgeeo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// SignalResult contains all domain intelligence signals from Redis.
type SignalResult struct {
	URLShortener            bool           `json:"url_shortener"`
	FreeSubdomainHost       bool           `json:"free_subdomain_host"`
	FreeFileHost            bool           `json:"free_file_host"`
	FreeEmailProvider       bool           `json:"free_email_provider"`
	DisposableEmailProvider bool           `json:"disposable_email_provider"`
	SuspiciousTLD           bool           `json:"suspicious_tld"`
	AfraidPublicReg         bool           `json:"afraid_public_reg"`
	ParkedNameservers       bool           `json:"parked_nameservers"`
	TrancoRank              *int           `json:"tranco_rank"`
	PSLIsPrivate            bool           `json:"psl_is_private"`
	PSLPrivateSuffix        string         `json:"psl_private_suffix,omitempty"`
	PSLPrivateOwner         string         `json:"psl_private_owner,omitempty"`
	PSLPublicSuffix         string         `json:"psl_public_suffix,omitempty"`
	DDNSProvider            string         `json:"ddns_provider,omitempty"`
	LOLFSaaS                *LOLFSaaSMatch `json:"lolfsaas,omitempty"`
}

// SignalEngine queries Redis for domain intelligence signals.
type SignalEngine struct {
	client *redis.Client
}

// NewSignalEngine connects to Redis and verifies connectivity.
func NewSignalEngine(redisURL string) (*SignalEngine, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("signals: invalid redis URL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("signals: redis connection failed: %w", err)
	}
	return &SignalEngine{client: client}, nil
}

// Close closes the Redis connection.
func (e *SignalEngine) Close() error {
	return e.client.Close()
}

// decomposeSuffixes returns progressively shorter suffixes of a domain.
// "foo.bar.github.io" → ["bar.github.io", "github.io", "io"]
func decomposeSuffixes(domain string) []string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 1 {
		return nil
	}
	var suffixes []string
	for i := 1; i < len(parts); i++ {
		suffixes = append(suffixes, strings.Join(parts[i:], "."))
	}
	return suffixes
}

// extractTLD returns the last label of a domain.
func extractTLD(domain string) string {
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	return parts[len(parts)-1]
}

// Unused import suppressors — Lookup() will be added in Task 3 and use these.
var _ = json.Marshal
