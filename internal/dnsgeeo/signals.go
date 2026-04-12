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

// Lookup checks a domain against all signal data in Redis.
// nameservers is optional — pass WHOIS NS data if available, nil otherwise.
func (e *SignalEngine) Lookup(ctx context.Context, domain string, nameservers []string) (*SignalResult, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return &SignalResult{}, nil
	}

	tld := extractTLD(domain)
	suffixes := decomposeSuffixes(domain)

	pipe := e.client.Pipeline()

	// Boolean set lookups (exact match on full domain)
	urlShortCmd := pipe.SIsMember(ctx, "signals:url_shorteners", domain)
	freeEmailCmd := pipe.SIsMember(ctx, "signals:free_email_providers", domain)
	dispEmailCmd := pipe.SIsMember(ctx, "signals:disposable_email_providers", domain)
	suspTLDCmd := pipe.SIsMember(ctx, "signals:suspicious_tlds", tld)

	// Suffix-based set lookups — check each suffix
	type suffixCheck struct {
		suffix string
		cmd    *redis.BoolCmd
	}
	var freeSubChecks, freeFileChecks, afraidChecks []suffixCheck
	for _, sfx := range suffixes {
		freeSubChecks = append(freeSubChecks, suffixCheck{sfx, pipe.SIsMember(ctx, "signals:free_subdomain_hosts", sfx)})
		freeFileChecks = append(freeFileChecks, suffixCheck{sfx, pipe.SIsMember(ctx, "signals:free_file_hosts", sfx)})
		afraidChecks = append(afraidChecks, suffixCheck{sfx, pipe.SIsMember(ctx, "signals:afraid_public_reg", sfx)})
	}

	// Parked nameservers — check suffixes of each NS
	type nsCheck struct {
		cmd *redis.BoolCmd
	}
	var parkedNSChecks []nsCheck
	for _, ns := range nameservers {
		nsSuffixes := decomposeSuffixes(strings.ToLower(ns))
		for _, nsSfx := range nsSuffixes {
			parkedNSChecks = append(parkedNSChecks, nsCheck{pipe.SIsMember(ctx, "signals:parked_nameservers", nsSfx)})
		}
	}

	// Tranco rank
	trancoCmd := pipe.ZScore(ctx, "signals:tranco", domain)

	// LOLFSaaS — exact + suffix
	lolExactCmd := pipe.HGet(ctx, "signals:lolfsaas", domain)
	type hashCheck struct {
		suffix string
		cmd    *redis.StringCmd
	}
	var lolSuffixCmds []hashCheck
	for _, sfx := range suffixes {
		lolSuffixCmds = append(lolSuffixCmds, hashCheck{sfx, pipe.HGet(ctx, "signals:lolfsaas", sfx)})
	}

	// PSL private — check suffixes
	var pslCmds []hashCheck
	for _, sfx := range suffixes {
		pslCmds = append(pslCmds, hashCheck{sfx, pipe.HGet(ctx, "signals:psl_private", sfx)})
	}

	// DDNS — check suffixes
	var ddnsCmds []hashCheck
	for _, sfx := range suffixes {
		ddnsCmds = append(ddnsCmds, hashCheck{sfx, pipe.HGet(ctx, "signals:ddns_suffixes", sfx)})
	}

	// Execute pipeline. redis.Nil errors are expected for HGET misses and ZSCORE
	// when the domain isn't in the sorted set — we check individual commands below.
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, fmt.Errorf("signals: redis pipeline failed: %w", err)
	}

	// Assemble result
	result := &SignalResult{
		PSLPublicSuffix: tld,
	}

	result.URLShortener, _ = urlShortCmd.Result()
	result.FreeEmailProvider, _ = freeEmailCmd.Result()
	result.DisposableEmailProvider, _ = dispEmailCmd.Result()
	result.SuspiciousTLD, _ = suspTLDCmd.Result()

	// Suffix matches — longest (first) match wins
	for _, sc := range freeSubChecks {
		if v, _ := sc.cmd.Result(); v {
			result.FreeSubdomainHost = true
			break
		}
	}
	for _, sc := range freeFileChecks {
		if v, _ := sc.cmd.Result(); v {
			result.FreeFileHost = true
			break
		}
	}
	for _, sc := range afraidChecks {
		if v, _ := sc.cmd.Result(); v {
			result.AfraidPublicReg = true
			break
		}
	}

	// Parked nameservers
	for _, nc := range parkedNSChecks {
		if v, _ := nc.cmd.Result(); v {
			result.ParkedNameservers = true
			break
		}
	}

	// Tranco rank
	if rank, err := trancoCmd.Result(); err == nil {
		r := int(rank)
		result.TrancoRank = &r
	}

	// LOLFSaaS — exact match first, then longest suffix
	if raw, err := lolExactCmd.Result(); err == nil {
		var match LOLFSaaSMatch
		if json.Unmarshal([]byte(raw), &match) == nil {
			result.LOLFSaaS = &match
		}
	}
	if result.LOLFSaaS == nil {
		for _, sc := range lolSuffixCmds {
			if raw, err := sc.cmd.Result(); err == nil {
				var match LOLFSaaSMatch
				if json.Unmarshal([]byte(raw), &match) == nil {
					result.LOLFSaaS = &match
					break
				}
			}
		}
	}

	// PSL private — longest suffix match
	for _, sc := range pslCmds {
		if _, err := sc.cmd.Result(); err == nil {
			result.PSLIsPrivate = true
			result.PSLPrivateSuffix = sc.suffix
			break
		}
	}

	// DDNS provider — longest suffix match
	for _, sc := range ddnsCmds {
		if provider, err := sc.cmd.Result(); err == nil {
			result.DDNSProvider = provider
			break
		}
	}

	return result, nil
}
