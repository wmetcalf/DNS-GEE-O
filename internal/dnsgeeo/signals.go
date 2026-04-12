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
	DDNSDomain              string         `json:"ddns_domain,omitempty"`
	DDNSDomainProvider      string         `json:"ddns_domain_provider,omitempty"`
	NewlyRegistered         bool           `json:"newly_registered"`
	BadASN                  bool           `json:"bad_asn"`
	BadASNNumber            uint           `json:"bad_asn_number,omitempty"`
	BadASNEntity            string         `json:"bad_asn_entity,omitempty"`
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
// asnNumbers is optional — pass ASN numbers from resolved IPs to check against bad ASN list.
func (e *SignalEngine) Lookup(ctx context.Context, domain string, nameservers []string, asnNumbers []uint) (*SignalResult, error) {
	domain = strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return &SignalResult{}, nil
	}

	tld := extractTLD(domain)
	suffixes := decomposeSuffixes(domain)

	pipe := e.client.Pipeline()

	// Boolean set lookups (exact match on full domain)
	freeEmailCmd := pipe.SIsMember(ctx, "signals:free_email_providers", domain)
	dispEmailCmd := pipe.SIsMember(ctx, "signals:disposable_email_providers", domain)
	suspTLDCmd := pipe.SIsMember(ctx, "signals:suspicious_tlds", tld)

	// Suffix-based set lookups — check domain and each suffix
	type suffixCheck struct {
		suffix string
		cmd    *redis.BoolCmd
	}
	var urlShortChecks, freeSubChecks, freeFileChecks, afraidChecks []suffixCheck
	urlShortChecks = append(urlShortChecks, suffixCheck{domain, pipe.SIsMember(ctx, "signals:url_shorteners", domain)})
	for _, sfx := range suffixes {
		urlShortChecks = append(urlShortChecks, suffixCheck{sfx, pipe.SIsMember(ctx, "signals:url_shorteners", sfx)})
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

	// DDNS — check suffixes against hardcoded provider list
	var ddnsCmds []hashCheck
	for _, sfx := range suffixes {
		ddnsCmds = append(ddnsCmds, hashCheck{sfx, pipe.HGet(ctx, "signals:ddns_suffixes", sfx)})
	}

	// DDNS domains — check domain and suffixes against dyn-dns-list
	var ddnsDomainCmds []hashCheck
	ddnsDomainCmds = append(ddnsDomainCmds, hashCheck{domain, pipe.HGet(ctx, "signals:ddns_domains", domain)})
	for _, sfx := range suffixes {
		ddnsDomainCmds = append(ddnsDomainCmds, hashCheck{sfx, pipe.HGet(ctx, "signals:ddns_domains", sfx)})
	}

	// NRD — check domain and suffixes
	nrdDomainCmd := pipe.SIsMember(ctx, "signals:nrd", domain)
	var nrdSuffixCmds []suffixCheck
	for _, sfx := range suffixes {
		nrdSuffixCmds = append(nrdSuffixCmds, suffixCheck{sfx, pipe.SIsMember(ctx, "signals:nrd", sfx)})
	}

	// Bad ASNs — check each ASN number from resolved IPs
	type asnCheck struct {
		asn uint
		cmd *redis.BoolCmd
		nameCmd *redis.StringCmd
	}
	var badASNCmds []asnCheck
	for _, asn := range asnNumbers {
		asnStr := fmt.Sprintf("%d", asn)
		badASNCmds = append(badASNCmds, asnCheck{
			asn:     asn,
			cmd:     pipe.SIsMember(ctx, "signals:bad_asns", asnStr),
			nameCmd: pipe.HGet(ctx, "signals:bad_asn_names", asnStr),
		})
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

	for _, sc := range urlShortChecks {
		if v, _ := sc.cmd.Result(); v {
			result.URLShortener = true
			break
		}
	}
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

	// DDNS domain — longest match from dyn-dns-list
	for _, sc := range ddnsDomainCmds {
		if provider, err := sc.cmd.Result(); err == nil {
			result.DDNSDomain = sc.suffix
			result.DDNSDomainProvider = provider
			break
		}
	}

	// NRD — check domain first, then suffixes
	if v, _ := nrdDomainCmd.Result(); v {
		result.NewlyRegistered = true
	}
	if !result.NewlyRegistered {
		for _, sc := range nrdSuffixCmds {
			if v, _ := sc.cmd.Result(); v {
				result.NewlyRegistered = true
				break
			}
		}
	}

	// Bad ASN — check each resolved IP's ASN
	for _, ac := range badASNCmds {
		if v, _ := ac.cmd.Result(); v {
			result.BadASN = true
			result.BadASNNumber = ac.asn
			if entity, err := ac.nameCmd.Result(); err == nil {
				result.BadASNEntity = entity
			}
			break
		}
	}

	return result, nil
}
