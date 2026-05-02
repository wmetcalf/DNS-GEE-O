package dnsgeeo

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
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

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *SignalEngine) {
	t.Helper()
	mr := miniredis.RunT(t)

	// Populate test data
	mr.SAdd("signals:url_shorteners", "bit.ly", "t.co", "tinyurl.com")
	mr.SAdd("signals:free_subdomain_hosts", "github.io", "herokuapp.com", "workers.dev")
	mr.SAdd("signals:free_file_hosts", "drive.google.com", "dropbox.com")
	mr.SAdd("signals:free_email_providers", "gmail.com", "yahoo.com")
	mr.SAdd("signals:disposable_email_providers", "tempmail.com", "throwaway.email")
	mr.SAdd("signals:suspicious_tlds", "xyz", "top", "buzz")
	mr.SAdd("signals:afraid_public_reg", "mooo.com", "chickenkiller.com")
	mr.SAdd("signals:parked_nameservers", "parkingcrew.net", "sedoparking.com")
	mr.ZAdd("signals:tranco", 1, "google.com")
	mr.ZAdd("signals:tranco", 57, "github.com")
	mr.HSet("signals:lolfsaas", "workers.dev", `{"name":"Cloudflare Workers","category":"Cloud","abuse":{"phishing":1,"c2":1,"exfil":0,"payload":0,"creds":0},"matched_pattern":"*.workers.dev"}`)
	mr.HSet("signals:lolfsaas", "duckdns.org", `{"name":"DuckDNS","category":"C2 Channel","abuse":{"phishing":1,"c2":1,"exfil":0,"payload":0,"creds":0},"matched_pattern":"*.duckdns.org"}`)
	mr.HSet("signals:psl_private", "github.io", "GitHub, Inc.")
	mr.HSet("signals:psl_private", "herokuapp.com", "Heroku, Inc.")
	mr.HSet("signals:ddns_suffixes", "duckdns.org", "duckdns")
	mr.HSet("signals:ddns_suffixes", "ddns.net", "noip")
	mr.HSet("signals:ddns_domains", "mooo.com", "afraid.org")
	mr.HSet("signals:ddns_domains", "duckdns.org", "duckdns.org")
	mr.SAdd("signals:nrd", "newlycreated.com", "fresh-phish.xyz")

	engine, err := NewSignalEngine("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewSignalEngine failed: %v", err)
	}
	t.Cleanup(func() { engine.Close() })
	return mr, engine
}

func TestLookup_URLShortener(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "bit.ly", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.URLShortener {
		t.Error("expected url_shortener=true for bit.ly")
	}
}

func TestLookup_FreeSubdomainHost(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "evil.github.io", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.FreeSubdomainHost {
		t.Error("expected free_subdomain_host=true for evil.github.io")
	}
	if !result.PSLIsPrivate {
		t.Error("expected psl_is_private=true for evil.github.io")
	}
	if result.PSLPrivateSuffix != "github.io" {
		t.Errorf("expected psl_private_suffix='github.io', got %q", result.PSLPrivateSuffix)
	}
	if result.PSLPrivateOwner != "GitHub, Inc." {
		t.Errorf("expected psl_private_owner='GitHub, Inc.', got %q", result.PSLPrivateOwner)
	}
}

func TestLookup_SuspiciousTLD(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "scam.xyz", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.SuspiciousTLD {
		t.Error("expected suspicious_tld=true for scam.xyz")
	}
}

func TestLookup_TrancoRank(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "github.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.TrancoRank == nil || *result.TrancoRank != 57 {
		t.Errorf("expected tranco_rank=57, got %v", result.TrancoRank)
	}
}

func TestLookup_LOLFSaaS(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "evil.workers.dev", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.LOLFSaaS == nil {
		t.Fatal("expected lolfsaas match for evil.workers.dev")
	}
	if result.LOLFSaaS.Name != "Cloudflare Workers" {
		t.Errorf("expected name='Cloudflare Workers', got %q", result.LOLFSaaS.Name)
	}
}

func TestLookup_DDNSProvider(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "evil.duckdns.org", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.DDNSProvider != "duckdns" {
		t.Errorf("expected ddns_provider='duckdns', got %q", result.DDNSProvider)
	}
}

func TestLookup_AfraidPublicReg(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "evil.mooo.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.AfraidPublicReg {
		t.Error("expected afraid_public_reg=true for evil.mooo.com")
	}
}

func TestLookup_CleanDomain(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "google.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.URLShortener || result.FreeSubdomainHost || result.SuspiciousTLD || result.AfraidPublicReg {
		t.Error("expected no flags set for google.com")
	}
	if result.TrancoRank == nil || *result.TrancoRank != 1 {
		t.Errorf("expected tranco_rank=1 for google.com, got %v", result.TrancoRank)
	}
}

func TestLookup_ParkedNameservers(t *testing.T) {
	_, engine := setupTestRedis(t)
	nameservers := []string{"ns1.parkingcrew.net", "ns2.parkingcrew.net"}
	result, err := engine.Lookup(context.Background(), "parked-domain.com", nameservers)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.ParkedNameservers {
		t.Error("expected parked_nameservers=true when NS matches parked list")
	}
}

func TestLookup_DDNSDomain(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "evil.mooo.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.DDNSDomain != "mooo.com" {
		t.Errorf("expected ddns_domain='mooo.com', got %q", result.DDNSDomain)
	}
	if result.DDNSDomainProvider != "afraid.org" {
		t.Errorf("expected ddns_domain_provider='afraid.org', got %q", result.DDNSDomainProvider)
	}
}

func TestLookup_DDNSDomainDirect(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "mooo.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.DDNSDomain != "mooo.com" {
		t.Errorf("expected ddns_domain='mooo.com' for direct lookup, got %q", result.DDNSDomain)
	}
}

func TestLookup_NewlyRegistered(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "newlycreated.com", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.NewlyRegistered {
		t.Error("expected newly_registered=true for newlycreated.com")
	}
}

func TestLookup_NewlyRegisteredSubdomain(t *testing.T) {
	_, engine := setupTestRedis(t)
	result, err := engine.Lookup(context.Background(), "sub.fresh-phish.xyz", nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.NewlyRegistered {
		t.Error("expected newly_registered=true for sub.fresh-phish.xyz (parent in NRD list)")
	}
}


