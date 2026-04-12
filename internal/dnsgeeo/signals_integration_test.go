//go:build integration

package dnsgeeo

import (
	"context"
	"os"
	"testing"
)

func TestSignalEngine_RealRedis(t *testing.T) {
	redisURL := os.Getenv("DNSGEEO_SIGNALS_REDIS")
	if redisURL == "" {
		redisURL = os.Getenv("DNSGEEO_WHOIS_REDIS_URL")
	}
	if redisURL == "" {
		t.Skip("No Redis URL configured; set DNSGEEO_SIGNALS_REDIS or DNSGEEO_WHOIS_REDIS_URL")
	}

	engine, err := NewSignalEngine(redisURL)
	if err != nil {
		t.Fatalf("NewSignalEngine failed: %v", err)
	}
	defer engine.Close()

	// This test assumes data_refresh.py has been run with DNSGEEO_SIGNALS=true
	// Test a known URL shortener
	result, err := engine.Lookup(context.Background(), "bit.ly", nil, nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if !result.URLShortener {
		t.Error("expected bit.ly to be flagged as url_shortener")
	}

	// Test a known clean domain with Tranco rank
	result, err = engine.Lookup(context.Background(), "google.com", nil, nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.TrancoRank == nil {
		t.Error("expected google.com to have a tranco_rank")
	}
	if result.URLShortener || result.FreeSubdomainHost || result.SuspiciousTLD {
		t.Error("expected no threat signals for google.com")
	}

	// Test a LOLFSaaS domain
	result, err = engine.Lookup(context.Background(), "test.workers.dev", nil, nil)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if result.LOLFSaaS == nil {
		t.Error("expected LOLFSaaS match for test.workers.dev")
	}
}
