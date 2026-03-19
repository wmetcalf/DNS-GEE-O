package dnsgeeo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func buildTestDB(t *testing.T) string {
	t.Helper()
	entries := []map[string]interface{}{
		{
			"name":     "Cloudflare Workers",
			"category": "hosting",
			"domains":  []string{"*.workers.dev"},
			"abuse": map[string]int{
				"phishing": 1,
				"c2":       1,
				"exfil":    1,
				"payload":  1,
				"creds":    0,
			},
		},
		{
			"name":     "Telegram",
			"category": "messaging",
			"domains":  []string{"api.telegram.org"},
			"abuse": map[string]int{
				"phishing": 0,
				"c2":       1,
				"exfil":    1,
				"payload":  0,
				"creds":    0,
			},
		},
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lolfsaas.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadLOLFSaaSDB(t *testing.T) {
	path := buildTestDB(t)
	db, err := LoadLOLFSaaSDB(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestLoadLOLFSaaSDB_MissingFile(t *testing.T) {
	db, err := LoadLOLFSaaSDB("/nonexistent/path/lolfsaas.json")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if db != nil {
		t.Fatal("expected nil DB for missing file")
	}
}

func TestLOLFSaaSMatch_Wildcard(t *testing.T) {
	path := buildTestDB(t)
	db, err := LoadLOLFSaaSDB(path)
	if err != nil {
		t.Fatal(err)
	}
	m := db.Match("evil.workers.dev")
	if m == nil {
		t.Fatal("expected match for evil.workers.dev")
	}
	if m.Name != "Cloudflare Workers" {
		t.Fatalf("expected Cloudflare Workers, got %s", m.Name)
	}
	if m.MatchedPattern != "*.workers.dev" {
		t.Fatalf("expected pattern *.workers.dev, got %s", m.MatchedPattern)
	}
}

func TestLOLFSaaSMatch_Exact(t *testing.T) {
	path := buildTestDB(t)
	db, err := LoadLOLFSaaSDB(path)
	if err != nil {
		t.Fatal(err)
	}
	m := db.Match("api.telegram.org")
	if m == nil {
		t.Fatal("expected match for api.telegram.org")
	}
	if m.Name != "Telegram" {
		t.Fatalf("expected Telegram, got %s", m.Name)
	}
}

func TestLOLFSaaSMatch_DeepSubdomain(t *testing.T) {
	path := buildTestDB(t)
	db, err := LoadLOLFSaaSDB(path)
	if err != nil {
		t.Fatal(err)
	}
	m := db.Match("a.b.c.workers.dev")
	if m == nil {
		t.Fatal("expected match for a.b.c.workers.dev")
	}
	if m.Name != "Cloudflare Workers" {
		t.Fatalf("expected Cloudflare Workers, got %s", m.Name)
	}
}

func TestLOLFSaaSMatch_NoMatch(t *testing.T) {
	path := buildTestDB(t)
	db, err := LoadLOLFSaaSDB(path)
	if err != nil {
		t.Fatal(err)
	}
	m := db.Match("example.com")
	if m != nil {
		t.Fatalf("expected no match for example.com, got %+v", m)
	}
}

func TestLOLFSaaSMatch_NilDB(t *testing.T) {
	var db *LOLFSaaSDB
	m := db.Match("evil.workers.dev")
	if m != nil {
		t.Fatalf("expected nil from nil DB, got %+v", m)
	}
}
