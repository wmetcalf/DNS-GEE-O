package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	content := `
# comment
dns = 1.1.1.1
timeout_ms=1500
prefer-ipv6=false
city-db="/tmp/City.mmdb"
maxmind-license-key=abc123
`
	cfg, err := parseConfig(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}

	if cfg["dns"] != "1.1.1.1" {
		t.Fatalf("expected dns to be parsed, got %q", cfg["dns"])
	}

	if cfg["timeout-ms"] != "1500" {
		t.Fatalf("expected timeout-ms key to be canonicalized, got %q", cfg["timeout-ms"])
	}

	if cfg["prefer-ipv6"] != "false" {
		t.Fatalf("prefer-ipv6 expected false, got %q", cfg["prefer-ipv6"])
	}

	if cfg["city-db"] != "/tmp/City.mmdb" {
		t.Fatalf("city-db expected quoted path to be trimmed, got %q", cfg["city-db"])
	}

	if cfg["maxmind-license-key"] != "abc123" {
		t.Fatalf("expected maxmind-license-key to be parsed, got %q", cfg["maxmind-license-key"])
	}
}

func TestApplyConfigValuesRespectsOverrides(t *testing.T) {
	cfg := map[string]string{
		"dns":             "1.1.1.1",
		"parallel":        "200",
		"prefer-ipv6":     "false",
		"pretty":          "true",
		"check-malicious": "true",
	}

	dnsServers := "8.8.8.8"
	parallel := 64
	preferIPv6 := true
	pretty := false
	checkMalicious := false

	setFlags := map[string]bool{"dns": true}

	opts := cliOptions{
		dnsServers:     &dnsServers,
		parallel:       &parallel,
		preferIPv6:     &preferIPv6,
		pretty:         &pretty,
		checkMalicious: &checkMalicious,
	}

	if err := applyConfigValues(cfg, setFlags, opts); err != nil {
		t.Fatalf("applyConfigValues returned error: %v", err)
	}

	if dnsServers != "8.8.8.8" {
		t.Fatalf("dns flag was explicitly set; expected CLI value to win, got %q", dnsServers)
	}

	if parallel != 200 {
		t.Fatalf("parallel expected 200, got %d", parallel)
	}

	if preferIPv6 {
		t.Fatalf("preferIPv6 expected false from config")
	}

	if !pretty {
		t.Fatalf("pretty expected true from config")
	}

	if !checkMalicious {
		t.Fatalf("checkMalicious expected true from config")
	}
}

func TestApplyConfigValuesRejectsInvalidNumbers(t *testing.T) {
	cfg := map[string]string{"parallel": "bad"}
	parallel := 64
	opts := cliOptions{parallel: &parallel}

	err := applyConfigValues(cfg, map[string]bool{}, opts)
	if err == nil {
		t.Fatal("expected error for invalid parallel value")
	}
}

func TestApplyConfigValuesParsesDbUpdateHours(t *testing.T) {
	cfg := map[string]string{"db-update-hours": "12"}
	val := 0
	opts := cliOptions{dbUpdateHours: &val}

	if err := applyConfigValues(cfg, map[string]bool{}, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if val != 12 {
		t.Fatalf("expected db-update-hours to be 12, got %d", val)
	}
}

func TestResolveConfigPathSearchesDefaults(t *testing.T) {
	tmp := t.TempDir()
	first := filepath.Join(tmp, "first.conf")
	second := filepath.Join(tmp, "second.conf")

	if err := os.WriteFile(second, []byte("dns=9.9.9.9"), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	originalPaths := configPathOverrides
	configPathOverrides = []string{first, second}
	t.Cleanup(func() { configPathOverrides = originalPaths })

	cfg, usedPath, err := resolveConfigPath("")
	if err != nil {
		t.Fatalf("resolveConfigPath error: %v", err)
	}

	if usedPath != second {
		t.Fatalf("expected second path to be selected, got %q", usedPath)
	}

	if cfg["dns"] != "9.9.9.9" {
		t.Fatalf("expected dns from second config, got %q", cfg["dns"])
	}
}

func TestResolveConfigPathExplicitMissing(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "missing.conf")

	_, _, err := resolveConfigPath(path)
	if err == nil {
		t.Fatal("expected error for missing explicit config path")
	}

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}
