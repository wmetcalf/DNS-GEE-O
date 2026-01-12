package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileNeedsRefreshHandlesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	needs, err := fileNeedsRefresh(path, time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !needs {
		t.Fatal("missing file should trigger refresh")
	}
}

func TestFileNeedsRefreshWithFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-ASN.mmdb")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	needs, err := fileNeedsRefresh(path, time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if needs {
		t.Fatal("recent file should not trigger refresh")
	}
}

func TestFileNeedsRefreshWithStaleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	needs, err := fileNeedsRefresh(path, time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !needs {
		t.Fatal("stale file should trigger refresh")
	}
}
