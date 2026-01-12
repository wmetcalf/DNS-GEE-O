package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const geoLiteDownloadEndpoint = "https://download.maxmind.com/app/geoip_download"

func maybeUpdateGeoLiteDatabases(ctx context.Context, licenseKey string, maxAge time.Duration, cityPath, asnPath string) error {
	if maxAge <= 0 {
		return nil
	}
	if strings.TrimSpace(licenseKey) == "" {
		return errors.New("maxmind license key is required when db-update-hours is set")
	}

	targets := []struct {
		path    string
		edition string
		label   string
	}{
		{cityPath, "GeoLite2-City", "GeoLite2 City"},
		{asnPath, "GeoLite2-ASN", "GeoLite2 ASN"},
	}

	for _, target := range targets {
		if target.path == "" {
			continue
		}

		needsRefresh, err := fileNeedsRefresh(target.path, maxAge)
		if err != nil {
			return fmt.Errorf("check %s freshness: %w", target.label, err)
		}
		if !needsRefresh {
			continue
		}

		fmt.Fprintf(os.Stderr, "Refreshing %s database (target: %s)\n", target.label, target.path)
		if err := downloadGeoLiteEdition(ctx, licenseKey, target.edition, target.path); err != nil {
			return fmt.Errorf("refresh %s database: %w", target.label, err)
		}
	}

	return nil
}

func fileNeedsRefresh(path string, maxAge time.Duration) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	if maxAge <= 0 {
		return false, nil
	}
	return time.Since(info.ModTime()) >= maxAge, nil
}

func downloadGeoLiteEdition(ctx context.Context, licenseKey, editionID, destPath string) error {
	if strings.TrimSpace(destPath) == "" {
		return errors.New("destination path is required")
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	params := url.Values{
		"edition_id":  {editionID},
		"license_key": {licenseKey},
		"suffix":      {"tar.gz"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geoLiteDownloadEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s archive: %w", editionID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("download %s archive: unexpected status %d: %s", editionID, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("read gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(hdr.Name), ".mmdb") {
			continue
		}
		if err := writeMMDBFile(tr, destPath); err != nil {
			return err
		}
		return nil
	}

	return errors.New("no .mmdb file found in archive")
}

func writeMMDBFile(r io.Reader, destPath string) error {
	tmp, err := os.CreateTemp(filepath.Dir(destPath), "geolite-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if _, err := io.Copy(tmp, r); err != nil {
		return fmt.Errorf("write mmdb: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync mmdb: %w", err)
	}

	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod mmdb: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close mmdb: %w", err)
	}

	if err := os.Rename(tmp.Name(), destPath); err != nil {
		return fmt.Errorf("rename mmdb: %w", err)
	}

	return nil
}
