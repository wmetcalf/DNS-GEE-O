package dnsgeeo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type WhoisToolInfo struct {
	Domain                     string      `json:"domain"`
	RootDomain                 string      `json:"root_domain,omitempty"`
	Registrar                  string      `json:"registrar,omitempty"`
	RegistrarCountry           string      `json:"registrar_country,omitempty"`
	RegistrantOrg              string      `json:"registrant_org,omitempty"`
	RegistrantAddress          string      `json:"registrant_address,omitempty"`
	NameServers                []string    `json:"name_servers,omitempty"`
	IsAfraidHosted             bool        `json:"is_afraid_hosted"`
	PSLRegistrableDomain       string      `json:"psl_registrable_domain,omitempty"`
	PSLPublicRegistrableDomain string      `json:"psl_public_registrable_domain,omitempty"`
	PSLPrivateSuffix           string      `json:"psl_private_suffix,omitempty"`
	PSLPublicSuffix            string      `json:"psl_public_suffix,omitempty"`
	PSLPrivateOwner            string      `json:"psl_private_owner,omitempty"`
	PSLIsPrivate               bool        `json:"psl_is_private"`
	DDNSProviderBySuffix       string      `json:"ddns_provider_by_suffix"`
	DDNSProvidersByNS          []string    `json:"ddns_providers_by_ns"`
	DDNSProviders              []string    `json:"ddns_providers"`
	CreatedAt                  string      `json:"created_at,omitempty"`
	CreatedAtSource            string      `json:"created_at_source,omitempty"`
	AgeDays                    *int        `json:"age_days,omitempty"`
	RDAPURL                    string      `json:"rdap_url,omitempty"`
	RDAPCreatedAt              string      `json:"rdap_created_at,omitempty"`
	RDAPStatus                 []string    `json:"rdap_status,omitempty"`
	RDAPEvents                 []RDAPEvent `json:"rdap_events,omitempty"`
	WhoisCreatedAt             string      `json:"whois_created_at,omitempty"`
	WhoisExpirationDate        string      `json:"whois_expiration_date,omitempty"`
	WhoisUpdatedDate           string      `json:"whois_updated_date,omitempty"`
	WhoisError                 string      `json:"whois_error,omitempty"`
	RDAPError                  string      `json:"rdap_error,omitempty"`
	CacheHit                   bool        `json:"cache_hit,omitempty"`
}

type RDAPEvent struct {
	Action string `json:"action,omitempty"`
	Date   string `json:"date,omitempty"`
}

type PSLPrivateEntry struct {
	Suffix string `json:"suffix"`
	Owner  string `json:"owner,omitempty"`
}

// validatePythonPath validates that the Python path is safe to execute.
// It checks against an allowlist and verifies the executable is actually Python.
func validatePythonPath(pythonPath string) error {
	// Allowlist of safe Python executables
	allowlist := []string{
		"python3",
		"python",
		"/usr/bin/python3",
		"/usr/bin/python",
		"/usr/local/bin/python3",
		"/usr/local/bin/python",
	}

	for _, safe := range allowlist {
		if pythonPath == safe {
			return nil
		}
	}

	// If not in allowlist, path must be absolute
	if !filepath.IsAbs(pythonPath) {
		return fmt.Errorf("python path must be absolute or in allowlist (python3, python, /usr/bin/python3, etc)")
	}

	// Check file exists
	info, err := os.Stat(pythonPath)
	if err != nil {
		return fmt.Errorf("python path not found: %w", err)
	}

	// Check it's not a directory
	if info.IsDir() {
		return fmt.Errorf("python path is a directory")
	}

	// Check file is executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("python path is not executable")
	}

	// Verify it's actually Python by running --version
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("not a valid python executable: %w", err)
	}

	if !strings.Contains(strings.ToLower(string(output)), "python") {
		return fmt.Errorf("executable is not Python (version output: %s)", strings.TrimSpace(string(output)))
	}

	return nil
}

// validateToolPath validates that the whois tool path is safe.
func validateToolPath(toolPath string) error {
	if toolPath == "" {
		return errors.New("tool path is empty")
	}

	// Must be absolute or relative path (not just a command name)
	if !strings.Contains(toolPath, "/") && !strings.Contains(toolPath, "\\") {
		return fmt.Errorf("tool path must be a file path, not a command name")
	}

	// Check file exists
	info, err := os.Stat(toolPath)
	if err != nil {
		return fmt.Errorf("tool path not found: %w", err)
	}

	// Check it's not a directory
	if info.IsDir() {
		return fmt.Errorf("tool path is a directory")
	}

	// For security, require .py extension
	if !strings.HasSuffix(strings.ToLower(toolPath), ".py") {
		return fmt.Errorf("tool path must be a Python script (.py)")
	}

	return nil
}

func RunWhoisTool(ctx context.Context, pythonPath, toolPath string, domains []string, timeout time.Duration) (map[string]*WhoisToolInfo, error) {
	if toolPath == "" {
		return nil, errors.New("whois tool path is empty")
	}
	if pythonPath == "" {
		pythonPath = "python3"
	}

	// Validate paths for security
	if err := validateToolPath(toolPath); err != nil {
		return nil, fmt.Errorf("invalid tool path: %w", err)
	}
	if err := validatePythonPath(pythonPath); err != nil {
		return nil, fmt.Errorf("invalid python path: %w", err)
	}

	if len(domains) == 0 {
		return map[string]*WhoisToolInfo{}, nil
	}
	joined := strings.Join(domains, ",")
	timeoutSeconds := int(timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 8
	}

	args := []string{toolPath, "--list", joined, "--timeout", fmt.Sprintf("%d", timeoutSeconds)}
	cmd := exec.CommandContext(ctx, pythonPath, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := stdout.Bytes()

	var parsed []WhoisToolInfo
	if len(output) == 0 {
		if err != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("whois tool failed: %s", strings.TrimSpace(stderr.String()))
			}
			return nil, fmt.Errorf("whois tool failed: %w", err)
		}
		return nil, errors.New("whois tool output was empty")
	}
	if unmarshalErr := json.Unmarshal(output, &parsed); unmarshalErr != nil {
		if err != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("whois tool failed: %s", strings.TrimSpace(stderr.String()))
			}
			return nil, fmt.Errorf("whois tool failed: %w", err)
		}
		return nil, fmt.Errorf("whois tool output parse error: %w", unmarshalErr)
	}

	result := make(map[string]*WhoisToolInfo, len(parsed))
	for i := range parsed {
		info := parsed[i]
		if info.Domain == "" {
			continue
		}
		if info.DDNSProvidersByNS == nil {
			info.DDNSProvidersByNS = []string{}
		}
		if info.DDNSProviders == nil {
			info.DDNSProviders = []string{}
		}
		result[info.Domain] = &info
	}
	return result, nil
}

func RunWhoisPSLPrivateList(ctx context.Context, pythonPath, toolPath string, timeout time.Duration) ([]PSLPrivateEntry, error) {
	if toolPath == "" {
		return nil, errors.New("whois tool path is empty")
	}
	if pythonPath == "" {
		pythonPath = "python3"
	}

	// Validate paths for security
	if err := validateToolPath(toolPath); err != nil {
		return nil, fmt.Errorf("invalid tool path: %w", err)
	}
	if err := validatePythonPath(pythonPath); err != nil {
		return nil, fmt.Errorf("invalid python path: %w", err)
	}

	timeoutSeconds := int(timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 8
	}

	args := []string{toolPath, "--psl-private-list", "--timeout", fmt.Sprintf("%d", timeoutSeconds)}
	cmd := exec.CommandContext(ctx, pythonPath, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := stdout.Bytes()

	if len(output) == 0 {
		if err != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("whois tool failed: %s", strings.TrimSpace(stderr.String()))
			}
			return nil, fmt.Errorf("whois tool failed: %w", err)
		}
		return nil, errors.New("whois tool output was empty")
	}

	var parsed []PSLPrivateEntry
	if unmarshalErr := json.Unmarshal(output, &parsed); unmarshalErr != nil {
		if err != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("whois tool failed: %s", strings.TrimSpace(stderr.String()))
			}
			return nil, fmt.Errorf("whois tool failed: %w", err)
		}
		return nil, fmt.Errorf("whois tool output parse error: %w", unmarshalErr)
	}
	return parsed, nil
}

func uniqueDomains(inputs []string) []string {
	seen := make(map[string]struct{}, len(inputs))
	var out []string
	for _, raw := range inputs {
		host := strings.TrimSpace(strings.TrimSuffix(raw, "."))
		if host == "" {
			continue
		}
		if net.ParseIP(host) != nil {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}
