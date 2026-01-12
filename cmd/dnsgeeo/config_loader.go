package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type cliOptions struct {
	dnsServers     *string
	timeoutMS      *int
	parallel       *int
	preferIPv6     *bool
	cityDB         *string
	asnDB          *string
	pretty         *bool
	checkMalicious *bool
	enableWhois    *bool
	whoisToolPath  *string
	whoisPython    *string
	whoisTimeoutMS *int
	outputFile     *string
	maxmindKey     *string
	dbUpdateHours  *int
}

func resolveConfigPath(explicitPath string) (map[string]string, string, error) {
	if explicitPath != "" {
		cfg, err := parseConfigFile(explicitPath)
		return cfg, explicitPath, err
	}

	for _, path := range defaultConfigPaths() {
		cfg, err := parseConfigFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, path, err
		}
		return cfg, path, nil
	}

	return nil, "", nil
}

var configPathOverrides []string

func defaultConfigPaths() []string {
	if len(configPathOverrides) > 0 {
		return configPathOverrides
	}
	paths := []string{"/usr/local/etc/dnsgeeo.conf", "/etc/dnsgeeo.conf"}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return paths
	}
	userPath := filepath.Join(home, ".config", "dnsgeeo", "dnsgeeo.conf")
	return append([]string{userPath}, paths...)
}

func parseConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseConfig(f)
}

func parseConfig(r io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(r)
	result := make(map[string]string)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		idx := strings.IndexRune(line, '=')
		if idx == -1 {
			return nil, fmt.Errorf("invalid config line %d: %q", lineNumber, line)
		}

		rawKey := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		key := canonicalKey(rawKey)

		if key == "" {
			return nil, fmt.Errorf("invalid config key on line %d", lineNumber)
		}

		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func canonicalKey(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	key = strings.ReplaceAll(key, "_", "-")
	return key
}

func applyConfigValues(values map[string]string, setFlags map[string]bool, opts cliOptions) error {
	for key, val := range values {
		switch key {
		case "dns":
			if opts.dnsServers != nil && !setFlags["dns"] {
				*opts.dnsServers = val
			}
		case "timeout-ms":
			if opts.timeoutMS != nil && !setFlags["timeout-ms"] {
				parsed, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("timeout-ms must be an integer: %w", err)
				}
				*opts.timeoutMS = parsed
			}
		case "parallel":
			if opts.parallel != nil && !setFlags["parallel"] {
				parsed, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("parallel must be an integer: %w", err)
				}
				*opts.parallel = parsed
			}
		case "prefer-ipv6":
			if opts.preferIPv6 != nil && !setFlags["prefer-ipv6"] {
				parsed, err := strconv.ParseBool(val)
				if err != nil {
					return fmt.Errorf("prefer-ipv6 must be a boolean: %w", err)
				}
				*opts.preferIPv6 = parsed
			}
		case "city-db":
			if opts.cityDB != nil && !setFlags["city-db"] {
				*opts.cityDB = val
			}
		case "asn-db":
			if opts.asnDB != nil && !setFlags["asn-db"] {
				*opts.asnDB = val
			}
		case "pretty":
			if opts.pretty != nil && !setFlags["pretty"] {
				parsed, err := strconv.ParseBool(val)
				if err != nil {
					return fmt.Errorf("pretty must be a boolean: %w", err)
				}
				*opts.pretty = parsed
			}
		case "check-malicious":
			if opts.checkMalicious != nil && !setFlags["check-malicious"] {
				parsed, err := strconv.ParseBool(val)
				if err != nil {
					return fmt.Errorf("check-malicious must be a boolean: %w", err)
				}
				*opts.checkMalicious = parsed
			}
		case "whois":
			if opts.enableWhois != nil && !setFlags["whois"] {
				parsed, err := strconv.ParseBool(val)
				if err != nil {
					return fmt.Errorf("whois must be a boolean: %w", err)
				}
				*opts.enableWhois = parsed
			}
		case "whois-tool":
			if opts.whoisToolPath != nil && !setFlags["whois-tool"] {
				*opts.whoisToolPath = val
			}
		case "whois-python":
			if opts.whoisPython != nil && !setFlags["whois-python"] {
				*opts.whoisPython = val
			}
		case "whois-timeout-ms":
			if opts.whoisTimeoutMS != nil && !setFlags["whois-timeout-ms"] {
				parsed, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("whois-timeout-ms must be an integer: %w", err)
				}
				*opts.whoisTimeoutMS = parsed
			}
		case "output":
			if opts.outputFile != nil && !setFlags["output"] {
				*opts.outputFile = val
			}
		case "maxmind-license-key":
			if opts.maxmindKey != nil && !setFlags["maxmind-license-key"] {
				*opts.maxmindKey = val
			}
		case "db-update-hours":
			if opts.dbUpdateHours != nil && !setFlags["db-update-hours"] {
				parsed, err := strconv.Atoi(val)
				if err != nil {
					return fmt.Errorf("db-update-hours must be an integer: %w", err)
				}
				*opts.dbUpdateHours = parsed
			}
		}
	}

	return nil
}
