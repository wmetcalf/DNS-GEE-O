package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"dnsgeeo/internal/dnsgeeo"
)

func main() {
	var list string
	var dnsServers string
	var timeoutMS int
	var parallel int
	var preferIPv6 bool
	var cityDB, asnDB string
	var pretty bool
	var checkMalicious bool
	var enableWhois bool
	var whoisToolPath string
	var whoisPython string
	var whoisTimeoutMS int
	var pslPrivateList bool
	var outputFile string
	var configPath string
	var maxmindKey string
	var dbUpdateHours int

	flag.StringVar(&list, "list", "", "Comma-separated list of hostnames or IPs")
	flag.StringVar(&dnsServers, "dns", "8.8.8.8:53,8.8.4.4:53", "Comma-separated DNS servers (host:port)")
	flag.IntVar(&timeoutMS, "timeout-ms", 2000, "Per-host lookup timeout (ms)")
	flag.IntVar(&parallel, "parallel", 64, "Max concurrent lookups")
	flag.BoolVar(&preferIPv6, "prefer-ipv6", true, "Also query AAAA (IPv6) addresses")
	flag.StringVar(&cityDB, "city-db", os.Getenv("GEOLITE2_CITY_DB"), "Path to GeoLite2-City.mmdb (or DB-IP City mmdb)")
	flag.StringVar(&asnDB, "asn-db", os.Getenv("GEOLITE2_ASN_DB"), "Path to GeoLite2-ASN.mmdb")
	flag.BoolVar(&pretty, "pretty", false, "Pretty-print JSON")
	flag.BoolVar(&checkMalicious, "check-malicious", true, "Check domains against Quad9 threat intelligence")
	flag.BoolVar(&enableWhois, "whois", true, "Include WHOIS/RDAP data via external tool")
	flag.StringVar(&whoisToolPath, "whois-tool", "", "Path to whois_rdap.py (used with --whois)")
	flag.StringVar(&whoisPython, "whois-python", "python3", "Python executable for whois_rdap.py")
	flag.IntVar(&whoisTimeoutMS, "whois-timeout-ms", 20000, "Timeout for whois_rdap.py in milliseconds")
	flag.BoolVar(&pslPrivateList, "psl-private-list", false, "Output PSL private suffix list via the WHOIS helper and exit")
	flag.StringVar(&outputFile, "output", "", "Output file path (default: stdout)")
	flag.StringVar(&configPath, "config", "", "Optional config file path (key=value format). CLI args override file values.")
	flag.StringVar(&maxmindKey, "maxmind-license-key", os.Getenv("MAXMIND_LICENSE_KEY"), "MaxMind license key for GeoLite2 auto-updates")
	flag.IntVar(&dbUpdateHours, "db-update-hours", 0, "Refresh GeoLite2 DBs when older than this many hours (0 disables)")
	flag.Parse()

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	configValues, configSource, err := resolveConfigPath(configPath)
	if err != nil {
		if configSource == "" {
			configSource = configPath
		}
		fmt.Fprintf(os.Stderr, "Config error (%s): %v\n", configSource, err)
		os.Exit(1)
	}

	if len(configValues) > 0 {
		opts := cliOptions{
			dnsServers:     &dnsServers,
			timeoutMS:      &timeoutMS,
			parallel:       &parallel,
			preferIPv6:     &preferIPv6,
			cityDB:         &cityDB,
			asnDB:          &asnDB,
			pretty:         &pretty,
			checkMalicious: &checkMalicious,
			enableWhois:    &enableWhois,
			whoisToolPath:  &whoisToolPath,
			whoisPython:    &whoisPython,
			whoisTimeoutMS: &whoisTimeoutMS,
			outputFile:     &outputFile,
			maxmindKey:     &maxmindKey,
			dbUpdateHours:  &dbUpdateHours,
		}

		if err := applyConfigValues(configValues, setFlags, opts); err != nil {
			if configSource == "" {
				configSource = "config file"
			}
			fmt.Fprintf(os.Stderr, "Config parse error (%s): %v\n", configSource, err)
			os.Exit(1)
		}
	}

	if whoisToolPath == "" {
		if _, err := os.Stat("./tools/whois_rdap.py"); err == nil {
			whoisToolPath = "./tools/whois_rdap.py"
		}
	}

	if pslPrivateList {
		if whoisToolPath == "" {
			fmt.Fprintln(os.Stderr, "psl-private-list requires whois-rdap tool path; use --whois-tool")
			os.Exit(2)
		}
		wctx, cancel := context.WithTimeout(context.Background(), time.Duration(whoisTimeoutMS)*time.Millisecond)
		defer cancel()
		entries, err := dnsgeeo.RunWhoisPSLPrivateList(wctx, whoisPython, whoisToolPath, time.Duration(whoisTimeoutMS)*time.Millisecond)
		if err != nil {
			fmt.Fprintln(os.Stderr, "PSL private list error:", err)
			os.Exit(1)
		}
		var out []byte
		if pretty {
			out, _ = json.MarshalIndent(entries, "", "  ")
		} else {
			out, _ = json.Marshal(entries)
		}
		if outputFile != "" {
			if err := os.WriteFile(outputFile, out, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
				os.Exit(1)
			}
			return
		}
		os.Stdout.Write(out)
		return
	}

	if !setFlags["whois"] {
		if _, ok := configValues["whois"]; !ok && whoisToolPath != "" && !enableWhois {
			enableWhois = true
		}
	}

	var inputs []string
	if list != "" {
		for _, t := range strings.Split(list, ",") {
			tt := strings.TrimSpace(t)
			if tt != "" {
				inputs = append(inputs, tt)
			}
		}
	}
	inputs = append(inputs, flag.Args()...)

	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: dnsgeeo [--config file] [--list host1,host2] [--dns servers] [--timeout-ms N] [--parallel N] [--prefer-ipv6 bool] [--city-db path] [--asn-db path] [--check-malicious] [--whois --whois-tool path] [--pretty] [hosts...]")
		os.Exit(2)
	}

	if dbUpdateHours < 0 {
		fmt.Fprintln(os.Stderr, "--db-update-hours cannot be negative")
		os.Exit(2)
	}

	dbUpdateInterval := time.Duration(dbUpdateHours) * time.Hour
	if dbUpdateInterval > 0 {
		if cityDB == "" && asnDB == "" {
			fmt.Fprintln(os.Stderr, "db-update-hours is set but no GeoLite2 DB paths were provided; skipping auto-update")
		} else {
			updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			if err := maybeUpdateGeoLiteDatabases(updateCtx, maxmindKey, dbUpdateInterval, cityDB, asnDB); err != nil {
				cancel()
				fmt.Fprintln(os.Stderr, "DB auto-update error:", err)
				os.Exit(1)
			}
			cancel()
		}
	}

	cfg := dnsgeeo.Config{
		DNSServers:     dnsgeeo.ParseServers(dnsServers),
		LookupTimeout:  time.Duration(timeoutMS) * time.Millisecond,
		Parallelism:    parallel,
		PreferIPv6:     preferIPv6,
		CheckMalicious: checkMalicious,
		EnableWhois:    enableWhois,
		WhoisToolPath:  whoisToolPath,
		WhoisPython:    whoisPython,
		WhoisTimeout:   time.Duration(whoisTimeoutMS) * time.Millisecond,
		CityDBPath:     cityDB,
		ASNDBPath:      asnDB,
		IPCacheSize:    10000,
		IPCacheTTL:     10 * time.Minute,
	}

	resolver := dnsgeeo.NewRRResolver(cfg.DNSServers)
	city, asn, err := dnsgeeo.OpenDBs(&cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DB error:", err)
		os.Exit(1)
	}
	defer func() {
		if city != nil {
			_ = city.Close()
		}
		if asn != nil {
			_ = asn.Close()
		}
	}()

	dnsgeeo.InitCache(cfg.IPCacheSize, cfg.IPCacheTTL)

	ctx := context.Background()
	results, err := dnsgeeo.ResolveAndEnrichBatch(ctx, resolver, inputs, &cfg, city, asn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Lookup error:", err)
		os.Exit(1)
	}

	var out []byte
	if pretty {
		out, _ = json.MarshalIndent(results, "", "  ")
	} else {
		out, _ = json.Marshal(results)
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, out, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(out)
	}
}
