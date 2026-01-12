package dnsgeeo

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
	geoip2 "github.com/oschwald/geoip2-golang"
)

// ---------------- Types ----------------

type Config struct {
	DNSServers     []string
	LookupTimeout  time.Duration
	Parallelism    int
	PreferIPv6     bool
	CheckMalicious bool
	EnableWhois    bool
	WhoisToolPath  string
	WhoisPython    string
	WhoisTimeout   time.Duration

	CityDBPath  string
	ASNDBPath   string
	IPCacheSize int
	IPCacheTTL  time.Duration
}

type GeoInfo struct {
	CountryISO  string  `json:"country_iso,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}

type ASNInfo struct {
	Number uint   `json:"number,omitempty"`
	Org    string `json:"organization,omitempty"`
}

type IPEnriched struct {
	IP     string   `json:"ip"`
	Family string   `json:"family"`
	Geo    *GeoInfo `json:"geo,omitempty"`
	ASN    *ASNInfo `json:"asn,omitempty"`
}

type HostResult struct {
	Domain     string         `json:"domain"`
	Resolved   bool           `json:"resolved"`
	DNSServer  string         `json:"dns_server,omitempty"`
	Malicious  *bool          `json:"malicious,omitempty"`
	IPs        []IPEnriched   `json:"ips,omitempty"`
	Whois      *WhoisToolInfo `json:"whois,omitempty"`
	WhoisError string         `json:"whois_error,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// -------------- Resolver ---------------

type RRResolver struct {
	servers []string
	rr      uint32
}

func NewRRResolver(servers []string) *RRResolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "8.8.4.4:53"}
	}
	return &RRResolver{servers: servers}
}

func (r *RRResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, string, error) {
	if len(r.servers) == 0 {
		return nil, "", errors.New("no DNS servers configured")
	}
	var usedServer string
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			idx := int(atomic.AddUint32(&r.rr, 1)-1) % len(r.servers)
			usedServer = r.servers[idx]
			d := &net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, usedServer)
		},
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	return ips, usedServer, err
}

func ParseServers(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return []string{"8.8.8.8:53", "8.8.4.4:53"}
	}
	parts := strings.Split(csv, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, ":") {
			p = p + ":53"
		}
		out = append(out, p)
	}
	return out
}

func classifyLookupError(err error) string {
	if err == nil {
		return ""
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such host"):
		return "nxdomain"
	case strings.Contains(msg, "server misbehaving"):
		return "servfail"
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "i/o timeout"):
		return "timeout"
	default:
		return "lookup_failed"
	}
}

// -------------- DB open/cache ----------

var ipCache *expirable.LRU[string, IPEnriched]

func InitCache(size int, ttl time.Duration) {
	if size <= 0 {
		size = 10000
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	ipCache = expirable.NewLRU[string, IPEnriched](size, nil, ttl)
}

func OpenDBs(cfg *Config) (city *geoip2.Reader, asn *geoip2.Reader, err error) {
	if cfg.CityDBPath != "" {
		c, e := geoip2.Open(cfg.CityDBPath)
		if e != nil {
			return nil, nil, e
		}
		city = c
	}
	if cfg.ASNDBPath != "" {
		a, e := geoip2.Open(cfg.ASNDBPath)
		if e != nil {
			if city != nil {
				_ = city.Close()
			}
			return nil, nil, e
		}
		asn = a
	}
	return city, asn, nil
}

// -------------- Malicious domain check -------------

// CheckMaliciousDomain uses Quad9's threat intelligence to check if a domain is malicious.
// Quad9 (9.9.9.9) blocks malicious domains by returning NXDOMAIN with RA flag set to 0.
// We only check Quad9 if the domain resolved successfully with our regular resolvers.
func CheckMaliciousDomain(ctx context.Context, domain string, resolvedSuccessfully bool, timeout time.Duration) bool {
	if !resolvedSuccessfully {
		return false
	}

	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: timeout,
	}

	response, _, err := client.Exchange(msg, "9.9.9.9:53")
	if err != nil {
		return false
	}

	if response.Rcode == dns.RcodeNameError && !response.RecursionAvailable {
		return true
	}

	return false
}

// -------------- Core logic -------------

func ResolveAndEnrichBatch(ctx context.Context, r *RRResolver, inputs []string, cfg *Config, cityDB *geoip2.Reader, asnDB *geoip2.Reader) ([]HostResult, error) {
	timeout := cfg.LookupTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	par := cfg.Parallelism
	if par <= 0 {
		par = 64
	}
	results := make([]HostResult, len(inputs))
	var whoisByDomain map[string]*WhoisToolInfo
	var whoisErr string
	if cfg.EnableWhois && cfg.WhoisToolPath != "" {
		domains := uniqueDomains(inputs)
		if len(domains) > 0 {
			perDomain := cfg.WhoisTimeout
			if perDomain <= 0 {
				perDomain = timeout
				if perDomain < 8*time.Second {
					perDomain = 8 * time.Second
				}
			}
			toolTimeout := perDomain * time.Duration(len(domains))
			if toolTimeout > 5*time.Minute {
				toolTimeout = 5 * time.Minute
			}
			wctx, cancel := context.WithTimeout(ctx, toolTimeout)
			info, err := RunWhoisTool(wctx, cfg.WhoisPython, cfg.WhoisToolPath, domains, toolTimeout)
			cancel()
			if err != nil {
				whoisErr = err.Error()
			} else {
				whoisByDomain = info
			}
		}
	}

	sem := make(chan struct{}, par)
	var wg sync.WaitGroup

	for i, raw := range inputs {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, token string) {
			defer wg.Done()
			defer func() { <-sem }()

			host := strings.TrimSpace(strings.TrimSuffix(token, "."))
			if host == "" {
				results[idx] = HostResult{Domain: host, Resolved: false, Error: "lookup_failed"}
				return
			}

			if ip := net.ParseIP(host); ip != nil {
				info, _ := EnrichIP(ip, cityDB, asnDB)
				results[idx] = HostResult{
					Domain:   host,
					Resolved: true,
					IPs:      []IPEnriched{info},
				}
				return
			}

			cctx, cancel := context.WithTimeout(ctx, timeout)
			addrs, usedServer, err := r.LookupIPAddr(cctx, host)
			cancel()

			var errText string
			if err != nil {
				errText = classifyLookupError(err)
			}
			if errText == "" && len(addrs) == 0 {
				errText = "no_records"
			}

			var maliciousPtr *bool
			if cfg.CheckMalicious && len(addrs) > 0 {
				isMalicious := CheckMaliciousDomain(ctx, host, true, timeout)
				maliciousPtr = &isMalicious
			}

			uniq := unique(addrs, cfg.PreferIPv6)
			enriched := make([]IPEnriched, 0, len(uniq))
			for _, a := range uniq {
				info, _ := EnrichIP(a.IP, cityDB, asnDB)
				enriched = append(enriched, info)
			}

			result := HostResult{
				Domain:    host,
				Resolved:  len(enriched) > 0,
				DNSServer: usedServer,
				Malicious: maliciousPtr,
				IPs:       enriched,
				Error:     errText,
			}
			if whoisByDomain != nil {
				if info, ok := whoisByDomain[host]; ok {
					result.Whois = info
				} else if whoisErr != "" {
					result.WhoisError = whoisErr
				}
			} else if whoisErr != "" {
				result.WhoisError = whoisErr
			}
			results[idx] = result
		}(i, raw)
	}

	wg.Wait()
	return results, nil
}

func unique(in []net.IPAddr, preferV6 bool) []net.IPAddr {
	seen := map[string]struct{}{}
	out := make([]net.IPAddr, 0, len(in))
	for _, a := range in {
		ip := a.IP
		if ip == nil {
			continue
		}
		if ip.To4() == nil && !preferV6 {
			continue
		}
		s := ip.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, a)
	}
	return out
}

func EnrichIP(ip net.IP, cityDB *geoip2.Reader, asnDB *geoip2.Reader) (IPEnriched, error) {
	key := ip.String()
	if ipCache != nil {
		if v, ok := ipCache.Get(key); ok {
			return v, nil
		}
	}
	info := IPEnriched{IP: key}
	if ip.To4() != nil {
		info.Family = "v4"
	} else {
		info.Family = "v6"
	}

	if cityDB != nil {
		if rec, err := cityDB.City(ip); err == nil {
			g := GeoInfo{
				CountryISO:  rec.Country.IsoCode,
				CountryName: rec.Country.Names["en"],
				Latitude:    rec.Location.Latitude,
				Longitude:   rec.Location.Longitude,
			}
			if len(rec.Subdivisions) > 0 {
				g.Region = rec.Subdivisions[0].Names["en"]
			}
			if rec.City.Names != nil {
				g.City = rec.City.Names["en"]
			}
			info.Geo = &g
		}
	}
	if asnDB != nil {
		if rec, err := asnDB.ASN(ip); err == nil {
			info.ASN = &ASNInfo{
				Number: rec.AutonomousSystemNumber,
				Org:    rec.AutonomousSystemOrganization,
			}
		}
	}

	if ipCache != nil {
		ipCache.Add(key, info)
	}
	return info, nil
}

// -------------- helpers ----------------

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

type JSON = map[string]any

func Marshal(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
