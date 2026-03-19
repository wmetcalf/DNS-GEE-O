package dnsgeeo

import (
	"encoding/json"
	"os"
	"strings"
)

type LOLFSaaSAbuse struct {
	Phishing int `json:"phishing"`
	C2       int `json:"c2"`
	Exfil    int `json:"exfil"`
	Payload  int `json:"payload"`
	Creds    int `json:"creds"`
}

type LOLFSaaSMatch struct {
	Name           string        `json:"name"`
	Category       string        `json:"category"`
	Abuse          LOLFSaaSAbuse `json:"abuse"`
	MatchedPattern string        `json:"matched_pattern"`
}

type lolfsaasEntry struct {
	Name     string        `json:"name"`
	Category string        `json:"category"`
	Domains  []string      `json:"domains"`
	Abuse    LOLFSaaSAbuse `json:"abuse"`
}

// LOLFSaaSDB holds parsed LOLFSaaS threat intelligence data for fast domain matching.
type LOLFSaaSDB struct {
	exact  map[string]*lolfsaasEntry
	suffix []suffixEntry
}

type suffixEntry struct {
	suffix  string
	pattern string
	entry   *lolfsaasEntry
}

// LoadLOLFSaaSDB reads and parses a LOLFSaaS JSON database file.
// Returns (nil, nil) if the file does not exist.
func LoadLOLFSaaSDB(path string) (*LOLFSaaSDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []lolfsaasEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	db := &LOLFSaaSDB{exact: make(map[string]*lolfsaasEntry)}
	for i := range entries {
		e := &entries[i]
		for _, d := range e.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if strings.HasPrefix(d, "*.") {
				sfx := d[1:] // ".workers.dev"
				db.suffix = append(db.suffix, suffixEntry{suffix: sfx, pattern: d, entry: e})
			} else {
				db.exact[d] = e
			}
		}
	}
	return db, nil
}

// Match checks whether a domain matches any entry in the LOLFSaaS database.
// Returns nil if no match is found or if db is nil.
func (db *LOLFSaaSDB) Match(domain string) *LOLFSaaSMatch {
	if db == nil {
		return nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	if e, ok := db.exact[domain]; ok {
		return &LOLFSaaSMatch{Name: e.Name, Category: e.Category, Abuse: e.Abuse, MatchedPattern: domain}
	}
	var best *suffixEntry
	for i := range db.suffix {
		s := &db.suffix[i]
		if strings.HasSuffix(domain, s.suffix) && domain != s.suffix[1:] {
			if best == nil || len(s.suffix) > len(best.suffix) {
				best = s
			}
		}
	}
	if best != nil {
		return &LOLFSaaSMatch{Name: best.entry.Name, Category: best.entry.Category, Abuse: best.entry.Abuse, MatchedPattern: best.pattern}
	}
	return nil
}
