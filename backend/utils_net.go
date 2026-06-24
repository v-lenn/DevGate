package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// caches compiled regular expressions for wildcard and pattern matching
var regexCache sync.Map // pattern string -> *regexp.Regexp

// domains allowed for package downloads
var whitelist = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"github.com",
	"golang.org",
	"proxy.golang.org",
	"nodejs.org",
}

// helper to match host against custom domain patterns (supports wildcards * and regex r/pattern/)
func matchDomainPattern(host, pattern string) bool {
	h := strings.ToLower(host)
	p := strings.TrimSpace(strings.ToLower(pattern))
	if p == "" {
		return false
	}

	// raw regex check: r/pattern/
	if strings.HasPrefix(p, "r/") && strings.HasSuffix(p, "/") && len(p) > 3 {
		regexStr := p[2 : len(p)-1]
		if val, ok := regexCache.Load(p); ok {
			return val.(*regexp.Regexp).MatchString(h)
		}
		if re, err := regexp.Compile(regexStr); err == nil {
			regexCache.Store(p, re)
			return re.MatchString(h)
		}
	}

	// wildcard check (contains '*')
	if strings.Contains(p, "*") {
		if val, ok := regexCache.Load(p); ok {
			return val.(*regexp.Regexp).MatchString(h)
		}
		var buf strings.Builder
		buf.WriteString("^")
		for _, r := range p {
			switch r {
			case '*':
				buf.WriteString(".*")
			case '.':
				buf.WriteString(`\.`)
			case '?':
				buf.WriteString(".")
			default:
				buf.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		buf.WriteString("$")
		if re, err := regexp.Compile(buf.String()); err == nil {
			regexCache.Store(p, re)
			return re.MatchString(h)
		}
	}

	// exact or standard suffix match fallback
	return h == p || strings.HasSuffix(h, "."+p)
}

// checks if domain is custom-blacklisted
func isDomainBlacklisted(host string) bool {
	h := strings.ToLower(host)
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	cfg := getSettings()
	for _, pattern := range cfg.CustomDomainBlacklist {
		if matchDomainPattern(h, pattern) {
			return true
		}
	}
	return false
}

// checks if domain is whitelisted (default or custom)
func isWhitelisted(host string) bool {
	h := strings.ToLower(host)
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	cfg := getSettings()
	// Check custom whitelist first
	for _, pattern := range cfg.CustomDomainWhitelist {
		if matchDomainPattern(h, pattern) {
			return true
		}
	}
	// Check default whitelist
	for _, domain := range whitelist {
		if h == domain || strings.HasSuffix(h, "."+domain) {
			return true
		}
	}
	return false
}

// check registry api online for package registration details
func checkOnlineMetadata(name string, isNpm bool) (bool, string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, // bypass environment variables to avoid loops
		},
	}

	if isNpm {
		url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
		resp, err := client.Get(url)
		if err != nil {
			return false, ""
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return true, "package not found in official registry"
		}
		if resp.StatusCode != http.StatusOK {
			return false, ""
		}

		var data struct {
			Time map[string]string `json:"time"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false, ""
		}

		createdStr, ok := data.Time["created"]
		if !ok {
			return false, ""
		}

		created, err := time.Parse(time.RFC3339, createdStr)
		if err != nil {
			return false, ""
		}

		// flag if package is less than 48 hours old
		if time.Since(created) < 48*time.Hour {
			return true, fmt.Sprintf("package is brand new (published %s)", created.Format("2006-01-02 15:04"))
		}
	} else {
		// PyPI registry metadata check
		url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
		resp, err := client.Get(url)
		if err != nil {
			return false, ""
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return true, "package not found in official registry"
		}
		if resp.StatusCode != http.StatusOK {
			return false, ""
		}

		var data struct {
			Urls []struct {
				UploadTimeIso8601 string `json:"upload_time_iso_8601"`
			} `json:"urls"`
			Releases map[string][]struct {
				UploadTimeIso8601 string `json:"upload_time_iso_8601"`
			} `json:"releases"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false, ""
		}

		// find earliest upload time (which corresponds to package creation/first upload)
		var earliest time.Time
		hasEarliest := false

		// Check all releases first to find the absolute earliest version
		for _, releaseFiles := range data.Releases {
			for _, file := range releaseFiles {
				if file.UploadTimeIso8601 != "" {
					t, err := time.Parse(time.RFC3339, file.UploadTimeIso8601)
					if err == nil {
						if !hasEarliest || t.Before(earliest) {
							earliest = t
							hasEarliest = true
						}
					}
				}
			}
		}

		// Fallback to current version's urls upload times if releases map was empty/deprecated
		if !hasEarliest {
			for _, file := range data.Urls {
				if file.UploadTimeIso8601 != "" {
					t, err := time.Parse(time.RFC3339, file.UploadTimeIso8601)
					if err == nil {
						if !hasEarliest || t.Before(earliest) {
							earliest = t
							hasEarliest = true
						}
					}
				}
			}
		}

		if !hasEarliest {
			return false, ""
		}

		// flag if package is less than 48 hours old
		if time.Since(earliest) < 48*time.Hour {
			return true, fmt.Sprintf("package is brand new (published %s)", earliest.Format("2006-01-02 15:04"))
		}
	}

	return false, ""
}
