package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type cachedResult struct {
	isMalicious bool
	reason      string
	expiry      time.Time
}

var (
	reputationHosts        = make(map[string]bool)
	reputationIPs          = make(map[string]bool)
	reputationMutex        sync.RWMutex
	reputationCacheMap     sync.Map // caches host/ip lookup results
	maliciousPackages      = make(map[string]bool)
	maliciousPackagesMutex sync.RWMutex
)

const (
	urlhausFeedURL       = "https://urlhaus.abuse.ch/downloads/hostfile/"
	feodoFeedURL         = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
	npmMaliciousFeedURL  = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json"
	pypiMaliciousFeedURL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
)

var (
	hostsFileLocal        = filepath.Join(getConfigDir(), "reputation_hosts.txt")
	ipsFileLocal          = filepath.Join(getConfigDir(), "reputation_ips.txt")
	maliciousPackagesFile = filepath.Join(getConfigDir(), "malicious_packages.json")
)

// initializes feeds and background sync loop
func initReputationEngine() {
	// create config directory if not exists
	os.MkdirAll(getConfigDir(), 0755)

	// load local files if they exist from a previous run
	loadLocalReputationFeeds()
	loadLocalMaliciousPackages()

	// sync fresh feeds in background
	go func() {
		// run initial sync
		syncReputationFeeds()
		// start recurring sync every 12 hours
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			syncReputationFeeds()
		}
	}()
}

// loads cached feeds from filesystem
func loadLocalReputationFeeds() {
	reputationMutex.Lock()
	defer reputationMutex.Unlock()

	// reset maps to clear any stale blocklist entries removed in recent synchronization
	reputationHosts = make(map[string]bool)
	reputationIPs = make(map[string]bool)

	loadedHosts := 0
	loadedIPs := 0

	// load hosts
	if f, err := os.Open(hostsFileLocal); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "127.0.0.1" {
				domain := strings.ToLower(parts[1])
				reputationHosts[domain] = true
				loadedHosts++
			}
		}
	}

	// load ips
	if f, err := os.Open(ipsFileLocal); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ipStr := strings.Fields(line)[0]
			if net.ParseIP(ipStr) != nil {
				reputationIPs[ipStr] = true
				loadedIPs++
			}
		}
	}

	log.Printf("[Reputation] Loaded cached feeds: %d hosts, %d IPs", loadedHosts, loadedIPs)
}

// downloads fresh blocklists from abuse.ch
func syncReputationFeeds() {
	cfg := getSettings()
	if !cfg.LocalFeedSyncActive {
		return
	}

	log.Println("[Reputation] Synchronizing threat feeds...")
	client := &http.Client{Timeout: 30 * time.Second}

	// download urlhaus hostfile
	if respHosts, err := client.Get(urlhausFeedURL); err == nil {
		if respHosts.StatusCode == http.StatusOK {
			if out, err := os.Create(hostsFileLocal); err == nil {
				io.Copy(out, respHosts.Body)
				out.Close()
			}
		} else {
			log.Printf("[Reputation] Failed to sync URLhaus hosts: status code %d", respHosts.StatusCode)
		}
		respHosts.Body.Close()
	} else {
		log.Printf("[Reputation] Failed to sync URLhaus hosts: %v", err)
	}

	// 2. Download Feodo Tracker IP list
	if respIPs, err := client.Get(feodoFeedURL); err == nil {
		if respIPs.StatusCode == http.StatusOK {
			if out, err := os.Create(ipsFileLocal); err == nil {
				io.Copy(out, respIPs.Body)
				out.Close()
			}
		} else {
			log.Printf("[Reputation] Failed to sync Feodo Tracker IPs: status code %d", respIPs.StatusCode)
		}
		respIPs.Body.Close()
	} else {
		log.Printf("[Reputation] Failed to sync Feodo Tracker IPs: %v", err)
	}

	// 3. Download NPM malicious packages list
	npmMalicious := make(map[string]interface{})
	if respNpm, err := client.Get(npmMaliciousFeedURL); err == nil {
		if respNpm.StatusCode == http.StatusOK {
			json.NewDecoder(respNpm.Body).Decode(&npmMalicious)
		} else {
			log.Printf("[Reputation] Failed to sync NPM malicious packages: status code %d", respNpm.StatusCode)
		}
		respNpm.Body.Close()
	} else {
		log.Printf("[Reputation] Failed to sync NPM malicious packages: %v", err)
	}

	// 4. Download PyPI malicious packages list
	pypiMalicious := make(map[string]interface{})
	if respPypi, err := client.Get(pypiMaliciousFeedURL); err == nil {
		if respPypi.StatusCode == http.StatusOK {
			json.NewDecoder(respPypi.Body).Decode(&pypiMalicious)
		} else {
			log.Printf("[Reputation] Failed to sync PyPI malicious packages: status code %d", respPypi.StatusCode)
		}
		respPypi.Body.Close()
	} else {
		log.Printf("[Reputation] Failed to sync PyPI malicious packages: %v", err)
	}

	// Consolidate package names
	packageSet := make(map[string]bool)
	for name := range npmMalicious {
		nameClean := strings.ToLower(strings.TrimSpace(name))
		if nameClean != "" {
			packageSet[nameClean] = true
		}
	}
	for name := range pypiMalicious {
		nameClean := strings.ToLower(strings.TrimSpace(name))
		if nameClean != "" {
			packageSet[nameClean] = true
		}
	}

	// Only overwrite/save if we successfully got any packages from remote (to prevent wiping local DB on network issues)
	if len(packageSet) > 0 {
		var list []string
		for pkg := range packageSet {
			list = append(list, pkg)
		}
		if data, err := json.MarshalIndent(list, "", "  "); err == nil {
			if err := os.WriteFile(maliciousPackagesFile, data, 0644); err != nil {
				log.Printf("[Reputation] Failed to write malicious packages file: %v", err)
			}
		}
	}

	// Reload feeds into memory
	loadLocalReputationFeeds()
	loadLocalMaliciousPackages()
}

// checkCloudflareDNS queries Cloudflare's security DNS 1.1.1.2 to verify if domain is blocked
func checkCloudflareDNS(domain string) (bool, string) {
	// Standard lookup (first check if it resolves at all on local DNS)
	stdIPs, stdErr := net.LookupHost(domain)
	if stdErr != nil {
		// If standard DNS can't resolve it, it's offline or NXDOMAIN anyway
		return false, ""
	}
	if len(stdIPs) == 0 {
		return false, ""
	}

	// Direct DNS request to Cloudflare Security DNS (1.1.1.2)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 200 * time.Millisecond}
			return d.DialContext(ctx, "udp", "1.1.1.2:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	cfIPs, cfErr := resolver.LookupHost(ctx, domain)
	if cfErr != nil {
		// NXDOMAIN on Cloudflare but standard DNS resolved it -> Blocked!
		if strings.Contains(cfErr.Error(), "no such host") {
			return true, "Cloudflare Security DNS blocked (NXDOMAIN)"
		}
		return false, ""
	}

	for _, ip := range cfIPs {
		if ip == "0.0.0.0" || ip == "::" {
			return true, "Cloudflare Security DNS blocked (resolved to 0.0.0.0/::)"
		}
	}

	// Standard DNS resolved it, but Cloudflare DNS returned no IPs -> Blocked!
	if len(cfIPs) == 0 && len(stdIPs) > 0 {
		return true, "Cloudflare Security DNS blocked (empty response)"
	}

	return false, ""
}

// checkURLhausLive performs a real-time HTTP query to URLhaus's API
func checkURLhausLive(host string) (bool, string) {
	client := &http.Client{Timeout: 300 * time.Millisecond}
	resp, err := client.PostForm("https://urlhaus-api.abuse.ch/v1/host/", url.Values{"host": {host}})
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, ""
	}

	var result struct {
		QueryStatus string `json:"query_status"`
		HostStatus  string `json:"host_status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, ""
	}

	if result.QueryStatus == "ok" && result.HostStatus == "malicious" {
		return true, "URLhaus Live API flagged as malicious"
	}
	return false, ""
}

// reverseIPv4 reverses IPv4 address bytes (e.g. 1.2.3.4 -> 4.3.2.1)
func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// checkIPDNSBL queries public DNSBLs (DroneBL / Spamhaus) to verify IP reputation
func checkIPDNSBL(ip string) (bool, string) {
	revIP := reverseIPv4(ip)
	if revIP == "" {
		return false, ""
	}

	lists := []struct {
		zone string
		name string
	}{
		{"dnsbl.dronebl.org", "DroneBL"},
		{"zen.spamhaus.org", "Spamhaus ZEN"},
	}

	for _, list := range lists {
		resolver := &net.Resolver{PreferGo: true}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		queryHost := fmt.Sprintf("%s.%s", revIP, list.zone)
		ips, err := resolver.LookupHost(ctx, queryHost)
		cancel()

		if err == nil && len(ips) > 0 {
			// Listed in DNSBL! Returns a loopback address like 127.0.0.x
			for _, resIP := range ips {
				if strings.HasPrefix(resIP, "127.0.0.") {
					return true, fmt.Sprintf("DNSBL Listed on %s (%s)", list.name, resIP)
				}
			}
		}
	}
	return false, ""
}

// checkHostReputation resolves host reputation against local cache, local feeds, and keyless APIs
func checkHostReputation(hostOrIp string) (bool, string) {
	hostOrIp = strings.ToLower(strings.TrimSpace(hostOrIp))
	if hostOrIp == "" {
		return false, ""
	}

	// 1. Bypass whitelist
	if isWhitelisted(hostOrIp) {
		return false, ""
	}

	// 2. Check Cache
	if val, ok := reputationCacheMap.Load(hostOrIp); ok {
		res := val.(cachedResult)
		if res.isMalicious {
			return true, res.reason
		}
		if time.Now().Before(res.expiry) {
			return false, ""
		}
		reputationCacheMap.Delete(hostOrIp)
	}

	cfg := getSettings()
	if !cfg.ThreatIntelActive {
		return false, ""
	}

	// Helper to extract IP if a port was provided (e.g. host:port)
	cleanHost := hostOrIp
	if idx := strings.Index(cleanHost, ":"); idx != -1 {
		cleanHost = cleanHost[:idx]
	}

	// Determine if it is an IP address
	parsedIP := net.ParseIP(cleanHost)
	isIP := parsedIP != nil

	// 3. Check Local Synchronized Feeds
	reputationMutex.RLock()
	isMaliciousLocal := false
	reasonLocal := ""
	if isIP {
		if reputationIPs[cleanHost] {
			isMaliciousLocal = true
			reasonLocal = "local threat feed blocklist (known malicious IP)"
		}
	} else {
		if reputationHosts[cleanHost] {
			isMaliciousLocal = true
			reasonLocal = "local threat feed blocklist (known malicious domain)"
		}
	}
	reputationMutex.RUnlock()

	if isMaliciousLocal {
		reputationCacheMap.Store(hostOrIp, cachedResult{
			isMalicious: true,
			reason:      reasonLocal,
			expiry:      time.Time{}, // permanent for current session
		})
		return true, reasonLocal
	}

	// 4. DNS Checks
	if isIP {
		// Query DNSBL for IP address
		if cfg.CloudflareDNSActive {
			if isMalicious, reason := checkIPDNSBL(cleanHost); isMalicious {
				reputationCacheMap.Store(hostOrIp, cachedResult{
					isMalicious: true,
					reason:      reason,
					expiry:      time.Time{},
				})
				return true, reason
			}
		}
	} else {
		// Query Cloudflare malware-blocking DNS for Domain
		if cfg.CloudflareDNSActive {
			if isMalicious, reason := checkCloudflareDNS(cleanHost); isMalicious {
				reputationCacheMap.Store(hostOrIp, cachedResult{
					isMalicious: true,
					reason:      reason,
					expiry:      time.Time{},
				})
				return true, reason
			}
		}
	}

	// 5. Live URLhaus API Lookup
	if cfg.URLhausLiveActive {
		if isMalicious, reason := checkURLhausLive(cleanHost); isMalicious {
			reputationCacheMap.Store(hostOrIp, cachedResult{
				isMalicious: true,
				reason:      reason,
				expiry:      time.Time{},
			})
			return true, reason
		}
	}

	// 6. Not flagged -> Store as clean in cache for 24h
	reputationCacheMap.Store(hostOrIp, cachedResult{
		isMalicious: false,
		reason:      "",
		expiry:      time.Now().Add(24 * time.Hour),
	})

	return false, ""
}

// loadLocalMaliciousPackages loads cached malicious package names from filesystem
func loadLocalMaliciousPackages() {
	maliciousPackagesMutex.Lock()
	defer maliciousPackagesMutex.Unlock()

	data, err := os.ReadFile(maliciousPackagesFile)
	if err != nil {
		log.Printf("[Reputation] No local malicious packages database found: %v", err)
		return
	}

	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("[Reputation] Failed to parse local malicious packages database: %v", err)
		return
	}

	// Reset map
	maliciousPackages = make(map[string]bool)
	for _, pkg := range list {
		maliciousPackages[strings.ToLower(strings.TrimSpace(pkg))] = true
	}

	log.Printf("[Reputation] Loaded cached threat feed: %d malicious packages", len(maliciousPackages))
}

// isPackageKnownMalicious returns whether the package name is flagged as a known threat
func isPackageKnownMalicious(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	maliciousPackagesMutex.RLock()
	defer maliciousPackagesMutex.RUnlock()
	return maliciousPackages[name]
}
