package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed dashboard.html
var dashboardHTML []byte

//go:embed dashboard.css
var dashboardCSS []byte

//go:embed dashboard.js
var dashboardJS []byte

//go:embed devgate_icon.png
var logoPng []byte

type Settings struct {
	Mode                         string   `json:"mode"` // "strict", "interactive", "audit"
	Honeypot                     bool     `json:"honeypot"`
	LockfileActive               bool     `json:"lockfileActive"`
	LockfileMode                 string   `json:"lockfileMode"` // "block", "prompt", "audit"
	LockfilePaths                string   `json:"lockfilePaths"`
	RegistryAgeCheck             bool     `json:"registryAgeCheck"`
	TyposquatCheck               bool     `json:"typosquatCheck"`
	TarballScan                  bool     `json:"tarballScan"`
	PypiScan                     bool     `json:"pypiScan"`
	EntropyScan                  bool     `json:"entropyScan"`
	ASTScan                      bool     `json:"astScan"`
	YaraActive                   bool     `json:"yaraActive"`
	WebUIEnabled                 bool     `json:"webUIEnabled"`
	CustomDomainWhitelist        []string `json:"customDomainWhitelist"`
	CustomDomainBlacklist        []string `json:"customDomainBlacklist"`
	CustomPackageWhitelist       []string `json:"customPackageWhitelist"`
	CustomPackageBlacklist       []string `json:"customPackageBlacklist"`
	CustomNpmRegistries          []string `json:"customNpmRegistries"`
	CustomPypiRegistries         []string `json:"customPypiRegistries"`
	PrivateScopes                []string `json:"privateScopes"`
	SandboxEvasionAction         string   `json:"sandboxEvasionAction"` // "block", "poison", "audit"
	DependencyConfusionActive    bool     `json:"dependencyConfusionActive"`
	SandboxSpoofing              bool     `json:"sandboxSpoofing"`
	PromptTimeout                int      `json:"promptTimeout"`
	KillInstallerOnThreat        bool     `json:"killInstallerOnThreat"`
	KillInstallerOnStaticThreat  bool     `json:"killInstallerOnStaticThreat"`
	AutoCleanupOnThreat          bool     `json:"autoCleanupOnThreat"`
	ThreatIntelActive            bool     `json:"threatIntelActive"`
	LocalFeedSyncActive          bool     `json:"localFeedSyncActive"`
	CloudflareDNSActive          bool     `json:"cloudflareDNSActive"`
	URLhausLiveActive            bool     `json:"urlhausLiveActive"`
	SubprocessInterceptionActive bool     `json:"subprocessInterceptionActive"`
	SensitiveFileAccessActive    bool     `json:"sensitiveFileAccessActive"`
	SensitiveFileAccessAction    string   `json:"sensitiveFileAccessAction"` // "block", "audit"
	HttpsInspectionActive        bool     `json:"httpsInspectionActive"`
	AntiEvasionActive            bool     `json:"antiEvasionActive"`
	SubprocessNetworkStrictness  string   `json:"subprocessNetworkStrictness"`  // "lenient", "strict", "block_all"
	StripLifecycleScripts        string   `json:"stripLifecycleScripts"`        // "never", "threats_only", "all_public", "always"
	StripLifecycleTargets        []string `json:"stripLifecycleTargets"`        // e.g. ["preinstall", "install", "postinstall"]
	StripLifecycleTriggerThreats []string `json:"stripLifecycleTriggerThreats"` // e.g. ["SandboxEvasionDetected", ...]
	StripLifecycleExemptions     []string `json:"stripLifecycleExemptions"`     // e.g. ["esbuild", "@babel/*"]
	RunOnStartup                 bool     `json:"runOnStartup"`
}

type SSEMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type PromptPayload struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	Package string `json:"package"`
}

var settingsFile = filepath.Join(getConfigDir(), "settings.json")
var isDaemon bool

var (
	settings = Settings{
		Mode:                         "strict",
		Honeypot:                     true,
		LockfileActive:               false,
		LockfileMode:                 "prompt",
		LockfilePaths:                "",
		RegistryAgeCheck:             true,
		TyposquatCheck:               true,
		TarballScan:                  true,
		PypiScan:                     true,
		EntropyScan:                  true,
		ASTScan:                      true,
		YaraActive:                   true,
		WebUIEnabled:                 true,
		CustomDomainWhitelist:        []string{},
		CustomDomainBlacklist:        []string{},
		CustomPackageWhitelist:       []string{},
		CustomPackageBlacklist:       []string{},
		CustomNpmRegistries:          []string{},
		CustomPypiRegistries:         []string{},
		PrivateScopes:                []string{},
		SandboxEvasionAction:         "block",
		DependencyConfusionActive:    true,
		SandboxSpoofing:              true,
		PromptTimeout:                45,
		KillInstallerOnThreat:        true,
		KillInstallerOnStaticThreat:  true,
		AutoCleanupOnThreat:          true,
		ThreatIntelActive:            true,
		LocalFeedSyncActive:          true,
		CloudflareDNSActive:          true,
		URLhausLiveActive:            true,
		SubprocessInterceptionActive: true,
		SensitiveFileAccessActive:    true,
		SensitiveFileAccessAction:    "block",
		HttpsInspectionActive:        false,
		AntiEvasionActive:            true,
		SubprocessNetworkStrictness:  "lenient",
		StripLifecycleScripts:        "threats_only",
		StripLifecycleTargets:        []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"},
		StripLifecycleTriggerThreats: []string{"SuspiciousReverseShell", "EnvironmentExfiltration", "ObfuscatedPayload", "DiscordExfiltration", "TelegramExfiltration", "CredentialPathTheft", "MaliciousInstallerDownloader", "SandboxEvasionDetected"},
		StripLifecycleExemptions:     []string{},
		RunOnStartup:                 false,
	}
	settingsMutex sync.Mutex

	// sse clients registry
	clients      = make(map[chan string]bool)
	clientsMutex sync.Mutex

	// interactive prompts pending user decision
	prompts      = make(map[string]chan string)
	promptsMutex sync.Mutex

	// logs and prompts cache to support multiple tabs
	recentLogs        []LogEvent
	recentLogsMutex   sync.Mutex
	logsFileMutex     sync.Mutex
	activePrompt      *PromptPayload
	activePromptMutex sync.Mutex
)

var logsFile = filepath.Join(getConfigDir(), "logs.json")

func loadLogs() {
	logsFileMutex.Lock()
	data, err := os.ReadFile(logsFile)
	logsFileMutex.Unlock()

	recentLogsMutex.Lock()
	defer recentLogsMutex.Unlock()

	if err == nil {
		var l []LogEvent
		if err := json.Unmarshal(data, &l); err == nil {
			recentLogs = l
			return
		}
	}
	recentLogs = []LogEvent{}
}

func validateSettings(s *Settings) {
	s.Mode = strings.ToLower(strings.TrimSpace(s.Mode))
	if s.Mode != "strict" && s.Mode != "interactive" && s.Mode != "audit" {
		s.Mode = "strict"
	}
	s.LockfileMode = strings.ToLower(strings.TrimSpace(s.LockfileMode))
	if s.LockfileMode != "block" && s.LockfileMode != "prompt" && s.LockfileMode != "audit" {
		s.LockfileMode = "prompt"
	}
	s.SandboxEvasionAction = strings.ToLower(strings.TrimSpace(s.SandboxEvasionAction))
	if s.SandboxEvasionAction != "block" && s.SandboxEvasionAction != "poison" && s.SandboxEvasionAction != "audit" {
		s.SandboxEvasionAction = "block"
	}
	s.SensitiveFileAccessAction = strings.ToLower(strings.TrimSpace(s.SensitiveFileAccessAction))
	if s.SensitiveFileAccessAction != "block" && s.SensitiveFileAccessAction != "audit" {
		s.SensitiveFileAccessAction = "block"
	}
	s.SubprocessNetworkStrictness = strings.ToLower(strings.TrimSpace(s.SubprocessNetworkStrictness))
	if s.SubprocessNetworkStrictness != "lenient" && s.SubprocessNetworkStrictness != "strict" && s.SubprocessNetworkStrictness != "block_all" {
		s.SubprocessNetworkStrictness = "lenient"
	}
	s.StripLifecycleScripts = strings.ToLower(strings.TrimSpace(s.StripLifecycleScripts))
	if s.StripLifecycleScripts != "never" && s.StripLifecycleScripts != "threats_only" && s.StripLifecycleScripts != "all_public" && s.StripLifecycleScripts != "always" {
		s.StripLifecycleScripts = "threats_only"
	}
	if s.PromptTimeout <= 0 {
		s.PromptTimeout = 45
	}

	cleanSlice := func(arr []string) []string {
		var res []string
		for _, v := range arr {
			trimmed := strings.TrimSpace(v)
			if trimmed != "" {
				res = append(res, trimmed)
			}
		}
		if res == nil {
			return []string{}
		}
		return res
	}

	s.CustomDomainWhitelist = cleanSlice(s.CustomDomainWhitelist)
	s.CustomDomainBlacklist = cleanSlice(s.CustomDomainBlacklist)
	s.CustomPackageWhitelist = cleanSlice(s.CustomPackageWhitelist)
	s.CustomPackageBlacklist = cleanSlice(s.CustomPackageBlacklist)
	s.CustomNpmRegistries = cleanSlice(s.CustomNpmRegistries)
	s.CustomPypiRegistries = cleanSlice(s.CustomPypiRegistries)
	s.PrivateScopes = cleanSlice(s.PrivateScopes)
	s.StripLifecycleTargets = cleanSlice(s.StripLifecycleTargets)
	if len(s.StripLifecycleTargets) == 0 && s.StripLifecycleScripts != "never" {
		s.StripLifecycleTargets = []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}
	}
	s.StripLifecycleTriggerThreats = cleanSlice(s.StripLifecycleTriggerThreats)
	if len(s.StripLifecycleTriggerThreats) == 0 && s.StripLifecycleScripts == "threats_only" {
		s.StripLifecycleTriggerThreats = []string{"SuspiciousReverseShell", "EnvironmentExfiltration", "ObfuscatedPayload", "DiscordExfiltration", "TelegramExfiltration", "CredentialPathTheft", "MaliciousInstallerDownloader", "SandboxEvasionDetected"}
	}
	s.StripLifecycleExemptions = cleanSlice(s.StripLifecycleExemptions)
}

func loadSettings() {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	data, err := os.ReadFile(settingsFile)
	if err == nil {
		s := settings
		if err := json.Unmarshal(data, &s); err == nil {
			validateSettings(&s)
			settings = s
			if isDaemon {
				_ = configureStartup(settings.RunOnStartup)
			}
			return
		}
	}
	saveSettingsLocked()
}

func saveSettings() {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	saveSettingsLocked()
}

func saveSettingsLocked() {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err == nil {
		os.WriteFile(settingsFile, data, 0644)
	}
	if !isDaemon {
		// cli process: notify the running daemon to reload settings
		go func() {
			url := "http://127.0.0.1:8081/api/settings"
			req, err := http.NewRequest("POST", url, bytes.NewReader(data))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{Timeout: 1 * time.Second}
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}()
	} else {
		_ = configureStartup(settings.RunOnStartup)
	}
}

// get config settings safely
func getSettings() Settings {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()
	return settings
}

// broadcast message to all connected dashboard browsers
func broadcastSSE(msgType string, payload interface{}) {
	if msgType == "event" {
		if logEvt, ok := payload.(LogEvent); ok {
			recentLogsMutex.Lock()
			recentLogs = append(recentLogs, logEvt)
			if len(recentLogs) > 1000 {
				recentLogs = recentLogs[len(recentLogs)-1000:]
			}
			logsCopy := make([]LogEvent, len(recentLogs))
			copy(logsCopy, recentLogs)
			recentLogsMutex.Unlock()

			go func(l []LogEvent) {
				logsFileMutex.Lock()
				defer logsFileMutex.Unlock()
				os.MkdirAll(filepath.Dir(logsFile), 0755)
				data, err := json.Marshal(l) // keep it compact and fast to write
				if err == nil {
					os.WriteFile(logsFile, data, 0644)
				}
			}(logsCopy)
		}
	} else if msgType == "prompt" {
		if promptMap, ok := payload.(map[string]string); ok {
			activePromptMutex.Lock()
			activePrompt = &PromptPayload{
				ID:      promptMap["id"],
				Host:    promptMap["host"],
				Path:    promptMap["path"],
				Package: promptMap["package"],
			}
			activePromptMutex.Unlock()
		}
	}

	data, err := json.Marshal(SSEMessage{Type: msgType, Payload: payload})
	if err != nil {
		return
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for ch := range clients {
		select {
		case ch <- string(data):
		default:
			// client disconnected or slow
		}
	}
}

// starts local web dashboard server
func startWebServer() error {
	loadSettings()
	loadLogs()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(dashboardHTML)
	})

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPng)
	})

	http.HandleFunc("/dashboard.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(dashboardCSS)
	})

	http.HandleFunc("/dashboard.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(dashboardJS)
	})

	// server sent events stream
	http.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}

		ch := make(chan string, 10)
		clientsMutex.Lock()
		clients[ch] = true
		clientsMutex.Unlock()

		defer func() {
			clientsMutex.Lock()
			delete(clients, ch)
			clientsMutex.Unlock()
			close(ch)
		}()

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			case <-ticker.C:
				fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})

	// get/set proxy configuration endpoints
	http.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodPost {
			var newSettings Settings
			if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			validateSettings(&newSettings)
			settingsMutex.Lock()
			settings = newSettings
			settingsMutex.Unlock()
			saveSettings()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getSettings())
	})

	// get system defaults endpoint
	http.HandleFunc("/api/defaults", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		secretNames := []string{}
		for _, p := range secretPatterns {
			secretNames = append(secretNames, p.Name)
		}

		res := map[string][]string{
			"defaultDomainWhitelist": whitelist,
			"popularPackages":        popularPkgs,
			"secretPatterns":         secretNames,
		}
		json.NewEncoder(w).Encode(res)
	})

	// client decision response endpoint
	http.HandleFunc("/api/respond", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		var req struct {
			ID       string `json:"id"`
			Decision string `json:"decision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		promptsMutex.Lock()
		ch, ok := prompts[req.ID]
		if ok {
			delete(prompts, req.ID)
		}
		promptsMutex.Unlock()

		if ok {
			activePromptMutex.Lock()
			if activePrompt != nil && activePrompt.ID == req.ID {
				activePrompt = nil
			}
			activePromptMutex.Unlock()

			// notify all other connected dashboard tabs to close their prompt modal
			broadcastSSE("prompt_resolved", req.ID)

			ch <- req.Decision
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "prompt ID not found or expired", http.StatusNotFound)
		}
	})

	// get recent logs (with filtering and pagination)
	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		// query params
		qLimit := r.URL.Query().Get("limit")
		qOffset := r.URL.Query().Get("offset")
		qType := r.URL.Query().Get("type")
		qSearch := r.URL.Query().Get("search")

		limit := 50
		if qLimit != "" {
			if l, err := strconv.Atoi(qLimit); err == nil && l > 0 {
				limit = l
			}
		}
		offset := 0
		if qOffset != "" {
			if o, err := strconv.Atoi(qOffset); err == nil && o >= 0 {
				offset = o
			}
		}

		recentLogsMutex.Lock()
		allLogs := make([]LogEvent, len(recentLogs))
		copy(allLogs, recentLogs)
		recentLogsMutex.Unlock()

		filteredLogs := []LogEvent{}
		searchLower := strings.ToLower(qSearch)
		typeLower := strings.ToLower(qType)

		// filter from newest to oldest
		for i := len(allLogs) - 1; i >= 0; i-- {
			logEvt := allLogs[i]

			// filter by type
			if qType != "" && strings.ToLower(logEvt.Type) != typeLower {
				continue
			}

			// filter by search (in message or path)
			if qSearch != "" {
				msgMatch := strings.Contains(strings.ToLower(logEvt.Message), searchLower)
				pathMatch := strings.Contains(strings.ToLower(logEvt.Path), searchLower)
				if !msgMatch && !pathMatch {
					continue
				}
			}

			filteredLogs = append(filteredLogs, logEvt)
		}

		// paginate
		totalCount := len(filteredLogs)
		start := offset
		if start > totalCount {
			start = totalCount
		}
		end := start + limit
		if end > totalCount {
			end = totalCount
		}

		// if start == end, prevent out of bounds slicing
		var paginatedLogs []LogEvent
		if start < end {
			paginatedLogs = filteredLogs[start:end]
		} else {
			paginatedLogs = []LogEvent{}
		}

		// calculate cumulative stats from all recent logs in session
		statsTotal := 0
		statsBlocked := 0
		statsPoisoned := 0
		statsSquats := 0
		for _, logEvt := range allLogs {
			statsTotal++
			if logEvt.Type == "BLOCKED" || logEvt.Type == "INSTALLER_KILLED" || logEvt.Type == "KILLED" {
				statsBlocked++
			} else if logEvt.Type == "EXFIL" {
				statsPoisoned++
			} else if logEvt.Type == "NEW_PKG" {
				statsSquats++
			}
		}

		// return paginated logs, total count, and cumulative stats
		res := map[string]interface{}{
			"logs":  paginatedLogs,
			"total": totalCount,
			"stats": map[string]int{
				"total":    statsTotal,
				"blocked":  statsBlocked,
				"poisoned": statsPoisoned,
				"squats":   statsSquats,
			},
		}
		json.NewEncoder(w).Encode(res)
	})

	// get active prompt
	http.HandleFunc("/api/prompt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		activePromptMutex.Lock()
		defer activePromptMutex.Unlock()

		json.NewEncoder(w).Encode(activePrompt)
	})

	// manual reputation feed sync trigger
	http.HandleFunc("/api/reputation/sync", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		go syncReputationFeeds()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Threat feed synchronization triggered in background",
		})
	})

	// instant whitelisting from dashboard
	http.HandleFunc("/api/whitelist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		settingsMutex.Lock()
		exists := false
		for _, d := range settings.CustomDomainWhitelist {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				exists = true
				break
			}
		}
		if !exists {
			settings.CustomDomainWhitelist = append(settings.CustomDomainWhitelist, domain)
			saveSettingsLocked()
		}
		settingsMutex.Unlock()

		// clear cached reputation for this domain
		reputationCacheMap.Delete(domain)

		// broadcast event warning so dashboard knows
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "WHITELISTED",
			Message: fmt.Sprintf("permanently whitelisted domain: %s (via dashboard action)", domain),
			Path:    "dashboard",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Successfully whitelisted domain '%s'", domain),
		})
	})

	// get root ca status
	http.HandleFunc("/api/cert/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		caCertPath := filepath.Join(getConfigDir(), "ca.crt")
		_, err := os.Stat(caCertPath)
		exists := !os.IsNotExist(err)
		trusted := isCATrusted()
		installedGlobally := isDevGateInstalledGlobally()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"exists":            exists,
			"trusted":           trusted,
			"installedGlobally": installedGlobally,
		})
	})

	// trust root ca endpoint
	http.HandleFunc("/api/cert/trust", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := trustCA()
		success := (err == nil)
		msg := "Root CA trusted successfully"
		if !success {
			msg = fmt.Sprintf("Failed to trust Root CA: %v", err)
		} else {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: "Root CA certificate was trusted in Windows Root Store",
				Path:    "dashboard",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": success,
			"message": msg,
		})
	})

	// untrust/delete root ca endpoint
	http.HandleFunc("/api/cert/untrust", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := untrustCA()
		success := (err == nil)
		msg := "Root CA untrusted successfully"
		if !success {
			msg = fmt.Sprintf("Failed to untrust Root CA: %v", err)
		} else {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: "Root CA certificate was removed from Windows Root Store",
				Path:    "dashboard",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": success,
			"message": msg,
		})
	})

	// global install / setup path endpoint
	http.HandleFunc("/api/install", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		alreadyInstalled, err := installDevGate()
		success := (err == nil)
		msg := "DevGate was successfully registered globally and added to your PATH. Please restart your terminals to apply changes!"
		if !success {
			msg = fmt.Sprintf("Failed to install: %v", err)
		} else if alreadyInstalled {
			msg = "DevGate is already registered globally. The executable was updated successfully!"
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: "DevGate executable was updated in global bin directory",
				Path:    "dashboard",
			})
		} else {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: "DevGate was registered globally in user Path",
				Path:    "dashboard",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": success,
			"message": msg,
		})
	})

	return http.ListenAndServe("127.0.0.1:8081", nil)
}
