package main

// 2000 line file some slight

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// log event representation for dashboard events
type LogEvent struct {
	Time    time.Time `json:"Time"`
	Type    string    `json:"Type"`
	Message string    `json:"Message"`
	Path    string    `json:"Path"`
}

type ProxyHandler struct{}

// packages the user explicitly allowed during this session via interactive prompt
var (
	tempAllowedPkgs      = make(map[string]bool)
	tempAllowedPkgsMutex sync.RWMutex
)

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// check if destination host is local (bypass process lookup and rules)
	host := req.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	hLower := strings.ToLower(host)
	isLocal := hLower == "localhost" || hLower == "127.0.0.1" || hLower == "::1" || hLower == "0.0.0.0"

	if isLocal {
		if req.Method == http.MethodConnect {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hj.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer clientConn.Close()

			remoteConn, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
			if err != nil {
				clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			defer remoteConn.Close()

			clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

			done := make(chan bool, 2)
			go func() {
				io.Copy(remoteConn, clientConn)
				done <- true
			}()
			go func() {
				io.Copy(clientConn, remoteConn)
				done <- true
			}()
			<-done
			return
		}

		var bodyBytes []byte
		if req.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewBuffer(bodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for k, vv := range req.Header {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Header.Set("Connection", "close")

		client := &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		}
		resp, err := client.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "failed to read server response", http.StatusInternalServerError)
			return
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBodyBytes)
		return
	}

	// check blacklist/whitelist first to lazy-resolve process tree only when needed
	isBlacklistedDomain := isDomainBlacklisted(req.Host)
	allowed := isWhitelisted(req.Host) && !isBlacklistedDomain

	var pNames []string
	var pPids []int
	pName := "whitelisted"
	pid := 0
	pPath := "direct (whitelisted)"

	if !allowed {
		// resolve process tree only for non-whitelisted destinations
		pNames, pPids, pName, pid, pPath = resolveProcessTree(req)

		// bypass if the calling process is devgate itself, desktop app, or webview
		isDevGate := false
		for _, name := range pNames {
			n := strings.ToLower(name)
			if strings.Contains(n, "devgate") || strings.Contains(n, "desktop") || strings.Contains(n, "msedgewebview2") {
				isDevGate = true
				break
			}
		}

		if isDevGate {
			if req.Method == http.MethodConnect {
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "hijacking not supported", http.StatusInternalServerError)
					return
				}
				clientConn, _, err := hj.Hijack()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				defer clientConn.Close()

				remoteConn, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
				if err != nil {
					clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer remoteConn.Close()

				clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

				done := make(chan bool, 2)
				go func() {
					io.Copy(remoteConn, clientConn)
					done <- true
				}()
				go func() {
					io.Copy(clientConn, remoteConn)
					done <- true
				}()
				<-done
				return
			}

			var bodyBytes []byte
			if req.Body != nil {
				var err error
				bodyBytes, err = io.ReadAll(req.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewBuffer(bodyBytes))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for k, vv := range req.Header {
				for _, v := range vv {
					outReq.Header.Add(k, v)
				}
			}
			outReq.Header.Set("Connection", "close")

			client := &http.Client{
				Timeout:   15 * time.Second,
				Transport: &http.Transport{Proxy: nil},
			}
			resp, err := client.Do(outReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			respBodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				http.Error(w, "failed to read server response", http.StatusInternalServerError)
				return
			}

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(respBodyBytes)
			return
		}

		// check domain blacklist
		if isBlacklistedDomain {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("domain blacklist blocked connection to host: %s", req.Host),
				Path:    pPath,
			})
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate: domain '%s' is in the custom domain blacklist.", req.Host)))
			return
		}
	}

	// build process path string for logs
	var pathItems []string
	for i, name := range pNames {
		pathItems = append(pathItems, fmt.Sprintf("%s(%d)", name, pPids[i]))
	}
	pPath = strings.Join(pathItems, " -> ")

	// log incoming connection info to dashboard
	broadcastSSE("event", LogEvent{
		Time:    time.Now(),
		Type:    "CONN",
		Message: fmt.Sprintf("%s %s", req.Method, req.URL.String()),
		Path:    pPath,
	})

	// handle HTTPS tunneling (CONNECT)
	if req.Method == http.MethodConnect {
		h.handleConnect(w, req, pid, pName, pPath, pNames, pPids)
		return
	}

	// handle HTTP requests (scanning and proxying)
	h.handleHTTP(w, req, pid, pName, pPath, pNames, pPids)
}

// tryKillInstaller attempts to kill the npm/pip/cargo installer process tree.
func tryKillInstaller(pNames []string, pPids []int, pPath, reason string, force bool, checkIsHook bool, targetPkg string) bool {
	cfg := getSettings()
	if !force && !cfg.KillInstallerOnThreat {
		return false
	}
	if checkIsHook && !isPostInstall(pNames, pPids) {
		return false
	}

	installerPid, installerName := findInstallerPID(pNames, pPids)
	if installerPid == 0 {
		return false
	}

	pkgName := targetPkg
	if pkgName == "" {
		pkgName = findPackageInLineage(pPids)
	}

	recommendation := ""
	if pkgName != "" {
		if installerName == "npm" || installerName == "yarn" || installerName == "pnpm" {
			recommendation = fmt.Sprintf(" Run \"%s uninstall %s\" to remove any partially written files.", installerName, pkgName)
		} else if installerName == "pip" {
			recommendation = fmt.Sprintf(" Run \"pip uninstall %s\" to remove any partially written files.", pkgName)
		} else if installerName == "cargo" {
			recommendation = fmt.Sprintf(" Delete the dependency '%s' from Cargo.toml and run \"cargo clean\".", pkgName)
		}
	} else {
		if installerName == "npm" || installerName == "yarn" || installerName == "pnpm" {
			recommendation = fmt.Sprintf(" Run \"%s uninstall <package>\" (replace with the threat package name) to clean up any partially written files.", installerName)
		} else if installerName == "pip" {
			recommendation = " Run \"pip uninstall <package>\" (replace with the threat package name) to clean up any partially written files."
		}
	}

	// construct console alert text with clean formatting and colors
	shellMsg := fmt.Sprintf("\n\033[1;31m[DevGate Alert] =========================================================\033[0m\n"+
		"\033[1;33m[DevGate Alert] INSTALLATION ABORTED - SECURITY THREAT INTERCEPTED\033[0m\n"+
		"\033[1;31m[DevGate Alert] =========================================================\033[0m\n"+
		"\033[1;33m[DevGate Alert] Reason:\033[0m %s\n"+
		"\033[1;33m[DevGate Alert] Action:\033[0m Terminated %s installer (PID %d) and its subprocesses.\n"+
		"\033[1;33m[DevGate Alert] Cleanup:\033[0m%s\n"+
		"\033[1;31m[DevGate Alert] =========================================================\033[0m\n",
		reason, installerName, installerPid, recommendation)

	// inject cancellation text directly into the shell console of the installer processes
	injectConsoleMessage(pPids, shellMsg)

	// wait 100ms for console output to flush/display before terminating
	time.Sleep(100 * time.Millisecond)

	// terminate the installer process tree
	err := killProcessTree(installerPid)
	if err != nil {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "WARNING",
			Message: fmt.Sprintf("attempted to kill %s installer (PID %d) but failed: %v", installerName, installerPid, err),
			Path:    pPath,
		})
		return false
	}

	if cfg.AutoCleanupOnThreat && pkgName != "" {
		projDir, _ := findPackageDirAndName(pPids)
		if projDir != "" {
			go runAutoCleanup(projDir, installerName, pkgName, pPids)
		}
	}

	broadcastSSE("event", LogEvent{
		Time:    time.Now(),
		Type:    "INSTALLER_KILLED",
		Message: fmt.Sprintf("killed %s installer (PID %d) — %s.%s", installerName, installerPid, reason, recommendation),
		Path:    pPath,
	})

	// spawn desktop popup modal in a background goroutine instead of a system notification
	go showPopup("DevGate: Installer Terminated",
		fmt.Sprintf("DevGate aborted the %s installer (PID %d) because a threat was detected.\n\nReason: %s\n\nRecommendation:%s", installerName, installerPid, reason, recommendation))

	return true
}

func (h *ProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request, pid int, pName, pPath string, pNames []string, pPids []int) {
	host := req.Host
	isHook := isPostInstall(pNames, pPids)
	allowed := isWhitelisted(host)
	cfg := getSettings()

	// intercept and decrypt HTTPS connection if enabled & Root CA is trusted
	if cfg.HttpsInspectionActive && isCATrusted() && (isPublicRegistry(host) || !allowed) {
		h.handleHTTPSMitm(w, req, pid, pName, pPath, pNames, pPids)
		return
	}

	// subprocess connection guard check
	if cfg.SubprocessInterceptionActive && isHook && !allowed && isHighRiskSubprocess(pName) {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("Subprocess Spawn Threat: hook script spawned high-risk process '%s' attempting outbound connection to %s %s", pName, host, pkgInfo),
			Path:    pPath,
		})
		tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("high-risk process '%s' spawned by hook connecting to %s", pName, host), true, true, triggeredPkg)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Blocked by DevGate Subprocess Guard: high-risk spawned process '%s' attempting outbound traffic. Package: %s", pName, triggeredPkg)))
		return
	}

	// check reputation first if not whitelisted
	if cfg.ThreatIntelActive && !allowed {
		if isMalicious, reason := checkHostReputation(host); isMalicious {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("Reputation Threat Blocked: connection to '%s' (Reason: %s)", host, reason),
				Path:    pPath,
			})
			killed := tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("Malicious connection to %s (%s)", host, reason), true, false, "")
			if !killed {
				injectConsoleMessage(pPids, fmt.Sprintf("\n\033[1;31m[DevGate] Blocked malicious connection to: %s (%s)\033[0m\n          To allow this domain, run: devgate list add dw %s\n", host, reason, host))
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate Threat Intelligence: malicious host '%s' (%s)", host, reason)))
			return
		}
	}

	// zero-trust rule check
	if isHook && !allowed {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}

		if cfg.KillInstallerOnThreat {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("auto-blocked hook connection %sto host: %s (kill threat active)", pkgInfo, host),
				Path:    pPath,
			})
			tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, host), true, true, triggeredPkg)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden (killed installer). Package: %s", triggeredPkg)))
			return
		}

		if cfg.Mode != "audit" {
			if cfg.Mode == "strict" {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, host),
					Path:    pPath,
				})
				tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, host), false, true, triggeredPkg)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg)))
				return
			} else if cfg.Mode == "interactive" {
				// request user input via web dashboard
				id := fmt.Sprintf("%d", time.Now().UnixNano())
				ch := make(chan string, 1)
				promptsMutex.Lock()
				prompts[id] = ch
				promptsMutex.Unlock()

				notifyMsg := fmt.Sprintf("A script is trying to connect to %s. Action required.", host)
				if triggeredPkg != "" {
					notifyMsg = fmt.Sprintf("Package '%s' is trying to connect to %s. Action required.", triggeredPkg, host)
				}
				showNotification("DevGate: Hook Blocked", notifyMsg)
				broadcastSSE("prompt", map[string]string{
					"id":      id,
					"host":    host,
					"package": triggeredPkg,
					"path":    getDetailedPath(pNames, pPids),
				})

				if !cfg.WebUIEnabled {
					exec.Command("cmd.exe", "/c", "start", "DevGate Intercept", os.Args[0], "prompt", id, host, getDetailedPath(pNames, pPids), triggeredPkg).Start()
				}

				var decision string
				select {
				case decision = <-ch:
				case <-time.After(time.Duration(cfg.PromptTimeout) * time.Second):
					decision = "block"
					promptsMutex.Lock()
					delete(prompts, id)
					promptsMutex.Unlock()

					activePromptMutex.Lock()
					if activePrompt != nil && activePrompt.ID == id {
						activePrompt = nil
					}
					activePromptMutex.Unlock()
				}

				if decision == "whitelist" {
					settingsMutex.Lock()
					h := strings.ToLower(host)
					if idx := strings.Index(h, ":"); idx != -1 {
						h = h[:idx]
					}
					h = strings.TrimSpace(h)
					exists := false
					for _, dom := range settings.CustomDomainWhitelist {
						if strings.ToLower(strings.TrimSpace(dom)) == h {
							exists = true
							break
						}
					}
					if !exists {
						settings.CustomDomainWhitelist = append(settings.CustomDomainWhitelist, h)
						saveSettingsLocked()
					}
					settingsMutex.Unlock()

					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "WHITELISTED",
						Message: fmt.Sprintf("permanently whitelisted domain: %s", host),
						Path:    pPath,
					})
				}

				if decision == "block" || decision == "kill" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("blocked hook connection %sto host: %s (user decision)", pkgInfo, host),
						Path:    pPath,
					})
					reason := fmt.Sprintf("blocked hook connection %s", pkgInfo)
					if decision == "kill" {
						reason = fmt.Sprintf("user aborted installation of package '%s'", triggeredPkg)
					}
					tryKillInstaller(pNames, pPids, pPath, reason, decision == "kill", true, triggeredPkg)
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg)))
					return
				}
			}
		}
	}

	// hijack connection for TCP tunneling
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// connect to target server
	remoteConn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remoteConn.Close()

	// tell client tunnel is ready
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// proxy bidirectional traffic
	done := make(chan bool, 2)
	go func() {
		io.Copy(remoteConn, clientConn)
		done <- true
	}()
	go func() {
		io.Copy(clientConn, remoteConn)
		done <- true
	}()
	<-done
}

func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request, pid int, pName, pPath string, pNames []string, pPids []int) {
	isHook := isPostInstall(pNames, pPids)
	allowed := isWhitelisted(req.Host)
	cfg := getSettings()

	// subprocess connection guard check
	if cfg.SubprocessInterceptionActive && isHook && !allowed && isHighRiskSubprocess(pName) {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("Subprocess Spawn Threat: hook script spawned high-risk process '%s' attempting outbound connection to %s %s", pName, req.Host, pkgInfo),
			Path:    pPath,
		})
		tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("high-risk process '%s' spawned by hook connecting to %s", pName, req.Host), true, true, triggeredPkg)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Blocked by DevGate Subprocess Guard: high-risk spawned process '%s' attempting outbound traffic. Package: %s", pName, triggeredPkg)))
		return
	}

	// check reputation first if not whitelisted
	if cfg.ThreatIntelActive && !allowed {
		if isMalicious, reason := checkHostReputation(req.Host); isMalicious {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("Reputation Threat Blocked: connection to '%s' (Reason: %s)", req.Host, reason),
				Path:    pPath,
			})
			killed := tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("Malicious connection to %s (%s)", req.Host, reason), true, false, "")
			if !killed {
				injectConsoleMessage(pPids, fmt.Sprintf("\n\033[1;31m[DevGate] Blocked malicious connection to: %s (%s)\033[0m\n          To allow this domain, run: devgate list add dw %s\n", req.Host, reason, req.Host))
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate Threat Intelligence: malicious host '%s' (%s)", req.Host, reason)))
			return
		}
	}

	// zero-trust rule check
	if isHook && !allowed {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}

		if cfg.KillInstallerOnThreat {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("auto-blocked hook connection %sto host: %s (kill threat active)", pkgInfo, req.Host),
				Path:    pPath,
			})
			tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, req.Host), true, true, triggeredPkg)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden (killed installer). Package: %s", triggeredPkg)))
			return
		}

		if cfg.Mode != "audit" {
			if cfg.Mode == "strict" {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, req.Host),
					Path:    pPath,
				})
				tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, req.Host), false, true, triggeredPkg)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg)))
				return
			} else if cfg.Mode == "interactive" {
				// request user input via web dashboard
				id := fmt.Sprintf("%d", time.Now().UnixNano())
				ch := make(chan string, 1)
				promptsMutex.Lock()
				prompts[id] = ch
				promptsMutex.Unlock()

				notifyMsg := fmt.Sprintf("A script is trying to connect to %s. Action required.", req.Host)
				if triggeredPkg != "" {
					notifyMsg = fmt.Sprintf("Package '%s' is trying to connect to %s. Action required.", triggeredPkg, req.Host)
				}
				showNotification("DevGate: Hook Blocked", notifyMsg)
				broadcastSSE("prompt", map[string]string{
					"id":      id,
					"host":    req.Host,
					"package": triggeredPkg,
					"path":    getDetailedPath(pNames, pPids),
				})

				if !cfg.WebUIEnabled {
					exec.Command("cmd.exe", "/c", "start", "DevGate Intercept", os.Args[0], "prompt", id, req.Host, getDetailedPath(pNames, pPids), triggeredPkg).Start()
				}

				var decision string
				select {
				case decision = <-ch:
				case <-time.After(time.Duration(cfg.PromptTimeout) * time.Second):
					decision = "block"
					promptsMutex.Lock()
					delete(prompts, id)
					promptsMutex.Unlock()

					activePromptMutex.Lock()
					if activePrompt != nil && activePrompt.ID == id {
						activePrompt = nil
					}
					activePromptMutex.Unlock()
				}

				if decision == "whitelist" {
					settingsMutex.Lock()
					h := strings.ToLower(req.Host)
					if idx := strings.Index(h, ":"); idx != -1 {
						h = h[:idx]
					}
					h = strings.TrimSpace(h)
					exists := false
					for _, dom := range settings.CustomDomainWhitelist {
						if strings.ToLower(strings.TrimSpace(dom)) == h {
							exists = true
							break
						}
					}
					if !exists {
						settings.CustomDomainWhitelist = append(settings.CustomDomainWhitelist, h)
						saveSettingsLocked()
					}
					settingsMutex.Unlock()

					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "WHITELISTED",
						Message: fmt.Sprintf("permanently whitelisted domain: %s", req.Host),
						Path:    pPath,
					})
				}

				if decision == "block" || decision == "kill" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("blocked hook connection %sto host: %s (user decision)", pkgInfo, req.Host),
						Path:    pPath,
					})
					reason := fmt.Sprintf("blocked hook connection %s", pkgInfo)
					if decision == "kill" {
						reason = fmt.Sprintf("user aborted installation of package '%s'", triggeredPkg)
					}
					tryKillInstaller(pNames, pPids, pPath, reason, decision == "kill", true, triggeredPkg)
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg)))
					return
				}
			}
		}
	}

	// extract package name from npm or pypi registry calls
	isNpm := strings.Contains(req.Host, "registry.npmjs.org")
	if !isNpm {
		for _, pattern := range cfg.CustomNpmRegistries {
			if matchDomainPattern(req.Host, pattern) {
				isNpm = true
				break
			}
		}
	}

	isPypiRegistry := strings.Contains(req.Host, "pypi.org")
	if !isPypiRegistry {
		for _, pattern := range cfg.CustomPypiRegistries {
			if matchDomainPattern(req.Host, pattern) {
				isPypiRegistry = true
				break
			}
		}
	}

	var pkgName string
	if isNpm {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" && !strings.HasPrefix(parts[0], "-") {
			pkgName = parts[0]
			// scoped package names like @scope/name
			if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
				pkgName = parts[0] + "/" + parts[1]
			}
		}
	} else if isPypiRegistry {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(parts) > 1 && (parts[0] == "simple" || parts[0] == "pypi") {
			pkgName = parts[1]
		}
	}

	// check package blacklist first
	if pkgName != "" && isPackageBlacklisted(pkgName) {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("package blacklist blocked: '%s' is explicitly blacklisted", pkgName),
			Path:    pPath,
		})
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is in the custom package blacklist.", pkgName)))
		return
	}

	// check malicious package database
	if pkgName != "" && isPackageKnownMalicious(pkgName) {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("Malicious package blocked: '%s' is identified as a known threat in feed", pkgName),
			Path:    pPath,
		})
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is flagged in the offline threat intelligence database.", pkgName)))
		return
	}

	if pkgName != "" {
		isPrivateScope := false
		for _, scopePattern := range cfg.PrivateScopes {
			if matchScopePattern(pkgName, scopePattern) {
				isPrivateScope = true
				break
			}
		}

		if isPrivateScope {
			if isPublicRegistry(req.Host) && cfg.DependencyConfusionActive {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("Dependency Confusion Blocked: private scope package '%s' requested from public registry '%s'", pkgName, req.Host),
					Path:    pPath,
				})
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Blocked by DevGate Dependency Confusion Defense: private scope package '%s' cannot be downloaded from public registry '%s'.", pkgName, req.Host)))
				return
			}

			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: fmt.Sprintf("private scope package '%s' bypassed typosquat and age checks", pkgName),
				Path:    pPath,
			})
		}

		// check lockfile drift
		if !isPackageWhitelisted(pkgName) && !isPkgInLockfile(pkgName) {
			// check if user already allowed this package in this session
			tempAllowedPkgsMutex.RLock()
			alreadyAllowed := tempAllowedPkgs[strings.ToLower(pkgName)]
			tempAllowedPkgsMutex.RUnlock()

			if !alreadyAllowed {
				lockMode := cfg.LockfileMode

				if cfg.KillInstallerOnThreat && lockMode != "audit" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("lockfile drift blocked: '%s' not in project dependencies (kill threat active)", pkgName),
						Path:    pPath,
					})
					tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("lockfile drift: %s", pkgName), true, false, pkgName)
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile (killed installer).", pkgName)))
					return
				}

				if lockMode == "block" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("lockfile drift blocked: '%s' not in project dependencies", pkgName),
						Path:    pPath,
					})
					tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("lockfile drift: %s", pkgName), false, false, pkgName)
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile.", pkgName)))
					return
				} else if lockMode == "prompt" {
					id := fmt.Sprintf("%d", time.Now().UnixNano())
					ch := make(chan string, 1)
					promptsMutex.Lock()
					prompts[id] = ch
					promptsMutex.Unlock()

					showNotification("DevGate: New Package", fmt.Sprintf("'%s' is not in your lockfile. Action required.", pkgName))
					broadcastSSE("prompt", map[string]string{
						"id":   id,
						"host": fmt.Sprintf("New package: %s", pkgName),
						"path": getDetailedPath(pNames, pPids),
					})

					if !cfg.WebUIEnabled {
						exec.Command("cmd.exe", "/c", "start", "DevGate Intercept", os.Args[0], "prompt", id, fmt.Sprintf("New package: %s", pkgName), getDetailedPath(pNames, pPids)).Start()
					}

					var decision string
					select {
					case decision = <-ch:
					case <-time.After(time.Duration(cfg.PromptTimeout) * time.Second):
						decision = "block"
						promptsMutex.Lock()
						delete(prompts, id)
						promptsMutex.Unlock()

						activePromptMutex.Lock()
						if activePrompt != nil && activePrompt.ID == id {
							activePrompt = nil
						}
						activePromptMutex.Unlock()
					}

					if decision == "whitelist" {
						settingsMutex.Lock()
						p := strings.ToLower(strings.TrimSpace(pkgName))
						exists := false
						for _, pkg := range settings.CustomPackageWhitelist {
							if strings.ToLower(strings.TrimSpace(pkg)) == p {
								exists = true
								break
							}
						}
						if !exists {
							settings.CustomPackageWhitelist = append(settings.CustomPackageWhitelist, p)
							saveSettingsLocked()
						}
						settingsMutex.Unlock()

						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "WHITELISTED",
							Message: fmt.Sprintf("permanently whitelisted package: %s", pkgName),
							Path:    pPath,
						})
					}

					if decision == "block" || decision == "kill" {
						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "BLOCKED",
							Message: fmt.Sprintf("lockfile drift blocked: '%s' (user decision)", pkgName),
							Path:    pPath,
						})
						reason := fmt.Sprintf("lockfile drift: %s", pkgName)
						if decision == "kill" {
							reason = "user aborted installation"
						}
						tryKillInstaller(pNames, pPids, pPath, reason, decision == "kill", false, pkgName)
						w.WriteHeader(http.StatusForbidden)
						w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile.", pkgName)))
						return
					}

					// user allowed it, cache so we dont prompt again this session
					tempAllowedPkgsMutex.Lock()
					tempAllowedPkgs[strings.ToLower(pkgName)] = true
					tempAllowedPkgsMutex.Unlock()
				} else {
					// audit mode, just log the warning
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "NEW_PKG",
						Message: fmt.Sprintf("lockfile drift warning: '%s' not in project dependencies (audit)", pkgName),
						Path:    pPath,
					})
				}
			}

			// typosquatting check (only if enabled)
			if cfg.TyposquatCheck && !isPackageWhitelisted(pkgName) && !isPrivateScope {
				isSquat, target := checkTyposquat(pkgName)
				if isSquat {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "NEW_PKG",
						Message: fmt.Sprintf("typosquat blocked: '%s' mimics '%s'", pkgName, target),
						Path:    pPath,
					})
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' resembles popular '%s' (typosquat check).", pkgName, target)))
					return
				}
			}

			// registry age alert (only if enabled in settings)
			if cfg.RegistryAgeCheck && !isPackageWhitelisted(pkgName) && !isPrivateScope {
				isNew, desc := checkOnlineMetadata(pkgName, isNpm)
				if isNew {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "NEW_PKG",
						Message: fmt.Sprintf("new package alert: %s (%s)", pkgName, desc),
						Path:    pPath,
					})
				}
			}
		}
	}

	// scan headers for secrets (Authorization, X-Api-Key, Cookie, etc.)
	if cfg.Honeypot {
		for hName, hValues := range req.Header {
			hLower := strings.ToLower(hName)
			if hLower == "authorization" || hLower == "x-api-key" || hLower == "cookie" || hLower == "x-auth-token" || hLower == "api-key" {
				for i, val := range hValues {
					newVal, detectedTypes, modified := sanitizePayload(val)
					if modified {
						triggeredPkg := findPackageInLineage(pPids)
						pkgSuffix := ""
						if triggeredPkg != "" {
							pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
						}
						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "EXFIL",
							Message: fmt.Sprintf("intercepted credentials (%s) in header '%s' (exfil poisoned)%s", strings.Join(detectedTypes, ", "), hName, pkgSuffix),
							Path:    getDetailedPath(pNames, pPids),
						})
						req.Header[hName][i] = newVal
					}
				}
			}
		}
	}

	// scan query parameters for secrets
	query := req.URL.RawQuery
	if query != "" && cfg.Honeypot {
		newQuery, detectedTypes, modified := sanitizePayload(query)
		if modified {
			triggeredPkg := findPackageInLineage(pPids)
			pkgSuffix := ""
			if triggeredPkg != "" {
				pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
			}
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "EXFIL",
				Message: fmt.Sprintf("intercepted credentials (%s) in query parameters (exfil poisoned)%s", strings.Join(detectedTypes, ", "), pkgSuffix),
				Path:    getDetailedPath(pNames, pPids),
			})
			req.URL.RawQuery = newQuery
		}
	}

	// scan request body for secrets
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err == nil && len(bodyBytes) > 0 {
			bodyStr := string(bodyBytes)
			if cfg.Honeypot {
				newBody, detectedTypes, modified := sanitizePayload(bodyStr)
				if modified {
					triggeredPkg := findPackageInLineage(pPids)
					pkgSuffix := ""
					if triggeredPkg != "" {
						pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
					}
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "EXFIL",
						Message: fmt.Sprintf("intercepted credentials (%s) in request body (exfil poisoned)%s", strings.Join(detectedTypes, ", "), pkgSuffix),
						Path:    getDetailedPath(pNames, pPids),
					})
					bodyBytes = []byte(newBody)
				}
			}
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// upgrade public registries from http to https for secure upstream transmission
	if req.URL.Scheme == "http" && isPublicRegistry(req.Host) {
		req.URL.Scheme = "https"
	}

	// compile proxy request
	outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewBuffer(bodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// copy headers to outbound request
	for k, vv := range req.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Set("Connection", "close")

	// transport request with timeout
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: nil}, // prevent local loops
	}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// check if this is an npm tarball download request (needs in-memory code scanning)
	isTarball := strings.HasSuffix(req.URL.Path, ".tgz")
	isPypi := strings.Contains(req.Host, "files.pythonhosted.org")

	// check package blacklist and dependency confusion for files.pythonhosted.org downloads
	if isPypi {
		pypiPkg := extractPypiPackageName(req.URL.Path)
		if pypiPkg != "" {
			// blacklist check
			if isPackageBlacklisted(pypiPkg) {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("package blacklist blocked download: '%s' is explicitly blacklisted", pypiPkg),
					Path:    pPath,
				})
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is in the custom package blacklist.", pypiPkg)))
				return
			}
			// malicious package check
			if isPackageKnownMalicious(pypiPkg) {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("Malicious package blocked download: '%s' is identified as a known threat in feed", pypiPkg),
					Path:    pPath,
				})
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Blocked by DevGate: package '%s' is flagged in the offline threat intelligence database.", pypiPkg)))
				return
			}
			// dependency confusion check
			if cfg.DependencyConfusionActive {
				isPrivate := false
				for _, scopePattern := range cfg.PrivateScopes {
					if matchScopePattern(pypiPkg, scopePattern) {
						isPrivate = true
						break
					}
				}
				if isPrivate {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("Dependency Confusion Blocked: private scope package download '%s' requested from public host '%s'", pypiPkg, req.Host),
						Path:    pPath,
					})
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Blocked by DevGate Dependency Confusion Defense: private scope package '%s' cannot be downloaded from public host '%s'.", pypiPkg, req.Host)))
					return
				}
			}
		}
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read server response", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode == http.StatusOK && len(respBodyBytes) > 0 {
		if isNpm && isTarball && cfg.TarballScan {
			if !isPackageWhitelisted(pkgName) {
				// run in-memory static scanner
				isMal, desc := scanTarball(respBodyBytes)
				if handleScanResult(isMal, desc, pkgName, w, pNames, pPids) {
					return
				}

				// if it wasn't blocked, check if we should strip lifecycle scripts
				shouldStrip := false
				if !isPackageExempt(pkgName, cfg.StripLifecycleExemptions) {
					mode := cfg.StripLifecycleScripts
					if mode == "always" {
						shouldStrip = true
					} else if mode == "all_public" && isPublicRegistry(req.Host) {
						shouldStrip = true
					} else if mode == "threats_only" && isMal && isTriggeredByThreat(desc, cfg.StripLifecycleTriggerThreats) {
						shouldStrip = true
					}
				}

				if shouldStrip {
					modifiedBytes, didStrip, err := stripNpmLifecycleScripts(respBodyBytes, cfg.StripLifecycleTargets)
					if err == nil {
						if didStrip {
							respBodyBytes = modifiedBytes
							warningMsg := fmt.Sprintf("\n\033[1;36m[DevGate Shield] Stripped lifecycle scripts (%s) from package '%s' to prevent installation RCE.\033[0m\n", strings.Join(cfg.StripLifecycleTargets, ", "), pkgName)
							injectConsoleMessage(pPids, warningMsg)
						}
					} else {
						fmt.Fprintf(os.Stderr, "[Error] Failed to strip lifecycle scripts for package %s: %v\n", pkgName, err)
					}
				}
			} else {
				// even if whitelisted, check if mode is "always" and not exempt
				if cfg.StripLifecycleScripts == "always" && !isPackageExempt(pkgName, cfg.StripLifecycleExemptions) {
					modifiedBytes, didStrip, err := stripNpmLifecycleScripts(respBodyBytes, cfg.StripLifecycleTargets)
					if err == nil && didStrip {
						respBodyBytes = modifiedBytes
						warningMsg := fmt.Sprintf("\n\033[1;36m[DevGate Shield] Stripped lifecycle scripts (%s) from package '%s' (always-strip mode).\033[0m\n", strings.Join(cfg.StripLifecycleTargets, ", "), pkgName)
						injectConsoleMessage(pPids, warningMsg)
					}
				}
			}
		} else if isPypi && cfg.PypiScan {
			pypiPkg := extractPypiPackageName(req.URL.Path)
			if !isPackageWhitelisted(pypiPkg) {
				// run pypi package scanner
				isMal, desc := scanPypiPackage(respBodyBytes, req.URL.Path)
				if handleScanResult(isMal, desc, pypiPkg, w, pNames, pPids) {
					return
				}

				// for pypi, if allowed but contains a trigger threat, print warning that setup.py scripts can't be safely stripped
				if isMal && isTriggeredByThreat(desc, cfg.StripLifecycleTriggerThreats) && (strings.HasSuffix(req.URL.Path, ".tar.gz") || strings.HasSuffix(req.URL.Path, ".zip")) {
					if !isPackageExempt(pypiPkg, cfg.StripLifecycleExemptions) && cfg.StripLifecycleScripts != "never" {
						warningMsg := fmt.Sprintf("\n\033[1;31m[DevGate Warning] PyPI source package '%s' contains executable setup scripts. DevGate cannot automatically strip Python scripts. Run this installation in an isolated VM/container!\033[0m\n", pypiPkg)
						injectConsoleMessage(pPids, warningMsg)
					}
				}
			}
		}
	}

	// copy response headers back
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// rewrite package metadata urls from https to http for local client interception
	if req.URL.Scheme == "http" && isPublicRegistry(req.Host) && resp.StatusCode == http.StatusOK {
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if contentType == "" || strings.Contains(contentType, "json") || strings.Contains(contentType, "html") || strings.Contains(contentType, "text") {
			// replace registry urls
			respBodyBytes = bytes.ReplaceAll(respBodyBytes, []byte("https://registry.npmjs.org"), []byte("http://registry.npmjs.org"))
			respBodyBytes = bytes.ReplaceAll(respBodyBytes, []byte("https://registry.yarnpkg.com"), []byte("http://registry.yarnpkg.com"))
			respBodyBytes = bytes.ReplaceAll(respBodyBytes, []byte("https://files.pythonhosted.org"), []byte("http://files.pythonhosted.org"))
			respBodyBytes = bytes.ReplaceAll(respBodyBytes, []byte("https://pypi.org"), []byte("http://pypi.org"))

			// update Content-Length header to match new size
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBodyBytes)))
		}
	}

	w.WriteHeader(resp.StatusCode)

	// copy downloaded bytes back
	w.Write(respBodyBytes)
}

func resolveProcessTree(req *http.Request) ([]string, []int, string, int, string) {
	_, portStr, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, nil, "unknown", 0, "unknown"
	}
	port, _ := strconv.Atoi(portStr)
	pid, _ := getPIDForPort(port)
	pNames, pPids := getProcessTree(pid)
	pName := "unknown"
	if len(pNames) > 0 {
		pName = pNames[0]
	}
	var pathItems []string
	for i, name := range pNames {
		pathItems = append(pathItems, fmt.Sprintf("%s(%d)", name, pPids[i]))
	}
	pPath := strings.Join(pathItems, " -> ")
	return pNames, pPids, pName, pid, pPath
}

func extractPypiPackageName(urlPath string) string {
	parts := strings.Split(urlPath, "/")
	if len(parts) == 0 {
		return ""
	}
	filename := parts[len(parts)-1]
	if idx := strings.Index(filename, "-"); idx != -1 {
		return filename[:idx]
	}
	if idx := strings.Index(filename, ".tar.gz"); idx != -1 {
		return filename[:idx]
	}
	if idx := strings.Index(filename, ".tgz"); idx != -1 {
		return filename[:idx]
	}
	return ""
}

func isPublicRegistry(host string) bool {
	h := strings.ToLower(host)
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	return h == "registry.npmjs.org" || h == "registry.yarnpkg.com" || h == "pypi.org" || h == "files.pythonhosted.org"
}

func handleScanResult(isMal bool, desc, pkgName string, w http.ResponseWriter, pNames []string, pPids []int) bool {
	if !isMal {
		return false
	}

	cfg := getSettings()

	isSensitiveFileAccess := strings.Contains(desc, "CredentialPathTheft") || strings.Contains(desc, "critical credentials file path access")
	if isSensitiveFileAccess {
		if !cfg.SensitiveFileAccessActive {
			return false
		}
		action := cfg.SensitiveFileAccessAction
		if action == "audit" {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "WARNING",
				Message: fmt.Sprintf("sensitive file access attempt detected in package '%s' (%s) - allowed under audit mode", pkgName, desc),
				Path:    getDetailedPath(pNames, pPids),
			})
			return false
		}
		// otherwise block (action == "block")
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("sensitive file access attempt blocked in package '%s': %s", pkgName, desc),
			Path:    getDetailedPath(pNames, pPids),
		})
		if cfg.KillInstallerOnStaticThreat {
			tryKillInstaller(pNames, pPids, getDetailedPath(pNames, pPids), fmt.Sprintf("sensitive file access: %s", desc), true, false, pkgName)
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("Blocked by DevGate Sensitive File Access Guard: %s", desc)))
		return true
	}

	isEvasion := strings.Contains(desc, "SandboxEvasionDetected")

	if isEvasion {
		action := cfg.SandboxEvasionAction
		if action == "block" {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("sandbox evasion check blocked package '%s': %s", pkgName, desc),
				Path:    getDetailedPath(pNames, pPids),
			})
			if cfg.KillInstallerOnStaticThreat {
				tryKillInstaller(pNames, pPids, getDetailedPath(pNames, pPids), fmt.Sprintf("evasion check: %s", desc), true, false, pkgName)
			}
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Blocked by DevGate: Sandbox Evasion detected in package '%s' (%s)", pkgName, desc)))
			return true
		} else if action == "poison" {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "WARNING",
				Message: fmt.Sprintf("sandbox evasion detected in package '%s' (%s) - allowed under poison mode", pkgName, desc),
				Path:    getDetailedPath(pNames, pPids),
			})
			warningMsg := fmt.Sprintf("\n\033[1;33m[DevGate Warning] Evasive malware was installed in \"poison\" mode. Keep DevGate proxy running! Evasive malware may delay activation until the proxy is disabled.\033[0m\n")
			injectConsoleMessage(pPids, warningMsg)
			// proceed, let it pass but exfiltration remains monitored/poisoned globally
			return false
		} else { // audit
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "WARNING",
				Message: fmt.Sprintf("sandbox evasion detected in package '%s' (%s) - allowed under audit mode", pkgName, desc),
				Path:    getDetailedPath(pNames, pPids),
			})
			warningMsg := fmt.Sprintf("\n\033[1;33m[DevGate Warning] Evasive malware was installed in \"audit\" mode. Keep DevGate proxy running! Evasive malware may delay activation until the proxy is disabled.\033[0m\n")
			injectConsoleMessage(pPids, warningMsg)
			return false
		}
	}

	// for all other malware detections, block completely
	broadcastSSE("event", LogEvent{
		Time:    time.Now(),
		Type:    "BLOCKED",
		Message: fmt.Sprintf("malicious pattern match in package '%s': %s", pkgName, desc),
		Path:    getDetailedPath(pNames, pPids),
	})
	if cfg.KillInstallerOnStaticThreat {
		tryKillInstaller(pNames, pPids, getDetailedPath(pNames, pPids), fmt.Sprintf("malicious pattern: %s", desc), true, false, pkgName)
	}
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(fmt.Sprintf("Blocked by DevGate Static Scanner: %s", desc)))
	return true
}

func extractPackageFromCmdLine(cmdLine string) string {
	cmdLower := strings.ToLower(cmdLine)

	// node.js (node_modules)
	if idx := strings.Index(cmdLower, "node_modules"); idx != -1 {
		sub := cmdLine[idx+len("node_modules"):]
		if len(sub) > 0 && (sub[0] == '/' || sub[0] == '\\') {
			sub = sub[1:]
		}
		if len(sub) == 0 {
			return ""
		}
		if strings.HasPrefix(sub, "@") {
			parts := strings.FieldsFunc(sub, func(r rune) bool {
				return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
			})
			if len(parts) >= 2 {
				return parts[0] + "/" + parts[1]
			}
		} else {
			parts := strings.FieldsFunc(sub, func(r rune) bool {
				return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
			})
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}

	// python (pip-install- / site-packages)
	if idx := strings.Index(cmdLower, "pip-install-"); idx != -1 {
		sub := cmdLine[idx:]
		parts := strings.FieldsFunc(sub, func(r rune) bool {
			return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
		})
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	if idx := strings.Index(cmdLower, "pip-req-build-"); idx != -1 {
		sub := cmdLine[idx:]
		parts := strings.FieldsFunc(sub, func(r rune) bool {
			return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
		})
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	if idx := strings.Index(cmdLower, "site-packages"); idx != -1 {
		sub := cmdLine[idx+len("site-packages"):]
		if len(sub) > 0 && (sub[0] == '/' || sub[0] == '\\') {
			sub = sub[1:]
		}
		parts := strings.FieldsFunc(sub, func(r rune) bool {
			return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
		})
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// cargo / rust (registry/src)
	if idx := strings.Index(cmdLower, "registry\\src"); idx != -1 || strings.Index(cmdLower, "registry/src") != -1 {
		sub := cmdLine[idx:]
		parts := strings.FieldsFunc(sub, func(r rune) bool {
			return r == '/' || r == '\\' || r == '"' || r == '\'' || r == ' '
		})
		if len(parts) >= 4 {
			pkgVer := parts[3]
			if hyphenIdx := strings.LastIndex(pkgVer, "-"); hyphenIdx != -1 {
				return pkgVer[:hyphenIdx]
			}
			return pkgVer
		}
	}

	return ""
}

func findPackageInLineage(pPids []int) string {
	// first pass: look for packages installed inside node_modules/pip-install/etc.
	for _, pid := range pPids {
		cmdLine := getCmdLine(pid)
		if cmdLine != "" {
			pkg := extractPackageFromCmdLine(cmdLine)
			if pkg != "" {
				pkgLower := strings.ToLower(pkg)
				// skip package managers themselves!
				if pkgLower == "npm" || pkgLower == "yarn" || pkgLower == "pnpm" || pkgLower == "pip" || pkgLower == "cargo" {
					continue
				}
				return pkg
			}
		}
	}

	// second pass: look for local package names if installing in-place (no node_modules in script command line)
	for _, pid := range pPids {
		cmdLine := getCmdLine(pid)
		if cmdLine != "" {
			script := extractScriptFromCmdLine(cmdLine)
			if script != "" {
				localPkg := findPackageNameForScript(script)
				if localPkg != "" {
					pkgLower := strings.ToLower(localPkg)
					if pkgLower != "npm" && pkgLower != "yarn" && pkgLower != "pnpm" && pkgLower != "pip" && pkgLower != "cargo" {
						return localPkg
					}
				}
			}
		}
	}
	return ""
}

func extractScriptFromCmdLine(cmdLine string) string {
	parts := strings.Fields(cmdLine)
	for _, part := range parts {
		part = strings.Trim(part, `"'`)
		if strings.HasSuffix(strings.ToLower(part), ".js") || strings.HasSuffix(strings.ToLower(part), ".py") || strings.HasSuffix(strings.ToLower(part), "setup.py") {
			return part
		}
	}
	return ""
}

func findPackageNameForScript(scriptPath string) string {
	scriptPath = strings.ReplaceAll(scriptPath, "\\", "/")

	// if it's absolute, check it directly
	if filepath.IsAbs(scriptPath) {
		dir := filepath.Dir(scriptPath)
		for i := 0; i < 5; i++ {
			if pkgName := readPackageNameFromDir(dir); pkgName != "" {
				return pkgName
			}
			dir = filepath.Dir(dir)
		}
		return ""
	}

	// search the workspace root directory (which is the parent/ancestor of backend)
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	// walk up to find the root folder containing the backend subdirectory
	searchDir := cwd
	for i := 0; i < 4; i++ {
		if _, err := os.Stat(filepath.Join(searchDir, "backend")); err == nil {
			break
		}
		parent := filepath.Dir(searchDir)
		if parent == searchDir {
			break
		}
		searchDir = parent
	}

	var foundDir string
	filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == ".gemini" {
				return filepath.SkipDir
			}
			return nil
		}

		normalized := strings.ReplaceAll(path, "\\", "/")
		if strings.HasSuffix(normalized, "/"+scriptPath) || normalized == scriptPath {
			foundDir = filepath.Dir(path)
			return fmt.Errorf("found") // stop walking
		}
		return nil
	})

	if foundDir != "" {
		dir := foundDir
		for i := 0; i < 5; i++ {
			if pkgName := readPackageNameFromDir(dir); pkgName != "" {
				return pkgName
			}
			dir = filepath.Dir(dir)
		}
	}

	return ""
}

func readPackageNameFromDir(dir string) string {
	// check package.json
	pJsonPath := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pJsonPath); err == nil {
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &p); err == nil && p.Name != "" {
			return p.Name
		}
	}
	// check Cargo.toml
	cargoPath := filepath.Join(dir, "Cargo.toml")
	if data, err := os.ReadFile(cargoPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "name") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[1])
					name = strings.Trim(name, `"'`)
					return name
				}
			}
		}
	}
	// check setup.py
	setupPath := filepath.Join(dir, "setup.py")
	if data, err := os.ReadFile(setupPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "name=") || strings.Contains(line, "name =") {
				idx := strings.Index(line, "name")
				sub := line[idx+4:]
				sub = strings.TrimSpace(strings.ReplaceAll(sub, "=", ""))
				sub = strings.Trim(sub, `"',()`)
				if sub != "" {
					return sub
				}
			}
		}
	}
	return ""
}

func getDetailedPath(pNames []string, pPids []int) string {
	if len(pNames) == 0 {
		return "unknown"
	}
	var pathItems []string
	for i, name := range pNames {
		cmdLine := getCmdLine(pPids[i])
		if cmdLine != "" {
			if len(cmdLine) > 150 {
				cmdLine = cmdLine[:147] + "..."
			}
			pathItems = append(pathItems, fmt.Sprintf("%s(%d) [%s]", name, pPids[i], cmdLine))
		} else {
			pathItems = append(pathItems, fmt.Sprintf("%s(%d)", name, pPids[i]))
		}
	}
	return strings.Join(pathItems, "\n -> ")
}

func findPackageDirAndName(pPids []int) (string, string) {
	// first check lineage for node_modules/pip-install/etc.
	for _, pid := range pPids {
		cmdLine := getCmdLine(pid)
		if cmdLine != "" {
			pkg := extractPackageFromCmdLine(cmdLine)
			if pkg != "" {
				pkgLower := strings.ToLower(pkg)
				if pkgLower == "npm" || pkgLower == "yarn" || pkgLower == "pnpm" || pkgLower == "pip" || pkgLower == "cargo" {
					continue
				}
				dir := findDirFromCmdLine(cmdLine, pkg)
				return dir, pkg
			}
		}
	}

	// local check
	for _, pid := range pPids {
		cmdLine := getCmdLine(pid)
		if cmdLine != "" {
			script := extractScriptFromCmdLine(cmdLine)
			if script != "" {
				dir, name := findLocalPackageDirAndName(script)
				if name != "" {
					pkgLower := strings.ToLower(name)
					if pkgLower != "npm" && pkgLower != "yarn" && pkgLower != "pnpm" && pkgLower != "pip" && pkgLower != "cargo" {
						return dir, name
					}
				}
			}
		}
	}
	return "", ""
}

func findDirFromCmdLine(cmdLine, pkg string) string {
	parts := strings.Fields(cmdLine)
	for _, part := range parts {
		part = strings.Trim(part, `"'`)
		idx := strings.Index(strings.ToLower(part), "node_modules")
		if idx != -1 {
			projDir := part[:idx]
			projDir = strings.TrimRight(projDir, "/\\")
			if projDir != "" {
				return projDir
			}
		}
	}
	root, err := os.Getwd()
	if err == nil {
		return root
	}
	return ""
}

func findLocalPackageDirAndName(scriptPath string) (string, string) {
	scriptPath = strings.ReplaceAll(scriptPath, "\\", "/")

	if filepath.IsAbs(scriptPath) {
		dir := filepath.Dir(scriptPath)
		for i := 0; i < 5; i++ {
			if pkgName := readPackageNameFromDir(dir); pkgName != "" {
				return dir, pkgName
			}
			dir = filepath.Dir(dir)
		}
		return "", ""
	}

	searchDir := getWorkspaceRoot()
	var foundDir string
	filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == ".gemini" {
				return filepath.SkipDir
			}
			return nil
		}

		normalized := strings.ReplaceAll(path, "\\", "/")
		if strings.HasSuffix(normalized, "/"+scriptPath) || normalized == scriptPath {
			foundDir = filepath.Dir(path)
			return fmt.Errorf("found")
		}
		return nil
	})

	if foundDir != "" {
		dir := foundDir
		for i := 0; i < 5; i++ {
			if pkgName := readPackageNameFromDir(dir); pkgName != "" {
				return dir, pkgName
			}
			dir = filepath.Dir(dir)
		}
	}

	return "", ""
}

func getWorkspaceRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := cwd
	for i := 0; i < 4; i++ {
		if _, err := os.Stat(filepath.Join(dir, "backend")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return cwd
}

func runAutoCleanup(dir, installer, pkg string, pPids []int) {
	// wait 500ms to let the installer processes fully exit and release file locks
	time.Sleep(500 * time.Millisecond)

	freeConsole.Call()

	attached := false
	for _, pid := range pPids {
		if pid <= 0 {
			continue
		}
		r, _, _ := attachConsole.Call(uintptr(pid))
		if r != 0 {
			attached = true
			break
		}
	}
	if !attached {
		r, _, _ := attachConsole.Call(ATTACH_PARENT_PROCESS)
		if r != 0 {
			attached = true
		}
	}

	var fOut *os.File
	if attached {
		hCon, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0)
		if err == nil {
			fOut = os.NewFile(uintptr(hCon), "/dev/stdout")
			fmt.Fprintf(fOut, "\n\033[1;33m[DevGate] Threat aborted. Auto-cleaning package '%s' using %s...\033[0m\n", pkg, installer)
		}
	}

	var cmd *exec.Cmd
	if installer == "npm" || installer == "yarn" || installer == "pnpm" {
		cmd = exec.Command(installer, "uninstall", pkg)
	} else if installer == "pip" {
		cmd = exec.Command("pip", "uninstall", "-y", pkg)
	} else if installer == "cargo" {
		cmd = exec.Command("cargo", "clean")
	}

	if cmd != nil {
		cmd.Dir = dir
		if fOut != nil {
			cmd.Stdout = fOut
			cmd.Stderr = fOut
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}

	if fOut != nil {
		fmt.Fprintln(fOut, "\033[1;32m[DevGate] Auto-cleanup completed successfully.\033[0m")
		fOut.Close()
	}
	freeConsole.Call()
}

func isHighRiskSubprocess(name string) bool {
	n := strings.ToLower(name)
	highRisk := []string{
		"powershell.exe", "powershell_ise.exe", "pwsh.exe", "powershell", "pwsh",
		"cmd.exe", "cmd",
		"curl.exe", "curl",
		"wget.exe", "wget",
		"wscript.exe", "wscript",
		"cscript.exe", "cscript",
		"bash.exe", "bash",
		"sh.exe", "sh",
		"certutil.exe", "certutil",
		"bitsadmin.exe", "bitsadmin",
		"mshta.exe", "mshta",
		"rundll32.exe", "rundll32",
		"regsvr32.exe", "regsvr32",
	}
	for _, hr := range highRisk {
		if n == hr || strings.HasSuffix(n, "\\"+hr) || strings.HasSuffix(n, "/"+hr) {
			return true
		}
	}
	return false
}

func (h *ProxyHandler) handleHTTPSMitm(w http.ResponseWriter, req *http.Request, pid int, pName, pPath string, pNames []string, pPids []int) {
	host := req.Host
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// generate dynamic domain certificate signed by Root CA
	tlsCert, err := getCertificateForHost(host)
	if err != nil {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "WARNING",
			Message: fmt.Sprintf("Failed to generate dynamic cert for %s: %v. Falling back to TCP tunnel.", host, err),
			Path:    pPath,
		})
		h.fallbackToTunnel(clientConn, host)
		return
	}

	// acknowledge connection established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// complete tls handshake with client
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "WARNING",
			Message: fmt.Sprintf("HTTPS handshake failed with client for host %s: %v (Is Root CA trusted?)", host, err),
			Path:    pPath,
		})
		return
	}
	defer tlsClientConn.Close()

	// dial upstream tls to target
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tlsRemoteConn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		// let Go verify the target's real certificate using system root store
	})
	if err != nil {
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "WARNING",
			Message: fmt.Sprintf("Failed to dial upstream TLS for %s: %v", host, err),
			Path:    pPath,
		})
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("DevGate MITM Error: failed to connect to upstream server %s: %v", host, err))),
		}
		resp.Write(tlsClientConn)
		return
	}
	defer tlsRemoteConn.Close()

	clientReader := bufio.NewReader(tlsClientConn)
	remoteReader := bufio.NewReader(tlsRemoteConn)

	for {
		// read decrypted http request from client
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			break
		}

		// ensure scheme & host are populated
		req.URL.Scheme = "https"
		req.URL.Host = host

		// scan request
		blocked, resBody := h.inspectInterceptedRequest(req, host, pid, pName, pPath, pNames, pPids)
		if blocked {
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(resBody)),
			}
			resp.Write(tlsClientConn)
			return
		}

		// forward request to remote tls connection
		err = req.Write(tlsRemoteConn)
		if err != nil {
			return
		}

		// read response from upstream tls connection
		resp, err := http.ReadResponse(remoteReader, req)
		if err != nil {
			return
		}

		// scan response package payloads (tarballs, wheels, etc.)
		resp, err = h.inspectInterceptedResponse(resp, req, host, pid, pName, pPath, pNames, pPids)
		if err != nil {
			// if scan blocked it, write a 403 forbidden response first so the installer gets the reason
			errResp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("Blocked by DevGate: %v\n", err))),
			}
			errResp.Write(tlsClientConn)
			return
		}

		// write response back to client
		err = resp.Write(tlsClientConn)
		if err != nil {
			return
		}
	}
}

func (h *ProxyHandler) inspectInterceptedRequest(req *http.Request, host string, pid int, pName, pPath string, pNames []string, pPids []int) (bool, []byte) {
	isHook := isPostInstall(pNames, pPids)
	allowed := isWhitelisted(host)
	cfg := getSettings()

	// log intercepted decrypted https request to dashboard
	broadcastSSE("event", LogEvent{
		Time:    time.Now(),
		Type:    "CONN",
		Message: fmt.Sprintf("[HTTPS MITM] %s %s", req.Method, req.URL.String()),
		Path:    pPath,
	})

	// 1. subprocess connection guard check
	if cfg.SubprocessInterceptionActive && isHook && !allowed && isHighRiskSubprocess(pName) {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}
		broadcastSSE("event", LogEvent{
			Time:    time.Now(),
			Type:    "BLOCKED",
			Message: fmt.Sprintf("[HTTPS MITM] Subprocess Spawn Threat: hook script spawned high-risk process '%s' attempting connection to %s %s", pName, host, pkgInfo),
			Path:    pPath,
		})
		tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("high-risk process '%s' spawned by hook connecting to %s", pName, host), true, true, triggeredPkg)
		return true, []byte(fmt.Sprintf("Blocked by DevGate Subprocess Guard: high-risk spawned process '%s' attempting outbound traffic. Package: %s", pName, triggeredPkg))
	}

	// reputation check
	if cfg.ThreatIntelActive && !allowed {
		if isMalicious, reason := checkHostReputation(host); isMalicious {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("[HTTPS MITM] Reputation Threat Blocked: connection to '%s' (Reason: %s)", host, reason),
				Path:    pPath,
			})
			killed := tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("Malicious connection to %s (%s)", host, reason), true, false, "")
			if !killed {
				injectConsoleMessage(pPids, fmt.Sprintf("\n\033[1;31m[DevGate] Blocked malicious connection to: %s (%s)\033[0m\n          To allow this domain, run: devgate list add dw %s\n", host, reason, host))
			}
			return true, []byte(fmt.Sprintf("Blocked by DevGate Threat Intelligence: malicious host '%s' (%s)", host, reason))
		}
	}

	// zero-trust hook rules
	if isHook && !allowed {
		triggeredPkg := findPackageInLineage(pPids)
		pkgInfo := ""
		if triggeredPkg != "" {
			pkgInfo = fmt.Sprintf("from package '%s' ", triggeredPkg)
		}

		if cfg.KillInstallerOnThreat {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("[HTTPS MITM] auto-blocked hook connection %sto host: %s (kill threat active)", pkgInfo, host),
				Path:    pPath,
			})
			tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, host), true, true, triggeredPkg)
			return true, []byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden (killed installer). Package: %s", triggeredPkg))
		}

		if cfg.Mode != "audit" {
			if cfg.Mode == "strict" {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] auto-blocked hook connection %sto host: %s", pkgInfo, host),
					Path:    pPath,
				})
				tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("auto-blocked hook connection %sto host: %s", pkgInfo, host), false, true, triggeredPkg)
				return true, []byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg))
			} else if cfg.Mode == "interactive" {
				id := fmt.Sprintf("%d", time.Now().UnixNano())
				ch := make(chan string, 1)
				promptsMutex.Lock()
				prompts[id] = ch
				promptsMutex.Unlock()

				notifyMsg := fmt.Sprintf("A script is trying to connect to %s (HTTPS). Action required.", host)
				if triggeredPkg != "" {
					notifyMsg = fmt.Sprintf("Package '%s' is trying to connect to %s (HTTPS). Action required.", triggeredPkg, host)
				}
				showNotification("DevGate: Hook Blocked", notifyMsg)
				broadcastSSE("prompt", map[string]string{
					"id":      id,
					"host":    host,
					"package": triggeredPkg,
					"path":    getDetailedPath(pNames, pPids),
				})

				if !cfg.WebUIEnabled {
					exec.Command("cmd.exe", "/c", "start", "DevGate Intercept", os.Args[0], "prompt", id, host, getDetailedPath(pNames, pPids), triggeredPkg).Start()
				}

				var decision string
				select {
				case decision = <-ch:
				case <-time.After(time.Duration(cfg.PromptTimeout) * time.Second):
					decision = "block"
					promptsMutex.Lock()
					delete(prompts, id)
					promptsMutex.Unlock()

					activePromptMutex.Lock()
					if activePrompt != nil && activePrompt.ID == id {
						activePrompt = nil
					}
					activePromptMutex.Unlock()
				}

				if decision == "whitelist" {
					settingsMutex.Lock()
					h := strings.ToLower(host)
					if idx := strings.Index(h, ":"); idx != -1 {
						h = h[:idx]
					}
					h = strings.TrimSpace(h)
					exists := false
					for _, dom := range settings.CustomDomainWhitelist {
						if strings.ToLower(strings.TrimSpace(dom)) == h {
							exists = true
							break
						}
					}
					if !exists {
						settings.CustomDomainWhitelist = append(settings.CustomDomainWhitelist, h)
						saveSettingsLocked()
					}
					settingsMutex.Unlock()

					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "WHITELISTED",
						Message: fmt.Sprintf("[HTTPS MITM] permanently whitelisted domain: %s", host),
						Path:    pPath,
					})
				}

				if decision == "block" || decision == "kill" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("[HTTPS MITM] blocked hook connection %sto host: %s (user decision)", pkgInfo, host),
						Path:    pPath,
					})
					reason := fmt.Sprintf("blocked hook connection %s", pkgInfo)
					if decision == "kill" {
						reason = fmt.Sprintf("user aborted installation of package '%s'", triggeredPkg)
					}
					tryKillInstaller(pNames, pPids, pPath, reason, decision == "kill", true, triggeredPkg)
					return true, []byte(fmt.Sprintf("Blocked by DevGate: postinstall outbound traffic forbidden. Package: %s", triggeredPkg))
				}
			}
		}
	}

	// registry extraction & package checks (blacklist, typosquatting, registry age)
	isNpm := strings.Contains(host, "registry.npmjs.org")
	if !isNpm {
		for _, pattern := range cfg.CustomNpmRegistries {
			if matchDomainPattern(host, pattern) {
				isNpm = true
				break
			}
		}
	}

	isPypiRegistry := strings.Contains(host, "pypi.org")
	if !isPypiRegistry {
		for _, pattern := range cfg.CustomPypiRegistries {
			if matchDomainPattern(host, pattern) {
				isPypiRegistry = true
				break
			}
		}
	}

	var pkgName string
	if isNpm {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" && !strings.HasPrefix(parts[0], "-") {
			pkgName = parts[0]
			if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
				pkgName = parts[0] + "/" + parts[1]
			}
		}
	} else if isPypiRegistry {
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		if len(parts) > 1 && (parts[0] == "simple" || parts[0] == "pypi") {
			pkgName = parts[1]
		}
	}

	if pkgName != "" {
		// package blacklist check
		if isPackageBlacklisted(pkgName) {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("[HTTPS MITM] package blacklist blocked: '%s' is explicitly blacklisted", pkgName),
				Path:    pPath,
			})
			return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' is in the custom package blacklist.", pkgName))
		}

		// malicious package database check
		if isPackageKnownMalicious(pkgName) {
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "BLOCKED",
				Message: fmt.Sprintf("[HTTPS MITM] malicious package blocked: '%s' is identified as a known threat in feed", pkgName),
				Path:    pPath,
			})
			return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' is flagged in the offline threat intelligence database.", pkgName))
		}

		isPrivateScope := false
		for _, scopePattern := range cfg.PrivateScopes {
			if matchScopePattern(pkgName, scopePattern) {
				isPrivateScope = true
				break
			}
		}

		if isPrivateScope {
			if isPublicRegistry(host) && cfg.DependencyConfusionActive {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] Dependency Confusion Blocked: private scope package '%s' requested from public registry '%s'", pkgName, host),
					Path:    pPath,
				})
				return true, []byte(fmt.Sprintf("Blocked by DevGate Dependency Confusion Defense: private scope package '%s' cannot be downloaded from public registry '%s'.", pkgName, host))
			}
			broadcastSSE("event", LogEvent{
				Time:    time.Now(),
				Type:    "INFO",
				Message: fmt.Sprintf("[HTTPS MITM] private scope package '%s' bypassed typosquat and age checks", pkgName),
				Path:    pPath,
			})
		}

		// lockfile drift check
		if !isPackageWhitelisted(pkgName) && !isPkgInLockfile(pkgName) && !isPrivateScope {
			tempAllowedPkgsMutex.RLock()
			alreadyAllowed := tempAllowedPkgs[strings.ToLower(pkgName)]
			tempAllowedPkgsMutex.RUnlock()

			if !alreadyAllowed {
				lockMode := cfg.LockfileMode
				if cfg.KillInstallerOnThreat && lockMode != "audit" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("[HTTPS MITM] lockfile drift blocked: '%s' not in project dependencies (kill threat active)", pkgName),
						Path:    pPath,
					})
					tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("lockfile drift: %s", pkgName), true, false, pkgName)
					return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile (killed installer).", pkgName))
				}

				if lockMode == "block" {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("[HTTPS MITM] lockfile drift blocked: '%s' not in project dependencies", pkgName),
						Path:    pPath,
					})
					tryKillInstaller(pNames, pPids, pPath, fmt.Sprintf("lockfile drift: %s", pkgName), false, false, pkgName)
					return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile.", pkgName))
				} else if lockMode == "prompt" {
					id := fmt.Sprintf("%d", time.Now().UnixNano())
					ch := make(chan string, 1)
					promptsMutex.Lock()
					prompts[id] = ch
					promptsMutex.Unlock()

					showNotification("DevGate: New Package", fmt.Sprintf("'%s' is not in your lockfile. Action required.", pkgName))
					broadcastSSE("prompt", map[string]string{
						"id":   id,
						"host": fmt.Sprintf("New package: %s", pkgName),
						"path": getDetailedPath(pNames, pPids),
					})

					if !cfg.WebUIEnabled {
						exec.Command("cmd.exe", "/c", "start", "DevGate Intercept", os.Args[0], "prompt", id, fmt.Sprintf("New package: %s", pkgName), getDetailedPath(pNames, pPids)).Start()
					}

					var decision string
					select {
					case decision = <-ch:
					case <-time.After(time.Duration(cfg.PromptTimeout) * time.Second):
						decision = "block"
						promptsMutex.Lock()
						delete(prompts, id)
						promptsMutex.Unlock()

						activePromptMutex.Lock()
						if activePrompt != nil && activePrompt.ID == id {
							activePrompt = nil
						}
						activePromptMutex.Unlock()
					}

					if decision == "whitelist" {
						settingsMutex.Lock()
						p := strings.ToLower(strings.TrimSpace(pkgName))
						exists := false
						for _, pkg := range settings.CustomPackageWhitelist {
							if strings.ToLower(strings.TrimSpace(pkg)) == p {
								exists = true
								break
							}
						}
						if !exists {
							settings.CustomPackageWhitelist = append(settings.CustomPackageWhitelist, p)
							saveSettingsLocked()
						}
						settingsMutex.Unlock()

						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "WHITELISTED",
							Message: fmt.Sprintf("[HTTPS MITM] permanently whitelisted package: %s", pkgName),
							Path:    pPath,
						})
					}

					if decision == "block" || decision == "kill" {
						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "BLOCKED",
							Message: fmt.Sprintf("[HTTPS MITM] lockfile drift blocked: '%s' (user decision)", pkgName),
							Path:    pPath,
						})
						reason := fmt.Sprintf("lockfile drift: %s", pkgName)
						if decision == "kill" {
							reason = "user aborted installation"
						}
						tryKillInstaller(pNames, pPids, pPath, reason, decision == "kill", false, pkgName)
						return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' is not listed in your lockfile.", pkgName))
					}

					tempAllowedPkgsMutex.Lock()
					tempAllowedPkgs[strings.ToLower(pkgName)] = true
					tempAllowedPkgsMutex.Unlock()
				} else {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "NEW_PKG",
						Message: fmt.Sprintf("[HTTPS MITM] lockfile drift warning: '%s' not in project dependencies (audit)", pkgName),
						Path:    pPath,
					})
				}
			}
		}

		// typosquat check
		if cfg.TyposquatCheck && !isPackageWhitelisted(pkgName) && !isPrivateScope {
			isSquat, target := checkTyposquat(pkgName)
			if isSquat {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "NEW_PKG",
					Message: fmt.Sprintf("[HTTPS MITM] typosquat blocked: '%s' mimics '%s'", pkgName, target),
					Path:    pPath,
				})
				return true, []byte(fmt.Sprintf("Blocked by DevGate: package '%s' resembles popular '%s' (typosquat check).", pkgName, target))
			}
		}

		// registry age check
		if cfg.RegistryAgeCheck && !isPackageWhitelisted(pkgName) && !isPrivateScope {
			isNew, desc := checkOnlineMetadata(pkgName, isNpm)
			if isNew {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "NEW_PKG",
					Message: fmt.Sprintf("[HTTPS MITM] new package alert: %s (%s)", pkgName, desc),
					Path:    pPath,
				})
			}
		}
	}

	// honeypot secrets exfiltration scanning (headers, query, request body)
	if cfg.Honeypot {
		for hName, hValues := range req.Header {
			hLower := strings.ToLower(hName)
			if hLower == "authorization" || hLower == "x-api-key" || hLower == "cookie" || hLower == "x-auth-token" || hLower == "api-key" {
				for i, val := range hValues {
					newVal, detectedTypes, modified := sanitizePayload(val)
					if modified {
						triggeredPkg := findPackageInLineage(pPids)
						pkgSuffix := ""
						if triggeredPkg != "" {
							pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
						}
						broadcastSSE("event", LogEvent{
							Time:    time.Now(),
							Type:    "EXFIL",
							Message: fmt.Sprintf("[HTTPS MITM] intercepted credentials (%s) in header '%s' (exfil poisoned)%s", strings.Join(detectedTypes, ", "), hName, pkgSuffix),
							Path:    getDetailedPath(pNames, pPids),
						})
						req.Header[hName][i] = newVal
					}
				}
			}
		}

		query := req.URL.RawQuery
		if query != "" {
			newQuery, detectedTypes, modified := sanitizePayload(query)
			if modified {
				triggeredPkg := findPackageInLineage(pPids)
				pkgSuffix := ""
				if triggeredPkg != "" {
					pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
				}
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "EXFIL",
					Message: fmt.Sprintf("[HTTPS MITM] intercepted credentials (%s) in query parameters (exfil poisoned)%s", strings.Join(detectedTypes, ", "), pkgSuffix),
					Path:    getDetailedPath(pNames, pPids),
				})
				req.URL.RawQuery = newQuery
			}
		}

		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err == nil && len(bodyBytes) > 0 {
				bodyStr := string(bodyBytes)
				newBody, detectedTypes, modified := sanitizePayload(bodyStr)
				if modified {
					triggeredPkg := findPackageInLineage(pPids)
					pkgSuffix := ""
					if triggeredPkg != "" {
						pkgSuffix = fmt.Sprintf(" [Package: %s]", triggeredPkg)
					}
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "EXFIL",
						Message: fmt.Sprintf("[HTTPS MITM] intercepted credentials (%s) in request body (exfil poisoned)%s", strings.Join(detectedTypes, ", "), pkgSuffix),
						Path:    getDetailedPath(pNames, pPids),
					})
					bodyBytes = []byte(newBody)
				}
			}
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
			req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		}
	}

	return false, nil
}

func (h *ProxyHandler) inspectInterceptedResponse(resp *http.Response, req *http.Request, host string, pid int, pName, pPath string, pNames []string, pPids []int) (*http.Response, error) {
	cfg := getSettings()

	isNpm := strings.Contains(host, "registry.npmjs.org")
	isTarball := strings.HasSuffix(req.URL.Path, ".tgz")
	isPypi := strings.Contains(host, "files.pythonhosted.org")

	if isPypi {
		pypiPkg := extractPypiPackageName(req.URL.Path)
		if pypiPkg != "" {
			if isPackageBlacklisted(pypiPkg) {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] package blacklist blocked download: '%s' is explicitly blacklisted", pypiPkg),
					Path:    pPath,
				})
				return nil, fmt.Errorf("package '%s' is explicitly blacklisted", pypiPkg)
			}
			if isPackageKnownMalicious(pypiPkg) {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] Malicious package blocked download: '%s' is identified as a known threat in feed", pypiPkg),
					Path:    pPath,
				})
				return nil, fmt.Errorf("package '%s' is identified as a known threat in feed", pypiPkg)
			}
			if cfg.DependencyConfusionActive {
				isPrivate := false
				for _, scopePattern := range cfg.PrivateScopes {
					if matchScopePattern(pypiPkg, scopePattern) {
						isPrivate = true
						break
					}
				}
				if isPrivate {
					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: fmt.Sprintf("[HTTPS MITM] Dependency Confusion Blocked: private scope package download '%s' requested from public host '%s'", pypiPkg, host),
						Path:    pPath,
					})
					return nil, fmt.Errorf("Dependency Confusion: private scope package '%s' requested from public registry", pypiPkg)
				}
			}
		}
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK && len(respBodyBytes) > 0 {
		var pkgName string
		if isNpm {
			parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
			if len(parts) > 0 && parts[0] != "" {
				pkgName = parts[0]
				if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
					pkgName = parts[0] + "/" + parts[1]
				}
			}
		} else if isPypi {
			pkgName = extractPypiPackageName(req.URL.Path)
		}

		// run static scanning layers (yara, ast, entropy)
		if isNpm && isTarball && cfg.TarballScan && !isPackageWhitelisted(pkgName) {
			isMal, desc := scanTarball(respBodyBytes)
			if isMal {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] malicious pattern match in package '%s': %s", pkgName, desc),
					Path:    getDetailedPath(pNames, pPids),
				})
				if cfg.KillInstallerOnStaticThreat {
					tryKillInstaller(pNames, pPids, getDetailedPath(pNames, pPids), fmt.Sprintf("malicious pattern: %s", desc), true, false, pkgName)
				}
				return nil, fmt.Errorf("malicious pattern match in npm package '%s': %s", pkgName, desc)
			}
		} else if isPypi && cfg.PypiScan && !isPackageWhitelisted(pkgName) {
			isMal, desc := scanPypiPackage(respBodyBytes, req.URL.Path)
			if isMal {
				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: fmt.Sprintf("[HTTPS MITM] malicious pattern match in package '%s': %s", pkgName, desc),
					Path:    getDetailedPath(pNames, pPids),
				})
				if cfg.KillInstallerOnStaticThreat {
					tryKillInstaller(pNames, pPids, getDetailedPath(pNames, pPids), fmt.Sprintf("malicious pattern: %s", desc), true, false, pkgName)
				}
				return nil, fmt.Errorf("malicious pattern match in pypi package '%s': %s", pkgName, desc)
			}
		}
	}

	// restore body
	resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
	resp.ContentLength = int64(len(respBodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(respBodyBytes)))

	return resp, nil
}

func (h *ProxyHandler) fallbackToTunnel(clientConn net.Conn, host string) {
	remoteConn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remoteConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	done := make(chan bool, 2)
	go func() {
		io.Copy(remoteConn, clientConn)
		done <- true
	}()
	go func() {
		io.Copy(clientConn, remoteConn)
		done <- true
	}()
	<-done
}

func isPackageExempt(pkgName string, exemptions []string) bool {
	for _, pattern := range exemptions {
		if pattern == "" {
			continue
		}
		// exact match
		if pkgName == pattern {
			return true
		}
		// glob match (e.g. @babel/*)
		if strings.HasSuffix(pattern, "*") {
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(pkgName, prefix) {
				return true
			}
		}
	}
	return false
}

func isTriggeredByThreat(desc string, triggerThreats []string) bool {
	for _, threat := range triggerThreats {
		if threat != "" && strings.Contains(desc, threat) {
			return true
		}
	}
	return false
}
