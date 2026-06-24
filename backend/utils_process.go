package main

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

type MIB_TCPROW_OWNER_PID struct {
	dwState      uint32
	dwLocalAddr  uint32
	dwLocalPort  uint32
	dwRemoteAddr uint32
	dwRemotePort uint32
	dwOwningPid  uint32
}

// get pid for local port using native GetExtendedTcpTable syscall (zero process spawns)
func getPIDForPort(port int) (int, error) {
	var size uint32 = 0
	getExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // order = true
		2, // AF_INET = 2
		4, // TCP_TABLE_OWNER_PID_ALL = 4
		0,
	)

	if size == 0 {
		return 0, fmt.Errorf("failed to get tcp table size")
	}

	buf := make([]byte, size)
	ret, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		2,
		4,
		0,
	)

	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed with code %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	ptr := uintptr(unsafe.Pointer(&buf[4])) // skip numEntries

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(ptr))
		p := uint16(row.dwLocalPort)
		localPort := int(((p & 0xff) << 8) | ((p >> 8) & 0xff))

		if localPort == port {
			return int(row.dwOwningPid), nil
		}
		ptr += rowSize
	}

	return 0, fmt.Errorf("pid not found for port %d", port)
}

// get parent pid and exe name using win32 snapshot api
func getParentPID(pid uint32) (uint32, string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirst := kernel32.NewProc("Process32FirstW")
	processNext := kernel32.NewProc("Process32NextW")

	handle, _, err := createSnapshot.Call(uintptr(0x00000002), 0) // TH32CS_SNAPPROCESS
	if handle == uintptr(syscall.InvalidHandle) {
		return 0, "", err
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	type ProcessEntry32W struct {
		Size            uint32
		Usage           uint32
		ProcessID       uint32
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [260]uint16
	}

	var entry ProcessEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := processFirst.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0, "", fmt.Errorf("first failed")
	}

	for {
		if entry.ProcessID == pid {
			var nameRunes []rune
			for _, r := range entry.ExeFile {
				if r == 0 {
					break
				}
				nameRunes = append(nameRunes, rune(r))
			}
			return entry.ParentProcessID, string(nameRunes), nil
		}
		ret, _, _ = processNext.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return 0, "", fmt.Errorf("not found")
}

// resolve process parent list tree
func getProcessTree(pid int) ([]string, []int) {
	parentMap, nameMap, err := getProcessSnapshotMaps()
	if err == nil {
		return getProcessTreeOptimized(pid, parentMap, nameMap)
	}

	var names []string
	var pids []int
	curr := uint32(pid)

	for i := 0; i < 8; i++ {
		parent, name, err := getParentPID(curr)
		if err != nil {
			break
		}
		names = append(names, name)
		pids = append(pids, int(curr))
		if parent == 0 || parent == curr {
			break
		}
		curr = parent
	}
	return names, pids
}

type cachedCmdLine struct {
	cmdLine  string
	cachedAt time.Time
}

var (
	cmdLineCache      = make(map[int]cachedCmdLine)
	cmdLineCacheMutex sync.RWMutex
)

// get active command line args using wmic (cached to prevent process storms with 10s ttl)
func getCmdLine(pid int) string {
	cmdLineCacheMutex.RLock()
	val, exists := cmdLineCache[pid]
	cmdLineCacheMutex.RUnlock()
	if exists && time.Since(val.cachedAt) < 10*time.Second {
		return val.cmdLine
	}

	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	var result string
	if len(lines) > 1 {
		result = strings.TrimSpace(lines[1])
	}

	cmdLineCacheMutex.Lock()
	cmdLineCache[pid] = cachedCmdLine{
		cmdLine:  result,
		cachedAt: time.Now(),
	}
	cmdLineCacheMutex.Unlock()

	return result
}

// kill an entire process tree using taskkill /F /T
func killProcessTree(pid int) error {
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// walk the process tree to find the npm/pip/cargo installer PID
func findInstallerPID(pNames []string, pPids []int) (int, string) {
	for i, name := range pNames {
		n := strings.ToLower(name)
		// npm runs inside node.exe, check command line
		if strings.Contains(n, "node.exe") {
			cmd := strings.ToLower(getCmdLine(pPids[i]))
			if strings.Contains(cmd, "npm-cli.js") || strings.Contains(cmd, "npm ") || strings.Contains(cmd, "npm.cmd") {
				return pPids[i], "npm"
			}
			if strings.Contains(cmd, "yarn") {
				return pPids[i], "yarn"
			}
			if strings.Contains(cmd, "pnpm") {
				return pPids[i], "pnpm"
			}
		}
		if strings.Contains(n, "npm") || strings.Contains(n, "npm.cmd") {
			return pPids[i], "npm"
		}
		if strings.Contains(n, "pip") || strings.Contains(n, "pip3") {
			return pPids[i], "pip"
		}
		if strings.Contains(n, "python.exe") {
			cmd := strings.ToLower(getCmdLine(pPids[i]))
			if strings.Contains(cmd, "pip") || strings.Contains(cmd, "setup.py") {
				return pPids[i], "pip"
			}
		}
		if strings.Contains(n, "cargo") {
			return pPids[i], "cargo"
		}
	}
	return 0, ""
}

// takes a single snapshot of all processes and builds parent/name maps
func getProcessSnapshotMaps() (map[uint32]uint32, map[uint32]string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirst := kernel32.NewProc("Process32FirstW")
	processNext := kernel32.NewProc("Process32NextW")

	handle, _, err := createSnapshot.Call(uintptr(0x00000002), 0) // TH32CS_SNAPPROCESS
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, nil, err
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	type ProcessEntry32W struct {
		Size            uint32
		Usage           uint32
		ProcessID       uint32
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [260]uint16
	}

	var entry ProcessEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := processFirst.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, nil, fmt.Errorf("first failed")
	}

	parentMap := make(map[uint32]uint32)
	nameMap := make(map[uint32]string)

	for {
		var nameRunes []rune
		for _, r := range entry.ExeFile {
			if r == 0 {
				break
			}
			nameRunes = append(nameRunes, rune(r))
		}
		exeName := string(nameRunes)

		parentMap[entry.ProcessID] = entry.ParentProcessID
		nameMap[entry.ProcessID] = exeName

		ret, _, _ = processNext.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return parentMap, nameMap, nil
}

// walks the parent hierarchy in-memory using the provided snapshot maps
func getProcessTreeOptimized(pid int, parentMap map[uint32]uint32, nameMap map[uint32]string) ([]string, []int) {
	var names []string
	var pids []int
	curr := uint32(pid)

	for i := 0; i < 8; i++ {
		name, exists := nameMap[curr]
		if !exists {
			break
		}
		names = append(names, name)
		pids = append(pids, int(curr))

		parent, exists := parentMap[curr]
		if !exists || parent == 0 || parent == curr {
			break
		}
		curr = parent
	}
	return names, pids
}

// starts a background task to check for proxy bypasses using optimized single snapshots
func startProxyBypassMonitor() {
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		// initial resolution
		cfg := getSettings()
		go resolveWhitelistedHosts(cfg)
		var lastResolve time.Time = time.Now()

		for range ticker.C {
			cfg = getSettings()
			if !cfg.SubprocessInterceptionActive {
				continue
			}

			if time.Since(lastResolve) > 2*time.Minute {
				lastResolve = time.Now()
				go resolveWhitelistedHosts(cfg)
			}

			// take a single snapshot of processes for the entire tick
			parentMap, nameMap, err := getProcessSnapshotMaps()
			if err != nil {
				continue
			}

			checkProxyBypassesOptimized(parentMap, nameMap)
			if cfg.AntiEvasionActive {
				checkSuspiciousSubprocessesOptimized(parentMap, nameMap)
			}
		}
	}()
}

// scans the active tcp table for connection bypasses using precompiled snapshot maps
func checkProxyBypassesOptimized(parentMap map[uint32]uint32, nameMap map[uint32]string) {
	var size uint32 = 0
	getExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // order = true
		2, // AF_INET = 2
		4, // TCP_TABLE_OWNER_PID_ALL = 4
		0,
	)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		2,
		4,
		0,
	)
	if ret != 0 {
		return
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	ptr := uintptr(unsafe.Pointer(&buf[4]))

	myPid := uint32(syscall.Getpid())
	checkedPids := make(map[uint32]bool)

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(ptr))
		ptr += rowSize

		pid := row.dwOwningPid
		if pid == 0 || pid == myPid {
			continue
		}

		// state check: ESTABLISHED (5) or SYN_SENT (3)
		if row.dwState != 5 && row.dwState != 3 {
			continue
		}

		// parse remote ip
		ipBytes := (*[4]byte)(unsafe.Pointer(&row.dwRemoteAddr))
		remoteIP := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

		// parse remote port
		p := uint16(row.dwRemotePort)
		remotePort := int(((p & 0xff) << 8) | ((p >> 8) & 0xff))

		// if loopback or local proxy/dashboard port, it's allowed
		if remoteIP.IsLoopback() || remotePort == 8080 || remotePort == 8081 {
			continue
		}

		cfg := getSettings()
		strictness := cfg.SubprocessNetworkStrictness
		if strictness == "block_all" {
			// proceed to block (do not allow local LAN or whitelist)
		} else if strictness == "strict" {
			// allow only whitelisted registries/domains, block LAN
			resolvedIPsMutex.RLock()
			isWhitelisted := resolvedIPs[remoteIP.String()]
			resolvedIPsMutex.RUnlock()
			if isWhitelisted {
				continue
			}
		} else { // lenient (default)
			// allow local LAN connections
			if remoteIP.IsPrivate() {
				continue
			}
			// allow whitelisted registries/domains
			resolvedIPsMutex.RLock()
			isWhitelisted := resolvedIPs[remoteIP.String()]
			resolvedIPsMutex.RUnlock()
			if isWhitelisted {
				continue
			}
		}

		isBypass := false
		if val, exists := checkedPids[pid]; exists {
			isBypass = val
		} else {
			names, pids := getProcessTreeOptimized(int(pid), parentMap, nameMap)
			if isPostInstall(names, pids) {
				isBypass = true
				checkedPids[pid] = true

				pPath := getDetailedPath(names, pids)
				msg := fmt.Sprintf("Proxy Bypass Blocked: script attempted direct TCP connection to %s:%d", remoteIP.String(), remotePort)

				broadcastSSE("event", LogEvent{
					Time:    time.Now(),
					Type:    "BLOCKED",
					Message: msg,
					Path:    pPath,
				})

				tryKillInstaller(names, pids, pPath, msg, true, false, "")
			} else {
				checkedPids[pid] = false
			}
		}

		if isBypass {
			break
		}
	}
}

// checks installer tree children for security tools scanning in-memory
func checkSuspiciousSubprocessesOptimized(parentMap map[uint32]uint32, nameMap map[uint32]string) {
	myPid := uint32(syscall.Getpid())

	for pid, exeName := range nameMap {
		if pid != 0 && pid != myPid {
			// check if this process is part of an installer tree
			names, pids := getProcessTreeOptimized(int(pid), parentMap, nameMap)
			if isPostInstall(names, pids) {
				cmdLine := getCmdLine(int(pid))
				if isEvasion, reason := isEvasionAttempt(exeName, cmdLine); isEvasion {
					pPath := getDetailedPath(names, pids)
					msg := fmt.Sprintf("Evasion Blocked: installer hook %s", reason)

					broadcastSSE("event", LogEvent{
						Time:    time.Now(),
						Type:    "BLOCKED",
						Message: msg,
						Path:    pPath,
					})

					// kill the installer before it evades us
					tryKillInstaller(names, pids, pPath, msg, true, false, "")
					break
				}
			}
		}
	}
}

// check if a subprocess is trying to query security programs or tools
func isEvasionAttempt(exeName, cmdLine string) (bool, string) {
	exeName = strings.ToLower(exeName)
	cmdLine = strings.ToLower(cmdLine)

	// check system utility spawns
	if exeName == "tasklist.exe" || exeName == "fltmc.exe" || exeName == "sc.exe" || exeName == "reg.exe" || exeName == "wmic.exe" {
		return true, fmt.Sprintf("ran suspicious system utility %s", exeName)
	}

	// check command line keywords
	keywords := []string{
		"wireshark", "fiddler", "charles", "processhacker", "procexp", "procmon",
		"ollydbg", "x64dbg", "windbg", "vboxservice", "vboxtray", "vmtoolsd",
		"defender", "windefend", "kaspersky", "mcafee", "symantec", "norton",
		"malwarebytes", "avg", "avast", "bitdefender", "crowdstrike", "sentinelone",
	}
	for _, word := range keywords {
		if strings.Contains(cmdLine, word) || strings.Contains(exeName, word) {
			return true, fmt.Sprintf("scanned for security/analysis tool (keyword: %s)", word)
		}
	}

	return false, ""
}

var (
	resolvedIPsMutex sync.RWMutex
	resolvedIPs      = make(map[string]bool)
	lastResolution   time.Time
)

func resolveWhitelistedHosts(cfg Settings) {
	resolvedIPsMutex.Lock()
	defer resolvedIPsMutex.Unlock()

	newResolvedIPs := make(map[string]bool)

	// default registries
	defaultRegistries := []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"pypi.org",
		"files.pythonhosted.org",
	}
	for _, domain := range defaultRegistries {
		ips, err := net.LookupHost(domain)
		if err == nil {
			for _, ip := range ips {
				newResolvedIPs[ip] = true
			}
		}
	}

	// custom registries
	for _, reg := range cfg.CustomNpmRegistries {
		host := extractHost(reg)
		if host != "" {
			ips, err := net.LookupHost(host)
			if err == nil {
				for _, ip := range ips {
					newResolvedIPs[ip] = true
				}
			}
		}
	}
	for _, reg := range cfg.CustomPypiRegistries {
		host := extractHost(reg)
		if host != "" {
			ips, err := net.LookupHost(host)
			if err == nil {
				for _, ip := range ips {
					newResolvedIPs[ip] = true
				}
			}
		}
	}

	// custom domain whitelist
	for _, domain := range cfg.CustomDomainWhitelist {
		ips, err := net.LookupHost(domain)
		if err == nil {
			for _, ip := range ips {
				newResolvedIPs[ip] = true
			}
		}
	}

	resolvedIPs = newResolvedIPs
	lastResolution = time.Now()
}

func extractHost(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
