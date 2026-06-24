package main

// ts file pmo
import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	attachConsole = kernel32.NewProc("AttachConsole")
	freeConsole   = kernel32.NewProc("FreeConsole")
)

const ATTACH_PARENT_PROCESS = ^uintptr(0)

// parent console hook
func attachToConsole() bool {
	r, _, _ := attachConsole.Call(ATTACH_PARENT_PROCESS)
	if r != 0 {
		hCon, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0)
		if err == nil {
			os.Stdout = os.NewFile(uintptr(hCon), "/dev/stdout")
			os.Stderr = os.NewFile(uintptr(hCon), "/dev/stderr")
			log.SetOutput(os.Stdout)
			return true
		}
	}
	return false
}

// cli dispatcher
func handleCLI() {
	if len(os.Args) < 2 {
		return
	}

	arg := strings.ToLower(os.Args[1])
	if arg != "env" && arg != "shell" && arg != "run" && arg != "help" && arg != "--help" && arg != "-h" && arg != "gui" && arg != "prompt" && arg != "config" && arg != "set" && arg != "list" && arg != "cert" && arg != "install" {
		return
	}

	if arg == "help" || arg == "--help" || arg == "-h" {
		attached := attachToConsole()
		defer func() {
			if attached {
				freeConsole := kernel32.NewProc("FreeConsole")
				freeConsole.Call()
			}
		}()

		fmt.Println("\nDevGate Zero-Trust Developer Proxy CLI")
		fmt.Println("Usage:")
		fmt.Println("  devgate.exe [command] [args...]")
		fmt.Println("\nCommands:")
		fmt.Println("  env           Detect parent shell and output proxy environment variable setup commands")
		fmt.Println("  shell         Spawn an interactive subshell pre-configured with proxy environment variables")
		fmt.Println("  run <cmd>     Execute a single command wrapped with proxy environment variables synchronously")
		fmt.Println("  gui [opt]     Enable or disable the Web UI dashboard auto-opening on startup (opt: enable/disable)")
		fmt.Println("  config        Show the current engine configuration and custom list rule counts")
		fmt.Println("  set <k> <v>   Change config settings (e.g. set mode strict, set honeypot off, set gui on, set killthreat on)")
		fmt.Println("  list <subcmd> Manage custom whitelists, blacklists, custom registries, and scopes (subcmds: show, add, remove, clear)")
		fmt.Println("                Lists: dw (domain whitelist), db (domain blacklist), pw (pkg whitelist), pb (pkg blacklist),")
		fmt.Println("                       nr (npm registry), pr (pypi registry), ps (private scope)")
		fmt.Println("  cert <subcmd> Manage Root CA certificate trust (subcmds: status, trust, untrust)")
		fmt.Println("  install       Register DevGate globally and add it to your user PATH variable")
		fmt.Println("  help          Show this help menu")
		fmt.Println("\nIf run without commands, DevGate runs quietly in the Windows system tray.")
		os.Exit(0)
	}

	if arg == "gui" {
		attached := attachToConsole()
		defer func() {
			if attached {
				freeConsole := kernel32.NewProc("FreeConsole")
				freeConsole.Call()
			}
		}()
		if len(os.Args) < 3 {
			fmt.Println("Usage: devgate.exe gui [enable|disable]")
			os.Exit(1)
		}
		cmdVal := strings.ToLower(os.Args[2])
		if cmdVal != "enable" && cmdVal != "disable" {
			fmt.Println("Error: Invalid argument. Use 'enable' or 'disable'.")
			os.Exit(1)
		}

		loadSettings()
		settingsMutex.Lock()
		if cmdVal == "enable" {
			settings.WebUIEnabled = true
			fmt.Println("[+] Web Dashboard Auto-Open enabled successfully.")
		} else {
			settings.WebUIEnabled = false
			fmt.Println("[+] Web Dashboard Auto-Open disabled successfully.")
		}
		saveSettingsLocked()
		settingsMutex.Unlock()
		os.Exit(0)
	}

	if arg == "prompt" {
		if len(os.Args) < 5 {
			fmt.Println("Error: Missing arguments for prompt command.")
			os.Exit(1)
		}
		allocateConsole()
		defer func() {
			freeConsole := kernel32.NewProc("FreeConsole")
			freeConsole.Call()
		}()

		promptID := os.Args[2]
		targetHost := os.Args[3]
		processPath := os.Args[4]
		triggeredPkg := ""
		if len(os.Args) > 5 {
			triggeredPkg = os.Args[5]
		}

		handleCLIPrompt(promptID, targetHost, processPath, triggeredPkg)
		os.Exit(0)
	}

	if arg == "config" {
		handleCLIConfig()
		os.Exit(0)
	}

	if arg == "set" {
		if len(os.Args) < 4 {
			attached := attachToConsole()
			fmt.Println("Error: Missing arguments. Usage: devgate.exe set <key> <value>")
			if attached {
				freeConsole := kernel32.NewProc("FreeConsole")
				freeConsole.Call()
			}
			os.Exit(1)
		}
		handleCLISet(os.Args[2], os.Args[3])
		os.Exit(0)
	}

	if arg == "list" {
		if len(os.Args) < 3 {
			attached := attachToConsole()
			fmt.Println("Error: Missing sub-command. Usage: devgate.exe list [show|add|remove|clear] [list_name] [entry]")
			if attached {
				freeConsole := kernel32.NewProc("FreeConsole")
				freeConsole.Call()
			}
			os.Exit(1)
		}
		subcmd := strings.ToLower(os.Args[2])
		listName := ""
		if len(os.Args) > 3 {
			listName = os.Args[3]
		}

		var restArgs []string
		if len(os.Args) > 4 {
			restArgs = os.Args[4:]
		}

		handleCLIList(subcmd, listName, restArgs)
		os.Exit(0)
	}

	if arg == "cert" {
		handleCLICert()
		os.Exit(0)
	}

	if arg == "install" {
		handleCLIInstall()
		os.Exit(0)
	}

	if arg == "run" {
		handleCLIRun()
		os.Exit(0)
	}

	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole := kernel32.NewProc("FreeConsole")
			freeConsole.Call()
		}
	}()

	// detect shell
	_, parentName, err := getParentPID(uint32(os.Getpid()))
	isPowerShell := false
	shellExe := "cmd.exe"

	if err == nil {
		pName := strings.ToLower(parentName)
		if strings.Contains(pName, "powershell") || strings.Contains(pName, "pwsh") {
			isPowerShell = true
			shellExe = parentName
		} else if strings.Contains(pName, "cmd") {
			shellExe = "cmd.exe"
		}
	}

	if arg == "env" {
		if isPowerShell {
			fmt.Println("\n# Run these commands in PowerShell to enable DevGate proxy:")
			fmt.Println(`$env:HTTP_PROXY="http://127.0.0.1:8080"`)
			fmt.Println(`$env:HTTPS_PROXY="http://127.0.0.1:8080"`)
			fmt.Println(`$env:http_proxy="http://127.0.0.1:8080"`)
			fmt.Println(`$env:https_proxy="http://127.0.0.1:8080"`)
			fmt.Println("\n# [No-Cert Fallback Option]")
			fmt.Println("# If you choose not to trust a Root CA certificate, configure npm/pip to use HTTP:")
			fmt.Println("#   npm config set registry http://registry.npmjs.org")
			fmt.Println("#   pip config set global.index-url http://pypi.org/simple")
			fmt.Println("# DevGate will scan locally and auto-upgrade outbound traffic to secure HTTPS.")
		} else {
			fmt.Println("\n:: Run these commands in CMD to enable DevGate proxy:")
			fmt.Println("set HTTP_PROXY=http://127.0.0.1:8080")
			fmt.Println("set HTTPS_PROXY=http://127.0.0.1:8080")
			fmt.Println("set http_proxy=http://127.0.0.1:8080")
			fmt.Println("set https_proxy=http://127.0.0.1:8080")
			fmt.Println("\n:: [No-Cert Fallback Option]")
			fmt.Println(":: If you choose not to trust a Root CA certificate, configure npm/pip to use HTTP:")
			fmt.Println("::   npm config set registry http://registry.npmjs.org")
			fmt.Println("::   pip config set global.index-url http://pypi.org/simple")
			fmt.Println(":: DevGate will scan locally and auto-upgrade outbound traffic to secure HTTPS.")
		}
		os.Exit(0)
	}

	// spawn shell window
	if arg == "shell" {
		loadSettings()
		cfg := getSettings()
		shellName := "Command Prompt"
		if isPowerShell {
			shellName = "PowerShell"
		}

		fmt.Printf("\n[DevGate] Spawning interactive %s subshell in a new window...\n", shellName)

		certTrusted := isCATrusted()
		var certStatusLine string
		var isInterceptionRunning bool
		if cfg.HttpsInspectionActive {
			if certTrusted {
				certStatusLine = "  HTTPS Intercept  = Active (Root CA Trusted)"
				isInterceptionRunning = true
			} else {
				certStatusLine = "  [Warning] HTTPS Intercept enabled, but Root CA is UNTRUSTED (decryption suspended; using No-Cert Fallback registry mapping)."
			}
		} else {
			certStatusLine = "  HTTPS Intercept  = Suspended (No-Cert Fallback registry mapping active)"
		}

		var cmd *exec.Cmd
		if isPowerShell {
			cmdStr := "Write-Host '[DevGate] Shield Active' -ForegroundColor Green; Write-Host '  HTTP_PROXY   =' $env:HTTP_PROXY; Write-Host '  HTTPS_PROXY  =' $env:HTTPS_PROXY;"
			if cfg.SandboxSpoofing {
				cmdStr += " Write-Host '  Deception Mode   = Active (CI, GITHUB_ACTIONS, VM_DETECTED)' -ForegroundColor Yellow;"
				cmdStr += " Write-Host '  [Tip] Deception Mode tricks malware into sleeping. If an install hangs, malware might be evasive.' -ForegroundColor Gray;"
			}
			if isInterceptionRunning {
				cmdStr += fmt.Sprintf(" Write-Host '%s' -ForegroundColor Green;", certStatusLine)
			} else {
				cmdStr += fmt.Sprintf(" Write-Host '%s' -ForegroundColor Yellow;", certStatusLine)
				cmdStr += " Write-Host '  NPM Registry =' $env:npm_config_registry -ForegroundColor Cyan;"
				cmdStr += " Write-Host '  PIP Index    =' $env:PIP_INDEX_URL -ForegroundColor Cyan;"
			}
			cmdStr += " $Host.UI.RawUI.WindowTitle = 'DevGate Shell'"
			cmd = exec.Command("cmd.exe", "/c", "start", shellExe, "-NoLogo", "-NoExit", "-Command", cmdStr)
		} else {
			cmdStr := "echo [DevGate] Shield Active && echo   HTTP_PROXY   = %HTTP_PROXY% && echo   HTTPS_PROXY  = %HTTPS_PROXY%"
			if cfg.SandboxSpoofing {
				cmdStr += " && echo   Deception Mode   = Active (CI, GITHUB_ACTIONS, VM_DETECTED)"
				cmdStr += " && echo   [Tip] Deception Mode tricks malware into sleeping. If an install hangs, malware might be evasive."
			}
			cmdStr += fmt.Sprintf(" && echo %s", certStatusLine)
			if !isInterceptionRunning {
				cmdStr += " && echo   NPM Registry = %npm_config_registry% && echo   PIP Index    = %PIP_INDEX_URL%"
			}
			cmdStr += " && title DevGate Shell"
			cmd = exec.Command("cmd.exe", "/c", "start", "cmd.exe", "/k", cmdStr)
		}

		env := append(os.Environ(),
			"HTTP_PROXY=http://127.0.0.1:8080",
			"HTTPS_PROXY=http://127.0.0.1:8080",
			"http_proxy=http://127.0.0.1:8080",
			"https_proxy=http://127.0.0.1:8080",
		)
		if !isInterceptionRunning {
			env = append(env,
				"npm_config_registry=http://registry.npmjs.org",
				"yarn_registry=http://registry.npmjs.org",
				"PIP_INDEX_URL=http://pypi.org/simple",
				"PIP_TRUSTED_HOST=pypi.org files.pythonhosted.org",
			)
		}
		if cfg.SandboxSpoofing {
			env = append(env,
				"CI=true",
				"GITHUB_ACTIONS=true",
				"RUNNER_OS=Windows",
				"SANDBOX_ACTIVE=true",
				"VM_DETECTED=true",
			)
		}
		cmd.Env = env

		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}

		if err := cmd.Start(); err != nil {
			fmt.Printf("[Error] Failed to spawn subshell: %v\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	}
}

func enableAnsi() {
	var mode uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	getStdHandle := kernel32.NewProc("GetStdHandle")

	// STD_OUTPUT_HANDLE = -11
	hOut, _, _ := getStdHandle.Call(uintptr(1<<32 - 11)) // 0xfffffff5

	if hOut != 0 && hOut != uintptr(^uintptr(0)) {
		if r, _, _ := getConsoleMode.Call(hOut, uintptr(unsafe.Pointer(&mode))); r != 0 {
			mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
			setConsoleMode.Call(hOut, uintptr(mode))
		}
	}
}

func handleCLIPrompt(id, host, path, triggeredPkg string) {
	enableAnsi()

	reset := "\033[0m"
	bold := "\033[1m"
	redBg := "\033[41m"
	yellow := "\033[1;33m"
	cyan := "\033[1;36m"
	red := "\033[1;31m"
	green := "\033[1;32m"
	gray := "\033[90m"

	fmt.Printf("\n")
	fmt.Printf("%s┌──────────────────────────────────────────────────────────────┐%s\n", yellow, reset)
	fmt.Printf("%s│ %s%s                  DEVGATE THREAT INTERCEPT                    %s%s│%s\n", yellow, redBg, bold, reset, yellow, reset)
	fmt.Printf("%s├──────────────────────────────────────────────────────────────┤%s\n", yellow, reset)
	if triggeredPkg != "" {
		fmt.Printf("%s│%s  Package Name:  %s%-44s%s %s│%s\n", yellow, reset, red, triggeredPkg, reset, yellow, reset)
	}
	fmt.Printf("%s│%s  Target Host:   %s%-44s%s %s│%s\n", yellow, reset, cyan, host, reset, yellow, reset)
	normalizedPath := strings.ReplaceAll(path, "\r\n", "\n")
	pathLines := strings.Split(normalizedPath, "\n")
	isFirst := true
	for _, line := range pathLines {
		lineTrimmed := strings.TrimSpace(line)
		if lineTrimmed == "" {
			continue
		}
		wrapped := wrapText(lineTrimmed, 44)
		for _, wLine := range wrapped {
			if isFirst {
				fmt.Printf("%s│%s  Process Path:  %s%-44s%s %s│%s\n", yellow, reset, gray, wLine, reset, yellow, reset)
				isFirst = false
			} else {
				fmt.Printf("%s│%s                 %s%-44s%s %s│%s\n", yellow, reset, gray, wLine, reset, yellow, reset)
			}
		}
	}
	if isFirst {
		fmt.Printf("%s│%s  Process Path:  %s%-44s%s %s│%s\n", yellow, reset, gray, "unknown", reset, yellow, reset)
	}
	fmt.Printf("%s│%s  Alert Status:  %s%-44s%s %s│%s\n", yellow, reset, red, "Paused - Pending Developer Decision", reset, yellow, reset)
	fmt.Printf("%s├──────────────────────────────────────────────────────────────┤%s\n", yellow, reset)
	fmt.Printf("%s│%s"+strings.Repeat(" ", 62)+"%s│%s\n", yellow, reset, yellow, reset)
	fmt.Printf("%s│%s  %s[A]%s Allow Once   - Let this connection pass through once.   %s│%s\n", yellow, reset, green, reset, yellow, reset)
	fmt.Printf("%s│%s  %s[B]%s Block        - Kill the connection immediately.         %s│%s\n", yellow, reset, red, reset, yellow, reset)
	fmt.Printf("%s│%s  %s[W]%s Allow Always - Whitelist this destination permanently.  %s│%s\n", yellow, reset, yellow, reset, yellow, reset)
	fmt.Printf("%s│%s  %s[K]%s Kill Install - Block connection AND abort the installer. %s│%s\n", yellow, reset, red, reset, yellow, reset)
	fmt.Printf("%s│%s"+strings.Repeat(" ", 62)+"%s│%s\n", yellow, reset, yellow, reset)
	fmt.Printf("%s└──────────────────────────────────────────────────────────────┘%s\n", yellow, reset)

	for {
		fmt.Printf("\nSelect action (%sA%s/%sB%s/%sW%s/%sK%s): ", green, reset, red, reset, yellow, reset, red, reset)
		var choice string
		fmt.Scanln(&choice)
		choice = strings.ToLower(strings.TrimSpace(choice))

		decision := ""
		if choice == "a" || choice == "allow" {
			decision = "allow"
		} else if choice == "b" || choice == "block" {
			decision = "block"
		} else if choice == "w" || choice == "whitelist" {
			decision = "whitelist"
		} else if choice == "k" || choice == "kill" {
			decision = "kill"
		} else {
			fmt.Printf("Invalid choice. Please enter A, B, W, or K.\n")
			continue
		}

		// submit decision via http post to backend
		url := "http://127.0.0.1:8081/api/respond"
		reqBody, err := json.Marshal(map[string]string{
			"id":       id,
			"decision": decision,
		})
		if err != nil {
			fmt.Printf("Error preparing request: %v\n", err)
			return
		}

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			fmt.Printf("Error sending decision to DevGate backend: %v\n", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Printf("\n%s[+] Decision '%s' submitted successfully. Resuming connection...%s\n", green, decision, reset)
			time.Sleep(1 * time.Second)
			return
		} else {
			fmt.Printf("\n%s[-] Error: decision request rejected (status %d). The prompt may have expired.%s\n", red, resp.StatusCode, reset)
			time.Sleep(2 * time.Second)
			return
		}
	}
}

func handleCLIConfig() {
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole := kernel32.NewProc("FreeConsole")
			freeConsole.Call()
		}
	}()

	enableAnsi()
	loadSettings()

	reset := "\033[0m"
	bold := "\033[1m"
	yellow := "\033[1;33m"
	cyan := "\033[1;36m"
	green := "\033[1;32m"
	red := "\033[1;31m"
	gray := "\033[90m"

	cfg := getSettings()

	fmt.Printf("\n%s%s=== DevGate Engine Configuration ===%s\n\n", bold, cyan, reset)

	fmt.Printf("  %sProtection Mode:%s        %s\n", bold, reset, colorizeMode(cfg.Mode, green, yellow, red))
	fmt.Printf("  %sCredential Honeypot:%s    %s\n", bold, reset, colorizeBool(cfg.Honeypot, green, red))
	fmt.Printf("  %sWeb Dashboard Auto-Open:%s %s\n", bold, reset, colorizeBool(cfg.WebUIEnabled, green, red))
	fmt.Printf("  %sLockfile Drift Check:%s   %s (Mode: %s)\n", bold, reset, colorizeBool(cfg.LockfileActive, green, red), colorizeMode(cfg.LockfileMode, green, yellow, red))
	if cfg.LockfilePaths != "" {
		fmt.Printf("    %sPaths:%s                 %s\n", gray, reset, cfg.LockfilePaths)
	}
	fmt.Printf("  %sRegistry Age Check:%s     %s\n", bold, reset, colorizeBool(cfg.RegistryAgeCheck, green, red))
	fmt.Printf("  %sTyposquatting Check:%s    %s\n", bold, reset, colorizeBool(cfg.TyposquatCheck, green, red))
	fmt.Printf("  %sNPM Tarball Analysis:%s   %s\n", bold, reset, colorizeBool(cfg.TarballScan, green, red))
	fmt.Printf("  %sPyPI Package Analysis:%s  %s\n", bold, reset, colorizeBool(cfg.PypiScan, green, red))
	fmt.Printf("  %sShannon Entropy Scan:%s   %s\n", bold, reset, colorizeBool(cfg.EntropyScan, green, red))
	fmt.Printf("  %sAST Parse Analysis:%s     %s\n", bold, reset, colorizeBool(cfg.ASTScan, green, red))
	fmt.Printf("  %sYARA Heuristic Scan:%s    %s\n", bold, reset, colorizeBool(cfg.YaraActive, green, red))
	fmt.Printf("  %sDependency Confusion Def:%s %s\n", bold, reset, colorizeBool(cfg.DependencyConfusionActive, green, red))
	fmt.Printf("  %sSandbox Deception Spoof:%s %s\n", bold, reset, colorizeBool(cfg.SandboxSpoofing, green, red))
	fmt.Printf("  %sSandbox Evasion Action:%s   %s\n", bold, reset, colorizeMode(cfg.SandboxEvasionAction, green, yellow, red))
	fmt.Printf("  %sStrip Lifecycle Scripts:%s  %s\n", bold, reset, colorizeMode(cfg.StripLifecycleScripts, green, yellow, red))
	if len(cfg.StripLifecycleTargets) > 0 {
		fmt.Printf("    %sTargets:%s               %s\n", gray, reset, strings.Join(cfg.StripLifecycleTargets, ", "))
	}
	if len(cfg.StripLifecycleTriggerThreats) > 0 {
		fmt.Printf("    %sTrigger Threats:%s       %s\n", gray, reset, strings.Join(cfg.StripLifecycleTriggerThreats, ", "))
	}
	if len(cfg.StripLifecycleExemptions) > 0 {
		fmt.Printf("    %sExemptions:%s            %s\n", gray, reset, strings.Join(cfg.StripLifecycleExemptions, ", "))
	}
	fmt.Printf("  %sThreat Intercept Timeout:%s %d seconds\n", bold, reset, cfg.PromptTimeout)
	fmt.Printf("  %sKill Installer on Threat:%s %s\n", bold, reset, colorizeBool(cfg.KillInstallerOnThreat, green, red))
	fmt.Printf("    %s(Overrides protection mode to immediately abort installer tree; on-disk files persist)%s\n", gray, reset)
	fmt.Printf("  %sReal-Time Threat Intel:%s   %s\n", bold, reset, colorizeBool(cfg.ThreatIntelActive, green, red))
	fmt.Printf("    %sFeed Sync:%s               %s\n", gray, reset, colorizeBool(cfg.LocalFeedSyncActive, green, red))
	fmt.Printf("    %sCloudflare DNS / DNSBL:%s  %s\n", gray, reset, colorizeBool(cfg.CloudflareDNSActive, green, red))
	fmt.Printf("    %sURLhaus Live API:%s        %s\n", gray, reset, colorizeBool(cfg.URLhausLiveActive, green, red))
	fmt.Printf("  %sSubprocess Connection:%s    %s (Strictness: %s)\n", bold, reset, colorizeBool(cfg.SubprocessInterceptionActive, green, red), colorizeMode(cfg.SubprocessNetworkStrictness, green, yellow, red))
	fmt.Printf("  %sAnti-Evasion Scanner:%s     %s\n", bold, reset, colorizeBool(cfg.AntiEvasionActive, green, red))
	fmt.Printf("  %sSensitive File Access:%s    %s (Action: %s)\n", bold, reset, colorizeBool(cfg.SensitiveFileAccessActive, green, red), colorizeMode(cfg.SensitiveFileAccessAction, green, yellow, red))

	trustedStr := red + "UNTRUSTED / INACTIVE" + reset
	if isCATrusted() {
		trustedStr = green + "TRUSTED & ACTIVE" + reset
	}
	fmt.Printf("  %sRoot CA Certificate:%s     %s\n", bold, reset, trustedStr)
	fmt.Printf("  %sHTTPS Decryption MITM:%s   %s\n", bold, reset, colorizeBool(cfg.HttpsInspectionActive, green, red))
	fmt.Printf("  %sRun on Startup:%s           %s\n", bold, reset, colorizeBool(cfg.RunOnStartup, green, red))

	fmt.Printf("\n%s%s=== Custom Rules Statistics ===%s\n\n", bold, yellow, reset)
	fmt.Printf("  %sDomain Whitelist (dw):%s     %d active rule(s)\n", bold, reset, len(cfg.CustomDomainWhitelist))
	fmt.Printf("  %sDomain Blacklist (db):%s     %d active rule(s)\n", bold, reset, len(cfg.CustomDomainBlacklist))
	fmt.Printf("  %sPackage Whitelist (pw):%s    %d active rule(s)\n", bold, reset, len(cfg.CustomPackageWhitelist))
	fmt.Printf("  %sPackage Blacklist (pb):%s    %d active rule(s)\n", bold, reset, len(cfg.CustomPackageBlacklist))
	fmt.Printf("  %sCustom NPM Registries (nr):%s %d active rule(s)\n", bold, reset, len(cfg.CustomNpmRegistries))
	fmt.Printf("  %sCustom PyPI Registries (pr):%s%d active rule(s)\n", bold, reset, len(cfg.CustomPypiRegistries))
	fmt.Printf("  %sPrivate Scopes (ps):%s        %d active rule(s)\n", bold, reset, len(cfg.PrivateScopes))
	fmt.Printf("\n")
}

func colorizeBool(val bool, green, red string) string {
	if val {
		return green + "ENABLED" + "\033[0m"
	}
	return red + "DISABLED" + "\033[0m"
}

func colorizeMode(mode, green, yellow, red string) string {
	m := strings.ToLower(mode)
	if m == "strict" || m == "block" || m == "block_all" || m == "always" || m == "all_public" {
		return red + strings.ToUpper(mode) + "\033[0m"
	} else if m == "interactive" || m == "prompt" || m == "threats_only" {
		return yellow + strings.ToUpper(mode) + "\033[0m"
	}
	return green + strings.ToUpper(mode) + "\033[0m" // audit / lenient / never
}

func handleCLISet(key, val string) {
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole := kernel32.NewProc("FreeConsole")
			freeConsole.Call()
		}
	}()

	loadSettings()
	settingsMutex.Lock()
	defer settingsMutex.Unlock()

	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.ToLower(strings.TrimSpace(val))

	isTrue := v == "on" || v == "true" || v == "enable" || v == "yes" || v == "1"
	isFalse := v == "off" || v == "false" || v == "disable" || v == "no" || v == "0"

	success := true
	message := ""

	switch k {
	case "mode":
		if v == "strict" || v == "interactive" || v == "audit" {
			settings.Mode = v
			message = fmt.Sprintf("[+] Protection Mode updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid mode. Choose 'strict', 'interactive', or 'audit'."
		}
	case "honeypot":
		if isTrue || isFalse {
			settings.Honeypot = isTrue
			message = fmt.Sprintf("[+] Credential Honeypot updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "gui", "webui":
		if isTrue || isFalse {
			settings.WebUIEnabled = isTrue
			message = fmt.Sprintf("[+] Web Dashboard Auto-Open updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "lockfile":
		if isTrue || isFalse {
			settings.LockfileActive = isTrue
			message = fmt.Sprintf("[+] Lockfile Drift Check updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "lockfile-mode":
		if v == "block" || v == "prompt" || v == "audit" {
			settings.LockfileMode = v
			message = fmt.Sprintf("[+] Lockfile Drift Action updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid mode. Choose 'block', 'prompt', or 'audit'."
		}
	case "lockfile-paths":
		settings.LockfilePaths = val // keep raw casing for paths
		message = fmt.Sprintf("[+] Lockfile paths updated to: %s", val)
	case "age-check", "registry-age":
		if isTrue || isFalse {
			settings.RegistryAgeCheck = isTrue
			message = fmt.Sprintf("[+] Registry Age Check updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "typosquat":
		if isTrue || isFalse {
			settings.TyposquatCheck = isTrue
			message = fmt.Sprintf("[+] Typosquatting Detection updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "tarball-scan", "npm-scan":
		if isTrue || isFalse {
			settings.TarballScan = isTrue
			message = fmt.Sprintf("[+] NPM Tarball Static Analysis updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "pypi-scan":
		if isTrue || isFalse {
			settings.PypiScan = isTrue
			message = fmt.Sprintf("[+] PyPI Package Static Analysis updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "entropy-scan", "entropy":
		if isTrue || isFalse {
			settings.EntropyScan = isTrue
			message = fmt.Sprintf("[+] Shannon Entropy Scan updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "ast-scan", "ast":
		if isTrue || isFalse {
			settings.ASTScan = isTrue
			message = fmt.Sprintf("[+] AST Parse Analysis updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "yara":
		if isTrue || isFalse {
			settings.YaraActive = isTrue
			message = fmt.Sprintf("[+] YARA Signature Engine updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "confusion", "dep-confusion":
		if isTrue || isFalse {
			settings.DependencyConfusionActive = isTrue
			message = fmt.Sprintf("[+] Dependency Confusion Defense updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "deception", "sandbox-spoof":
		if isTrue || isFalse {
			settings.SandboxSpoofing = isTrue
			message = fmt.Sprintf("[+] Sandbox Deception Spoofing updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "evasion-action", "evasion-mode":
		if v == "block" || v == "poison" || v == "audit" {
			settings.SandboxEvasionAction = v
			message = fmt.Sprintf("[+] Sandbox Evasion Action updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid action. Choose 'block', 'poison', or 'audit'."
		}
	case "timeout", "prompt-timeout":
		var sec int
		_, err := fmt.Sscan(val, &sec)
		if err == nil && sec >= 5 && sec <= 300 {
			settings.PromptTimeout = sec
			message = fmt.Sprintf("[+] Threat intercept timeout updated to: %d seconds", sec)
		} else {
			success = false
			message = "Error: Invalid timeout value. Please provide a number between 5 and 300 (seconds)."
		}
	case "killthreat", "killinstaller":
		if isTrue || isFalse {
			settings.KillInstallerOnThreat = isTrue
			if isTrue {
				message = fmt.Sprintf("[+] Kill Installer on Threat updated to: true\n" +
					"    Note: This overrides protection mode (strict/interactive) to automatically abort\n" +
					"    the installer tree immediately on blocked threats. Files already on disk persist.")
			} else {
				message = fmt.Sprintf("[+] Kill Installer on Threat updated to: false")
			}
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "killstaticthreat", "killstatic":
		if isTrue || isFalse {
			settings.KillInstallerOnStaticThreat = isTrue
			message = fmt.Sprintf("[+] Kill Installer on Static Threat updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "autocleanup", "cleanup":
		if isTrue || isFalse {
			settings.AutoCleanupOnThreat = isTrue
			message = fmt.Sprintf("[+] Auto-Clean Aborted Packages updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "threatintel", "threat-intel":
		if isTrue || isFalse {
			settings.ThreatIntelActive = isTrue
			message = fmt.Sprintf("[+] Real-Time Threat Intelligence updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "feeds", "feed-sync":
		if isTrue || isFalse {
			settings.LocalFeedSyncActive = isTrue
			message = fmt.Sprintf("[+] Background Feed Sync updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "cfdns", "cloudflare-dns":
		if isTrue || isFalse {
			settings.CloudflareDNSActive = isTrue
			message = fmt.Sprintf("[+] Cloudflare Security DNS & DNSBL updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "urlhauslive", "urlhaus-live":
		if isTrue || isFalse {
			settings.URLhausLiveActive = isTrue
			message = fmt.Sprintf("[+] URLhaus Live Lookup updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "subprocessguard", "subprocess-guard", "subprocess":
		if isTrue || isFalse {
			settings.SubprocessInterceptionActive = isTrue
			message = fmt.Sprintf("[+] Subprocess Connection Guard updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "subprocess-strictness", "strictness", "subprocessstrictness":
		if v == "lenient" || v == "strict" || v == "block_all" {
			settings.SubprocessNetworkStrictness = v
			message = fmt.Sprintf("[+] Subprocess Connection Strictness updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid strictness level. Choose 'lenient', 'strict', or 'block_all'."
		}
	case "antievasion", "anti-evasion", "evasion":
		if isTrue || isFalse {
			settings.AntiEvasionActive = isTrue
			message = fmt.Sprintf("[+] Anti-Evasion Process Scanner updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "sensitivefiles", "sensitive-files", "sensitivefile":
		if isTrue || isFalse {
			settings.SensitiveFileAccessActive = isTrue
			message = fmt.Sprintf("[+] Sensitive File Access Guard updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "sensitiveaction", "sensitivefilesaction", "sensitive-files-action":
		if v == "block" || v == "audit" {
			settings.SensitiveFileAccessAction = v
			message = fmt.Sprintf("[+] Sensitive File Access Action updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid action. Choose 'block' or 'audit'."
		}
	case "strip-scripts-mode", "strip-scripts", "strip-lifecycle":
		if v == "never" || v == "threats_only" || v == "all_public" || v == "always" {
			settings.StripLifecycleScripts = v
			message = fmt.Sprintf("[+] Strip Lifecycle Scripts Mode updated to: %s", v)
		} else {
			success = false
			message = "Error: Invalid mode. Choose 'never', 'threats_only', 'all_public', or 'always'."
		}
	case "strip-scripts-targets", "strip-targets":
		parts := strings.Split(val, ",")
		var targets []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				targets = append(targets, p)
			}
		}
		settings.StripLifecycleTargets = targets
		message = fmt.Sprintf("[+] Strip Lifecycle Targets updated to: %v", targets)
	case "strip-scripts-threats", "strip-threats", "strip-trigger-threats":
		parts := strings.Split(val, ",")
		var threats []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				threats = append(threats, p)
			}
		}
		settings.StripLifecycleTriggerThreats = threats
		message = fmt.Sprintf("[+] Strip Lifecycle Trigger Threats updated to: %v", threats)
	case "strip-scripts-exemptions", "strip-exemptions", "strip-exempt":
		parts := strings.Split(val, ",")
		var exemptions []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				exemptions = append(exemptions, p)
			}
		}
		settings.StripLifecycleExemptions = exemptions
		message = fmt.Sprintf("[+] Strip Lifecycle Exemptions updated to: %v", exemptions)
	case "https", "https-inspection", "mitm":
		if isTrue || isFalse {
			settings.HttpsInspectionActive = isTrue
			message = fmt.Sprintf("[+] HTTPS Decryption MITM updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	case "startup", "run-on-startup", "runonstartup":
		if isTrue || isFalse {
			settings.RunOnStartup = isTrue
			message = fmt.Sprintf("[+] Run on Startup updated to: %t", isTrue)
		} else {
			success = false
			message = "Error: Invalid value. Use 'on' or 'off'."
		}
	default:
		success = false
		message = fmt.Sprintf("Error: Unknown setting key '%s'. Run 'devgate help' or 'devgate config' for help.", key)
	}

	if success {
		saveSettingsLocked()
		fmt.Println(message)
	} else {
		fmt.Fprintln(os.Stderr, message)
		os.Exit(1)
	}
}

func handleCLIList(subcmd, listName string, args []string) {
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole := kernel32.NewProc("FreeConsole")
			freeConsole.Call()
		}
	}()

	loadSettings()
	settingsMutex.Lock()
	defer settingsMutex.Unlock()

	lname := strings.ToLower(strings.TrimSpace(listName))
	if lname == "" {
		fmt.Fprintln(os.Stderr, "Error: Missing list name. Use dw, db, pw, pb, nr, pr, or ps.")
		os.Exit(1)
	}

	var targetList *[]string
	displayName := ""

	switch lname {
	case "dw", "domain-whitelist":
		targetList = &settings.CustomDomainWhitelist
		displayName = "Custom Domain Whitelist (dw)"
	case "db", "domain-blacklist":
		targetList = &settings.CustomDomainBlacklist
		displayName = "Custom Domain Blacklist (db)"
	case "pw", "package-whitelist", "pkg-whitelist":
		targetList = &settings.CustomPackageWhitelist
		displayName = "Custom Package Whitelist (pw)"
	case "pb", "package-blacklist", "pkg-blacklist":
		targetList = &settings.CustomPackageBlacklist
		displayName = "Custom Package Blacklist (pb)"
	case "nr", "npm-registry", "custom-npm-registries":
		targetList = &settings.CustomNpmRegistries
		displayName = "Custom NPM Registries (nr)"
	case "pr", "pypi-registry", "custom-pypi-registries":
		targetList = &settings.CustomPypiRegistries
		displayName = "Custom PyPI Registries (pr)"
	case "ps", "scope", "private-scope", "private-scopes":
		targetList = &settings.PrivateScopes
		displayName = "Private Scopes (ps)"
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown list '%s'. Use dw, db, pw, pb, nr, pr, or ps.\n", listName)
		os.Exit(1)
	}

	switch subcmd {
	case "show", "list", "view":
		fmt.Printf("\n=== %s Rules ===\n", displayName)
		if len(*targetList) == 0 {
			fmt.Println("  (no active rules)")
		} else {
			for _, item := range *targetList {
				fmt.Printf("  - %s\n", item)
			}
		}
		fmt.Println()

	case "add":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Missing rule entry to add.")
			os.Exit(1)
		}
		entry := strings.TrimSpace(args[0])
		if entry == "" {
			fmt.Fprintln(os.Stderr, "Error: Cannot add empty entry.")
			os.Exit(1)
		}
		entryLower := strings.ToLower(entry)

		exists := false
		for _, item := range *targetList {
			if strings.ToLower(item) == entryLower {
				exists = true
				break
			}
		}
		if exists {
			fmt.Printf("[*] Rule '%s' already exists in %s.\n", entry, displayName)
		} else {
			*targetList = append(*targetList, entry)
			saveSettingsLocked()
			fmt.Printf("[+] Added rule '%s' to %s successfully.\n", entry, displayName)
		}

	case "remove", "delete", "rm":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Missing rule entry to remove.")
			os.Exit(1)
		}
		entry := strings.TrimSpace(args[0])
		entryLower := strings.ToLower(entry)

		found := false
		var newList []string
		for _, item := range *targetList {
			if strings.ToLower(item) == entryLower {
				found = true
			} else {
				newList = append(newList, item)
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "[-] Error: Rule '%s' not found in %s.\n", entry, displayName)
			os.Exit(1)
		} else {
			*targetList = newList
			saveSettingsLocked()
			fmt.Printf("[+] Removed rule '%s' from %s successfully.\n", entry, displayName)
		}

	case "clear", "empty":
		if len(*targetList) == 0 {
			fmt.Printf("[*] %s is already empty.\n", displayName)
		} else {
			*targetList = []string{}
			saveSettingsLocked()
			fmt.Printf("[+] Cleared all rules in %s successfully.\n", displayName)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown subcommand '%s'. Use show, add, remove, or clear.\n", subcmd)
		os.Exit(1)
	}
}

func truncateString(s string, max int) string {
	if len(s) > max {
		return "..." + s[len(s)-max+3:]
	}
	return s
}

func allocateConsole() bool {
	allocConsole := kernel32.NewProc("AllocConsole")
	r, _, _ := allocConsole.Call()
	if r != 0 {
		hCon, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0)
		if err == nil {
			os.Stdout = os.NewFile(uintptr(hCon), "/dev/stdout")
			os.Stderr = os.NewFile(uintptr(hCon), "/dev/stderr")
			log.SetOutput(os.Stdout)
		}
		hConIn, err := syscall.Open("CONIN$", syscall.O_RDWR, 0)
		if err == nil {
			os.Stdin = os.NewFile(uintptr(hConIn), "/dev/stdin")
		}
		return true
	}
	return false
}

func wrapText(text string, width int) []string {
	var lines []string
	runes := []rune(text)
	for len(runes) > 0 {
		if len(runes) <= width {
			lines = append(lines, string(runes))
			break
		}
		// try to find a space near the width to break cleanly
		breakIdx := width
		for i := width; i > width-15 && i > 0; i-- {
			if runes[i] == ' ' {
				breakIdx = i
				break
			}
		}
		lines = append(lines, string(runes[:breakIdx]))
		runes = runes[breakIdx:]
		// strip leading space
		if len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
	return lines
}

// attaches to the console of one of the process ids in the lineage (or the caller), writes the cancellation message, and then detaches.
func injectConsoleMessage(pids []int, message string) {
	freeConsole.Call() // detach from our own console first if any

	attached := false
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		r, _, _ := attachConsole.Call(uintptr(pid))
		if r != 0 {
			attached = true
			break
		}
	}

	// fallback to attach parent process if we couldn't attach to any process in the lineage
	if !attached {
		r, _, _ := attachConsole.Call(ATTACH_PARENT_PROCESS)
		if r != 0 {
			attached = true
		}
	}

	if attached {
		hCon, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0)
		if err == nil {
			f := os.NewFile(uintptr(hCon), "/dev/stdout")
			fmt.Fprintln(f, message)
			f.Close()
		}
		freeConsole.Call()
	}
}

func handleCLICert() {
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole.Call()
		}
	}()

	if len(os.Args) < 3 {
		fmt.Println("Error: Missing sub-command. Usage: devgate.exe cert [status|trust|untrust]")
		os.Exit(1)
	}

	sub := strings.ToLower(os.Args[2])
	switch sub {
	case "status":
		enableAnsi()
		trusted := isCATrusted()
		if trusted {
			fmt.Println("\033[1;32m[+] Root CA status: TRUSTED & ACTIVE\033[0m")
		} else {
			fmt.Println("\033[1;31m[-] Root CA status: UNTRUSTED / INACTIVE\033[0m")
		}
	case "trust":
		if err := initCertificates(); err != nil {
			fmt.Printf("[-] Error initializing certificates: %v\n", err)
			os.Exit(1)
		}
		if err := trustCA(); err != nil {
			fmt.Printf("[-] Failed to trust Root CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Root CA certificate trusted successfully in Windows Root Store.")
	case "untrust", "remove", "delete":
		if err := untrustCA(); err != nil {
			fmt.Printf("[-] Failed to untrust Root CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Root CA certificate removed from Windows Root Store successfully.")
	default:
		fmt.Printf("Error: Unknown subcommand '%s'. Use 'trust', 'untrust', or 'status'.\n", os.Args[2])
		os.Exit(1)
	}
}

func handleCLIInstall() {
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole.Call()
		}
	}()

	fmt.Println("[*] Registering DevGate globally...")
	alreadyInstalled, err := installDevGate()
	if err != nil {
		fmt.Printf("[-] Failed to register DevGate globally: %v\n", err)
		os.Exit(1)
	}
	if alreadyInstalled {
		fmt.Println("[+] DevGate is already registered globally in your PATH. Updated the binary successfully!")
	} else {
		fmt.Println("[+] DevGate installed globally successfully!")
		fmt.Println("    Please restart your terminal to reload PATH and try running 'devgate shell' from any folder.")
	}
}

func handleCLIRun() {
	// check if proxy is running
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 200*time.Millisecond)
	if err != nil {
		attached := attachToConsole()
		fmt.Println("[!] Warning: DevGate proxy is not running. Please start the DevGate application first so it can protect your installation.")
		if attached {
			freeConsole.Call()
		}
		os.Exit(1)
	}
	conn.Close()

	// check if they passed a command
	if len(os.Args) < 3 {
		attached := attachToConsole()
		fmt.Println("Error: Missing command to run. Usage: devgate run <cmd> [args...]")
		if attached {
			freeConsole.Call()
		}
		os.Exit(1)
	}

	// check if they passed an invalid command
	_, pathErr := exec.LookPath(os.Args[2])
	if pathErr != nil {
		attached := attachToConsole()
		fmt.Printf(" [DevGate] Error: Command '%s' not found. Make sure it is installed and added to your PATH.\n", os.Args[2])
		if attached {
			freeConsole.Call()
		}
		os.Exit(1)
	}

	// load config and check if ca is trusted
	loadSettings()
	cfg := getSettings()
	certTrusted := isCATrusted()
	isInterceptionRunning := cfg.HttpsInspectionActive && certTrusted

	// prepare environment variables for the proxy wrapper
	env := append(os.Environ(),
		"HTTP_PROXY=http://127.0.0.1:8080",
		"HTTPS_PROXY=http://127.0.0.1:8080",
		"http_proxy=http://127.0.0.1:8080",
		"https_proxy=http://127.0.0.1:8080",
	)

	if isInterceptionRunning {
		caPath := filepath.Join(getConfigDir(), "ca.crt")
		env = append(env,
			fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caPath),
			fmt.Sprintf("PIP_CERT=%s", caPath),
			fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", caPath),
		)
	} else {
		env = append(env,
			"npm_config_registry=http://registry.npmjs.org",
			"yarn_registry=http://registry.npmjs.org",
			"PIP_INDEX_URL=http://pypi.org/simple",
			"PIP_TRUSTED_HOST=pypi.org files.pythonhosted.org",
		)
	}

	// fake the sandbox environment to confuse malware
	if cfg.SandboxSpoofing {
		env = append(env,
			"CI=true",
			"GITHUB_ACTIONS=true",
			"RUNNER_OS=Windows",
			"SANDBOX_ACTIVE=true",
			"VM_DETECTED=true",
		)
	}

	// build command line string
	var fullCmd []string
	for _, arg := range os.Args[2:] {
		if strings.Contains(arg, " ") {
			fullCmd = append(fullCmd, fmt.Sprintf(`"%s"`, arg))
		} else {
			fullCmd = append(fullCmd, arg)
		}
	}
	cmdString := strings.Join(fullCmd, " ")

	// attach console and print shield info
	attached := attachToConsole()
	defer func() {
		if attached {
			freeConsole.Call()
		}
	}()

	fmt.Printf("\n[DevGate] Shielding command: %s\n", cmdString)
	fmt.Println("[DevGate]   HTTP_PROXY  = http://127.0.0.1:8080")
	fmt.Println("[DevGate]   HTTPS_PROXY = http://127.0.0.1:8080")
	if isInterceptionRunning {
		fmt.Println("[DevGate]   Intercept   = Active (Root CA Trusted)")
	} else {
		fmt.Println("[DevGate]   Intercept   = Suspended (No-Cert Fallback active)")
	}
	if cfg.SandboxSpoofing {
		fmt.Println("[DevGate]   Deception   = Active (CI, GITHUB_ACTIONS, VM_DETECTED)")
	}
	fmt.Println("[DevGate] -------------------------------------------------------------")

	// run command directly
	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	fmt.Println("[DevGate] -------------------------------------------------------------")
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Printf("[DevGate] Command failed! Exit code: %d\n", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		fmt.Printf("[DevGate] Error executing command: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[DevGate] Command finished successfully! Exit code: 0")
	os.Exit(0)
}
