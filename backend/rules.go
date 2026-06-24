package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"devgate/yargo/parser"
	"devgate/yargo/scanner"
)

//go:embed config/secrets.json
var secretsJSON []byte

//go:embed config/popular_packages.json
var popularPkgsJSON []byte

//go:embed config/rules.yar
var yaraRulesYar []byte

type SecretPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Regex   *regexp.Regexp
}

var (
	secretPatterns    []SecretPattern
	popularPkgs       []string
	compiledYaraRules *scanner.Rules
)

func init() {
	// unmarshal secrets
	var rawSecrets []struct {
		Name    string `json:"name"`
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(secretsJSON, &rawSecrets); err == nil {
		for _, rs := range rawSecrets {
			if re, err := regexp.Compile(rs.Pattern); err == nil {
				secretPatterns = append(secretPatterns, SecretPattern{
					Name:    rs.Name,
					Pattern: rs.Pattern,
					Regex:   re,
				})
			}
		}
	}

	// fallback if loading failed or empty
	if len(secretPatterns) == 0 {
		secretPatterns = []SecretPattern{
			{Name: "AWS Access Key ID", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{Name: "Stripe Live Key", Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
			{Name: "Private Key Header", Regex: regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)},
			{Name: "Slack Token", Regex: regexp.MustCompile(`xoxp-[0-9a-zA-Z]{10,}`)},
		}
	}

	// unmarshal popular packages
	if err := json.Unmarshal(popularPkgsJSON, &popularPkgs); err != nil || len(popularPkgs) == 0 {
		popularPkgs = []string{
			"axios", "express", "lodash", "react", "chalk", "commander",
			"request", "moment", "fs-extra", "dotenv", "tslib", "uuid",
		}
	}

	// compile yara rules
	p := parser.New()
	if ruleSet, err := p.Parse(string(yaraRulesYar)); err == nil {
		if rules, err := scanner.Compile(ruleSet); err == nil {
			compiledYaraRules = rules
		}
	}
}

func splitCmdLine(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '"' {
			inQuotes = !inQuotes
		} else if c == ' ' && !inQuotes {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func isBinaryOrInstaller(base string) bool {
	base = strings.ToLower(base)
	return base == "node.exe" || base == "node" ||
		base == "npm" || base == "npm.cmd" || base == "npm-cli.js" ||
		base == "yarn" || base == "yarn.js" || base == "yarn.cmd" ||
		base == "pnpm" || base == "pnpm.exe" || base == "pnpm.cmd" ||
		base == "pip" || base == "pip3" || base == "pip.exe" ||
		base == "python" || base == "python.exe" || base == "python3" || base == "python3.exe" ||
		base == "cargo" || base == "cargo.exe"
}

func getSubcommand(cmdLine string) string {
	args := splitCmdLine(cmdLine)
	for _, arg := range args {
		base := filepath.Base(arg)
		if isBinaryOrInstaller(base) {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return strings.ToLower(arg)
	}
	return ""
}

// check process names and command lines for installer hooks
func isPostInstall(names []string, pids []int) bool {
	hasInstaller := false
	hasHookScript := false

	for i, name := range names {
		n := strings.ToLower(name)
		var isThisInstaller bool
		var cmdLine string

		if strings.Contains(n, "npm") || strings.Contains(n, "pip") || strings.Contains(n, "cargo") || strings.Contains(n, "yarn") || strings.Contains(n, "pnpm") {
			isThisInstaller = true
			cmdLine = getCmdLine(pids[i])
		}
		// on windows npm/yarn/pnpm/pip runs inside node.exe or python.exe, check command line
		if strings.Contains(n, "node.exe") || strings.Contains(n, "python.exe") {
			cmd := getCmdLine(pids[i])
			cmdLower := strings.ToLower(cmd)
			if strings.Contains(cmdLower, "npm-cli.js") || strings.Contains(cmdLower, "npm ") ||
				strings.Contains(cmdLower, "yarn") || strings.Contains(cmdLower, "pnpm") ||
				strings.Contains(cmdLower, "pip") || strings.Contains(cmdLower, "setup.py") {
				isThisInstaller = true
				cmdLine = cmd
			}
		}

		if isThisInstaller {
			sub := getSubcommand(cmdLine)

			// if it's npm/yarn/pnpm, skip if subcommand is a script runner command
			isNpmLike := strings.Contains(n, "npm") || strings.Contains(n, "yarn") || strings.Contains(n, "pnpm") ||
				strings.Contains(strings.ToLower(cmdLine), "npm-cli.js") || strings.Contains(strings.ToLower(cmdLine), "yarn") || strings.Contains(strings.ToLower(cmdLine), "pnpm")

			if isNpmLike {
				if sub == "run" || sub == "run-script" || sub == "start" || sub == "test" || sub == "dev" || sub == "build" || sub == "exec" || sub == "serve" || sub == "publish" {
					continue // skip: not an installation command
				}
			}

			// if it's pip, verify it's an install/download/wheel command
			isPipLike := strings.Contains(n, "pip") || strings.Contains(strings.ToLower(cmdLine), "pip") || strings.Contains(strings.ToLower(cmdLine), "setup.py")
			if isPipLike {
				if sub != "install" && sub != "download" && sub != "wheel" && sub != "setup.py" {
					continue // skip: not installing
				}
			}

			hasInstaller = true
		}

		// shell or script engines spawned under package installer
		if strings.Contains(n, "node.exe") || strings.Contains(n, "python.exe") || strings.Contains(n, "powershell.exe") || strings.Contains(n, "cmd.exe") || strings.Contains(n, "sh.exe") || strings.Contains(n, "bash.exe") {
			hasHookScript = true
		}
	}
	return hasInstaller && hasHookScript
}

func isPackageBlacklisted(name string) bool {
	cfg := getSettings()
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, pkg := range cfg.CustomPackageBlacklist {
		pkg = strings.ToLower(strings.TrimSpace(pkg))
		if pkg == "" {
			continue
		}
		if matchPackagePattern(name, pkg) {
			return true
		}
	}
	return false
}

func isPackageWhitelisted(name string) bool {
	cfg := getSettings()
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, pkg := range cfg.CustomPackageWhitelist {
		pkg = strings.ToLower(strings.TrimSpace(pkg))
		if pkg == "" {
			continue
		}
		if matchPackagePattern(name, pkg) {
			return true
		}
	}
	return false
}

var (
	allowedPackages      = make(map[string]bool)
	allowedPackagesMutex sync.RWMutex
)

// check if package is registered in local lockfiles/dependencies
func isPkgInLockfile(name string) bool {
	cfg := getSettings()
	if !cfg.LockfileActive {
		return true
	}

	allowedPackagesMutex.RLock()
	defer allowedPackagesMutex.RUnlock()

	return allowedPackages[strings.ToLower(name)]
}

// starts background thread to refresh lockfile allowed list
func startLockfileCache() {
	// run initial scan immediately on startup
	go func() {
		for {
			cfg := getSettings()
			if cfg.LockfileActive {
				newPkgs := scanForLockfiles()
				allowedPackagesMutex.Lock()
				allowedPackages = newPkgs
				allowedPackagesMutex.Unlock()
			}
			time.Sleep(30 * time.Second)
		}
	}()
}

func getProjectDirs() []string {
	cfg := getSettings()
	if cfg.LockfilePaths != "" {
		var paths []string
		for _, p := range strings.Split(cfg.LockfilePaths, ",") {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				paths = append(paths, trimmed)
			}
		}
		if len(paths) > 0 {
			return paths
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return []string{"."}
	}

	dirs := []string{cwd}
	parent := filepath.Dir(cwd)
	if parent != cwd && parent != "" {
		dirs = append(dirs, parent)
		gparent := filepath.Dir(parent)
		if gparent != parent && gparent != "" {
			dirs = append(dirs, gparent)
		}
	}
	return dirs
}

func scanForLockfiles() map[string]bool {
	pkgs := make(map[string]bool)
	dirs := getProjectDirs()
	processed := make(map[string]bool)

	for _, dir := range dirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				name := strings.ToLower(info.Name())
				if name == "node_modules" || name == ".git" || name == "vendor" || name == "venv" || name == ".venv" || name == "dist" || name == "build" {
					return filepath.SkipDir
				}
				return nil
			}

			filename := strings.ToLower(info.Name())
			absPath, err := filepath.Abs(path)
			if err != nil {
				absPath = path
			}

			if processed[absPath] {
				return nil
			}
			processed[absPath] = true

			switch filename {
			case "package.json":
				parsePackageJson(absPath, pkgs)
			case "package-lock.json":
				parsePackageLockJson(absPath, pkgs)
			case "yarn.lock":
				parseYarnLock(absPath, pkgs)
			case "pnpm-lock.yaml":
				parsePnpmLock(absPath, pkgs)
			case "requirements.txt":
				parseRequirementsTxt(absPath, pkgs)
			case "poetry.lock":
				parsePoetryLock(absPath, pkgs)
			}
			return nil
		})
	}
	return pkgs
}

func parsePackageJson(path string, pkgs map[string]bool) {
	f, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data struct {
		Deps         map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
		PeerDeps     map[string]string `json:"peerDependencies"`
		OptionalDeps map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(f, &data); err != nil {
		return
	}
	for name := range data.Deps {
		pkgs[strings.ToLower(name)] = true
	}
	for name := range data.DevDeps {
		pkgs[strings.ToLower(name)] = true
	}
	for name := range data.PeerDeps {
		pkgs[strings.ToLower(name)] = true
	}
	for name := range data.OptionalDeps {
		pkgs[strings.ToLower(name)] = true
	}
}

func parsePackageLockJson(path string, pkgs map[string]bool) {
	f, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var data struct {
		Packages     map[string]interface{} `json:"packages"`
		Dependencies map[string]interface{} `json:"dependencies"`
	}
	if err := json.Unmarshal(f, &data); err != nil {
		return
	}

	for key := range data.Packages {
		if key == "" {
			continue
		}
		name := key
		if strings.HasPrefix(name, "node_modules/") {
			name = name[len("node_modules/"):]
		}
		if idx := strings.LastIndex(name, "node_modules/"); idx != -1 {
			name = name[idx+len("node_modules/"):]
		}
		if name != "" {
			pkgs[strings.ToLower(name)] = true
		}
	}

	for key := range data.Dependencies {
		pkgs[strings.ToLower(key)] = true
	}
}

func parseYarnLock(path string, pkgs map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			line = strings.TrimSuffix(line, ":")
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				part = strings.Trim(part, `"`+"`"+`'`)
				if part == "" {
					continue
				}
				name := part
				if strings.HasPrefix(part, "@") {
					subParts := strings.Split(part[1:], "@")
					if len(subParts) > 0 {
						name = "@" + subParts[0]
					}
				} else {
					subParts := strings.Split(part, "@")
					if len(subParts) > 0 {
						name = subParts[0]
					}
				}
				if name != "" {
					pkgs[strings.ToLower(name)] = true
				}
			}
		}
	}
}

func parsePnpmLock(path string, pkgs map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "'/") || strings.HasPrefix(line, "/") {
			line = strings.Trim(line, `':`)
			if strings.HasPrefix(line, "/") {
				line = line[1:]
			}
			var name string
			if strings.HasPrefix(line, "@") {
				parts := strings.Split(line[1:], "@")
				if len(parts) > 0 {
					name = "@" + parts[0]
				}
			} else {
				parts := strings.Split(line, "@")
				if len(parts) > 0 {
					name = parts[0]
				}
			}
			if idx := strings.Index(name, "("); idx != -1 {
				name = name[:idx]
			}
			if name != "" {
				pkgs[strings.ToLower(name)] = true
			}
		} else if idx := strings.Index(line, ":"); idx != -1 {
			name := strings.TrimSpace(line[:idx])
			name = strings.Trim(name, `'"`)
			if name != "" && !strings.Contains(name, " ") && !strings.HasPrefix(name, "-") {
				pkgs[strings.ToLower(name)] = true
			}
		}
	}
}

func parseRequirementsTxt(path string, pkgs map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name := line
		for _, op := range []string{"==", ">=", "<=", "!=", "~=", ">", "<", ";", "@", "["} {
			if idx := strings.Index(name, op); idx != -1 {
				name = name[:idx]
			}
		}
		name = strings.TrimSpace(name)
		if name != "" {
			pkgs[strings.ToLower(name)] = true
		}
	}
}

func parsePoetryLock(path string, pkgs map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "name = ") {
			name := strings.TrimPrefix(line, "name = ")
			name = strings.Trim(name, `'"`)
			if name != "" {
				pkgs[strings.ToLower(name)] = true
			}
		}
	}
}

// scan payload for secrets and replace with fake values
func sanitizePayload(payload string) (string, []string, bool) {
	modified := false
	out := payload
	var detected []string
	for _, pat := range secretPatterns {
		if pat.Regex.MatchString(out) {
			out = pat.Regex.ReplaceAllString(out, "POISONED_FAKE_KEY_BLOCKED")
			modified = true
			detected = append(detected, pat.Name)
		}
	}
	return out, detected, modified
}

// scan payload with yara rules
func scanYara(payload []byte) (bool, string) {
	cfg := getSettings()
	if !cfg.YaraActive || compiledYaraRules == nil {
		return false, ""
	}
	var matches scanner.MatchRules
	if err := compiledYaraRules.ScanMem(payload, 0, 2*time.Second, &matches); err == nil && len(matches) > 0 {
		var matched []string
		for _, m := range matches {
			matched = append(matched, m.Rule)
		}
		return true, fmt.Sprintf("YARA matched: %s", strings.Join(matched, ", "))
	}
	return false, ""
}

func matchScopePattern(pkgName, pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	name := strings.ToLower(strings.TrimSpace(pkgName))
	if p == "" || name == "" {
		return false
	}
	if p == name {
		return true
	}
	if strings.Contains(p, "*") {
		regexStr := "^" + regexp.QuoteMeta(p) + "$"
		regexStr = strings.ReplaceAll(regexStr, "\\*", ".*")
		if re, err := regexp.Compile(regexStr); err == nil {
			return re.MatchString(name)
		}
	}
	if strings.HasSuffix(p, "/") && strings.HasPrefix(name, p) {
		return true
	}
	return false
}

func matchPackagePattern(pkgName, pattern string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	name := strings.ToLower(strings.TrimSpace(pkgName))
	if p == "" || name == "" {
		return false
	}
	if p == name {
		return true
	}
	if strings.Contains(p, "*") {
		regexStr := "^" + regexp.QuoteMeta(p) + "$"
		regexStr = strings.ReplaceAll(regexStr, "\\*", ".*")
		if re, err := regexp.Compile(regexStr); err == nil {
			return re.MatchString(name)
		}
	}
	return false
}
