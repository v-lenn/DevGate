# DevGate 🛡️
> A Zero-Trust local developer proxy and firewall that shields your machine from malicious package manager installs and supply chain attacks.

DevGate sits silently between your package manager (`npm`, `pip`, `cargo`, etc.) and the internet, monitoring all outbound connections and dependencies in real-time. It intercepts malicious installer scripts, flags typosquatting attempts, sanitizes exfiltrated secrets, and alerts you before threats reach your computer.

<p align="center">
  <img src="devgate_icon.png" alt="DevGate Logo" width="150">
</p>

---

## Key Features

### ⚡ Core Proxy Engine
DevGate operates as a local HTTP/HTTPS forward proxy on `127.0.0.1:8080`. Using the native Windows `GetExtendedTcpTable` API, it resolves active network connections back to their originating process without child process spawning overhead, keeping resource consumption minimal.

### 🛡️ Multi-Level Protection Modes
- **Strict:** Automatically blocks all unapproved installer connections.
- **Interactive:** Pauses suspicious connection attempts and prompts you via the dashboard for decision.
- **Audit:** Logs warnings but lets all traffic pass through cleanly.

### 🍯 Credential Honeypotting
Postinstall scripts often attempt to exfiltrate env variables, AWS credentials, or API keys. DevGate scans outbound payloads for over 20+ secret formats (AWS, Stripe, Discord, Slack, SSH keys, etc.) and automatically poisons the payload with fake values (`POISONED_FAKE_KEY_BLOCKED`) before the request exits your machine.

### 🔍 In-Memory Tarball Scanning
DevGate intercepts `.tgz` (npm) and `.whl` / `.tar.gz` (pypi) downloads in memory, extracts them, and runs static analysis rules (including AST and Shannon Entropy calculations) to detect packed payloads, obfuscation, DNS data exfiltration, or reverse shells before files are written to disk.

### ⚠️ Typosquatting & Age Alerts
- Checks requested package names against a database of popular packages to identify typosquatting / lookalike names (using Levenshtein distance and comboshadowing).
- Queries the registry API to flag any packages published within the last 48 hours.

### 🌐 Lockfile Drift Check
Cross-references package downloads against your project's lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, etc.). If a package is requested that is not defined in the lockfile, it triggers your configured action mode.

### 📊 Web Dashboard & System Tray
- Runs silently in the Windows system tray.
- Opens a beautiful glassmorphic Web UI served on `127.0.0.1:8081` with live-streaming Server-Sent Events (SSE) detailing logs, statistics, and interactive block/allow popups.

---

## CLI Usage

Configure DevGate directly from your terminal:

```bash
# Show configuration overview
devgate config

# Set protection settings
devgate set mode interactive
devgate set honeypot on
devgate set startup on

# Spawn a shell wrapped in proxy environment variables
devgate shell

# Register DevGate globally on Windows User PATH
devgate install
```

---

## Building from Source

To compile the self-contained production binary for Windows (runs silently in the system tray without spawning a console window):

```bash
# Enter backend directory
cd backend

# Build binary
go build -ldflags "-H=windowsgui" -o devgate.exe
```

---

## License
MIT License.
