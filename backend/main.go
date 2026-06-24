package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	// 0. check and handle developer CLI commands (env, shell, help)
	handleCLI()
	isDaemon = true

	addr := flag.String("addr", "127.0.0.1:8080", "proxy listen address")
	flag.Parse()

	// load settings from settings.json on startup before background tasks start
	loadSettings()

	// start background lockfile monitoring/caching
	startLockfileCache()

	// start background threat intelligence syncing and cache
	initReputationEngine()

	// start background proxy bypass monitoring
	startProxyBypassMonitor()

	// initialize certificate generator (generate/load Root CA and prepare dynamic signing keys)
	if err := initCertificates(); err != nil {
		log.Printf("[Warning] Failed to initialize certificates system: %v. HTTPS Inspection will be unavailable.", err)
	}

	// start HTTP/HTTPS proxy engine
	go func() {
		handler := &ProxyHandler{}
		log.Printf("Starting proxy on %s", *addr)
		if err := http.ListenAndServe(*addr, handler); err != nil {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	// start local settings web server
	go func() {
		log.Printf("Starting web server on 127.0.0.1:8081")
		if err := startWebServer(); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// auto-launch settings dashboard in default browser on startup
	go func() {
		time.Sleep(300 * time.Millisecond)
		cfg := getSettings()
		if cfg.WebUIEnabled {
			log.Printf("Opening dashboard at http://localhost:8081")
			openBrowser("http://localhost:8081")
		} else {
			log.Printf("Web Dashboard UI auto-open is disabled (running in headless mode)")
		}
	}()

	// block main thread with Windows Tray message loop
	startTrayIcon()
}
