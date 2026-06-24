package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

var configDirCached string

// returns the absolute path to the global DevGate configuration directory.
func getConfigDir() string {
	if configDirCached != "" {
		return configDirCached
	}

	// detect if running inside go test
	isTest := flag.Lookup("test.v") != nil ||
		strings.HasSuffix(os.Args[0], ".test") ||
		strings.HasSuffix(os.Args[0], ".test.exe") ||
		strings.Contains(os.Args[0], "/_test/") ||
		strings.Contains(os.Args[0], "\\_test\\")

	if isTest {
		configDirCached = "test_config"
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			configDirCached = filepath.Join(home, ".devgate")
		} else {
			// fallback to local config if home directory cannot be resolved
			configDirCached = "config"
		}
	}
	os.MkdirAll(configDirCached, 0755)
	return configDirCached
}
