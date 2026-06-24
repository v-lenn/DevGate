package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// copies the current binary to C:\Users\<Username>\.devgate\bin\
// and appends that directory to the User PATH variable in the Windows registry.
func installDevGate() (bool, error) {
	// get path of current executable
	execPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("failed to get executable path: %w", err)
	}

	// define install directory: C:\Users\<Username>\.devgate\bin
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("failed to get user home directory: %w", err)
	}

	installDir := filepath.Join(homeDir, ".devgate", "bin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return false, fmt.Errorf("failed to create install directory: %w", err)
	}

	destPath := filepath.Join(installDir, "devgate.exe")

	// add the directory to current user environment Path registry key
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	pathVal, valType, err := k.GetStringValue("Path")
	if err != nil {
		pathVal = ""
		valType = registry.SZ
	}

	// check if already in Path list
	cleanInstallDir := filepath.Clean(installDir)
	paths := filepath.SplitList(pathVal)
	inPath := false
	for _, p := range paths {
		if filepath.Clean(p) == cleanInstallDir {
			inPath = true
			break
		}
	}

	_, statErr := os.Stat(destPath)
	destExists := (statErr == nil)
	alreadyInstalled := inPath && destExists

	// prevent self-copying if already running from install location
	if filepath.Clean(execPath) == filepath.Clean(destPath) {
		return true, nil // already installed at this path
	}

	if err := copyFileNative(execPath, destPath); err != nil {
		return alreadyInstalled, fmt.Errorf("failed to copy binary to destination: %w", err)
	}

	if !inPath {
		var newPath string
		if pathVal == "" {
			newPath = installDir
		} else {
			if !strings.HasSuffix(pathVal, ";") {
				newPath = pathVal + ";" + installDir
			} else {
				newPath = pathVal + installDir
			}
		}
		var setErr error
		if valType == registry.EXPAND_SZ {
			setErr = k.SetExpandStringValue("Path", newPath)
		} else {
			setErr = k.SetStringValue("Path", newPath)
		}
		if setErr != nil {
			return alreadyInstalled, fmt.Errorf("failed to update Path environment variable in registry: %w", setErr)
		}

		// broadcast wm settingchange to notify running shell windows of path changes
		sendMessageTimeout := syscall.NewLazyDLL("user32.dll").NewProc("SendMessageTimeoutW")
		const HWND_BROADCAST = 0xffff
		const WM_SETTINGCHANGE = 0x001A
		var result uintptr
		sendMessageTimeout.Call(
			uintptr(HWND_BROADCAST),
			uintptr(WM_SETTINGCHANGE),
			0,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Environment"))),
			0x0002, // SMTO_ABORTIFHUNG
			1000,   // timeout in ms
			uintptr(unsafe.Pointer(&result)),
		)
	}

	return alreadyInstalled, nil
}

// checks if the devgate binary exists in .devgate/bin and is in the path
func isDevGateInstalledGlobally() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	installDir := filepath.Join(homeDir, ".devgate", "bin")
	destPath := filepath.Join(installDir, "devgate.exe")

	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		return false
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	pathVal, _, err := k.GetStringValue("Path")
	if err != nil {
		return false
	}

	cleanInstallDir := filepath.Clean(installDir)
	paths := filepath.SplitList(pathVal)
	for _, p := range paths {
		if filepath.Clean(p) == cleanInstallDir {
			return true
		}
	}
	return false
}

// performs a native file copy with rollback protection, avoiding external cmd spawns
func copyFileNative(src, dest string) error {
	backupPath := dest + ".old"
	os.Remove(backupPath) // ignore error

	hasBackup := false
	if err := os.Rename(dest, backupPath); err == nil {
		hasBackup = true
	}

	err := func() error {
		sf, err := os.Open(src)
		if err != nil {
			return err
		}
		defer sf.Close()

		df, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		defer df.Close()

		_, err = io.Copy(df, sf)
		return err
	}()

	if err != nil {
		if hasBackup {
			os.Rename(backupPath, dest) // restore backup on failure
		}
		return err
	}

	if hasBackup {
		os.Remove(backupPath) // clean up old backup on success
	}
	return nil
}

// configureStartup toggles DevGate as a Windows startup program in HKCU Run registry key
func configureStartup(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open startup registry key: %w", err)
	}
	defer k.Close()

	if enable {
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		homeDir, err := os.UserHomeDir()
		if err == nil {
			globalPath := filepath.Join(homeDir, ".devgate", "bin", "devgate.exe")
			if _, err := os.Stat(globalPath); err == nil {
				execPath = globalPath
			}
		}

		quotedPath := fmt.Sprintf(`"%s"`, execPath)
		err = k.SetStringValue("DevGate", quotedPath)
		if err != nil {
			return fmt.Errorf("failed to set registry startup value: %w", err)
		}
	} else {
		err = k.DeleteValue("DevGate")
		if err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("failed to delete registry startup value: %w", err)
		}
	}
	return nil
}
