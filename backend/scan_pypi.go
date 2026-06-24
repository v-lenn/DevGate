package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

func isPythonMalicious(content string) (bool, string) {
	cfg := getSettings()

	// shannon entropy check
	if cfg.EntropyScan && len(content) > 500 {
		ent := calculateEntropy(content)
		if ent > 6.5 {
			return true, fmt.Sprintf("extreme shannon entropy detected (%.2f)", ent)
		}
	}

	c := strings.ToLower(content)

	// heuristic 1: file paths containing credentials
	if strings.Contains(c, ".aws/credentials") || strings.Contains(c, ".ssh/id_rsa") || strings.Contains(c, "etc/passwd") {
		return true, "critical credentials file path access"
	}

	// heuristic 2: obfuscated execution patterns commonly used in python malware
	if strings.Contains(c, "eval(base64") || strings.Contains(c, "exec(base64") || strings.Contains(c, "subprocess.popen(base64") || strings.Contains(c, "eval(marshal.loads") || strings.Contains(c, "exec(marshal.loads") {
		return true, "obfuscated dynamic execution path (base64/marshal)"
	}

	// heuristic 3: dynamic script execution on setup/import
	if strings.Contains(c, "requests.post(") || strings.Contains(c, "requests.get(") || strings.Contains(c, "urllib.request") || strings.Contains(c, "urllib3") || strings.Contains(c, "httpx") || strings.Contains(c, "aiohttp") {
		if strings.Contains(c, "os.environ") && (strings.Contains(c, "secret") || strings.Contains(c, "key") || strings.Contains(c, "token") || strings.Contains(c, "password")) {
			return true, "network request targeting sensitive environment variables"
		}
	}

	// heuristic 4: system command execution
	if strings.Contains(c, "os.system(") || strings.Contains(c, "subprocess.run(") || strings.Contains(c, "subprocess.call(") || strings.Contains(c, "subprocess.check_output(") {
		if strings.Contains(c, "curl") || strings.Contains(c, "wget") || strings.Contains(c, "powershell") || strings.Contains(c, "bash") || strings.Contains(c, "sh ") || strings.Contains(c, "python ") {
			return true, "suspicious system command execution executing downloader or shell"
		}
	}

	// heuristic 5: reverse shell / socket
	if strings.Contains(c, "socket.socket") && strings.Contains(c, "connect(") {
		if strings.Contains(c, "subprocess") || strings.Contains(c, "pty") || strings.Contains(c, "dup2") || strings.Contains(c, "os.system") {
			return true, "potential reverse shell raw socket connection"
		}
	}

	// heuristic 6: dynamic import
	if strings.Contains(c, "__import__(") || strings.Contains(c, "import_module(") {
		if strings.Contains(c, "base64") || strings.Contains(c, "rot13") || strings.Contains(c, "getattr") || strings.Contains(c, "codecs") {
			return true, "dynamic module import coupled with string decoding/obfuscation"
		}
	}

	// heuristic 7: compile + exec chain
	if strings.Contains(c, "compile(") && strings.Contains(c, "exec(") {
		return true, "obfuscated compile and exec chain execution"
	}

	// heuristic 8: platform fingerprinting + exfil
	if (strings.Contains(c, "platform.system") || strings.Contains(c, "platform.uname") || strings.Contains(c, "getpass.getuser") || strings.Contains(c, "socket.gethostname")) && (strings.Contains(c, "requests.") || strings.Contains(c, "urllib.") || strings.Contains(c, "socket.connect")) {
		return true, "host environment fingerprinting with outbound network call"
	}

	// heuristic 9: codecs.decode / ROT13
	if strings.Contains(c, "codecs.decode") && (strings.Contains(c, "rot13") || strings.Contains(c, "rot_13") || strings.Contains(c, "base64") || strings.Contains(c, "hex")) {
		return true, "rot13 / codecs-based string decoding obfuscation"
	}

	return false, ""
}

// scan pypi wheel package (which is a standard zip archive)
func scanPypiWheel(body []byte) (bool, string) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return false, ""
	}

	for _, file := range zr.File {
		ext := ""
		if idx := strings.LastIndex(file.Name, "."); idx != -1 {
			ext = strings.ToLower(file.Name[idx:])
		}
		isTarget := ext == ".py" || file.Name == "setup.cfg" || file.Name == "pyproject.toml" || strings.HasSuffix(file.Name, "metadata.json")

		if isTarget {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			limitedReader := io.LimitReader(rc, 10*1024*1024+1)
			buf := new(bytes.Buffer)
			n, err := io.Copy(buf, limitedReader)
			rc.Close()
			if err != nil {
				continue
			}
			if n > 10*1024*1024 {
				return true, fmt.Sprintf("file %s exceeds maximum allowed size (10MB)", file.Name)
			}

			content := buf.String()
			if isMal, desc := scanYara([]byte(content)); isMal {
				return true, fmt.Sprintf("YARA match inside file %s: %s", file.Name, desc)
			}
			if isMal, desc := isPythonMalicious(content); isMal {
				return true, fmt.Sprintf("malicious pattern match (%s) inside file: %s", desc, file.Name)
			}
		}
	}
	return false, ""
}

// scan pypi source distribution package (which is a tar.gz archive)
func scanPypiTarGz(body []byte) (bool, string) {
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return false, ""
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, ""
		}

		ext := ""
		if idx := strings.LastIndex(hdr.Name, "."); idx != -1 {
			ext = strings.ToLower(hdr.Name[idx:])
		}
		isTarget := ext == ".py" || strings.HasSuffix(hdr.Name, "setup.cfg") || strings.HasSuffix(hdr.Name, "pyproject.toml")

		if isTarget {
			limitedReader := io.LimitReader(tr, 10*1024*1024+1)
			buf := new(bytes.Buffer)
			n, err := io.Copy(buf, limitedReader)
			if err != nil {
				continue
			}
			if n > 10*1024*1024 {
				return true, fmt.Sprintf("source file %s exceeds maximum allowed size (10MB)", hdr.Name)
			}

			content := buf.String()
			if isMal, desc := scanYara([]byte(content)); isMal {
				return true, fmt.Sprintf("YARA match inside source file %s: %s", hdr.Name, desc)
			}
			if isMal, desc := isPythonMalicious(content); isMal {
				return true, fmt.Sprintf("malicious pattern match (%s) inside source file: %s", desc, hdr.Name)
			}
		}
	}
	return false, ""
}

// dispatch pypi file scanning based on package format type
func scanPypiPackage(body []byte, urlPath string) (bool, string) {
	if strings.HasSuffix(urlPath, ".whl") {
		return scanPypiWheel(body)
	}
	if strings.HasSuffix(urlPath, ".tar.gz") || strings.HasSuffix(urlPath, ".tgz") {
		return scanPypiTarGz(body)
	}
	return false, ""
}
