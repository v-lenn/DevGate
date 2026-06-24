package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
)

// parses a .tgz (gzipped tar) archive, finds package.json, and rebuilds the archive.
func stripNpmLifecycleScripts(tgzBytes []byte, targets []string) ([]byte, bool, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(tgzBytes))
	if err != nil {
		return nil, false, err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	var newTgzBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&newTgzBuffer)
	tarWriter := tar.NewWriter(gzipWriter)

	anyStripped := false

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // end of tar archive
		}
		if err != nil {
			return nil, false, err
		}

		// check if this is the package.json file
		if strings.HasSuffix(header.Name, "package.json") {
			var packageJsonBuf bytes.Buffer
			if _, err := io.Copy(&packageJsonBuf, tarReader); err != nil {
				return nil, false, err
			}

			var packageMap map[string]interface{}
			if err := json.Unmarshal(packageJsonBuf.Bytes(), &packageMap); err == nil {
				didStrip := false
				if scripts, exists := packageMap["scripts"]; exists {
					if scriptsMap, ok := scripts.(map[string]interface{}); ok {
						for _, target := range targets {
							if _, present := scriptsMap[target]; present {
								delete(scriptsMap, target)
								didStrip = true
								anyStripped = true
							}
						}
					}
				}

				if didStrip {
					newJsonBytes, err := json.Marshal(packageMap)
					if err == nil {
						header.Size = int64(len(newJsonBytes))
						if err := tarWriter.WriteHeader(header); err != nil {
							return nil, false, err
						}
						if _, err := tarWriter.Write(newJsonBytes); err != nil {
							return nil, false, err
						}
						continue
					}
				} else {
					// no targeted lifecycle scripts found; write the original package.json content back
					header.Size = int64(packageJsonBuf.Len())
					if err := tarWriter.WriteHeader(header); err != nil {
						return nil, false, err
					}
					if _, err := tarWriter.Write(packageJsonBuf.Bytes()); err != nil {
						return nil, false, err
					}
					continue
				}
			}
		}

		// copy file unchanged
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, false, err
		}
		if _, err := io.Copy(tarWriter, tarReader); err != nil {
			return nil, false, err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return nil, false, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, false, err
	}

	return newTgzBuffer.Bytes(), anyStripped, nil
}
