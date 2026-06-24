package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// regex to find obfuscated base64 payload strings
var base64Regex = regexp.MustCompile(`[a-zA-Z0-9+/]{80,}=*`)
var hexObfuscationRegex = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}`)

// check if package.json contains dangerous hook scripts
func isHookSuspicious(content string) bool {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return false
	}
	for hook, script := range pkg.Scripts {
		h := strings.ToLower(hook)
		s := strings.ToLower(script)
		if h == "preinstall" || h == "postinstall" || h == "install" {
			// alert if script runs curl/wget or executes obfuscated shell commands
			if strings.Contains(s, "curl") || strings.Contains(s, "wget") || strings.Contains(s, "eval") || strings.Contains(s, "sh ") || strings.Contains(s, "bash ") || strings.Contains(s, "powershell") {
				return true
			}
		}
	}
	return false
}

// scan js/ts files for exfiltration or malicious loaders
func isCodeMalicious(content string) (bool, string) {
	cfg := getSettings()

	// shannon entropy check
	if cfg.EntropyScan && len(content) > 500 {
		ent := calculateEntropy(content)
		if ent > 6.5 {
			return true, fmt.Sprintf("extreme shannon entropy detected (%.2f)", ent)
		}
	}

	// ast parsing check
	if cfg.ASTScan {
		if program, err := parser.ParseFile(nil, "", content, 0); err == nil {
			var astMal bool
			var astReason string
			walkAST(program, func(node ast.Node) {
				if astMal {
					return
				}
				switch n := node.(type) {
				case *ast.CallExpression:
					if id, ok := n.Callee.(*ast.Identifier); ok {
						if id.Name == "eval" {
							astMal = true
							astReason = "eval invocation"
						} else if id.Name == "Function" {
							astMal = true
							astReason = "dynamic Function constructor"
						} else if id.Name == "require" && len(n.ArgumentList) > 0 {
							if _, ok := n.ArgumentList[0].(*ast.StringLiteral); !ok {
								astMal = true
								astReason = "dynamic require call"
							}
						}
					}
					// window["eval"](...) or global["eval"](...)
					if br, ok := n.Callee.(*ast.BracketExpression); ok {
						if id, ok := br.Left.(*ast.Identifier); ok {
							if id.Name == "window" || id.Name == "global" || id.Name == "globalThis" || id.Name == "process" {
								if mStr, ok := br.Member.(*ast.StringLiteral); ok {
									val := mStr.Value
									if val == "eval" || val == "exec" || val == "execSync" || val == "spawn" {
										astMal = true
										astReason = fmt.Sprintf("dynamic bracket access global[%s]", val)
									}
								}
							}
						}
					}
				case *ast.DotExpression:
					if n.Identifier.Name == "mainModule" || n.Identifier.Name == "binding" {
						if id, ok := n.Left.(*ast.Identifier); ok && id.Name == "process" {
							astMal = true
							astReason = fmt.Sprintf("suspicious property process.%s", n.Identifier.Name)
						}
					}
				}
			})
			if astMal {
				return true, fmt.Sprintf("AST analyzer flagged: %s", astReason)
			}
		}
	}

	c := strings.ToLower(content)

	// heuristic 1: searching for critical credentials files
	if strings.Contains(c, ".aws/credentials") || strings.Contains(c, ".ssh/id_rsa") || strings.Contains(c, "etc/passwd") || strings.Contains(c, ".git-credentials") {
		return true, "critical credentials file path access"
	}

	// heuristic 2: searching for common obfuscated javascript execution paths
	if strings.Contains(c, "eval(string.fromcharcode") || strings.Contains(c, "eval(buffer.from") || strings.Contains(c, "execsync(buffer.from") {
		return true, "obfuscated dynamic evaluation path"
	}

	// heuristic 3: checking for large base64 payload chunks matching shellcodes
	if base64Regex.MatchString(content) {
		// only flag if coupled with eval/exec execution patterns
		if strings.Contains(c, "eval") || strings.Contains(c, "exec") || strings.Contains(c, "require") || strings.Contains(c, "run") {
			return true, "large base64 payload coupled with dynamic execution"
		}
	}

	// heuristic 4: stealing process environments and exfiltrating
	if strings.Contains(c, "process.env") && (strings.Contains(c, "http.request") || strings.Contains(c, "http.get") || strings.Contains(c, "fetch(") || strings.Contains(c, "axios") || strings.Contains(c, "request(")) {
		// checks if targeting sensitive vars
		if strings.Contains(c, "secret") || strings.Contains(c, "token") || strings.Contains(c, "key") || strings.Contains(c, "password") {
			return true, "environment variable harvesting and exfiltration"
		}
	}

	// heuristic 5: child process execution
	if (strings.Contains(c, "child_process") || strings.Contains(c, "child-process")) && (strings.Contains(c, "exec(") || strings.Contains(c, "execsync(") || strings.Contains(c, "spawn(")) {
		// check if running shell interpreter or downloads
		if strings.Contains(c, "curl") || strings.Contains(c, "wget") || strings.Contains(c, "sh") || strings.Contains(c, "bash") || strings.Contains(c, "cmd") || strings.Contains(c, "powershell") {
			return true, "suspicious child process invocation executing shell or download commands"
		}
	}

	// heuristic 6: dns exfiltration
	if (strings.Contains(c, "require('dns')") || strings.Contains(c, "require(\"dns\")") || strings.Contains(c, "import dns")) && (strings.Contains(c, "lookup") || strings.Contains(c, "resolve")) {
		if strings.Contains(c, "process.env") || strings.Contains(c, "secret") || strings.Contains(c, "token") || strings.Contains(c, "key") {
			return true, "suspicious dns query usage (potential credential exfiltration)"
		}
	}

	// heuristic 7: reverse shell / net.Socket
	if strings.Contains(c, "net.socket") || (strings.Contains(c, "require('net')") && (strings.Contains(c, "connect(") || strings.Contains(c, "createconnection("))) {
		if strings.Contains(c, "process.env") || strings.Contains(c, "exec") || strings.Contains(c, "spawn") || strings.Contains(c, "sh") || strings.Contains(c, "bash") || strings.Contains(c, "cmd") {
			return true, "reverse shell / raw tcp socket execution"
		}
	}

	// heuristic 8: browser credential store theft
	if strings.Contains(c, "login data") || strings.Contains(c, "cookies.sqlite") || strings.Contains(c, "key4.db") || strings.Contains(c, "key3.db") || strings.Contains(c, "local state") {
		if strings.Contains(c, "appdata") || strings.Contains(c, "application support") || strings.Contains(c, "roaming") {
			return true, "unauthorized access to browser credential/cookie databases"
		}
	}

	// heuristic 9: hex-escaped string obfuscation
	if hexObfuscationRegex.MatchString(content) {
		return true, "hex-encoded string obfuscation detected"
	}

	// heuristic 10: WScript.Shell / ActiveXObject
	if strings.Contains(c, "wscript.shell") || strings.Contains(c, "activexobject") {
		return true, "Windows Script Host / ActiveX control execution"
	}

	return false, ""
}

func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range data {
		counts[r]++
	}
	var ent float64
	length := float64(len(data))
	for _, count := range counts {
		p := float64(count) / length
		ent -= p * math.Log2(p)
	}
	return ent
}

func walkAST(node ast.Node, fn func(ast.Node)) {
	if node == nil {
		return
	}
	fn(node)
	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			walkAST(stmt, fn)
		}
	case *ast.BlockStatement:
		for _, stmt := range n.List {
			walkAST(stmt, fn)
		}
	case *ast.ExpressionStatement:
		walkAST(n.Expression, fn)
	case *ast.VariableStatement:
		for _, decl := range n.List {
			walkAST(decl, fn)
		}
	case *ast.VariableDeclaration:
		for _, decl := range n.List {
			walkAST(decl.Target, fn)
			walkAST(decl.Initializer, fn)
		}
	case *ast.FunctionLiteral:
		walkAST(n.Body, fn)
	case *ast.IfStatement:
		walkAST(n.Test, fn)
		walkAST(n.Consequent, fn)
		walkAST(n.Alternate, fn)
	case *ast.ReturnStatement:
		walkAST(n.Argument, fn)
	case *ast.BinaryExpression:
		walkAST(n.Left, fn)
		walkAST(n.Right, fn)
	case *ast.AssignExpression:
		walkAST(n.Left, fn)
		walkAST(n.Right, fn)
	case *ast.DotExpression:
		walkAST(n.Left, fn)
		walkAST(&n.Identifier, fn)
	case *ast.BracketExpression:
		walkAST(n.Left, fn)
		walkAST(n.Member, fn)
	case *ast.CallExpression:
		walkAST(n.Callee, fn)
		for _, arg := range n.ArgumentList {
			walkAST(arg, fn)
		}
	case *ast.ArrayLiteral:
		for _, val := range n.Value {
			walkAST(val, fn)
		}
	case *ast.ObjectLiteral:
		for _, prop := range n.Value {
			switch p := prop.(type) {
			case *ast.PropertyKeyed:
				walkAST(p.Key, fn)
				walkAST(p.Value, fn)
			case *ast.PropertyShort:
				walkAST(&p.Name, fn)
				walkAST(p.Initializer, fn)
			}
		}
	case *ast.ObjectPattern:
		for _, prop := range n.Properties {
			switch p := prop.(type) {
			case *ast.PropertyKeyed:
				walkAST(p.Key, fn)
				walkAST(p.Value, fn)
			case *ast.PropertyShort:
				walkAST(&p.Name, fn)
				walkAST(p.Initializer, fn)
			}
		}
		walkAST(n.Rest, fn)
	case *ast.ArrayPattern:
		for _, val := range n.Elements {
			walkAST(val, fn)
		}
		walkAST(n.Rest, fn)
	}
}

// unzip and scan package files in memory
func scanTarball(body []byte) (bool, string) {
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

		// check package files (extend to js, mjs, cjs, ts, json)
		ext := ""
		if idx := strings.LastIndex(hdr.Name, "."); idx != -1 {
			ext = strings.ToLower(hdr.Name[idx:])
		}
		isJSorTS := ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts"

		if isJSorTS || strings.HasSuffix(hdr.Name, "package.json") {
			// limit to 10mb per file
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

			if strings.HasSuffix(hdr.Name, "package.json") {
				if isHookSuspicious(content) {
					return true, "malicious script hook detected inside package.json"
				}
			}

			if isJSorTS {
				if isMal, desc := scanYara([]byte(content)); isMal {
					return true, fmt.Sprintf("YARA match inside source file %s: %s", hdr.Name, desc)
				}
				if isMal, desc := isCodeMalicious(content); isMal {
					return true, fmt.Sprintf("malicious pattern match (%s) inside source file: %s", desc, hdr.Name)
				}
			}
		}
	}
	return false, ""
}
