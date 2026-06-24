package main

import "strings"

// levenshtein distance calculation
func levenshtein(a, b string) int {
	runesA := []rune(a)
	runesB := []rune(b)
	la := len(runesA)
	lb := len(runesB)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if runesA[i-1] == runesB[j-1] {
				cost = 0
			}
			d[i][j] = minInt(d[i-1][j]+1, minInt(d[i][j-1]+1, d[i-1][j-1]+cost))
		}
	}
	return d[la][lb]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var combosquatSuffixes = []string{"-security", "-helper", "-utils", "-config", "-test", "-dev", "-prod", "-api", "-plugin", "-core", "-sdk", "-support", "-fix"}
var combosquatPrefixes = []string{"lib-", "dev-", "test-", "node-", "py-", "go-"}

func normalizeVisual(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "1", "l")
	s = strings.ReplaceAll(s, "0", "o")
	s = strings.ReplaceAll(s, "rn", "m")
	s = strings.ReplaceAll(s, "vv", "w")
	return s
}

// check if package name matches typosquat patterns
func checkTyposquat(name string) (bool, string) {
	n := strings.ToLower(name)
	for _, p := range popularPkgs {
		if n == p {
			return false, ""
		}

		// levenshtein distance check
		dist := levenshtein(n, p)
		if dist >= 1 && dist <= 2 {
			return true, p
		}

		// combosquatting check (prefix/suffix matching)
		for _, suffix := range combosquatSuffixes {
			if strings.HasSuffix(n, suffix) && strings.TrimSuffix(n, suffix) == p {
				return true, p
			}
		}
		for _, prefix := range combosquatPrefixes {
			if strings.HasPrefix(n, prefix) && strings.TrimPrefix(n, prefix) == p {
				return true, p
			}
		}

		// visual similarity substitution check
		if normalizeVisual(n) == normalizeVisual(p) {
			return true, p
		}
	}
	return false, ""
}
