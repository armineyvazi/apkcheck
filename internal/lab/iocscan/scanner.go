// Package iocscan performs static indicator-of-compromise scanning across
// decompiled Android project sources (Java, Smali, XML, native libs).
//
// All findings are OBSERVATIONS, not confirmed vulnerabilities. A tester
// must review each match before drawing any conclusion.
package iocscan

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Severity levels for IOC findings — match the security package's terminology.
type Severity string

const (
	SeverityHigh    Severity = "needs_review"
	SeverityMedium  Severity = "potential"
	SeverityInfo    Severity = "informational"
)

// Finding is one IOC match inside a source file.
type Finding struct {
	ID       string   `json:"id"`
	File     string   `json:"file"`     // path relative to scan root
	Line     int      `json:"line"`
	PatternID string  `json:"pattern_id"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Match    string   `json:"match"`
	Context  string   `json:"context"`  // surrounding line content
}

// Result is the full scan output for one artifact.
type Result struct {
	ArtifactID string             `json:"artifact_id"`
	ScanRoot   string             `json:"scan_root"`
	Findings   []Finding          `json:"findings"`
	Summary    map[string]int     `json:"summary"`   // category → count
	FilesScanned int              `json:"files_scanned"`
	Error      string             `json:"error,omitempty"`
}

// pattern is a named regex with metadata.
type pattern struct {
	ID       string
	Category string
	Severity Severity
	Re       *regexp.Regexp
	// skipRFC1918 causes matches that look like RFC-1918 addresses to be dropped.
	skipRFC1918 bool
}

var patterns = []*pattern{
	{
		ID: "hardcoded_secret", Category: "credentials", Severity: SeverityHigh,
		Re: regexp.MustCompile(`(?i)(?:api[_\-]?key|secret[_\-]?key|password|passwd|auth[_\-]?token|bearer[_\-]?token|access[_\-]?token|private[_\-]?key)\s*[=:]\s*["']([^"']{8,})["']`),
	},
	{
		ID: "hardcoded_url", Category: "network", Severity: SeverityMedium,
		Re: regexp.MustCompile(`https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"'<>]*)?`),
	},
	{
		ID: "public_ipv4", Category: "network", Severity: SeverityHigh,
		Re:          regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`),
		skipRFC1918: true,
	},
	{
		ID: "base64_payload", Category: "obfuscation", Severity: SeverityMedium,
		Re: regexp.MustCompile(`[A-Za-z0-9+/]{48,}={0,2}`),
	},
	{
		ID: "dynamic_dex_load", Category: "dynamic_code", Severity: SeverityHigh,
		Re: regexp.MustCompile(`(?i)DexClassLoader|InMemoryDexClassLoader|PathClassLoader|loadDex|loadClass\s*\(`),
	},
	{
		ID: "reflection_invoke", Category: "dynamic_code", Severity: SeverityMedium,
		Re: regexp.MustCompile(`java\.lang\.reflect\.|\.getMethod\(|\.getDeclaredMethod\(|\.invoke\(`),
	},
	{
		ID: "native_exec", Category: "native", Severity: SeverityMedium,
		Re: regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.exec\(\s*new\s+String|System\.loadLibrary|System\.load\(`),
	},
	{
		ID: "ssl_bypass", Category: "tls", Severity: SeverityHigh,
		Re: regexp.MustCompile(`(?i)AllowAllHostnameVerifier|TrustAllCerts|X509TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|setDefaultHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER`),
	},
	{
		ID: "c2_keyword", Category: "backdoor", Severity: SeverityHigh,
		Re: regexp.MustCompile(`(?i)\b(command.{0,4}control|c2.server|phone.home|beacon|exfiltrat|rat\.server|reverse.shell|backdoor|keylog)\b`),
	},
	{
		ID: "crypto_hardcoded_key", Category: "cryptography", Severity: SeverityHigh,
		Re: regexp.MustCompile(`(?i)(?:AES|DES|RSA|ChaCha|Blowfish)[^A-Za-z0-9].*?["'][0-9a-fA-F]{32,}["']`),
	},
	{
		ID: "hex_blob", Category: "obfuscation", Severity: SeverityInfo,
		Re: regexp.MustCompile(`\b[0-9a-fA-F]{64,}\b`),
	},
	{
		ID: "smali_invoke_dynamic", Category: "dynamic_code", Severity: SeverityInfo,
		Re: regexp.MustCompile(`invoke-custom|filled-new-array`),
	},
	{
		ID: "root_check_bypass", Category: "anti_tamper", Severity: SeverityMedium,
		Re: regexp.MustCompile(`(?i)(isRooted|checkRoot|detectRoot|su.binary|/system/bin/su|/system/xbin/su|BuildConfig\.DEBUG)`),
	},
	{
		ID: "telephony_leak", Category: "privacy", Severity: SeverityMedium,
		Re: regexp.MustCompile(`(?i)getDeviceId|getImei|getImsi|getSubscriberId|getLine1Number|getCellLocation`),
	},
}

var rfc1918 = []*regexp.Regexp{
	regexp.MustCompile(`^10\.`),
	regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.`),
	regexp.MustCompile(`^192\.168\.`),
	regexp.MustCompile(`^127\.`),
}

func isRFC1918(ip string) bool {
	for _, r := range rfc1918 {
		if r.MatchString(ip) {
			return true
		}
	}
	return false
}

// Scan walks root, applies all patterns, and returns de-duplicated findings.
// root is typically the decompiled project directory from JADX or apktool.
func Scan(artifactID, root string) *Result {
	res := &Result{
		ArtifactID: artifactID,
		ScanRoot:   root,
		Summary:    map[string]int{},
	}
	if root == "" {
		res.Error = "empty scan root"
		return res
	}
	if _, err := os.Stat(root); err != nil {
		res.Error = fmt.Sprintf("scan root not found: %v", err)
		return res
	}

	seen := map[string]struct{}{} // dedup by hash(file+line+pattern+match)

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !isTextExt(ext) {
			return nil
		}
		res.FilesScanned++
		scanFile(path, root, patterns, seen, res)
		return nil
	})

	// Sort: severity (high first) then file + line.
	sort.Slice(res.Findings, func(i, j int) bool {
		si := severityOrder(res.Findings[i].Severity)
		sj := severityOrder(res.Findings[j].Severity)
		if si != sj {
			return si < sj
		}
		if res.Findings[i].File != res.Findings[j].File {
			return res.Findings[i].File < res.Findings[j].File
		}
		return res.Findings[i].Line < res.Findings[j].Line
	})
	return res
}

func scanFile(path, root string, pats []*pattern, seen map[string]struct{}, res *Result) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	rel, _ := filepath.Rel(root, path)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, p := range pats {
			matches := p.Re.FindAllString(line, -1)
			for _, m := range matches {
				if p.skipRFC1918 && isRFC1918(m) {
					continue
				}
				// Drop trivial base64 that matches common code patterns.
				if p.ID == "base64_payload" && looksLikeCode(m) {
					continue
				}
				key := dedupKey(rel, lineNo, p.ID, m)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				lineCtx := truncate(strings.TrimSpace(line), 200)
				finding := Finding{
					ID:        key,
					File:      rel,
					Line:      lineNo,
					PatternID: p.ID,
					Category:  p.Category,
					Severity:  p.Severity,
					Match:     truncate(m, 120),
					Context:   lineCtx,
				}
				res.Findings = append(res.Findings, finding)
				res.Summary[p.Category]++
			}
		}
	}
	// scanner.Err returns nil for io.EOF, non-nil for actual errors — safe to ignore here.
	_ = scanner.Err()
}

func isTextExt(ext string) bool {
	switch ext {
	case ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".gradle", ".pro", ".txt", ".yaml", ".yml":
		return true
	}
	return false
}

// looksLikeCode filters out base64 false-positives that are clearly identifiers or paths.
func looksLikeCode(s string) bool {
	if strings.Contains(s, ".") || strings.Contains(s, "/") || strings.Contains(s, "_") {
		return true
	}
	upper := strings.ToUpper(s)
	if upper == s || strings.ToLower(s) == s {
		// all-upper or all-lower identifiers
		return true
	}
	return false
}

func dedupKey(file string, line int, patID, match string) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s|%d|%s|%s", file, line, patID, match))
	return fmt.Sprintf("%x", h[:8])
}

// truncate cuts s to at most n runes (not bytes) to avoid splitting multi-byte UTF-8.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func severityOrder(s Severity) int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	default:
		return 2
	}
}
