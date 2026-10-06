// Package findings produces actionable security triage items with evidence discipline.
// It is intentionally not a noisy MobSF clone: every finding carries an EvidenceClass
// and links into APK/DEX/class/method/manifest evidence when available.
package findings

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/armin/apkcheck/internal/ir"
	"github.com/armin/apkcheck/pkg/model"
)

var dangerousPerms = map[string]string{
	"android.permission.READ_SMS":                 "SMS access",
	"android.permission.SEND_SMS":                 "SMS send",
	"android.permission.RECEIVE_SMS":              "SMS receive",
	"android.permission.READ_CONTACTS":            "contacts",
	"android.permission.WRITE_CONTACTS":           "contacts write",
	"android.permission.ACCESS_FINE_LOCATION":     "fine location",
	"android.permission.ACCESS_COARSE_LOCATION":   "coarse location",
	"android.permission.CAMERA":                   "camera",
	"android.permission.RECORD_AUDIO":             "microphone",
	"android.permission.READ_PHONE_STATE":         "phone state",
	"android.permission.CALL_PHONE":               "phone call",
	"android.permission.READ_CALL_LOG":            "call log",
	"android.permission.WRITE_CALL_LOG":           "call log write",
	"android.permission.READ_EXTERNAL_STORAGE":    "external storage read",
	"android.permission.WRITE_EXTERNAL_STORAGE":   "external storage write",
	"android.permission.MANAGE_EXTERNAL_STORAGE":  "manage all files",
	"android.permission.SYSTEM_ALERT_WINDOW":      "overlay window",
	"android.permission.REQUEST_INSTALL_PACKAGES": "install packages",
	"android.permission.WRITE_SETTINGS":           "write settings",
	"android.permission.QUERY_ALL_PACKAGES":       "query all packages",
}

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
	sev  model.Severity
}{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), model.SeverityCritical},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), model.SeverityHigh},
	{"generic_api_key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`), model.SeverityHigh},
	{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`), model.SeverityHigh},
	{"private_key_pem", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`), model.SeverityCritical},
	{"password_literal", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`), model.SeverityMedium},
	{"token_literal", regexp.MustCompile(`(?i)(access[_-]?token|auth[_-]?token|refresh[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{12,})["']`), model.SeverityHigh},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`), model.SeverityCritical},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), model.SeverityCritical},
}

var weakCrypto = []string{
	"DES/ECB", "DES/CBC", "DESede", "RC4", "Blowfish",
	"AES/ECB", "PBEWithMD5", "MD5", "SHA1withRSA",
}

// Input aggregates artifacts needed for the findings layer.
type Input struct {
	APK      model.APKInfo
	Manifest string
	Methods  []model.MethodResult
	MethodIR []*ir.MethodIR
}

// Scan produces findings. Inferences are labeled INFERENCE; never as facts.
func Scan(in Input) []model.Finding {
	var out []model.Finding
	id := 0
	next := func() string {
		id++
		return fmt.Sprintf("F-%04d", id)
	}

	out = append(out, scanExported(next, in.APK, in.Manifest)...)
	out = append(out, scanPermissions(next, in.APK)...)
	out = append(out, scanAppFlags(next, in.APK, in.Manifest)...)
	out = append(out, scanSecrets(next, in.MethodIR, in.APK.Path)...)
	out = append(out, scanMethodTags(next, in.Methods)...)
	out = append(out, scanWeakCrypto(next, in.MethodIR, in.APK.Path)...)
	out = append(out, scanDisagreements(next, in.Methods)...)

	sort.Slice(out, func(i, j int) bool {
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func scanExported(next func() string, info model.APKInfo, manifest string) []model.Finding {
	var out []model.Finding
	type item struct {
		kind string
		list []string
		cat  model.FindingCategory
	}
	for _, it := range []item{
		{"Activity", info.ExportedActivities, model.CatExportedComponent},
		{"Service", info.ExportedServices, model.CatExportedComponent},
		{"BroadcastReceiver", info.ExportedReceivers, model.CatExportedComponent},
		{"ContentProvider", info.ExportedProviders, model.CatExportedComponent},
	} {
		for _, name := range it.list {
			sev := model.SeverityMedium
			if it.kind == "ContentProvider" || it.kind == "Service" {
				sev = model.SeverityHigh
			}
			out = append(out, model.Finding{
				ID: next(), Category: it.cat,
				Title:    fmt.Sprintf("Exported %s: %s", it.kind, name),
				Severity: sev, Class: model.EvidenceStatic,
				Confidence: model.ConfidenceSourceOfTruth,
				Summary:    fmt.Sprintf("Manifest declares exported %s %s", it.kind, name),
				Why:        "android:exported=true (or implied by intent-filter on older targets) in AndroidManifest",
				Evidence: []model.EvidenceLink{{
					APK: info.Path, Class: name, Manifest: componentManifestHint(manifest, name),
				}},
				Tags:        []string{"exported", strings.ToLower(it.kind)},
				ManualCheck: true,
			})
		}
	}
	return out
}

func scanPermissions(next func() string, info model.APKInfo) []model.Finding {
	var out []model.Finding
	for _, p := range info.Permissions {
		why, ok := dangerousPerms[p]
		if !ok {
			continue
		}
		out = append(out, model.Finding{
			ID: next(), Category: model.CatDangerousPerm,
			Title:    "Dangerous permission: " + p,
			Severity: model.SeverityMedium, Class: model.EvidenceStatic,
			Confidence: model.ConfidenceSourceOfTruth,
			Summary:    "uses-permission declares " + p + " (" + why + ")",
			Why:        "Permission appears in decoded AndroidManifest uses-permission list",
			Evidence: []model.EvidenceLink{{
				APK: info.Path, Manifest: `uses-permission android:name="` + p + `"`,
			}},
			Tags: []string{"permission", why},
		})
	}
	return out
}

func scanAppFlags(next func() string, info model.APKInfo, manifest string) []model.Finding {
	var out []model.Finding
	if info.Debuggable != nil && *info.Debuggable {
		out = append(out, model.Finding{
			ID: next(), Category: model.CatDebuggable,
			Title:    "Application is debuggable",
			Severity: model.SeverityCritical, Class: model.EvidenceStatic,
			Confidence: model.ConfidenceSourceOfTruth,
			Summary:    "android:debuggable=true",
			Why:        "application@android:debuggable in manifest",
			Evidence:   []model.EvidenceLink{{APK: info.Path, Manifest: `android:debuggable="true"`}},
			Tags:       []string{"debuggable"},
		})
	}
	if info.AllowBackup != nil && *info.AllowBackup {
		out = append(out, model.Finding{
			ID: next(), Category: model.CatBackup,
			Title:    "Backup allowed",
			Severity: model.SeverityLow, Class: model.EvidenceStatic,
			Confidence:  model.ConfidenceSourceOfTruth,
			Summary:     "android:allowBackup=true (or default true on older targets)",
			Why:         "application@android:allowBackup",
			Evidence:    []model.EvidenceLink{{APK: info.Path, Manifest: `android:allowBackup="true"`}},
			Tags:        []string{"backup"},
			ManualCheck: true,
		})
	}
	if info.UsesCleartext != nil && *info.UsesCleartext {
		out = append(out, model.Finding{
			ID: next(), Category: model.CatCleartext,
			Title:    "Cleartext HTTP traffic permitted",
			Severity: model.SeverityHigh, Class: model.EvidenceStatic,
			Confidence: model.ConfidenceSourceOfTruth,
			Summary:    "android:usesCleartextTraffic=true",
			Why:        "application@android:usesCleartextTraffic",
			Evidence:   []model.EvidenceLink{{APK: info.Path, Manifest: `android:usesCleartextTraffic="true"`}},
			Tags:       []string{"cleartext", "network"},
		})
	}
	if info.NetworkSecurityCfg != "" {
		out = append(out, model.Finding{
			ID: next(), Category: model.CatNetworkConfig,
			Title:    "Custom network security config",
			Severity: model.SeverityLow, Class: model.EvidenceStatic,
			Confidence: model.ConfidenceSourceOfTruth,
			Summary:    "networkSecurityConfig=" + info.NetworkSecurityCfg,
			Why:        "Manifest references a network security config resource — review for cleartext/trust anchors",
			Evidence: []model.EvidenceLink{{
				APK: info.Path, Manifest: `android:networkSecurityConfig="` + info.NetworkSecurityCfg + `"`,
				Resource: info.NetworkSecurityCfg,
			}},
			Tags:        []string{"network_config"},
			ManualCheck: true,
		})
	}
	_ = manifest
	return out
}

func scanSecrets(next func() string, methods []*ir.MethodIR, apkPath string) []model.Finding {
	var out []model.Finding
	seen := map[string]struct{}{}
	for _, m := range methods {
		if m == nil {
			continue
		}
		var parts []string
		for _, c := range m.Constants {
			parts = append(parts, c.Value)
		}
		parts = append(parts, m.RawSource)
		blob := strings.Join(parts, "\n")
		for _, pat := range secretPatterns {
			loc := pat.re.FindString(blob)
			if loc == "" {
				continue
			}
			key := pat.name + "|" + m.ClassName + "|" + m.MethodName + "|" + loc
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			redacted := redact(loc)
			out = append(out, model.Finding{
				ID: next(), Category: model.CatHardcodedSecret,
				Title:    fmt.Sprintf("Possible hardcoded secret (%s)", pat.name),
				Severity: pat.sev, Class: model.EvidenceStatic,
				Confidence: model.ConfidencePartiallyConsistent,
				Summary:    fmt.Sprintf("Pattern %s matched in %s.%s → %s", pat.name, m.ClassName, m.MethodName, redacted),
				Why:        "Const-string / Smali constant matched a secret heuristic — verify manually; may be test/dummy data",
				Evidence: []model.EvidenceLink{{
					APK: apkPath, Class: m.ClassName, Method: m.MethodName,
					Descriptor: m.Descriptor, SmaliInsn: redacted,
				}},
				Tags:        []string{"secret", pat.name},
				Related:     []string{m.ClassName + "->" + m.MethodName},
				ManualCheck: true,
			})
		}
	}
	return out
}

func scanMethodTags(next func() string, methods []model.MethodResult) []model.Finding {
	var out []model.Finding
	interesting := map[string]model.FindingCategory{
		"webview":           model.CatWebView,
		"command_exec":      model.CatDangerousAPI,
		"dynamic_code":      model.CatDangerousAPI,
		"deserialization":   model.CatDangerousAPI,
		"sql":               model.CatDangerousAPI,
		"auth":              model.CatAuthz,
		"authz":             model.CatAuthz,
		"sensitive_storage": model.CatInsecureStorage,
		"crypto":            model.CatWeakCrypto,
	}
	for _, m := range methods {
		if !m.SecurityRelevant {
			continue
		}
		for _, tag := range m.SecurityTags {
			cat, ok := interesting[tag]
			if !ok {
				continue
			}
			sev := model.SeverityLow
			cls := model.EvidenceInference
			conf := model.ConfidenceInsufficientEvidence
			title := "Security-sensitive API pattern: " + tag
			why := "Method tagged via Smali call/name heuristics — presence is STATIC_EVIDENCE of the call pattern; vulnerability is INFERENCE"
			if tag == "webview" || tag == "command_exec" || tag == "dynamic_code" {
				sev = model.SeverityMedium
			}
			// The *call pattern* is static evidence; exploitability is inference.
			out = append(out, model.Finding{
				ID: next(), Category: cat, Title: title,
				Severity: sev, Class: cls, Confidence: conf,
				Summary: fmt.Sprintf("%s.%s tagged [%s]", m.Ref.Class, m.Ref.Name, tag),
				Why:     why,
				Evidence: []model.EvidenceLink{{
					Class: m.Ref.Class, Method: m.Ref.Name, Descriptor: m.Ref.Descriptor,
				}},
				Tags:        []string{tag},
				Related:     []string{m.Ref.Key()},
				ManualCheck: true,
			})
			break // one finding per method
		}
	}
	return out
}

func scanWeakCrypto(next func() string, methods []*ir.MethodIR, apkPath string) []model.Finding {
	var out []model.Finding
	seen := map[string]struct{}{}
	for _, m := range methods {
		if m == nil {
			continue
		}
		var parts []string
		for _, c := range m.Constants {
			parts = append(parts, c.Value)
		}
		blob := strings.Join(parts, " ")
		for _, w := range weakCrypto {
			if !strings.Contains(blob, w) && !strings.Contains(strings.ToUpper(blob), strings.ToUpper(w)) {
				continue
			}
			key := m.ClassName + "->" + m.MethodName + "|" + w
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model.Finding{
				ID: next(), Category: model.CatWeakCrypto,
				Title:    "Weak / legacy crypto indicator: " + w,
				Severity: model.SeverityMedium, Class: model.EvidenceStatic,
				Confidence: model.ConfidencePartiallyConsistent,
				Summary:    fmt.Sprintf("Constant/string %q appears in %s.%s", w, m.ClassName, m.MethodName),
				Why:        "Smali constant suggests legacy algorithm — confirm Cipher.getInstance usage manually",
				Evidence: []model.EvidenceLink{{
					APK: apkPath, Class: m.ClassName, Method: m.MethodName, SmaliInsn: w,
				}},
				Tags:        []string{"crypto", "weak"},
				Related:     []string{m.ClassName + "->" + m.MethodName},
				ManualCheck: true,
			})
		}
	}
	return out
}

func scanDisagreements(next func() string, methods []model.MethodResult) []model.Finding {
	var out []model.Finding
	for _, m := range methods {
		if m.Status != model.ConfidenceDisagreement {
			continue
		}
		out = append(out, model.Finding{
			ID: next(), Category: model.CatDecompilerDisagree,
			Title:    "Decompiler disagreement: " + m.Ref.Class + "." + m.Ref.Name,
			Severity: model.SeverityLow, Class: model.EvidenceStatic,
			Confidence: model.ConfidenceDisagreement,
			Summary:    m.Verdict,
			Why:        "JADX/CFR/FernFlower reconstructions disagree relative to Smali ground truth",
			Evidence: []model.EvidenceLink{{
				Class: m.Ref.Class, Method: m.Ref.Name, Descriptor: m.Ref.Descriptor,
			}},
			Tags:        []string{"disagreement"},
			Related:     []string{m.Ref.Key()},
			ManualCheck: true,
		})
	}
	return out
}

func componentManifestHint(manifest, name string) string {
	short := name
	if i := strings.LastIndex(name, "."); i >= 0 {
		short = name[i+1:]
	}
	if strings.Contains(manifest, name) {
		return `android:name="` + name + `"`
	}
	if strings.Contains(manifest, short) {
		return `android:name="…` + short + `"`
	}
	return name
}

func redact(s string) string {
	if len(s) <= 8 {
		return s[:len(s)/2] + "…"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	default:
		return 1
	}
}
