package security

// Catalog returns built-in security test templates for authorized research.
func Catalog() []Template {
	return []Template{
		{
			ID: "exported-components", Name: "Inspect Exported Components",
			Category: CatIPC, Description: "Enumerate exported activities/services/receivers/providers from manifest; optionally probe launchable activities on a test runtime.",
			RequiresDevice: false, CLIHint: "apkcheck lab security run exported-components --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Analyze AndroidManifest"},
				{Kind: StepListExported, Label: "Identify exported components + intent filters"},
				{Kind: StepRecordObservation, Label: "Record review candidates (not auto-vulns)"},
				{Kind: StepLaunchComponent, Label: "Launch exported activities (device, if available)", Params: map[string]string{"mode": "exported_activities"}},
				{Kind: StepCaptureLogs, Label: "Capture application logs"},
				{Kind: StepRecordObservation, Label: "Record launch outcomes / crashes"},
			},
		},
		{
			ID: "deep-link-audit", Name: "Deep Link Audit",
			Category: CatDeepLink, Description: "List custom schemes / App Links from manifest; open candidates on test device.",
			RequiresDevice: false, CLIHint: "apkcheck lab security run deep-link-audit --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Extract deep link / intent-filter data"},
				{Kind: StepRecordObservation, Label: "List schemes and hosts for review"},
				{Kind: StepOpenDeepLink, Label: "Open deep links on device (if available)"},
				{Kind: StepCaptureLogs, Label: "Capture logs after deep link"},
			},
		},
		{
			ID: "background-behavior", Name: "Background Behavior Audit",
			Category: CatLifecycle, RequiresDevice: true,
			Description: "Launch target, monitor, background app, continue monitoring for unexpected activity.",
			CLIHint: "apkcheck lab security run background-behavior --artifact <id> --device <serial>",
			Steps: []Step{
				{Kind: StepLaunchApp, Label: "Start target APK"},
				{Kind: StepStartMonitor, Label: "Start monitoring (process/logs/network hints)"},
				{Kind: StepUserAction, Label: "Perform selected user actions (manual or scenario)"},
				{Kind: StepWait, Label: "Settle foreground", Params: map[string]string{"duration": "5s"}},
				{Kind: StepBackgroundApp, Label: "Move target to background (HOME)"},
				{Kind: StepWait, Label: "Observe background window", Params: map[string]string{"duration": "15s"}},
				{Kind: StepAssertProcess, Label: "Record process/service state"},
				{Kind: StepCaptureNetwork, Label: "Capture network observations"},
				{Kind: StepCaptureLogs, Label: "Capture logs"},
				{Kind: StepRecordObservation, Label: "Compare before/after background activity"},
			},
		},
		{
			ID: "webview-audit", Name: "WebView Audit", Category: CatWebView, StaticOnly: true,
			Description: "Static cues for WebView JS, file access, and bridge patterns (Smali/manifest review).",
			CLIHint: "apkcheck lab security run webview-audit --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Manifest + package context"},
				{Kind: StepRecordObservation, Label: "Flag WebView-related review notes from static cues"},
			},
		},
		{
			ID: "storage-audit", Name: "Storage Audit", Category: CatStorage, RequiresDevice: true,
			Description: "Inspect app-private and shared storage paths on a test runtime for sensitive data exposure candidates.",
			CLIHint: "apkcheck lab security run storage-audit --artifact <id> --device <serial>",
			Steps: []Step{
				{Kind: StepLaunchApp, Label: "Ensure app installed/ran once"},
				{Kind: StepInspectStorage, Label: "List shared_prefs / databases / files (run-as / backup when available)"},
				{Kind: StepRecordObservation, Label: "Record storage review candidates"},
			},
		},
		{
			ID: "network-audit", Name: "Network Audit", Category: CatNetwork, RequiresDevice: true,
			Description: "Observe cleartext/TLS behavior via runtime network hints and optional mitmproxy (authorized only).",
			CLIHint: "apkcheck lab security run network-audit --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "usesCleartextTraffic / networkSecurityConfig review"},
				{Kind: StepLaunchApp, Label: "Launch and exercise briefly"},
				{Kind: StepCaptureNetwork, Label: "Collect network observations"},
				{Kind: StepRecordObservation, Label: "Record network review candidates"},
			},
		},
		{
			ID: "auth-flow-audit", Name: "Authentication Flow Audit", Category: CatAuthn, RequiresDevice: true,
			Description: "Template for login/logout/session observations — requires tester-driven credentials on authorized apps.",
			CLIHint: "apkcheck lab security run auth-flow-audit --artifact <id>",
			Steps: []Step{
				{Kind: StepLaunchApp, Label: "Launch app"},
				{Kind: StepUserAction, Label: "Perform login (scenario / manual)"},
				{Kind: StepCaptureNetwork, Label: "Observe auth requests (authorized MITM if enabled)"},
				{Kind: StepInspectStorage, Label: "Check token/session storage candidates"},
				{Kind: StepBackgroundApp, Label: "Background and re-open"},
				{Kind: StepRecordObservation, Label: "Session persistence notes"},
			},
		},
		{
			ID: "permission-audit", Name: "Permission Behavior Audit", Category: CatRuntime, RequiresDevice: true,
			Description: "Dump runtime permission state and related log events.",
			CLIHint: "apkcheck lab security run permission-audit --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Declared permissions"},
				{Kind: StepInspectPermissions, Label: "Runtime permission grants"},
				{Kind: StepCaptureLogs, Label: "Permission-related logs"},
				{Kind: StepRecordObservation, Label: "Permission review notes"},
			},
		},
		{
			ID: "privacy-exposure", Name: "Privacy / Data Exposure Audit", Category: CatPrivacy, RequiresDevice: true,
			Description: "Screenshots, logs, clipboard-adjacent notes, and storage candidates for sensitive data.",
			CLIHint: "apkcheck lab security run privacy-exposure --artifact <id>",
			Steps: []Step{
				{Kind: StepLaunchApp, Label: "Launch app"},
				{Kind: StepCaptureScreenshot, Label: "Capture UI screenshot"},
				{Kind: StepCaptureLogs, Label: "Scan recent logs for sensitive patterns (heuristic)"},
				{Kind: StepInspectStorage, Label: "Storage candidates"},
				{Kind: StepRecordObservation, Label: "Privacy review notes"},
			},
		},
		{
			ID: "ipc-intent-handling", Name: "Intent Handling Probe", Category: CatIPC, RequiresDevice: true, RequiresHarness: true,
			Description: "Use adb/test harness to send controlled intents to exported components on a test runtime.",
			CLIHint: "apkcheck lab security run ipc-intent-handling --artifact <id>",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "List exported + filters"},
				{Kind: StepHarnessInstall, Label: "Ensure test harness available"},
				{Kind: StepSendIntent, Label: "Send controlled probe intents"},
				{Kind: StepCaptureLogs, Label: "Capture responses / crashes"},
				{Kind: StepRecordObservation, Label: "IPC handling observations"},
			},
		},
		{
			ID: "cross-app-bg-data", Name: "Cross-App Background Data Probe (SC-12)",
			Category: CatIPC, RequiresDevice: true, RequiresHarness: true,
			Description: "Browse Divar (city + search), background it, then probe from the Lab harness for IPC/provider data leakage. Use with record=true (≥120s). Scenario: divar-sc12-bg-attack.",
			CLIHint: "apkcheck lab security run cross-app-bg-data --artifact <id> --record",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Map exported surface"},
				{Kind: StepHarnessInstall, Label: "Build/install test harness"},
				{Kind: StepLaunchApp, Label: "Ensure Divar installed"},
				{Kind: StepUserAction, Label: "SETUP: city select + product search", Params: map[string]string{"scenario": "divar-city-search"}},
				{Kind: StepCaptureScreenshot, Label: "Screenshot after browse (SETUP)"},
				{Kind: StepUserAction, Label: "ATTACK: background + harness/IPC/provider probes", Params: map[string]string{"scenario": "divar-sc12-bg-attack"}},
				{Kind: StepCaptureLogs, Label: "Capture logs after attack window"},
				{Kind: StepCaptureScreenshot, Label: "Screenshot harness / result (RESULT)"},
				{Kind: StepInspectStorage, Label: "Storage candidates post-probe"},
				{Kind: StepRecordObservation, Label: "H1 evidence checkpoint (not auto-vuln)"},
			},
		},
		{
			ID: "provider-uri-theft", Name: "Provider / URI Data Probe (SC-13)",
			Category: CatStorage, RequiresDevice: true, RequiresHarness: true,
			Description: "After a short Divar browse, background app and query providers / shared paths from harness. Scenario: divar-sc13-provider-theft.",
			CLIHint: "apkcheck lab security run provider-uri-theft --artifact <id> --record",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "List providers + grantUriPermissions"},
				{Kind: StepHarnessInstall, Label: "Ensure harness"},
				{Kind: StepUserAction, Label: "Browse then provider probes", Params: map[string]string{"scenario": "divar-sc13-provider-theft"}},
				{Kind: StepCaptureLogs, Label: "Capture provider errors / data"},
				{Kind: StepRecordObservation, Label: "SC-13 evidence checkpoint"},
			},
		},
		{
			ID: "lifecycle-force-stop", Name: "Force Stop / Restart", Category: CatLifecycle, RequiresDevice: true,
			Description: "Force-stop target and relaunch; observe persistence of local state.",
			Steps: []Step{
				{Kind: StepLaunchApp, Label: "Launch"},
				{Kind: StepForceStop, Label: "Force stop"},
				{Kind: StepLaunchApp, Label: "Relaunch"},
				{Kind: StepInspectStorage, Label: "Compare storage markers"},
				{Kind: StepRecordObservation, Label: "Lifecycle persistence notes"},
			},
		},
		{
			ID: "cryptography-static", Name: "Cryptography Static Cues", Category: CatCrypto, StaticOnly: true,
			Description: "Static review cues for hardcoded material / weak crypto APIs (evidence, not confirmation).",
			Steps: []Step{
				{Kind: StepAnalyzeManifest, Label: "Package context"},
				{Kind: StepRecordObservation, Label: "Point tester to Smali search / findings pipeline"},
			},
		},
	}
}

// Presets returns composed audit presets.
func Presets() []Preset {
	return []Preset{
		{ID: "quick-android-security", Name: "Quick Android Security Audit",
			Description: "Fast static + light dynamic pass for authorized triage.",
			TemplateIDs: []string{"exported-components", "deep-link-audit", "network-audit", "permission-audit"}},
		{ID: "full-android-security", Name: "Full Android Security Audit",
			Description: "Broader template set for authorized research.",
			TemplateIDs: []string{"exported-components", "deep-link-audit", "webview-audit", "storage-audit", "network-audit", "auth-flow-audit", "permission-audit", "privacy-exposure", "background-behavior", "ipc-intent-handling", "cross-app-bg-data", "provider-uri-theft", "lifecycle-force-stop", "cryptography-static"}},
		{ID: "preset-cross-app-bg", Name: "Cross-App Background Data (SC-12/13)",
			Description: "Primary H1 hypotheses with video-friendly scenarios.",
			TemplateIDs: []string{"exported-components", "cross-app-bg-data", "provider-uri-theft", "ipc-intent-handling"}},
		{ID: "preset-deep-link", Name: "Deep Link Audit", TemplateIDs: []string{"deep-link-audit"}},
		{ID: "preset-exported", Name: "Exported Component Audit", TemplateIDs: []string{"exported-components", "ipc-intent-handling"}},
		{ID: "preset-webview", Name: "WebView Audit", TemplateIDs: []string{"webview-audit"}},
		{ID: "preset-storage", Name: "Storage Audit", TemplateIDs: []string{"storage-audit"}},
		{ID: "preset-network", Name: "Network Audit", TemplateIDs: []string{"network-audit"}},
		{ID: "preset-auth", Name: "Authentication Flow Audit", TemplateIDs: []string{"auth-flow-audit"}},
		{ID: "preset-background", Name: "Background Behavior Audit", TemplateIDs: []string{"background-behavior"}},
		{ID: "preset-privacy", Name: "Privacy/Data Exposure Audit", TemplateIDs: []string{"privacy-exposure"}},
	}
}

// TemplateByID looks up a built-in template.
func TemplateByID(id string) (Template, bool) {
	for _, t := range Catalog() {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// PresetByID looks up a preset.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// Categories lists category metadata for the UI.
func Categories() []map[string]string {
	return []map[string]string{
		{"id": string(CatLifecycle), "name": "App Lifecycle"},
		{"id": string(CatIPC), "name": "IPC / Components"},
		{"id": string(CatStorage), "name": "Storage"},
		{"id": string(CatNetwork), "name": "Network"},
		{"id": string(CatAuthn), "name": "Authentication"},
		{"id": string(CatAuthz), "name": "Authorization"},
		{"id": string(CatWebView), "name": "WebView"},
		{"id": string(CatDeepLink), "name": "Deep Links"},
		{"id": string(CatClipboard), "name": "Clipboard"},
		{"id": string(CatUI), "name": "Screenshots / UI"},
		{"id": string(CatRuntime), "name": "Runtime / OS"},
		{"id": string(CatCrypto), "name": "Cryptography"},
		{"id": string(CatPrivacy), "name": "Privacy"},
	}
}
