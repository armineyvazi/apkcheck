# APKCheck ASK / Product Specification

> Living specification for **APKCheck / APK Lab**.  
> Updated: 2026-10-02 · Tool version target: **0.6.0**

## Core differentiator (unchanged)

```text
DEX / Smali          = ground truth
Decompilers          = reconstructions
Runtime              = partial observation (NOT OBSERVED ≠ ABSENT)
AI / MCP             = reasons over evidence, never invents facts
```

Do **not** turn APKCheck into a generic MobSF clone. Lab features strengthen Smali-backed evidence + runtime observation.

---

## Phase 1 assessment (existing codebase)

### Implemented

| Area | Status |
|------|--------|
| APK inspect, multidex, native inventory | Done |
| Apktool Smali ground truth + IR/CFG/diff | Done |
| JADX / CFR / FernFlower cross-check | Done |
| Security findings + evidence classes | Done |
| Hunt / CI / REPORT.md / HTML browser | Done |
| Split / XAPK / AAB resolve | Done |
| Device + macOS emulator runtime | Done (boot fixed: platform-tools symlink) |
| Scenarios YAML (launch/wait/tap/input/shell) | Scaffold |
| Frida dynamic instrumentation | **Done** (`internal/lab/frida`; SSL unpin, method trace, DEX loader, network trace) |
| MCP / AI digest | Done |
| Network observe | Hints only (no MITM by default) |
| Static IOC scanner | **Done** (`internal/lab/iocscan`; 14 pattern categories over decompiled sources) |

### Missing (this ASK extension) — implementation status 2026-10-02

| Area | Status |
|------|--------|
| Decompile → **rebuild** → **sign** → install → **validate** | **Done** (`internal/lab/pipeline`) |
| Artifact / variant lineage (original vs rebuilt) | **Done** (`lab.Store`) |
| Parallel multi-APK runtime sessions | **Partial** (multi-artifact targets + compare; parallel sessions next) |
| Rich scenario engine + assertions | **Partial** (lab scenarios + runtime YAML actions) |
| React workstation dashboard | **Done** (`web/`) |
| Live event bus (SSE) | **Done** (`/api/events/stream`) |
| Certificate manager + mitmproxy first-class | **Done** (status + mitmdump mgr; CA install helper best-effort) |
| Comparison view (original vs rebuilt) | **Done** (`lab compare` + UI) |
| Lab HTTP API | **Done** (`apkcheck lab serve`) |
| Security test scenario library + presets | **Done** (`internal/lab/security`) |
| Observations (not auto-vulns) + evidence export | **Done** |
| Manifest security panel | **Done** |
| Authorized test harness scaffold | **Done** (`testdata/lab/harness`) |
| Command palette (⌘K) + CLI↔UI command map | **Done** |
| Scenario builder UI | **Partial** (builder + save; drag-drop polish next) |
| Parallel security matrix runs | **Partial** (`/api/security/matrix` sequential) |
| Runtime instance start/stop/restart/count | **Done** (`lab runtime` + Devices UI) |

### Bugs fixed in Lab work

5. Lab CLI flags after positional args were ignored → `parseLabArgs` allows either order.
6. Relative `lab-data` paths → workspace root absolutized.
7. Empty package on binary-manifest APKs → aapt badging fallback on import.
8. mitmdump killed when HTTP request ended → proxy uses independent process lifetime.

### Bugs fixed recently (do not regress)

1. Emulator boot looked like download (npm-style on boot) → boot is plain + spinner; fetch bar only for downloads.
2. Emulator FATAL `Broken AVD system path` → auto-symlink `platform-tools` into `ANDROID_HOME`.
3. Empty emulator crash log → capture stdout+stderr; print log tail on fail.
4. AVD name prop empty → accept single booted emulator.

---

## Architecture (Lab extension)

```text
apkcheck (Go CLI + Lab API)
├── existing: analyze / hunt / ci / runtime / mcp
└── lab/  (NEW)
    ├── store/          artifact + project persistence (JSON/SQLite-lite files)
    ├── pipeline/       decode → build → sign → validate
    ├── events/         in-process event bus (+ WS fanout)
    ├── scenarios/      extends runtime/scenarios
    ├── proxy/          mitmproxy manager + CA install helpers
    ├── certs/          debug keystore + user CA handling
    ├── api/            HTTP + WebSocket
    └── ui/             React dashboard (Vite)

No Rust in v0.6 unless a measured bottleneck appears.
Prefer Go + existing ADB/runtime stack.
```

### Artifact lineage

```text
original.apk
  → project (apktool d)
  → unsigned.apk (apktool b)
  → signed.apk (apksigner / jarsigner)
  → validate run (install/launch/smoke)
```

Each artifact has: id, parent_id, kind, sha256, created_at, cert_id, runtime_results[].

### Validation pipeline (success ≠ “apk file exists”)

```text
BUILD → SIGN → INSTALL → LAUNCH → STARTUP → NO_CRASH → SMOKE → (optional NETWORK)
```

Any stage failure stops and reports stage + logs.

### Runtime abstraction

```text
RuntimeTarget
  ├── DeviceRuntime   (USB ADB)
  └── EmulatorRuntime (macOS AVD)
```

Multiple sessions = multiple targets (parallel original vs rebuilt).

### Events

`APK_IMPORTED`, `DECOMPILE_*`, `BUILD_*`, `SIGN_*`, `INSTALL_*`, `RUNTIME_*`, `SCENARIO_*`, `NETWORK_*`, `LOG_EVENT`, `CRASH_DETECTED`, `VALIDATE_*`

---

## Security / isolation

- Untrusted APKs run only via ADB on device/emulator — never as host processes.
- Workspaces under `./lab-data/` (configurable).
- Private keys never logged or sent to React UI.
- MITM/proxy off by default; explicit enable + authorized testing only.
- Clear limitations when system CA install is blocked (Android 7+ user CA / Magisk / rooted test images).

---

## CLI (Lab)

```bash
apkcheck lab import app.apk
apkcheck lab decompile <apk-id>
apkcheck lab build <project-id>
apkcheck lab sign <artifact-id>
apkcheck lab validate <artifact-id> [--emulator AVD|--device]
apkcheck lab compare <original-id> <rebuilt-id>
apkcheck lab security catalog|presets|manifest|run|preset|observations|export|harness
apkcheck lab serve [--addr :8787]   # API + UI
```

Legacy commands (`analyze`, `hunt`, `runtime`, …) remain.

---

## §34 Security testing / bug-bounty workbench (authorized only)

### Principle

- Templates produce **Observations** with evidence (`informational` / `potential` / `needs_review`).
- Never auto-claim “this is a vulnerability.”
- No stealth, persistence, credential theft, or unauthorized-access features.
- CLI and React UI share the same `internal/lab/security` + `/api/security/*` engine.

### Built-ins

- Catalog: exported components, deep links, background behavior, WebView, storage, network, auth flow, permissions, privacy, IPC probe, lifecycle, crypto static cues.
- Presets: quick / full / deep-link / exported / webview / storage / network / auth / background / privacy.
- Manifest review panel + review notes.
- Evidence export: JSON / Markdown / HTML / ZIP.
- Explicit **test harness** APK scaffold (`com.apkcheck.testharness`) — visible, documented, for IPC probes on test runtimes.
- Command palette ⌘K maps UI actions ↔ CLI.

### Still extending

- Richer assertion DSL, drag-drop builder polish, true parallel dual-runtime security sessions, mitm flow body timeline correlation.

---

## Acceptance criteria (priority)

1. Rebuild signed APK from apktool project installs and launches.
2. Validation report shows per-stage pass/fail with logs.
3. Original vs rebuilt can be registered as separate targets.
4. Same scenario YAML runnable against both.
5. Lab UI shows projects, builds, live events/logs (streaming).
6. mitmproxy can be started; CA status visible; traffic listed when enabled.
7. Tests cover pipeline unit paths; integration where tools exist.
8. README + Obsidian + this ASK stay in sync.
9. Security catalog runnable from CLI and UI; observations exportable.
10. Manifest panel highlights review candidates without auto-vuln claims.
