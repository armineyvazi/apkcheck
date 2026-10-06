# APKCheck — What it is & how to use it

APKCheck is a **Smali-first Android reverse-engineering and security triage toolkit**.  
It helps you understand what an APK actually contains, how decompilers reconstruct it, what happens when you rebuild it, and what you can observe on a device or emulator — without inventing “95% correct” scores or claiming vulnerabilities from weak evidence.

You get four surfaces that share one engine:

| Surface | Best for |
|---------|----------|
| **CLI** | Scripts, CI, precise control |
| **Lab UI** | Day-to-day rebuild / Devices / security work |
| **HTTP API** | Automation / integration |
| **MCP** | AI agents in Cursor / Claude |

---

## What APKCheck is for

1. **Static truth** — DEX/Smali is ground truth; JADX/CFR/FernFlower are reconstructions.  
2. **Hunt** — one command first-pass: findings, disagreements, native/JNI, reports.  
3. **APK Lab** — import → decompile → rebuild → sign → install → validate → compare.  
4. **Devices** — start/stop/restart Android emulators and see counts in the UI.  
5. **Authorized security tests** — templates that produce *observations* (review candidates), not auto-confirmed vulns.  
6. **AI agents** — MCP tools so models call Lab/analysis APIs instead of scraping terminal text.

### What it is *not*

- Not a “one-click auto exploit” tool.  
- Not a substitute for human disclosure judgment.  
- Not permission to test apps you don’t own or aren’t authorized to assess.

---

## Core rules (read once)

```text
DEX / Smali     = ground truth
Decompilers     = reconstructions
Runtime         = partial observation
NOT OBSERVED    ≠ ABSENT
Rebuild success ≠ runtime success
Lab observation ≠ automatic vulnerability
```

---

## Install (once)

Full platform-specific dependency instructions: [README.md § Install](../README.md#install).

```bash
# macOS / Linux — after installing all prerequisites:
cd /path/to/apkcheck
./scripts/setup          # go build + npm build
./bin/apkcheck doctor    # verify tools

# Windows (PowerShell):
go build -o bin\apkcheck.exe .\cmd\apkcheck
cd web; npm install; npm run build; cd ..
bin\apkcheck.exe doctor
```

Optional emulator:

```bash
./bin/apkcheck emulator-create --name Pixel_8_API_34
```

---

## How to use — five common workflows

### 1) Quick static hunt (understand an APK)

```bash
./bin/apkcheck hunt app.apk --output ./hunt-out
open ./hunt-out/REPORT.md          # or report.html
```

Also works on `.xapk`, `.apks`, `.aab`, and split-APK directories.

AI-oriented digest:

```bash
./bin/apkcheck analyze app.apk --format ai --limit 500
```

---

### 2) Lab UI (recommended daily path)

```bash
./bin/apkcheck lab ui
# → http://127.0.0.1:8787
```

Then in the browser:

1. **Workspace** — paste absolute APK path → **Import** → **Full rebuild** → enable **Record device** → **Validate**  
2. **Devices** — start/stop emulators (header shows `emu running/configured`)  
3. **Runs** — watch device recording synchronized with MCP/scenario/network/assert events  
4. **Security** — pick artifact → run template or preset (authorized only)  
5. **Findings** — review observations → export MD/ZIP  
6. **⌘K** — command palette (same actions as CLI)

Without opening a browser: `apkcheck lab ui --no-open`

---

### 3) Lab from the CLI (rebuild ↔ validate)

```bash
./bin/apkcheck lab import ./app.apk --workspace ./lab-data --label original
./bin/apkcheck lab runtime start --avd Pixel_8_API_34
./bin/apkcheck lab rebuild <apk-id>
./bin/apkcheck lab validate <signed-id> --emulator Pixel_8_API_34 --duration 20s --record --profile balanced
./bin/apkcheck lab compare <apk-id> <signed-id>
```

`--record` binds a Lab session + device screen recording (watch in **Runs**). Signature mismatches between Play-signed originals and Lab-signed rebuilds trigger an automatic uninstall+reinstall when validating with reinstall mode.

Workspace data lives under `./lab-data/` (apks, projects, builds, runs, proxy, …).

**Tip:** A rebuilt APK is only “working” after validation stages pass (install, launch, crash checks, smoke, …).

---

### 4) Manage Android instances (Devices)

```bash
./bin/apkcheck lab runtime list
./bin/apkcheck lab runtime start --avd Pixel_8_API_34
./bin/apkcheck lab runtime stop --avd Pixel_8_API_34
./bin/apkcheck lab runtime stop --all
./bin/apkcheck lab runtime restart --avd Pixel_8_API_34
```

Same controls exist in the UI **Devices** tab and via MCP `apkcheck_lab_runtime_*`.

---

### 4b) Device recording + timeline (Runs)

When **Record device** is enabled (UI checkbox or MCP `record: true`), validate creates a Lab **test run** and captures segmented `adb screenrecord` video bound to the same clock as timeline events.

```text
apkcheck_lab_validate { "artifact_id": "<signed>", "record": true, "profile": "balanced" }
apkcheck_lab_sessions_list
apkcheck_lab_sessions_get { "run_id": "run-…" }
```

Then open **Runs** in the UI: play/pause, seek by event, filter categories, bookmark, side-by-side compare of two runs, retention cleanup.

---

### 5) Authorized security library

```bash
./bin/apkcheck lab security catalog
./bin/apkcheck lab security run exported-components --artifact <id>
./bin/apkcheck lab security preset quick-android-security --artifact <id>
./bin/apkcheck lab security observations
./bin/apkcheck lab security export <obs-id> --format markdown
```

Severity is only: `informational` | `potential` | `needs_review`.  
**You** decide what becomes a finding for disclosure.

---

## How to use — AI agents (MCP)

```bash
./bin/apkcheck mcp
```

In Cursor, point MCP at `bin/apkcheck` (see `configs/mcp.cursor.json`). For Claude Desktop use `configs/mcp.claude.json` — **same server**, no extra Lab code. Restart MCP after rebuilds.

**Agent playbook:**

1. Call `apkcheck_lab_help`  
2. Call `apkcheck_lab_status`  
3. Prefer one-shot recipes via `apkcheck_lab_workflow`:

| `action` | Meaning |
|----------|---------|
| `ensure_runtime` | Start emulator if none running |
| `import_rebuild_validate` | Import → rebuild → smoke validate |
| `security_quick` | Manifest + quick security preset |

Aliases that reduce mistakes: `id`↔`artifact_id`, `path`↔`apk`, `serial`↔`device_id`.

Full tool list: [`docs/mcp.md`](mcp.md).

---

## Static IOC Scanner (no device needed)

The IOC scanner walks decompiled Java/Smali/XML sources and flags 14 pattern categories: hardcoded secrets, public IPs, base64 payloads, DexClassLoader, SSL bypass, C2 keywords, telephony leaks, and more.

**UI (Security tab → IOC Scanner):**
1. Select any artifact (original APK or project)
2. Click **Scan**
3. Findings appear grouped by severity and category; each row shows the file:line, matched text, and surrounding context

**MCP:**
```json
{ "tool": "apkcheck_lab_ioc_scan", "arguments": { "artifact_id": "<id>" } }
```

Tip: pass the original APK artifact ID — the scanner automatically finds the companion decompiled project artifact if one exists; otherwise it scans the artifact directory directly.

All findings are **observations**. A match is a lead for manual review, not a confirmed vulnerability.

---

## Dynamic analysis with Frida (device required)

Frida enables runtime method hooking, SSL pinning bypass, and covert-traffic detection against an APK running on a physical or emulator device. **Authorized testing only.**

### One-time setup (do this once per machine)

```bash
# 1. Install frida Python tools on the host
pip install frida-tools

# 2. Check which arch your device uses
#    UI: Security → Frida → Check status → look for device_arch
#    CLI: adb shell getprop ro.product.cpu.abi
#    Common values: arm64-v8a, armeabi-v7a, x86_64, x86

# 3. Download the matching frida-server binary from GitHub releases
#    Replace X.Y.Z with the version matching your frida CLI (frida --version)
#    arm64 device: frida-server-X.Y.Z-android-arm64.xz
#    arm32 device: frida-server-X.Y.Z-android-arm.xz
curl -Lo /tmp/frida-server.xz \
  https://github.com/frida/frida/releases/download/X.Y.Z/frida-server-X.Y.Z-android-arm64.xz
xz -d /tmp/frida-server.xz
# binary is now at /tmp/frida-server

# 4. Push to device (UI: Security → Frida → fill host_path → push button)
#    Or via MCP:
{ "tool": "apkcheck_lab_frida_push", "arguments": { "serial": "emulator-5554", "host_path": "/tmp/frida-server" } }

# 5. Start frida-server on the device
#    UI: Security → Frida → Start Server button
#    frida-server needs root or a debuggable APK target
```

### Available hooks

| Hook | What it does | UI button | MCP tool |
|------|-------------|-----------|----------|
| **SSL Unpin** | Bypasses TrustManager, OkHttp3, Conscrypt, HostnameVerifier — combine with Proxy→Start to capture full traffic | SSL Unpin | `apkcheck_lab_frida_ssl_unpin` |
| **Method Trace** | Hooks all methods matching a name pattern and logs args + return values | Method Trace | `apkcheck_lab_frida_method_trace` |
| **DEX Loader** | Detects DexClassLoader, InMemoryDexClassLoader, PathClassLoader at runtime (obfuscation/packing signal) | DEX Loader | `apkcheck_lab_frida_dex_loader` |
| **Network Trace** | Intercepts Socket, URL.openConnection, OkHttp3 connections — surfaces undocumented endpoints | Network Trace | `apkcheck_lab_frida_network_trace` |

### Full SSL intercept workflow

```bash
# Terminal order:
# 1. Start mitmproxy (Proxy tab → Start, or apkcheck_lab_proxy_start)
# 2. Push + start frida-server (see setup above)
# 3. Run SSL unpin hook against the target package
{ "tool": "apkcheck_lab_frida_ssl_unpin",
  "arguments": { "serial": "emulator-5554", "package": "com.example.app", "timeout_sec": 60 } }
# 4. Open the app and interact — traffic flows through mitmproxy unencrypted
# 5. Import flows into a session (UI → Proxy → import, or apkcheck_lab_sessions_import_proxy)
```

### Method trace example

```json
{ "tool": "apkcheck_lab_frida_method_trace",
  "arguments": { "package": "com.example.app", "pattern": "auth", "timeout_sec": 30 } }
```

Returns a list of `{type, payload}` events for every method whose name contains "auth".

### Version matching

The `frida` Python CLI version **must match** the `frida-server` binary version on the device, or Frida refuses to attach. Run `frida --version` and download the matching release.

---

## Optional: network intercept

```bash
brew install mitmproxy
./bin/apkcheck lab ui
# UI → Proxy → Start   (off by default)
```

Only for APKs you are authorized to analyze. Certificates UI shows fingerprints — never private keys. Android 7+ often needs a user CA / test image.

---

## CI

```bash
./bin/apkcheck ci app.apk --config configs/ci.yaml
```

Only strong **STATIC_EVIDENCE** at/above threshold fails the build. Pure **INFERENCE** never fails CI by itself.

---

## Choosing a path

| Goal | Use this |
|------|----------|
| Fast understanding of an APK | `hunt` |
| Interactive rebuild + devices | `lab ui` |
| Scripted rebuild/validate | `lab import/rebuild/validate` |
| Emulator count / start / kill | `lab runtime …` or Devices tab |
| Authorized security triage | `lab security …` or Security tab |
| Static IOC scan (no device) | Security tab → IOC Scanner, or `apkcheck_lab_ioc_scan` |
| SSL pinning bypass + traffic capture | Frida panel + Proxy, or `apkcheck_lab_frida_ssl_unpin` |
| Runtime method / class loader trace | Frida panel, or `apkcheck_lab_frida_method_trace` |
| Dual-APK authorized assessment | `lab security preset full-android-security` |
| AI agent automation | `mcp` + `apkcheck_lab_workflow` |
| Gate PRs on static evidence | `ci` |

---

## Where to read next

| Doc | Contents |
|-----|----------|
| [README.md](../README.md) | Full product reference |
| [mcp.md](mcp.md) | MCP tool table |
| [ASK.md](ASK.md) | Spec / Lab requirements |
| Obsidian `03 Dev/APKCheck/` | Lab, Security, MCP, Commands, Runtime — System-Design diagrams |

---

## One-sentence summary

**APKCheck** tells you what the bytecode supports, what decompilers claim, what a rebuild can prove on a device, and what an authorized security pass observed — then exposes that same engine to humans (CLI/UI) and AI (MCP) without pretending weak evidence is certainty.
