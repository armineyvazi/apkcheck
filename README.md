# APKCheck

**Smali-backed Android reverse-engineering & security triage**, plus **APK Lab**: decompile → rebuild → sign → validate → observe — with a React UI, HTTP API, and MCP tools for AI agents.

```text
DEX / Smali  =  ground truth
Decompilers  =  reconstructions (never absolute authority)
Runtime      =  partial observation (NOT OBSERVED ≠ ABSENT)
Lab          =  rebuild + variant testing (still Smali-first)
MCP / AI     =  reasons over evidence — never invents facts
```

APKCheck does **not** ask *“which decompiler is correct?”*  
It asks *“which parts of each reconstruction are supported by the bytecode?”*

**Parity:** CLI ↔ HTTP API ↔ React UI ↔ MCP share one Lab engine. Do not reimplement Lab logic in agents or scripts.

---

## Table of contents

1. [What’s new in v0.6](#whats-new-in-v06--apk-lab)
2. [Quick start](#quick-start)
3. [Install](#install)
4. [Static analysis & hunt](#static-analysis--hunt)
5. [APK Lab](#apk-lab)
6. [Devices / runtime instances](#devices--runtime-instances)
7. [Security testing (authorized)](#security-testing-authorized)
8. [AI / MCP](#ai--mcp)
9. [Certificates & mitmproxy](#certificates--mitmproxy)
10. [Evidence model](#evidence-model)
11. [Architecture](#architecture)
12. [Design principles](#design-principles)
13. [Testing](#testing)
14. [Docs map](#docs-map)

---

## What’s new in v0.6 — APK Lab

| Capability | How |
|------------|-----|
| Decompile → rebuild → sign | `apkcheck lab rebuild <id>` |
| Runtime validation stages | `apkcheck lab validate <signed-id>` |
| Artifact lineage | `apkcheck lab list` |
| Compare variants | `apkcheck lab compare <left> <right>` |
| HTTP API + SSE events | `apkcheck lab serve` / `lab ui` → `:8787` |
| React workstation | `apkcheck lab ui` (Devices, **Runs**, Security, ⌘K, …) |
| Device recording + timeline | Validate with **Record device** → Runs tab (§35) |
| Emulator instance management | `lab runtime list\|start\|stop\|restart` |
| Authorized security library | `lab security …` + UI Security tab |
| mitmproxy (optional) | `/api/proxy/*` — **off by default** |
| Certificate status | `/api/certs` — **never private keys** |
| MCP for AI agents | `apkcheck mcp` — help / status / workflow recipes |
| Static IOC scanner | `lab security ioc-scan` / API / UI — 14 pattern categories |
| Frida dynamic hooks | SSL unpin, method trace, DEX loader, network trace |

**Rebuild success ≠ runtime success.** Validation reports per-stage pass/fail (install, launch, crash_detection, smoke, …).

---

## Docker

Run Lab in Docker (Linux/amd64 with KVM for emulators):

```bash
docker compose up -d lab
# → http://localhost:8787
```

Details: [`docs/DOCKER.md`](docs/DOCKER.md).

## Quick start

**New users:** read [`docs/GUIDE.md`](docs/GUIDE.md) for a plain-language description and the five main workflows.

```bash
cd apkcheck
./scripts/setup                 # tools + CLI + UI build (or go build + npm run build)
./bin/apkcheck doctor
./bin/apkcheck lab ui           # API + React dashboard (opens browser)
# without browser:  ./bin/apkcheck lab ui --no-open
# Vite hot reload:  ./bin/apkcheck lab ui --dev --no-open

# Static first-pass hunt
./bin/apkcheck hunt app.apk --output ./hunt-out
```

### Lab rebuild ↔ validate

```bash
./bin/apkcheck lab import ./app.apk --workspace ./lab-data --label original
./bin/apkcheck lab runtime start --avd Pixel_8_API_34
./bin/apkcheck lab rebuild <apk-id>
./bin/apkcheck lab validate <signed-id> --emulator Pixel_8_API_34 --duration 20s --record

./bin/apkcheck lab compare <apk-id> <signed-id>
```

Workspace layout:

```text
lab-data/
  apks/  projects/  builds/  certs/  runs/  logs/
  scenarios/  proxy/  exports/  harness/
```

---

## Install

APKCheck runs on **macOS**, **Linux**, and **Windows**. All three platforms require the same set of dependencies; only the package manager commands differ.

### Prerequisites

| Dependency | Purpose | Min version |
|------------|---------|-------------|
| Go | build the binary | 1.22 |
| Node.js + npm | build the React UI | 18 |
| JDK | apktool / sdkmanager / avdmanager | 17 |
| Android SDK | build-tools (apksigner, zipalign, aapt) | build-tools 34 |
| `adb` (platform-tools) | device/emulator control | any recent |
| jadx | Java decompiler | 1.4+ |
| apktool | Smali decompile/rebuild | 2.9+ |
| FernFlower | Java decompiler | bundled with jadx or standalone |
| mitmproxy _(optional)_ | HTTPS traffic capture | 10+ |
| ffmpeg _(optional)_ | video segment merge | any recent |

### macOS

```bash
brew install openjdk@17 jadx apktool fernflower android-platform-tools mitmproxy ffmpeg

# Android SDK (build-tools 34 required for apksigner/zipalign/aapt)
brew install --cask android-commandlinetools
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_SDK_ROOT="$ANDROID_HOME"
sdkmanager "build-tools;34.0.0" "platforms;android-34"
```

### Linux (Debian / Ubuntu)

```bash
sudo apt install openjdk-17-jdk adb ffmpeg

# jadx — download release jar from github.com/skylot/jadx/releases
# apktool — download jar from apktool.org, place on PATH as 'apktool'
# mitmproxy — pip install mitmproxy  OR  download from mitmproxy.org

# Android SDK (build-tools)
# Download sdk-tools from developer.android.com/tools, then:
export ANDROID_HOME=$HOME/Android/Sdk
export ANDROID_SDK_ROOT="$ANDROID_HOME"
sdkmanager "build-tools;34.0.0" "platforms;android-34"
```

### Windows

```powershell
# Install Android Studio (includes SDK, adb, emulator)
# https://developer.android.com/studio

# Install remaining tools (winget or Chocolatey):
winget install --id EclipseAdoptium.Temurin.17.JDK
winget install --id Gyan.FFmpeg

# jadx — download release zip from github.com/skylot/jadx/releases
# apktool — download jar from apktool.org, create apktool.bat wrapper on PATH
# mitmproxy — winget install mitmproxy  OR  download from mitmproxy.org

# Set SDK env vars (Android Studio sets these; verify they exist):
# ANDROID_HOME  = C:\Users\<you>\AppData\Local\Android\Sdk
# ANDROID_SDK_ROOT = same
```

### Build

After installing all prerequisites:

```bash
# macOS / Linux
./scripts/setup
# equivalent to:
go build -o bin/apkcheck ./cmd/apkcheck
cd web && npm install && npm run build && cd ..

# Windows (PowerShell)
go build -o bin\apkcheck.exe .\cmd\apkcheck
cd web; npm install; npm run build; cd ..
```

Verify:

```bash
./bin/apkcheck doctor   # (bin\apkcheck.exe doctor on Windows)
```

Optional — create a default AVD (requires Android SDK emulator package):

```bash
./bin/apkcheck emulator-create --name Pixel_8_API_34
# sdkmanager "system-images;android-34;google_apis;x86_64"  # if not yet downloaded
```

> **Emulator on Linux**: KVM is required for hardware acceleration.  
> Enable it with: `sudo apt install qemu-kvm && sudo usermod -aG kvm $USER`  
> **Emulator on Windows**: Hyper-V or HAXM must be enabled.  
> **Remote emulator**: set `APKCHECK_ADB_HOST=<host>` to route `adb` and screencap to a remote Linux ADB server.

---

## Static analysis & hunt

### One-command first pass

```bash
apkcheck hunt app.apk --output ./hunt-out
apkcheck hunt app.xapk --output ./hunt-out
apkcheck hunt ./splits/ --output ./hunt-out
apkcheck hunt app.apk --runtime --emulator auto
apkcheck hunt app.apk --frida --package com.example
# → REPORT.md + report.html + report.json + ai-digest.json
```

### Focused commands

| Command | Purpose |
|---------|---------|
| `apkcheck analyze <input>` | Cross-validation + findings + evidence graph |
| `apkcheck methods\|method\|diff\|report` | Focused method / decompiler views |
| `apkcheck analyze … --format ai` | Compact digest for agents |
| `apkcheck ci <input> --config configs/ci.yaml` | Gates: only `STATIC_EVIDENCE` can fail CI |

**Formats:** APK, split dirs, XAPK, APKS, APKM, AAB (base/dex).

---

## APK Lab

Workbench for **authorized** rebuild and runtime validation while Smali remains ground truth.

### Core loop

```text
Original APK
  → apktool d (project)
  → edit Smali/resources (optional)
  → apktool b (unsigned)
  → zipalign + apksigner (signed)
  → install / launch / smoke validate
  → compare vs original
```

### CLI

```bash
apkcheck lab import <apk> [--workspace DIR] [--label NAME]
apkcheck lab list
apkcheck lab decompile <apk-id>
apkcheck lab build <project-id>
apkcheck lab sign <unsigned-id>
apkcheck lab rebuild <apk-id>              # decompile+build+sign
apkcheck lab validate <signed-id> [--emulator AVD|--device-id ID] [--record] [--profile balanced]
apkcheck lab compare <left-id> <right-id>
apkcheck lab ui | serve
apkcheck lab runtime …
apkcheck lab security …
```

### UI tabs

`apkcheck lab ui` → http://127.0.0.1:8787

| Tab | Role |
|-----|------|
| Workspace | Import, rebuild, validate (+ **Record device**) |
| Artifacts | Lineage table |
| **Devices** | Emulator/device counts; start/stop/restart/stop-all |
| **Runs** | Test-run recordings + synchronized event timeline (§35) |
| Security | Templates, presets, harness |
| Manifest | Review notes (not auto-vulns) |
| Findings | Observations + export |
| Compare | Variant metrics |
| Scenarios | Step builder + run |
| Proxy / Certificates | mitm + keystore fingerprints |
| Events | Live SSE bus |
| ⌘K | Command palette (CLI↔UI map) |

### Device recording (§35)

Every validate/security/scenario can bind a **test run** (`run_id`) with optional device screen recording:

```text
Test Run
 ├── APK / runtime / scenario
 ├── Recording (segmented adb screenrecord)
 ├── Timeline events (MCP, network, asserts, bookmarks)
 └── Result + failure seek
```

UI: Workspace → enable **Record device** → Validate → **Runs** tab → watch video + click events to seek.  
MCP: `apkcheck_lab_validate { "record": true }` then `apkcheck_lab_sessions_get`.  
CLI: `apkcheck lab validate <id> --record --profile balanced`.  
API: `POST /api/validate` with `"record": true`, `GET /api/sessions`, `GET /api/recordings/<id>/media`.

Profiles: `low` | `balanced` | `high`. Retention: `GET/POST /api/recordings/retention`.  
Validate auto-uninstalls on signing mismatch (`UPDATE_INCOMPATIBLE`) when reinstalling Lab-signed APKs over Play-signed installs.

### HTTP API (selected)

| Method | Path | Role |
|--------|------|------|
| GET | `/api/health` | Liveness |
| GET/POST | `/api/artifacts`, `/api/import`, `/api/rebuild`, `/api/validate` | Pipeline |
| GET/POST | `/api/runtimes*` | Device/emulator instances |
| GET/POST | `/api/sessions*`, `/api/recordings*` | Test runs + device recordings |
| GET/POST | `/api/security/*` | Catalog, run, observations, export |
| GET | `/api/events/stream` | SSE |
| GET/POST | `/api/proxy/*`, `/api/certs` | MITM / certs |

Unknown `/api/*` routes return **JSON** 404 (never plain-text `404 page not found`).

---

## Devices / runtime instances

Manage how many Android emulators are running — same controls in CLI, UI, API, and MCP.

```bash
apkcheck lab runtime list
apkcheck lab runtime start --avd Pixel_8_API_34
apkcheck lab runtime stop --avd Pixel_8_API_34
apkcheck lab runtime stop --serial emulator-5554
apkcheck lab runtime stop --all
apkcheck lab runtime restart --avd Pixel_8_API_34
apkcheck lab runtime list --json
```

| Surface | Entry |
|---------|--------|
| UI | **Devices** tab + header pill `emu running/configured` |
| API | `GET /api/runtimes`, `POST …/start\|stop\|stop-all\|restart` |
| MCP | `apkcheck_lab_runtime_*` or workflow `ensure_runtime` |

Classic runtime session (install + observe one APK):

```bash
apkcheck runtime app.apk --emulator auto
apkcheck runtime app.apk --device
```

---

## Security testing (authorized)

Templates produce **observations** with evidence — severity `informational` | `potential` | `needs_review`.  
The tester decides disclosure. **Never** treat Lab output as an automatic confirmed vulnerability.

```bash
apkcheck lab security catalog
apkcheck lab security run exported-components --artifact <id>
apkcheck lab security run background-behavior --artifact <id>
apkcheck lab security preset quick-android-security --artifact <id>
apkcheck lab security manifest --artifact <id>
apkcheck lab security observations
apkcheck lab security export <obs-id> --format markdown|zip
apkcheck lab security harness seed|build|status   # build force-refreshes scaffold (rev 2)
```

Test harness package: `com.apkcheck.testharness` (`testdata/lab/harness`).  
Requires apktool framework (`platforms;android-34`). Host `adb am` remains a valid IPC probe fallback.  
Use only on apps/devices/emulators you are authorized to test.

---

## AI / MCP

Stdio MCP so **Cursor, Claude Desktop, Claude Code, and other MCP clients** call apkcheck **without scraping CLI text**.

**One server, many clients.** There is no separate Claude implementation — the same `bin/apkcheck mcp` process exposes `apkcheck_lab_*` tools. You only add a client config where you use that app.

```bash
apkcheck mcp
apkcheck analyze app.apk --format ai --limit 500
```

### Connect a client

| Client | Config |
|--------|--------|
| **Cursor** | Merge [`configs/mcp.cursor.json`](configs/mcp.cursor.json) into Cursor MCP settings |
| **Claude Desktop** | Merge [`configs/mcp.claude.json`](configs/mcp.claude.json) into Claude Desktop MCP config (same `command` / `args`) |
| **Claude Code / other** | Point MCP at `…/bin/apkcheck` with args `["mcp"]` |

After rebuilding `bin/apkcheck`, **restart the MCP server** in that client so it loads the new binary. Adjust `ANDROID_HOME` / paths if your SDK differs.

```text
Cursor / Claude Agent
        │  MCP (stdio)
        ▼
  bin/apkcheck mcp     ← Lab tools (validate, record, security, …)
        │
        ▼
  same engine as CLI + React UI
```

### Agent playbook (start here)

1. `apkcheck_lab_help` — recipes, aliases, rules, **recording** section  
2. `apkcheck_lab_status` — workspace + runtimes + sessions/recordings counts  
3. `apkcheck_lab_workflow` — one-shot power tools  

| Workflow `action` | What it does |
|-------------------|--------------|
| `status` / `help` | Dashboard / playbook |
| `ensure_runtime` | Start default AVD if none running |
| `import_rebuild` | Import APK → full rebuild |
| `import_rebuild_validate` | Import → rebuild → validate (**records by default**) |
| `security_quick` | Manifest + preset (pass `record: true` for video) |

**Aliases (fewer agent mistakes):** `id`↔`artifact_id`, `path`↔`apk`, `serial`↔`device_id`, `template`↔`template_id`, `preset`↔`preset_id`, `run_id`↔`session_id`.

Useful responses include a `next` array. Long jobs (rebuild, validate, emulator boot) are **detached** from short-lived MCP request cancellation.

### Lab MCP tool groups

| Group | Tools |
|-------|--------|
| Orientation | `apkcheck_lab_help`, `status`, `workflow`, `ui` |
| Pipeline | `import`, `list`, `decompile`, `build`, `sign`, `rebuild`, `validate`, `compare` |
| Runtime | `runtime_list`, `runtime_start`, `runtime_stop`, `runtime_restart` |
| Sessions / recording | `sessions_*` (list/get/event/bookmark/screenshot), `recordings_*` (list/get/retention); pass `record=true` on validate/security/scenarios; `import_rebuild_validate` records by default |
| Security | `security_catalog`, `run`, `preset`, `manifest`, `observations`, `export`, `harness` |
| Other | `scenarios_*`, `proxy_*`, `certs`, `events` |

Analysis tools remain available: `apkcheck_doctor`, `apkcheck_analyze_ai`, `apkcheck_hunt`, `apkcheck_findings`, `apkcheck_principles`, …

Full reference: [`docs/mcp.md`](docs/mcp.md).

---

## Certificates & mitmproxy

```bash
brew install mitmproxy    # mitmdump
apkcheck lab ui
# UI → Proxy → Start   or   POST /api/proxy/start
```

- MITM is **off by default**. Enable only for APKs you are authorized to analyze.
- `/api/certs` and `apkcheck_lab_certs` expose paths + fingerprints — **never private keys**.
- Android 7+ often blocks system CA install; prefer user CA / test images and expect clear limitation notes.
- Proxy status uses a **pid file** under `lab-data/proxy/` so CLI, UI, and MCP agree on running state.

---

## Evidence model

| Class | Meaning |
|-------|---------|
| `STATIC_EVIDENCE` / `FACT` | From APK / DEX / Smali / manifest |
| `RUNTIME_OBSERVATION` | Seen on an exercised path |
| `INFERENCE` | Heuristic — **never** a confirmed vuln |
| `UNCERTAINTY` | Insufficient evidence |
| **NOT OBSERVED ≠ ABSENT** | Hard rule for runtime |

Reports: **REPORT.md**, interactive **HTML**, **JSON** (schema `2.0.0`), **AI digest**.

---

## Architecture

```text
APK / XAPK / AAB / splits
        │
        ├─► Static: Smali IR, CFG, findings, native/JNI
        ├─► Decompilers: JADX / CFR / FernFlower (reconstructions)
        ├─► Runtime: ADB device / emulator / optional Frida
        └─► Lab: import → rebuild → validate → security observations
                    │
                    ├─ CLI
                    ├─ HTTP + SSE + React UI
                    └─ MCP (agents)
```

Go packages (Lab): `internal/lab/{pipeline,api,events,proxy,certs,scenarios,compare,runtimes,security,iocscan,frida}`.  
MCP: `internal/mcp`. UI: `web/` (Vite + React).

No Rust in v0.6 — Go + existing ADB/runtime stack.

---

## Design principles

1. DEX/Smali answers what the program **contains**.
2. Decompilers answer how tools **reconstruct** that content.
3. Runtime answers what was **observed** on one path.
4. Never equate runtime coverage with complete behavior.
5. Never output simplistic “% correctness” scores.
6. Never present `INFERENCE` as a confirmed vulnerability.
7. Lab **observations** are review candidates — not auto-vulns.
8. A rebuilt APK is only “working” after validation stages pass.
9. CLI ↔ API ↔ UI ↔ MCP stay in parity; agents should call Lab tools, not reimplement them.

---

## Testing

```bash
go test ./internal/lab/...
go test ./internal/mcp/...
go test ./...
go test -race ./internal/lab/runtimes/... ./internal/lab/pipeline/... ./internal/mcp/...
```

---

## Docs map

| Doc | Contents |
|-----|----------|
| [`docs/GUIDE.md`](docs/GUIDE.md) | **What it is & how to use** (start here) |
| [`docs/mcp.md`](docs/mcp.md) | Full MCP tool table + agent playbook |
| [`docs/DOCKER.md`](docs/DOCKER.md) | Docker / remote Lab host setup |
| [`docs/ASK.md`](docs/ASK.md) | Product / Lab specification |
| [`docs/architecture.md`](docs/architecture.md) | Package layout |
| [`configs/mcp.cursor.json`](configs/mcp.cursor.json) | Cursor MCP sample |
| [`configs/mcp.claude.json`](configs/mcp.claude.json) | Claude Desktop MCP sample (same server) |

---

## License

MIT — see [LICENSE](LICENSE).
