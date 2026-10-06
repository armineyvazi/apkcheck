# APKCheck MCP (AI agents)

Stdio Model Context Protocol server so **Cursor, Claude Desktop, Claude Code, and other MCP clients** can call apkcheck **without shell scraping**.

Lab tools share the **same engine** as CLI + React UI. Prefer MCP over reinventing rebuild/emulator logic.

**One binary, many clients.** No separate Claude implementation — configure each app to run `bin/apkcheck mcp`.

## Start

```bash
./bin/apkcheck mcp
```

### Client setup

| Client | Sample config |
|--------|----------------|
| Cursor | [`configs/mcp.cursor.json`](../configs/mcp.cursor.json) |
| Claude Desktop | [`configs/mcp.claude.json`](../configs/mcp.claude.json) |

Both use the same `command` + `args: ["mcp"]`. Adjust absolute paths / `ANDROID_HOME` for your machine. After `go build -o bin/apkcheck`, **restart** the MCP server in that client.

```text
Cursor / Claude
      │ MCP stdio
      ▼
bin/apkcheck mcp  →  apkcheck_lab_* tools  →  lab-data / devices / recordings
```

## Agent playbook (start here)

1. `apkcheck_lab_help` — recipes, aliases, rules, **recording** section  
2. `apkcheck_lab_status` — workspace + runtimes + sessions/recordings  
3. `apkcheck_lab_workflow` — one-shot power tools  

| Workflow `action` | What it does |
|-------------------|--------------|
| `status` / `help` | Dashboard / playbook |
| `ensure_runtime` | Start Pixel_8_API_34 if no emulator running |
| `workspace_reset` / `fresh_start` | Wipe sessions/recordings/logs/runs/proxy flows (keeps APKs) |
| `fresh_scenario_rerun` | **Reset → ensure runtime → harness → run scenario with record** |
| `import_rebuild` | Import APK → full rebuild |
| `import_rebuild_validate` | Import → rebuild → validate (**records by default**) |
| `security_quick` | Manifest + preset (optional `record: true`) |

### Example: full security rerun

```json
{
  "tool": "apkcheck_lab_workflow",
  "arguments": {
    "action": "fresh_scenario_rerun",
    "workspace": "/data/lab",
    "scenario_id": "your-scenario-id",
    "package": "com.example.app",
    "record": true,
    "profile": "high"
  }
}
```

Video file is named after the scenario (e.g. `your-scenario-id-sc-12.mp4`).  
After the run: UI **Runs** → filter **Mitmproxy** / **App** + **From/To** timeframe → **Import mitm** if proxy was on.

**Aliases (bug-resistant):** `id`↔`artifact_id`, `path`↔`apk`, `serial`↔`device_id`, `template`↔`template_id`, `preset`↔`preset_id`, `run_id`↔`session_id`, `emulator`↔`avd`.

CLI also supports: `lab validate --record`, `lab security run|preset --emulator AVD`, `lab runtime start --workspace` (accepted/ignored), `lab security harness build` (force-reseeds scaffold).

Responses include a `next` array when useful.

## Analysis tools

| Tool | Purpose |
|------|---------|
| `apkcheck_doctor` | Tool readiness |
| `apkcheck_analyze_ai` | Static → `apkcheck.ai.v1` digest |
| `apkcheck_hunt` | First-pass hunt summary |
| `apkcheck_findings` / `disagreements` / `evidence` / `query_methods` | Report queries |
| `apkcheck_digest_file` | `report.json` → digest |
| `apkcheck_devices` / `emulators` / `emulator_create` / `runtime` | Runtime env |
| `apkcheck_principles` | Evidence rules |

## Lab tools

### Orientation

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_help` | Playbook |
| `apkcheck_lab_status` | Dashboard |
| `apkcheck_lab_workflow` | One-shot recipes |
| `apkcheck_lab_ui` | Open React UI |

### Pipeline

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_import` | Import APK |
| `apkcheck_lab_list` | List artifacts |
| `apkcheck_lab_decompile` / `build` / `sign` / `rebuild` | Steps / full rebuild |
| `apkcheck_lab_validate` | Install/launch/smoke (`record=true` for device video) |
| `apkcheck_lab_compare` | Compare artifacts |

### Sessions / recording (§35)

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_validate` / `security_*` / `scenarios_run` | Pass `record=true` (+ optional `profile`) |
| `apkcheck_lab_workflow` `import_rebuild_validate` | **Records by default** (`record=false` to opt out) |
| `apkcheck_lab_sessions_list` | List test runs |
| `apkcheck_lab_sessions_get` | Run + timeline + recording metadata |
| `apkcheck_lab_sessions_event` | Append MCP/AI timeline event |
| `apkcheck_lab_sessions_bookmark` | Bookmark (protected from cleanup) |
| `apkcheck_lab_sessions_screenshot` | Screenshot linked to run timeline |
| `apkcheck_lab_recordings_list` / `get` | List / metadata + `media_url` |
| `apkcheck_lab_recordings_retention` | Retention policy + optional cleanup |

Video **playback** is in the UI **Runs** tab (`apkcheck lab ui`). MCP returns `lab_run_id` / `recording_id` / timeline JSON.

### Runtime (= UI Devices)

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_runtime_list` | Counts + instances |
| `apkcheck_lab_runtime_start` / `stop` / `restart` | Manage AVDs |

### Security (authorized)

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_security_catalog` | Templates + presets |
| `apkcheck_lab_security_run` / `preset` | Execute (`record=true`; `emulator`/`avd` resolves serial) |
| `apkcheck_lab_security_manifest` | Manifest notes via aapt xmltree (exports/deeplinks) |
| `apkcheck_lab_security_observations` / `export` | Evidence |
| `apkcheck_lab_security_harness` | Test harness (`build` force-refreshes scaffold) |

### Static IOC scanner (no device needed)

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_ioc_scan` | Grep decompiled sources for hardcoded secrets, public IPs, base64 blobs, DexClassLoader, SSL bypass, C2 keywords, telephony leaks. Pass `artifact_id` of the original APK or any artifact — the scanner finds the companion project directory automatically. |

Results include `findings[]` (file, line, pattern_id, category, severity, match, context) and `summary` (category→count). All findings are **observations** for manual review.

### Dynamic instrumentation — Frida (device required)

Requires `pip install frida-tools` on the host and `frida-server` running on the device (root or debuggable APK). **Frida CLI version must match frida-server version.**

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_frida_status` | Check host frida CLI + device frida-server presence/running. Returns `device_arch` so you know which server binary to download. |
| `apkcheck_lab_frida_push` | Push a local frida-server binary to `/data/local/tmp/frida-server` on the device. Pass `host_path` (the extracted binary) + `serial`. |
| `apkcheck_lab_frida_ssl_unpin` | Bypass TrustManager, OkHttp3, Conscrypt, HostnameVerifier at runtime. Combine with `apkcheck_lab_proxy_start` to capture decrypted traffic. Pass `package` + optional `serial`, `timeout_sec`. |
| `apkcheck_lab_frida_method_trace` | Hook all methods whose name contains `pattern`. Returns `{type, payload}` events per call. Pass `package`, `pattern`, optional `serial`, `timeout_sec`. |
| `apkcheck_lab_frida_dex_loader` | Detect DexClassLoader / InMemoryDexClassLoader / PathClassLoader at runtime — signals packed/obfuscated code loading. |
| `apkcheck_lab_frida_network_trace` | Intercept Socket, URL.openConnection, OkHttp3 RealCall — surfaces endpoints not visible in static analysis. |

**Setup sequence (once):**
```
1. apkcheck_lab_frida_status { serial }           → get device_arch
2. download frida-server-X.Y.Z-android-<arch>.xz  → extract
3. apkcheck_lab_frida_push { serial, host_path }   → push binary
4. (start frida-server on device)                  → root/debuggable required
5. apkcheck_lab_frida_ssl_unpin / method_trace / … → run hooks
```

### Other

| Tool | Purpose |
|------|---------|
| `apkcheck_lab_scenarios_list` / `run` | Custom scenarios |
| `apkcheck_lab_proxy_*` / `certs` | MITM (off by default) |
| `apkcheck_lab_events` | Recent events |

## Rules (always)

1. DEX/Smali is the source of truth  
2. Decompiler agreement ≠ correctness  
3. Runtime `NOT OBSERVED` ≠ absent  
4. Never present `INFERENCE` as a confirmed vulnerability  
5. Lab **observations** are review candidates — not auto-vulns  
6. MITM only for authorized targets  
7. Prefer `apkcheck_lab_workflow` over multi-step reinvention  

## CLI without MCP

```bash
apkcheck analyze app.apk --format ai --limit 500
apkcheck lab ui
apkcheck lab runtime list
```
