# Roadmap

## Phase 1 — MVP (implemented)

- [x] APK inspection
- [x] JADX integration
- [x] Apktool / Smali ground truth
- [x] Method IR extraction
- [x] Basic CFG + call comparison
- [x] Terminal / JSON / HTML reports
- [x] `doctor`, `analyze`, `methods`, `method`, `diff`, `report`

## Phase 2 — Multi-decompiler semantics (partially implemented)

- [x] CFR / FernFlower adapters (optional, soft-fail)
- [x] JSON schema versioning
- [ ] Stronger Java AST (tree-sitter or JavaParser bridge)
- [ ] Boolean expression normalization
- [ ] Richer exception-edge CFG comparison

## Phase 3 — Security focus & scale

- [x] `--focus security` tagging
- [ ] Interprocedural call-graph slicing from entrypoints
- [x] HTML interactive method browser (basic)
- [x] SHA-256 cache scaffolding
- [ ] Incremental re-analysis of changed methods only

## Phase 4 — Runtime evidence (implemented scaffold)

- [x] `apkcheck devices` / `emulators` / `runtime`
- [x] `analyze --runtime` pipeline hook
- [x] Emulator lifecycle + physical device mode
- [x] Install / launch / logcat / crashes / permissions / timeline
- [x] Optional screenshots + connection hints (no MITM by default)
- [x] Stack-frame → static method correlation
- [x] Evidence classes (`STATIC_*` / `RUNTIME_*` / `NOT_OBSERVED` / …)
- [x] HTML report runtime sections
- [x] `emulator-create` with Google CDN fallback when sdkmanager 404s
- [x] `--format ai` agent digest (`apkcheck.ai.v1`)
- [x] MCP stdio server (`apkcheck mcp`) for Cursor / agents
- [ ] Rich UI automation scenarios (a11y IDs, swipe, screenshots-per-step)
- [ ] Optional Frida provider (off by default)
- [ ] APK before/after runtime compare

## Phase 6 — APK Lab (v0.6 — implemented core)

- [x] `apkcheck lab import|decompile|build|sign|rebuild|validate|compare|serve`
- [x] Artifact lineage store under `./lab-data`
- [x] Validation stages: build/sign/install/launch/startup/crash/smoke/network
- [x] React dashboard (`web/`) + SSE live events
- [x] mitmproxy manager + cert status API
- [x] Scenario persistence engine (extends runtime scenarios)
- [x] Unit/integration tests for store/pipeline/compare/scenarios/certs
- [x] Security scenario catalog + presets + observations/evidence export
- [x] Manifest security panel (review notes, not auto-vulns)
- [x] Authorized test harness scaffold + CLI/UI
- [x] Command palette ⌘K (CLI↔UI command map)
- [x] 3-mode shell: Prepare / Run / Investigate with Tools drawer (replaces 12 flat tabs)
- [x] Portrait phone-frame video (9:16) in Runs studio
- [x] Meaningful run card titles (scenario + result instead of raw IDs)
- [x] Bug fixes: health error when API ok=false, seekingRef stuck on video error,
       compare panel leaked across run switches, missing `.stage.warn` CSS,
       double setMediaReady call, timelineDur not reset on run switch
- [ ] True parallel dual-runtime sessions (original + rebuilt simultaneously)
- [ ] Rich network timeline UI with request/response bodies from mitm flows
- [ ] Automated system CA install on rooted/test images
- [ ] Full E2E Playwright coverage of Lab UI
- [ ] Drag-drop scenario builder polish + richer assertions
- [ ] Zoomable time-range scrubber with breadcrumbs (focus 0:12–0:45)
- [ ] Stacked/reorderable tracks: Scenario · Auth · App · Kernel · Network
- [ ] Auto-bookmarks on AUTH_PROMPT, failure, and permission dialogs
- [ ] One-click export pack: video + timeline JSON + MD report

## Non-goals

- Claiming a decompiler is “N% correct”
- Automatic vulnerability confirmation
- Treating runtime as complete ground truth
- Silent MITM / credential injection / production account use
- Executing APK or native code
