# Architecture

## Principle

```text
Do not ask: "Which decompiler is correct?"
Ask: "Which parts of each reconstruction are supported by DEX bytecode?"
```

Smali produced by Apktool (from DEX) is the **source of truth**. Decompiler outputs are compared against that evidence.

## Package layout

```text
cmd/apkcheck          CLI entrypoint
internal/
  apk/                APK zip inspection, safe extract, manifest enrichment
  dex/                DEX header metadata (bytecode decode deferred)
  smali/              Smali → MethodIR + side effects
  decompiler/         Decompiler interface
    jadx/             JADX CLI
    cfr/              CFR (optional)
    fernflower/       FernFlower (optional)
    apktool/          Apktool decode + Smali roots
  parser/javaast/     Java source → MethodIR (heuristic AST)
  ir/                 Normalized IR types
  cfg/                CFG construction + structural compare
  diff/               Semantic comparison + confidence
  security/           Security-relevant prioritization (non-vuln claims)
  analyze/            Pipeline orchestration
  report/{text,json,html}
  cache/              SHA-256 keyed artifact cache
  runner/             Safe subprocess execution
  doctor/             Tool availability
  runtime/            Android device/emulator dynamic analysis
    adb/ emulator/ device/ installer/ launcher/
    logcat/ process/ permissions/ network/ screenshots/
    scenarios/ timeline/ correlation/ instrumentation/ config/
  lab/                APK Laboratory workbench (v0.6)
    pipeline/         decode → build → sign → validate
    api/              HTTP + SSE events + static UI
    events/           in-process event bus
    proxy/            mitmdump manager
    certs/            keystore/CA status (no private key export)
    scenarios/        lab scenario persistence + run
    compare/          original vs rebuilt metrics
    iocscan/          static IOC scanner (regex patterns over decompiled sources)
    frida/            Frida dynamic instrumentation (SSL unpin, method trace, DEX loader)
  evidence/           Static + runtime evidence merge (epistemic labels)
  cli/                Flag parsing / commands
pkg/model             Versioned report schema
web/                  React Lab dashboard (Vite)
```

## Runtime boundary (macOS)

```text
apkcheck CLI (host)
    ├── Docker (optional) → JADX / CFR / FernFlower / Apktool
    └── ADB → physical device OR macOS Android Emulator
              └── Untrusted APK (never as privileged host process)
```

Runtime evidence is **observed under tested conditions only**.
`NOT OBSERVED` never means “does not exist”.
DEX/Smali remains the primary static reference.

## Pipeline

1. **Inspect APK** — zip structure, DEX list, native libs, hash
2. **Doctor** — tool versions / availability
3. **Apktool** — Smali + AndroidManifest
4. **Parse Smali** — MethodIR, CFG, calls, fields, exceptions
5. **Decompile** — JADX (required path), CFR/FernFlower optional
6. **Parse Java** — MethodIR approximations
7. **Match methods** — class+name (+ arity) fuzzy match
8. **Diff** — CFG / calls / exceptions / returns
9. **Classify** — CONSISTENT / PARTIAL / DISAGREEMENT / UNRESOLVED
10. **Report** — text, JSON schema 1.0.0, HTML

## Confidence semantics

| Label | Meaning |
|-------|---------|
| `CONSISTENT` | Reconstruction structurally compatible with bytecode evidence |
| `PARTIALLY_CONSISTENT` | Core match with residual differences or missing evidence |
| `DISAGREEMENT` | Material CFG/call/exception divergence from bytecode |
| `UNRESOLVED` | Decompiler missing method / insufficient evidence |
| `SOURCE_OF_TRUTH` | Reserved for Smali/DEX side |

Failures are labeled as tool/parse failures — **never** as “decompiler wrong.”

## Extending decompilers

Implement:

```go
type Decompiler interface {
    Name() string
    Version(ctx context.Context) (string, error)
    Available(ctx context.Context) bool
    Decompile(ctx context.Context, input Input) (*Result, error)
}
```

Register via `analyze.Config.Decompilers` / CLI `--decompiler`.

## IOC Scanner (`internal/lab/iocscan`)

Static indicator-of-compromise scan across decompiled Android source trees (Java, Smali, XML):

| Pattern ID | Category | What it detects |
|---|---|---|
| `hardcoded_secret` | credentials | `api_key=`, `password=`, `auth_token=` literals |
| `public_ipv4` | network | Non-RFC-1918 IP addresses |
| `hardcoded_url` | network | HTTP/HTTPS URLs hardcoded in source |
| `base64_payload` | obfuscation | Long base64 strings (≥48 chars) |
| `dynamic_dex_load` | dynamic_code | `DexClassLoader`, `InMemoryDexClassLoader` |
| `reflection_invoke` | dynamic_code | `java.lang.reflect`, `getDeclaredMethod` |
| `ssl_bypass` | tls | `X509TrustManager`, `ALLOW_ALL_HOSTNAME_VERIFIER` |
| `c2_keyword` | backdoor | `command-control`, `exfiltrat`, `keylog`, `backdoor` |
| `crypto_hardcoded_key` | cryptography | AES/RSA key literals |
| `telephony_leak` | privacy | `getImei`, `getSubscriberId`, `getCellLocation` |

All results are de-duplicated by (file, line, pattern, match) SHA-256. The scan root is the JADX project artifact if one exists for the artifact, else the artifact directory.

## Frida (`internal/lab/frida`)

Runtime dynamic instrumentation via the Frida framework:

```
host: frida CLI (pip install frida-tools)
    └── frida-server on device (/data/local/tmp/frida-server)
        └── JS hook injected into target app process
```

Built-in hooks (embedded Go string constants, no separate JS files):

| Hook | Purpose |
|---|---|
| `ssl_unpin` | Patches TrustManager, OkHttp3, Conscrypt, HostnameVerifier to accept all certs |
| `method_trace` | Hooks all methods matching a name pattern; logs args + return values |
| `dex_loader` | Intercepts DexClassLoader, InMemoryDexClassLoader, PathClassLoader |
| `network_trace` | Intercepts Socket, URL.openConnection, OkHttp3 RealCall |

**Authorization boundary**: frida-server requires root or debuggable APK on the device. All operations target devices and apps under explicit authorization. Hooks emit events to the Lab event bus and return structured `TraceEvent` arrays.

## Concurrency

- Optional decompilers run in a small errgroup
- Method comparison uses a worker pool (`--workers`)
- External tools always use `CommandContext`
