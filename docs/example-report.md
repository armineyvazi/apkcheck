# Example report (illustrative)

```text
APKCheck v0.1.0

APK: ./testdata/sample.apk
SHA-256: 0123abcd…
Package: com.example.app
Version: 1.0 (1)
minSdk=24 targetSdk=34 DEX=1 native_libs=0

Methods analyzed: 42
  Consistent:             35
  Partially consistent:   5
  Disagreement:           2
  Unresolved:             0
  Security-relevant:      6

Most important findings:

⚠ com.example.Auth.authenticate(java.lang.String)
  Status: PARTIALLY_CONSISTENT
  Core behavior appears compatible, but some aspects differ or lack evidence.
  - [medium/exception_flow_difference] bytecode has exception handlers; reconstruction shows none

⚠ com.example.WebViewActivity.loadUrl(java.lang.String)
  Status: DISAGREEMENT
  One or more reconstructions differ from bytecode in control flow, calls, or exception handling.

Notes:
  • Never treat a single decompiler as authoritative.
  • Insufficient evidence is reported explicitly rather than guessed.
```

JSON excerpt:

```json
{
  "schema_version": "1.0.0",
  "apk": { "package": "com.example.app", "dex_count": 1 },
  "methods": [
    {
      "ref": { "class": "com.example.Auth", "method": "authenticate" },
      "status": "PARTIALLY_CONSISTENT",
      "decompilers": {
        "jadx": { "status": "CONSISTENT" },
        "cfr": { "status": "PARTIALLY_CONSISTENT" }
      },
      "issues": [
        {
          "type": "exception_flow_difference",
          "severity": "medium"
        }
      ]
    }
  ]
}
```
