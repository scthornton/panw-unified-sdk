# Architecture

## Design Philosophy

This SDK solves a specific problem: customers building AI applications that process both text and files need two completely separate Palo Alto Networks APIs with different auth patterns, protocols, and response formats. The SDK unifies them behind one interface.

### Core Principles

1. **Wrap, don't replace** — Uses the official `pan-aisecurity` SDK for AIRS; builds a raw HTTP client for WildFire (no official SDK exists).
2. **Smart routing** — Content type determines the target API automatically.
3. **Unified verdicts** — Both APIs normalize into the same `ScanVerdict` dataclass.
4. **Graceful degradation** — Works with one API key. Helpful errors for missing capabilities.
5. **Async-first** — Internal async with sync wrappers for convenience.

## API Comparison

| Dimension | AIRS Runtime API | WildFire API |
|---|---|---|
| Content Type | Text (prompts, responses) | Files (PE, PDF, APK, Office, etc.) |
| Protocol | JSON REST | XML multipart/form-data |
| Auth | API key via `x-pan-token` header | API key as form parameter |
| Scan Pattern | Synchronous (100-500ms) | Submit-then-poll (seconds to minutes) |
| Verdicts | `allow`/`block` with category | Integer codes (0, 1, 2, 4, 5, -100) |
| Rate Limits | Token-based (1B tokens/month) | 150 uploads/day (standard) |

## Data Flow

```
User Call: client.scan(prompt="...", file="...")
    │
    ▼
Smart Router
    │  Inspects content types
    │  Returns RouteDecision(target=BOTH)
    │
    ├──────────────────────┐
    │                      │
    ▼                      ▼
AIRS Client           WildFire Client
    │                      │
    │  sync_scan()         │  submit_file()
    │                      │  poll for verdict
    │                      │
    ▼                      ▼
AIRS Response         WildFire XML
(action, category,    (verdict code)
 detection flags)          │
    │                      │
    ▼                      ▼
ScanVerdict           ScanVerdict
(from AIRS)           (from WildFire)
    │                      │
    └──────────┬───────────┘
               │
               ▼
        merge_verdicts()
               │
               ▼
        Combined ScanVerdict
        (most restrictive wins)
```

## Verdict Normalization

### WildFire Code Mapping

WildFire returns integer verdict codes. The SDK maps them to semantic values:

- **0** → `verdict=allow, category=benign`
- **1** → `verdict=block, category=malicious` (malware, severity=critical)
- **2** → `verdict=block, category=grayware` (severity=medium)
- **4** → `verdict=block, category=phishing` (severity=high)
- **5** → `verdict=block, category=c2` (command & control, severity=critical)
- **-100** → `verdict=pending` (still analyzing, re-poll)

### AIRS Response Mapping

AIRS returns structured detection results. The SDK inspects each flag:

- `prompt_detected` → `threat_type=prompt_injection`
- `url_category_detected` → `threat_type=malicious_url`
- `dlp_detected` → `threat_type=dlp_violation`
- `injection_detected` → `threat_type=injection`
- `malware_detected` → `threat_type=malware`
- `toxicity_detected` → `threat_type=toxic_content`

### Verdict Merging

When both APIs return results (mixed content scan), the merge logic is:

1. If either says "block", the combined result is "block"
2. If either says "pending", the combined result is "pending"
3. Otherwise, the combined result is "allow"
4. Threats from both sources are concatenated
5. The higher confidence score is used
6. Duration is summed

## Error Handling

The exception hierarchy provides specific, actionable errors:

- `ConfigurationError` — Always includes which env vars are missing
- `AIRSError` — Wraps pan-aisecurity SDK exceptions + HTTP status
- `WildFireError` — Wraps HTTP failures + XML parse errors
- `ScanTimeoutError` — Includes elapsed time and SHA-256 hash
- `ContentRouterError` — Includes what was provided vs what's needed
