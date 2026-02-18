# API Reference

## UnifiedClient

The main entry point. Routes content to the correct API and returns unified verdicts.

### Constructor

```python
UnifiedClient(
    config: SecurityConfig = None,  # Full config object
    airs_api_key: str = "",         # Override AIRS key
    wildfire_api_key: str = "",     # Override WildFire key
    ai_profile: str = "",           # Override AI profile
    region: str = "",               # Override AIRS region
)
```

### Methods

#### `scan(**kwargs) -> ScanVerdict`

Smart scan that auto-routes based on content type.

```python
# Text → AIRS
result = client.scan(prompt="Hello")

# File → WildFire
result = client.scan(file="doc.pdf")

# Both → parallel dispatch
result = client.scan(prompt="Analyze this", file="doc.pdf")
```

**Parameters:**
- `prompt` (str) — User prompt text
- `response` (str) — AI response text
- `file` (str | Path | bytes) — File to scan
- `filename` (str) — Filename hint for bytes
- `ai_profile` (str) — Override AI profile
- `metadata` (dict) — Additional AIRS metadata

#### `scan_text(prompt, response="", **kwargs) -> ScanVerdict`

Explicitly scan text via AIRS. Raises `ConfigurationError` if AIRS is not configured.

#### `scan_file(file, filename=None, **kwargs) -> ScanVerdict`

Explicitly scan a file via WildFire. Raises `ConfigurationError` if WildFire is not configured.

#### `scan_async(**kwargs) -> ScanVerdict`

Async version of `scan()`. Same parameters.

#### `close()` / `close_async()`

Close HTTP sessions. Also supports context manager:

```python
with UnifiedClient() as client:
    result = client.scan(prompt="test")

async with UnifiedClient() as client:
    result = await client.scan_async(prompt="test")
```

---

## ScanVerdict

Unified result from any scan operation.

### Fields

| Field | Type | Description |
|---|---|---|
| `verdict` | `Verdict` | `ALLOW`, `BLOCK`, or `PENDING` |
| `category` | `Category` | `BENIGN`, `MALICIOUS`, `GRAYWARE`, `PHISHING`, `C2` |
| `confidence` | `float` | 0.0 to 1.0 |
| `source` | `Source` | `AIRS`, `WILDFIRE`, or `COMBINED` |
| `scan_id` | `str` | Unique identifier |
| `threats` | `list[ThreatDetail]` | Detected threats |
| `raw_response` | `dict` | Original API response |
| `duration_ms` | `int` | Total scan time |
| `timestamp` | `datetime` | When the scan completed |

### Properties

| Property | Returns | Description |
|---|---|---|
| `is_safe` | `bool` | `verdict == ALLOW` |
| `is_blocked` | `bool` | `verdict == BLOCK` |
| `is_pending` | `bool` | `verdict == PENDING` |
| `threat_count` | `int` | Number of threats |

### Methods

| Method | Returns | Description |
|---|---|---|
| `to_dict()` | `dict` | Serialize to dictionary |

---

## ThreatDetail

A single detected threat.

| Field | Type | Description |
|---|---|---|
| `threat_type` | `str` | e.g., `prompt_injection`, `malware`, `dlp_violation` |
| `severity` | `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `description` | `str` | Human-readable description |
| `location` | `str` | `prompt`, `response`, or `file` |

---

## SecurityConfig

Configuration container. Usually auto-loaded from environment.

### Properties

| Property | Returns | Description |
|---|---|---|
| `has_airs` | `bool` | AIRS text scanning available |
| `has_wildfire` | `bool` | WildFire file scanning available |
| `mode_description` | `str` | Human-readable mode description |

---

## Exceptions

| Exception | When |
|---|---|
| `PanAISecurityError` | Base for all SDK exceptions |
| `ConfigurationError` | Missing API keys or invalid config |
| `AIRSError` | AIRS API failures |
| `WildFireError` | WildFire API failures |
| `ContentRouterError` | Cannot determine content type |
| `ScanTimeoutError` | WildFire verdict polling timeout |
