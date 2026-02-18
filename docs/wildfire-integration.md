# WildFire Integration Guide

## How WildFire Works

WildFire is Palo Alto Networks' cloud-based malware analysis service. Unlike AIRS (which scans text synchronously), WildFire uses a **submit-then-poll** pattern:

1. **Submit** a file via multipart/form-data POST
2. WildFire returns a SHA-256 hash immediately
3. **Poll** for the verdict using that hash
4. Verdict arrives once analysis completes (seconds to minutes)

The SDK handles this entire flow automatically via `scan_file()`.

## Supported File Types

WildFire analyzes a wide range of file types:

- **Executables:** PE (.exe, .dll, .sys), ELF, Mach-O
- **Documents:** PDF, Microsoft Office (.doc, .docx, .xls, .xlsx, .ppt, .pptx), RTF
- **Archives:** ZIP, RAR, 7z, TAR, GZIP
- **Scripts:** JavaScript, VBScript, PowerShell, Batch
- **Mobile:** Android APK, iOS IPA
- **Email:** EML, MSG
- **Other:** JAR, SWF, LNK, MSI

## Usage Patterns

### Basic File Scan

```python
from pan_ai_security import UnifiedClient

client = UnifiedClient()
result = client.scan(file="document.pdf")

if result.is_blocked:
    print(f"Threat: {result.category.value}")
    for t in result.threats:
        print(f"  {t.threat_type}: {t.description}")
```

### Scan Raw Bytes

```python
# Useful for files received from uploads, APIs, etc.
file_bytes = request.files["upload"].read()
result = client.scan(file=file_bytes, filename="upload.pdf")
```

### Custom Polling

```python
result = client.scan_file(
    file="large_archive.zip",
    poll_interval=5,    # Check every 5 seconds
    max_wait=600,       # Wait up to 10 minutes
)
```

### Low-Level Access

```python
from pan_ai_security.wildfire import WildFireClient
from pan_ai_security.config import SecurityConfig

config = SecurityConfig()
wf = WildFireClient(config)

# Step 1: Submit
submit = wf.submit_file("malware_sample.exe")
print(f"SHA-256: {submit.sha256}")

# Step 2: Poll
verdict = wf.get_verdict(submit.sha256)
print(f"Verdict code: {verdict.verdict_code}")
```

## Rate Limits

- **Standard license:** 150 file uploads per day
- **Maximum file size:** 100 MB
- **Polling:** No rate limit on verdict checks

## Verdict Codes

| Code | Meaning | SDK Maps To |
|---|---|---|
| 0 | Benign | `allow` / `benign` |
| 1 | Malware | `block` / `malicious` |
| 2 | Grayware | `block` / `grayware` |
| 4 | Phishing | `block` / `phishing` |
| 5 | Command & Control | `block` / `c2` |
| -100 | Pending | `pending` (re-poll) |

## EICAR Test File

Use the EICAR test file to verify your WildFire integration without real malware:

```python
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
result = client.scan(file=eicar, filename="eicar.com")
assert result.is_blocked  # Should be detected as malware
```

## Error Handling

```python
from pan_ai_security.exceptions import WildFireError, ScanTimeoutError

try:
    result = client.scan_file(file="huge.zip", max_wait=60)
except ScanTimeoutError as e:
    print(f"Still analyzing after {e.elapsed_seconds}s")
    # Could retry later with the SHA-256 hash
except WildFireError as e:
    print(f"API error: {e}")
    if e.status_code == 403:
        print("Check your WildFire API key")
```
