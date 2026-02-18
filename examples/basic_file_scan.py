"""Basic file scanning with WildFire API.

Submits a file for malware analysis and polls until a verdict is returned.
Requires PANW_WILDFIRE_API_KEY.

Usage:
    export PANW_WILDFIRE_API_KEY=your-key
    python examples/basic_file_scan.py
"""

import sys
from pathlib import Path

from pan_ai_security import UnifiedClient

client = UnifiedClient()

# Scan a file from the command line, or use a default
file_path = sys.argv[1] if len(sys.argv) > 1 else __file__

print(f"Scanning: {file_path}")
result = client.scan(file=file_path)

print(f"Verdict: {result.verdict.value}")
print(f"Category: {result.category.value}")
print(f"Safe: {result.is_safe}")
print(f"Duration: {result.duration_ms}ms")
print(f"Scan ID (SHA-256): {result.scan_id[:16]}...")

if result.threats:
    print(f"\nThreats detected ({result.threat_count}):")
    for threat in result.threats:
        print(f"  [{threat.severity.value}] {threat.threat_type}: {threat.description}")
else:
    print("\nNo threats detected.")

client.close()
