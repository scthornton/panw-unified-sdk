"""Mixed content scanning — text + file in parallel.

When you provide both a prompt and a file, the SDK dispatches to AIRS and
WildFire simultaneously, then merges the verdicts. The most restrictive
verdict wins.

Requires both PANW_AI_SEC_API_KEY + PANW_AI_PROFILE and PANW_WILDFIRE_API_KEY.

Usage:
    python examples/mixed_content_scan.py
"""

import sys

from pan_ai_security import UnifiedClient

client = UnifiedClient()

file_path = sys.argv[1] if len(sys.argv) > 1 else __file__

print(f"Scanning prompt + file: {file_path}")
result = client.scan(
    prompt="Please analyze the attached document for any sensitive information",
    file=file_path,
)

print(f"Source: {result.source.value}")  # "combined"
print(f"Verdict: {result.verdict.value}")
print(f"Category: {result.category.value}")
print(f"Duration: {result.duration_ms}ms")

if result.threats:
    print(f"\nThreats ({result.threat_count}):")
    for threat in result.threats:
        print(f"  [{threat.location}] {threat.threat_type}: {threat.description}")
else:
    print("\nAll clear — no threats from either API.")

client.close()
