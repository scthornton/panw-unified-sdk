# Getting Started

## Prerequisites

- Python 3.10+
- At least one of:
  - **AIRS Runtime API key** + AI security profile (for text scanning)
  - **WildFire API key** (for file scanning)

## Installation

```bash
pip install pan-ai-security
```

For development:

```bash
git clone https://github.com/scthornton/panw-unified-sdk.git
cd panw-unified-sdk
pip install -e ".[dev]"
```

## Configuration

Create a `.env` file in your project root (or export env vars):

```bash
# Required for text scanning
PANW_AI_SEC_API_KEY=your-airs-key
PANW_AI_PROFILE=your-profile-name

# Required for file scanning
PANW_WILDFIRE_API_KEY=your-wildfire-key

# Optional
PANW_AI_SEC_REGION=us  # us, eu, in, sg
```

## Your First Scan

```python
from pan_ai_security import UnifiedClient

# Auto-loads credentials from env vars / .env file
client = UnifiedClient()

# Scan a prompt
result = client.scan(prompt="What is the weather today?")
print(f"Safe: {result.is_safe}")

# Scan a file
result = client.scan(file="document.pdf")
print(f"Verdict: {result.verdict.value}")

# Always close when done
client.close()
```

## Degraded Mode

The SDK works with just one API key. If you only have AIRS credentials, text scanning works normally, but file scanning raises a `ConfigurationError` with a clear message about what's missing.

```python
# With only AIRS configured:
client.scan(prompt="Hello")          # Works
client.scan(file="test.pdf")         # Raises ConfigurationError
```

## Next Steps

- [Configuration Guide](configuration.md) — All config options and env vars
- [API Reference](api-reference.md) — Complete method signatures
- [Architecture](architecture.md) — How the SDK works internally
