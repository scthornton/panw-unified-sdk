# Configuration

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PANW_AI_SEC_API_KEY` | For text scanning | AIRS Runtime API key |
| `PANW_AI_PROFILE` | For text scanning | AI security profile name |
| `PANW_AI_SEC_REGION` | No (default: `us`) | AIRS region: `us`, `eu`, `in`, `sg` |
| `PANW_WILDFIRE_API_KEY` | For file scanning | WildFire API key |
| `PANW_AIRS_BASE_URL` | No | Override AIRS endpoint |
| `PANW_WILDFIRE_BASE_URL` | No | Override WildFire endpoint |

## Configuration Methods

### 1. Environment Variables (Recommended)

```bash
export PANW_AI_SEC_API_KEY=your-key
export PANW_AI_PROFILE=your-profile
export PANW_WILDFIRE_API_KEY=your-wf-key
```

### 2. `.env` File

Create a `.env` file in your project root. The SDK auto-discovers it.

### 3. Direct Initialization

```python
from pan_ai_security import UnifiedClient, SecurityConfig

config = SecurityConfig(
    airs_api_key="your-key",
    ai_profile="your-profile",
    wildfire_api_key="your-wf-key",
    airs_region="eu",
)
client = UnifiedClient(config=config)
```

## AIRS Regions

| Region | Base URL |
|---|---|
| `us` | `service.api.aisecurity.paloaltonetworks.com` |
| `eu` | `service.api.aisecurity.eu.paloaltonetworks.com` |
| `in` | `service.api.aisecurity.in.paloaltonetworks.com` |
| `sg` | `service.api.aisecurity.sg.paloaltonetworks.com` |

## Timeout Configuration

```python
config = SecurityConfig(
    airs_timeout=30,              # AIRS scan timeout (seconds)
    wildfire_submit_timeout=60,   # WildFire file upload timeout
    wildfire_poll_interval=2,     # Seconds between verdict polls
    wildfire_max_wait=300,        # Max wait for WildFire verdict
)
```

## Operation Modes

The SDK detects which APIs are available and operates accordingly:

| Mode | AIRS Key | WildFire Key | Available Operations |
|---|---|---|---|
| **Full** | Set | Set | Text + file + mixed scanning |
| **Text-only** | Set | Missing | Text scanning only |
| **File-only** | Missing | Set | File scanning only |
| **Unconfigured** | Missing | Missing | Error at init |

Check the current mode:

```python
client = UnifiedClient()
print(client._config.mode_description)  # "full (text + file scanning)"
```
