"""Configuration and credential management for the AI Security SDK."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from pan_ai_security.exceptions import ConfigurationError

logger = logging.getLogger("pan_ai_security")

# AIRS base URLs by region
AIRS_REGION_URLS: dict[str, str] = {
    "us": "https://service.api.aisecurity.paloaltonetworks.com",
    "eu": "https://service.api.aisecurity.eu.paloaltonetworks.com",
    "in": "https://service.api.aisecurity.in.paloaltonetworks.com",
    "sg": "https://service.api.aisecurity.sg.paloaltonetworks.com",
}

WILDFIRE_BASE_URL = "https://wildfire.paloaltonetworks.com/publicapi"


@dataclass
class SecurityConfig:
    """Configuration for the Palo Alto Networks AI Security SDK.

    Credentials load automatically from environment variables. You can also pass
    them directly or point to a .env file.

    Environment variables:
        PANW_AI_SEC_API_KEY   — AIRS Runtime API key
        PANW_AI_PROFILE       — AIRS AI security profile name
        PANW_AI_SEC_REGION    — AIRS region (us, eu, in, sg)
        PANW_WILDFIRE_API_KEY — WildFire API key
    """

    # AIRS configuration
    airs_api_key: str = ""
    ai_profile: str = ""
    airs_region: str = "us"
    airs_base_url: str = ""

    # WildFire configuration
    wildfire_api_key: str = ""
    wildfire_base_url: str = WILDFIRE_BASE_URL

    # Timeouts (seconds)
    airs_timeout: int = 30
    wildfire_submit_timeout: int = 60
    wildfire_poll_interval: int = 2
    wildfire_max_wait: int = 300

    # Misc
    env_file: str | None = None
    _loaded: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if not self._loaded:
            self._load_from_env()
            self._loaded = True

    def _load_from_env(self) -> None:
        """Load missing values from environment variables / .env file."""
        if self.env_file:
            env_path = Path(self.env_file)
            if env_path.exists():
                load_dotenv(env_path)
            else:
                logger.warning("Specified .env file not found: %s", self.env_file)
        else:
            load_dotenv()  # auto-discover .env in cwd or parents

        if not self.airs_api_key:
            self.airs_api_key = os.getenv("PANW_AI_SEC_API_KEY", "")
        if not self.ai_profile:
            self.ai_profile = os.getenv("PANW_AI_PROFILE", "")
        if not self.airs_region:
            self.airs_region = os.getenv("PANW_AI_SEC_REGION", "us")
        if not self.wildfire_api_key:
            self.wildfire_api_key = os.getenv("PANW_WILDFIRE_API_KEY", "")

        # Resolve AIRS base URL from region
        if not self.airs_base_url:
            override = os.getenv("PANW_AIRS_BASE_URL", "")
            if override:
                self.airs_base_url = override
            else:
                self.airs_base_url = AIRS_REGION_URLS.get(
                    self.airs_region, AIRS_REGION_URLS["us"]
                )

        # Allow WildFire URL override
        wf_override = os.getenv("PANW_WILDFIRE_BASE_URL", "")
        if wf_override:
            self.wildfire_base_url = wf_override

    def validate(self) -> None:
        """Validate the configuration. Raises ConfigurationError if unusable."""
        if not self.airs_api_key and not self.wildfire_api_key:
            raise ConfigurationError(
                "No API keys configured. Set at least one of: "
                "PANW_AI_SEC_API_KEY (for text scanning) or "
                "PANW_WILDFIRE_API_KEY (for file scanning). "
                "See .env.example for all options."
            )

        if self.airs_api_key and not self.ai_profile:
            raise ConfigurationError(
                "AIRS API key is set but PANW_AI_PROFILE is missing. "
                "You need an AI security profile to scan text. "
                "Create one in the Prisma AIRS console."
            )

        if self.airs_region not in AIRS_REGION_URLS:
            raise ConfigurationError(
                f"Invalid AIRS region '{self.airs_region}'. "
                f"Valid regions: {', '.join(AIRS_REGION_URLS.keys())}"
            )

    @property
    def has_airs(self) -> bool:
        """True if AIRS text scanning is available."""
        return bool(self.airs_api_key and self.ai_profile)

    @property
    def has_wildfire(self) -> bool:
        """True if WildFire file scanning is available."""
        return bool(self.wildfire_api_key)

    @property
    def mode_description(self) -> str:
        """Human-readable description of available capabilities."""
        if self.has_airs and self.has_wildfire:
            return "full (text + file scanning)"
        if self.has_airs:
            return "text-only (AIRS)"
        if self.has_wildfire:
            return "file-only (WildFire)"
        return "unconfigured"
