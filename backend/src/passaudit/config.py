"""Application configuration.

All settings come from environment variables prefixed with ``PASSAUDIT_`` (or from a
local ``.env`` file in the working directory). Defaults are deliberately conservative:
the API binds to loopback only and nothing leaves the machine unless explicitly enabled.

Several validators turn security rules into start-up failures instead of documentation:

* a non-loopback ``host`` is refused unless ``allow_non_loopback_bind`` is set explicitly;
* a wildcard CORS origin or Host allow-list entry is refused;
* the rate-limit burst must be able to afford a full batch request.
"""

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and loopback IP literals (``127.0.0.0/8``, ``::1``)."""
    cleaned = host.strip().strip("[]").lower()
    if cleaned == "localhost":
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    """Typed, validated runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="PASSAUDIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # ``PASSAUDIT_BREACH_LOCAL_FILE=`` (as Docker Compose and .env templates produce) means
        # "not set", never "the current directory".
        env_ignore_empty=True,
    )

    env: Literal["development", "test", "production"] = "development"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"

    # The service is local-only. Binding anywhere but loopback needs this explicit opt-in -
    # and authentication, which does not exist yet (see docs/security.md).
    allow_non_loopback_bind: bool = False

    # Origins allowed to call the API from a browser. Provide as a JSON list in the env,
    # e.g. PASSAUDIT_CORS_ORIGINS='["http://localhost:5173"]'. Exact origins only.
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # Accepted values of the HTTP Host header (DNS-rebinding defence). Hostnames only, no port.
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "[::1]"])

    # --- request limits -------------------------------------------------------------------
    # Upper bound on accepted password length; protects against resource exhaustion.
    max_password_length: int = Field(default=1024, ge=8, le=65536)
    # Largest accepted request body for single-password endpoints.
    max_body_bytes: int = Field(default=65_536, ge=1_024, le=10_000_000)
    # Batch endpoint limits: passwords per request and the (larger) body limit.
    batch_max_items: int = Field(default=50, ge=1, le=1_000)
    batch_max_body_bytes: int = Field(default=1_048_576, ge=1_024, le=50_000_000)

    # --- rate limiting (token bucket per client; see docs/api.md) --------------------------
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = Field(default=300, ge=1, le=1_000_000)  # refill, in cost units
    rate_limit_burst: int = Field(default=100, ge=1, le=1_000_000)  # bucket size, in cost units

    # --- analysis concurrency --------------------------------------------------------------
    max_concurrent_analyses: int = Field(default=2, ge=1, le=32)
    analysis_queue_timeout_seconds: float = Field(default=10.0, gt=0, le=300)

    # Any outbound network call (the online breach check) is opt-in: it needs this flag *and*
    # a request that asks for it. Only a 5-character SHA-1 prefix is ever sent (docs/security.md).
    external_lookups_enabled: bool = False
    # The k-anonymity "range" endpoint. A self-hosted mirror is fine; it must be https.
    breach_api_url: str = "https://api.pwnedpasswords.com/range"
    breach_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    # Time budget for the online lookups of one batch; the rest are reported as unavailable.
    breach_batch_deadline_seconds: float = Field(default=20.0, gt=0, le=300)
    # A local, sorted "SHA1[:count]" hash file (Pwned Passwords offline format). Searching it
    # needs no network, so it does not require ``external_lookups_enabled``.
    breach_local_file: Path | None = None

    # --- authorised reuse auditing (all three must be set together; see docs/security.md) ---
    reuse_index_path: Path | None = None
    reuse_key_file: Path | None = None
    # Who vouches that the indexed datasets may be held and compared. Recorded in reports.
    reuse_authorization_reference: str | None = Field(default=None, max_length=120)

    # --- policy profiles and dictionaries ---------------------------------------------------
    # A JSON/TOML file of extra policy profiles (see docs/api.md).
    policy_profiles_path: Path | None = None
    # Extra word lists (one word per line) merged into the "words" dictionary.
    dictionary_paths: list[Path] = Field(default_factory=list)

    @field_validator("breach_api_url")
    @classmethod
    def _https_only(cls, url: str) -> str:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "breach_api_url must be an https URL without credentials, query or fragment"
            )
        return url.rstrip("/")

    @field_validator("cors_origins")
    @classmethod
    def _exact_origins_only(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            parts = urlsplit(origin)
            exact = f"{parts.scheme}://{parts.netloc}"
            if (
                parts.scheme not in {"http", "https"}
                or not parts.netloc
                or origin != exact
                or "*" in origin
            ):
                raise ValueError(
                    "cors_origins entries must be exact origins like 'http://localhost:5173' "
                    "(scheme and host[:port], no wildcard, path or trailing slash)"
                )
        return origins

    @field_validator("allowed_hosts")
    @classmethod
    def _no_wildcard_hosts(cls, hosts: list[str]) -> list[str]:
        cleaned = [h.strip().lower() for h in hosts]

        def bad(host: str) -> bool:
            bracketed_ipv6 = host.startswith("[") and host.endswith("]")
            return not host or "*" in host or "/" in host or (":" in host and not bracketed_ipv6)

        if not cleaned or any(bad(h) for h in cleaned):
            raise ValueError("allowed_hosts must list bare hostnames (no wildcard, port or path)")
        return cleaned

    @model_validator(mode="after")
    def _enforce_local_only_and_consistency(self) -> Self:
        if not self.allow_non_loopback_bind and not is_loopback_host(self.host):
            raise ValueError(
                "host must be a loopback address (127.0.0.1, ::1 or localhost): PassAudit has "
                "no authentication and must not be exposed. Set allow_non_loopback_bind only "
                "after reviewing docs/security.md"
            )
        if self.rate_limit_burst < self.batch_max_items:
            raise ValueError("rate_limit_burst must be at least batch_max_items")
        if self.batch_max_body_bytes < self.max_body_bytes:
            raise ValueError("batch_max_body_bytes must be at least max_body_bytes")
        if self.reuse_index_path is not None and (
            self.reuse_key_file is None or not (self.reuse_authorization_reference or "").strip()
        ):
            raise ValueError(
                "reuse_index_path requires reuse_key_file and reuse_authorization_reference: "
                "reuse auditing is only enabled with an explicit authorisation statement"
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def effective_allowed_hosts(self) -> list[str]:
        """Allowed Host values; the test client's ``testserver`` is accepted in ``test`` only."""
        return [*self.allowed_hosts, "testserver"] if self.env == "test" else self.allowed_hosts


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()
