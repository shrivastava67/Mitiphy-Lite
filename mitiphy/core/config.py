"""Runtime configuration.

Resolves the state dir (~/.mitiphy/), loads config.toml if present, exposes
typed settings via pydantic. Environment overrides are prefixed MITIPHY_.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from platformdirs import user_data_dir
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_state_dir() -> Path:
    """Resolve ~/.mitiphy or the platform-appropriate equivalent."""
    env = os.environ.get("MITIPHY_HOME")
    if env:
        return Path(env).expanduser().resolve()
    home = Path.home() / ".mitiphy"
    if home.exists() or os.name != "nt":
        return home
    return Path(user_data_dir("mitiphy", appauthor=False))


class Settings(BaseSettings):
    """Runtime settings. Override via env (MITIPHY_*) or config.toml."""

    model_config = SettingsConfigDict(
        env_prefix="MITIPHY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    state_dir: Path = Field(default_factory=default_state_dir)
    port: int = 7331
    host: str = "127.0.0.1"
    profile: str = "lite"
    llm_provider: str = "none"  # none | llamacpp | ollama
    llm_model_path: str = ""
    llm_endpoint: str = ""
    quota_default: int = 100
    quota_window_seconds: int = 86400
    enable_telemetry: bool = False  # always False; CI test enforces this
    aup_revision: str = "2026-06-06-v1"
    user_agent: str = "Mitiphy/0.1 (+https://github.com/mitiphy/mitiphy)git "

    @property
    def cases_dir(self) -> Path:
        return self.state_dir / "cases"

    @property
    def feeds_dir(self) -> Path:
        return self.state_dir / "feeds"

    @property
    def models_dir(self) -> Path:
        return self.state_dir / "models"

    @property
    def plugins_dir(self) -> Path:
        return self.state_dir / "plugins"

    @property
    def keys_dir(self) -> Path:
        return self.state_dir / "keys"

    @property
    def logs_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def graph_dir(self) -> Path:
        return self.state_dir / "graph"

    @property
    def vectors_dir(self) -> Path:
        return self.state_dir / "vectors"

    @property
    def audit_db(self) -> Path:
        return self.state_dir / "audit.sqlite"

    @property
    def quota_db(self) -> Path:
        return self.state_dir / "quota.sqlite"

    @property
    def config_file(self) -> Path:
        return self.state_dir / "config.toml"

    @property
    def aup_acceptance_file(self) -> Path:
        return self.state_dir / "aup_accepted.json"

    def ensure_dirs(self) -> None:
        for d in (
            self.state_dir,
            self.cases_dir,
            self.feeds_dir,
            self.models_dir,
            self.plugins_dir,
            self.keys_dir,
            self.logs_dir,
            self.graph_dir,
            self.vectors_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    """Lazy singleton. Reads config.toml if present."""
    global _settings
    if _settings is not None:
        return _settings
    s = Settings()
    cfg = s.config_file
    if cfg.exists():
        try:
            with cfg.open("rb") as fp:
                data = tomllib.load(fp)
            for k, v in data.items():
                if hasattr(s, k):
                    setattr(s, k, v)
        except Exception:
            pass
    _settings = s
    return s


def reset_settings_for_tests() -> None:
    """Clear the cached singleton (tests only)."""
    global _settings
    _settings = None
