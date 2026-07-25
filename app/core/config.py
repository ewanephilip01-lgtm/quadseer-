"""
Configuration management - reads from DB-stored configs.
"""
import os
import json
from typing import Optional, Any
from sqlalchemy import select
from app.core.database import async_session
from app.models.system_config import SystemConfig


class ConfigManager:
    """Manages system configuration from database."""

    _cache = {}

    @classmethod
    async def get(cls, key: str, default: Any = None) -> Any:
        """Get a config value by key."""
        if key in cls._cache:
            return cls._cache[key]

        async with async_session() as session:
            result = await session.execute(
                select(SystemConfig).where(SystemConfig.config_key == key)
            )
            config = result.scalar_one_or_none()

            if config is None:
                return default

            value = cls._parse_value(config.config_value, config.config_type)
            cls._cache[key] = value
            return value

    @classmethod
    async def set(cls, key: str, value: Any, config_type: str = "string", description: str = ""):
        """Set a config value."""
        async with async_session() as session:
            result = await session.execute(
                select(SystemConfig).where(SystemConfig.config_key == key)
            )
            config = result.scalar_one_or_none()

            str_value = cls._stringify_value(value, config_type)

            if config is None:
                config = SystemConfig(
                    config_key=key,
                    config_value=str_value,
                    config_type=config_type,
                    description=description,
                )
                session.add(config)
            else:
                config.config_value = str_value
                config.config_type = config_type

            await session.commit()
            cls._cache[key] = value

    @classmethod
    def _parse_value(cls, value: str, config_type: str) -> Any:
        if value is None:
            return None
        if config_type == "json":
            return json.loads(value)
        if config_type == "int":
            return int(value)
        if config_type == "bool":
            return value.lower() in ("true", "1", "yes")
        if config_type == "secret":
            return value  # Still return the value, just marked as secret
        return value

    @classmethod
    def _stringify_value(cls, value: Any, config_type: str) -> str:
        if config_type == "json":
            return json.dumps(value)
        if config_type == "int":
            return str(value)
        if config_type == "bool":
            return "true" if value else "false"
        return str(value)

    @classmethod
    def clear_cache(cls):
        cls._cache.clear()


# Default configurations
DEFAULT_CONFIGS = {
    # API Keys
    "hibp_api_key": ("", "secret", "Have I Been Pwned API key"),
    "dehashed_email": ("", "secret", "DeHashed account email"),
    "dehashed_api_key": ("", "secret", "DeHashed API key"),
    "ransomware_live_api_key": ("", "secret", "Ransomware.live API key (optional)"),

    # Dark Web / TOR
    "tor_proxy_host": ("tor", "string", "TOR proxy hostname"),
    "tor_proxy_port": ("9050", "int", "TOR proxy port"),
    "darkweb_timeout": ("30", "int", "Dark web request timeout in seconds"),

    # Scan settings
    "scan_concurrent_limit": ("5", "int", "Max concurrent scans"),
    "port_scan_range": ("top100", "string", "Port scan range (top100, top1000, all)"),
    "ssl_check_expiry_days": ("30", "int", "SSL expiry warning threshold in days"),

    # Notifications
    "smtp_host": ("", "string", "SMTP server hostname"),
    "smtp_port": ("587", "int", "SMTP server port"),
    "smtp_username": ("", "secret", "SMTP username"),
    "smtp_password": ("", "secret", "SMTP password"),
    "smtp_from_email": ("alerts@quadseer.local", "string", "From email address"),
    "slack_webhook_url": ("", "secret", "Slack webhook URL"),
    "discord_webhook_url": ("", "secret", "Discord webhook URL"),

    # Platform
    "platform_name": ("QuadSeer", "string", "Platform display name"),
    "risk_scoring_enabled": ("true", "bool", "Enable risk scoring"),
    "auto_alert_critical": ("true", "bool", "Auto-alert on critical findings"),
}


async def initialize_default_configs():
    """Initialize all default configurations."""
    for key, (value, config_type, description) in DEFAULT_CONFIGS.items():
        await ConfigManager.set(key, value, config_type, description)
