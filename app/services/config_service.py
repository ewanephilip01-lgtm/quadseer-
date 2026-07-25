"""
System Configuration Service
Manages reading and writing configuration values from the database.
Provides fallback to environment variables if DB value not set.
"""
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import os
import json

from app.models.system_config import SystemConfig


class ConfigService:
    """Service for managing system configuration."""

    # Default configuration definitions
    # These define what configs exist, their types, labels, etc.
    DEFAULT_CONFIGS = [
        # API Keys - Dark Web & Breach
        {
            "category": "api_keys",
            "key": "hibp_api_key",
            "label": "Have I Been Pwned API Key",
            "description": "API key for Have I Been Pwned breach checking service. Get one at haveibeenpwned.com/API/Key",
            "placeholder": "Enter your HIBP API key",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "HIBP_API_KEY"
        },
        {
            "category": "api_keys",
            "key": "dehashed_api_key",
            "label": "DeHashed API Key",
            "description": "API key for DeHashed credential search service",
            "placeholder": "Enter your DeHashed API key",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "DEHASHED_API_KEY"
        },
        {
            "category": "api_keys",
            "key": "dehashed_username",
            "label": "DeHashed Username",
            "description": "Username for DeHashed API authentication",
            "placeholder": "Enter your DeHashed username",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "DEHASHED_USERNAME"
        },
        {
            "category": "api_keys",
            "key": "shodan_api_key",
            "label": "Shodan API Key",
            "description": "API key for Shodan internet scanning service",
            "placeholder": "Enter your Shodan API key",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "SHODAN_API_KEY"
        },
        {
            "category": "api_keys",
            "key": "censys_api_id",
            "label": "Censys API ID",
            "description": "API ID for Censys internet scanning service",
            "placeholder": "Enter your Censys API ID",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "CENSYS_API_ID"
        },
        {
            "category": "api_keys",
            "key": "censys_api_secret",
            "label": "Censys API Secret",
            "description": "API secret for Censys authentication",
            "placeholder": "Enter your Censys API secret",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "CENSYS_API_SECRET"
        },

        # Network & Proxy Settings
        {
            "category": "network",
            "key": "tor_proxy",
            "label": "TOR Proxy URL",
            "description": "SOCKS5 proxy URL for TOR access (e.g., socks5://tor:9050 or socks5://127.0.0.1:9050)",
            "placeholder": "socks5://127.0.0.1:9050",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "TOR_PROXY"
        },
        {
            "category": "network",
            "key": "http_proxy",
            "label": "HTTP Proxy URL",
            "description": "HTTP proxy for outbound requests (optional)",
            "placeholder": "http://proxy.company.com:8080",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "HTTP_PROXY"
        },
        {
            "category": "network",
            "key": "scan_timeout",
            "label": "Scan Timeout (seconds)",
            "description": "Default timeout for network scan operations",
            "placeholder": "30",
            "input_type": "number",
            "value_type": "int",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "SCAN_TIMEOUT"
        },

        # Scan Settings
        {
            "category": "scan_settings",
            "key": "default_scan_types",
            "label": "Default Scan Types",
            "description": "Comma-separated list of default scan types for new targets",
            "placeholder": "dns,port,ssl,tech",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "DEFAULT_SCAN_TYPES"
        },
        {
            "category": "scan_settings",
            "key": "max_concurrent_scans",
            "label": "Max Concurrent Scans",
            "description": "Maximum number of scans that can run simultaneously",
            "placeholder": "5",
            "input_type": "number",
            "value_type": "int",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "MAX_CONCURRENT_SCANS"
        },
        {
            "category": "scan_settings",
            "key": "port_scan_range",
            "label": "Port Scan Range",
            "description": "Default port range for port scans (e.g., 1-1000 or 80,443,8080)",
            "placeholder": "1-1000",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "PORT_SCAN_RANGE"
        },

        # Notifications
        {
            "category": "notifications",
            "key": "email_smtp_host",
            "label": "SMTP Host",
            "description": "SMTP server for sending alert emails",
            "placeholder": "smtp.gmail.com",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "EMAIL_SMTP_HOST"
        },
        {
            "category": "notifications",
            "key": "email_smtp_port",
            "label": "SMTP Port",
            "description": "SMTP server port",
            "placeholder": "587",
            "input_type": "number",
            "value_type": "int",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "EMAIL_SMTP_PORT"
        },
        {
            "category": "notifications",
            "key": "email_smtp_user",
            "label": "SMTP Username",
            "description": "Username for SMTP authentication",
            "placeholder": "alerts@yourdomain.com",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "EMAIL_SMTP_USER"
        },
        {
            "category": "notifications",
            "key": "email_smtp_password",
            "label": "SMTP Password",
            "description": "Password for SMTP authentication",
            "placeholder": "Enter SMTP password",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "EMAIL_SMTP_PASSWORD"
        },
        {
            "category": "notifications",
            "key": "alert_email_recipients",
            "label": "Alert Recipients",
            "description": "Comma-separated email addresses for critical alerts",
            "placeholder": "security@company.com, admin@company.com",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "ALERT_EMAIL_RECIPIENTS"
        },
        {
            "category": "notifications",
            "key": "slack_webhook_url",
            "label": "Slack Webhook URL",
            "description": "Slack incoming webhook URL for notifications",
            "placeholder": "https://hooks.slack.com/services/...",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "SLACK_WEBHOOK_URL"
        },
        {
            "category": "notifications",
            "key": "discord_webhook_url",
            "label": "Discord Webhook URL",
            "description": "Discord webhook URL for notifications",
            "placeholder": "https://discord.com/api/webhooks/...",
            "input_type": "password",
            "is_sensitive": True,
            "required": False,
            "env_fallback": "DISCORD_WEBHOOK_URL"
        },

        # Application Settings
        {
            "category": "app_settings",
            "key": "app_name",
            "label": "Application Name",
            "description": "Name displayed in the UI and reports",
            "placeholder": "QuadSeer",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "APP_NAME"
        },
        {
            "category": "app_settings",
            "key": "company_name",
            "label": "Company Name",
            "description": "Your company name for report headers",
            "placeholder": "Your Company Inc.",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "COMPANY_NAME"
        },
        {
            "category": "app_settings",
            "key": "report_logo_url",
            "label": "Report Logo URL",
            "description": "URL to logo image for PDF reports",
            "placeholder": "https://yourdomain.com/logo.png",
            "input_type": "text",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "REPORT_LOGO_URL"
        },
        {
            "category": "app_settings",
            "key": "auto_scan_enabled",
            "label": "Enable Auto-Scanning",
            "description": "Automatically scan targets on a schedule",
            "input_type": "toggle",
            "value_type": "bool",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "AUTO_SCAN_ENABLED"
        },
        {
            "category": "app_settings",
            "key": "auto_scan_interval_days",
            "label": "Auto-Scan Interval (days)",
            "description": "Number of days between automatic scans",
            "placeholder": "7",
            "input_type": "number",
            "value_type": "int",
            "is_sensitive": False,
            "required": False,
            "env_fallback": "AUTO_SCAN_INTERVAL_DAYS"
        },
    ]

    def __init__(self, db: AsyncSession):
        self.db = db

    async def initialize_defaults(self) -> None:
        """Initialize default configuration entries if they don't exist."""
        for config_def in self.DEFAULT_CONFIGS:
            # Check if config already exists
            result = await self.db.execute(
                select(SystemConfig).where(SystemConfig.key == config_def["key"])
            )
            existing = result.scalar_one_or_none()

            if not existing:
                # Get value from environment or use empty string
                env_value = os.getenv(config_def.get("env_fallback", ""), "")

                config = SystemConfig(
                    category=config_def["category"],
                    key=config_def["key"],
                    value=env_value,
                    value_type=config_def.get("value_type", "string"),
                    label=config_def.get("label"),
                    description=config_def.get("description"),
                    placeholder=config_def.get("placeholder"),
                    input_type=config_def.get("input_type", "text"),
                    required=config_def.get("required", False),
                    is_sensitive=config_def.get("is_sensitive", False),
                    is_editable=config_def.get("is_editable", True),
                    is_active=True
                )
                self.db.add(config)

        await self.db.commit()

    async def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a configuration value by key. Checks DB first, then env fallback."""
        # Try database first
        result = await self.db.execute(
            select(SystemConfig).where(SystemConfig.key == key).where(SystemConfig.is_active == True)
        )
        config = result.scalar_one_or_none()

        if config and config.value:
            return config.value

        # Fallback to environment variable
        for config_def in self.DEFAULT_CONFIGS:
            if config_def["key"] == key and config_def.get("env_fallback"):
                env_value = os.getenv(config_def["env_fallback"])
                if env_value:
                    return env_value

        return default

    async def get_bool(self, key: str, default: bool = False) -> bool:
        """Get a boolean configuration value."""
        value = await self.get(key)
        if value is None:
            return default
        return value.lower() in ("true", "1", "yes", "on")

    async def get_int(self, key: str, default: int = 0) -> int:
        """Get an integer configuration value."""
        value = await self.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    async def set(self, key: str, value: str, updated_by: Optional[int] = None) -> bool:
        """Set a configuration value."""
        result = await self.db.execute(
            select(SystemConfig).where(SystemConfig.key == key)
        )
        config = result.scalar_one_or_none()

        if config:
            config.value = value
            config.updated_by = updated_by
            await self.db.commit()
            return True
        return False

    async def get_all_by_category(self, category: Optional[str] = None) -> List[SystemConfig]:
        """Get all configuration items, optionally filtered by category."""
        query = select(SystemConfig).where(SystemConfig.is_active == True)
        if category:
            query = query.where(SystemConfig.category == category)
        query = query.order_by(SystemConfig.category, SystemConfig.key)

        result = await self.db.execute(query)
        return result.scalars().all()

    async def get_categories(self) -> List[Dict[str, Any]]:
        """Get all unique categories with their display info."""
        categories = {
            "api_keys": {"label": "API Keys", "description": "Third-party service API keys and credentials", "icon": "🔑"},
            "network": {"label": "Network & Proxy", "description": "Proxy settings and network configuration", "icon": "🌐"},
            "scan_settings": {"label": "Scan Settings", "description": "Default scan behavior and limits", "icon": "🔍"},
            "notifications": {"label": "Notifications", "description": "Alert channels and delivery settings", "icon": "🔔"},
            "app_settings": {"label": "Application", "description": "General application settings", "icon": "⚙️"},
        }
        return categories
