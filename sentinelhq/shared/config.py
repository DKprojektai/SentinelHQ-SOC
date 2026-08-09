"""SentinelHQ configuration validation and loading."""

import os
import sys
import logging

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Configuration is invalid or incomplete."""
    pass


# Required environment variables (no defaults, must be set)
# Base: required by ALL services
REQUIRED_VARS = {
    'DATABASE_URL': 'PostgreSQL connection string (dsn format)',
}

# Service-specific var groups — pass to validate_config(extra=...)
OPENSEARCH_VARS = {
    'OPENSEARCH_URL':  'OpenSearch/Wazuh Indexer URL',
    'OPENSEARCH_USER': 'OpenSearch/Wazuh Indexer username',
    'OPENSEARCH_PASS': 'OpenSearch/Wazuh Indexer password',
}
WAZUH_VARS = {
    'WAZUH_API_URL':  'Wazuh Manager API URL',
    'WAZUH_API_USER': 'Wazuh Manager API username',
    'WAZUH_API_PASS': 'Wazuh Manager API password',
}

# Optional environment variables (have safe defaults)
OPTIONAL_VARS = {
    'DB_HOST': ('localhost', 'PostgreSQL hostname'),
    'DB_PORT': ('5432', 'PostgreSQL port'),
    'WAZUH_VERIFY_SSL': ('false', 'Verify SSL certificates (true/false)'),
    'LOG_LEVEL': ('WARNING', 'Logging level (DEBUG/INFO/WARNING/ERROR)'),
    'COLLECT_INTERVAL_SECONDS': ('30', 'Collector interval in seconds'),
    'ANALYZE_INTERVAL_SECONDS': ('600', 'Analyzer interval in seconds'),
}


def validate_config(extra: dict = None):
    """
    Validate required environment variables are set.
    Call this at service startup to fail fast if configuration missing.

    Args:
        extra: dict of {VAR_NAME: description} for service-specific required vars.
               Use OPENSEARCH_VARS, WAZUH_VARS constants or custom dict.

    Raises:
        ConfigError: If any required variable is missing
    """
    missing = []
    all_required = {**REQUIRED_VARS, **(extra or {})}

    for var_name, description in all_required.items():
        value = os.environ.get(var_name)
        if not value:
            missing.append(f"  {var_name}: {description}")

    if missing:
        error_msg = (
            "Missing required environment variables:\n" +
            "\n".join(missing) +
            "\n\nSet these in .env file or docker-compose environment section."
        )
        log.error(error_msg)
        raise ConfigError(error_msg)

    log.info("✓ All required configuration variables set")


def get_config(var_name: str, default=None) -> str:
    """
    Get configuration value from environment.

    Args:
        var_name: Environment variable name
        default: Default value (only used for non-required vars)

    Returns:
        Configuration value

    Raises:
        ConfigError: If var is required and not set
    """
    # Required variables (no defaults allowed)
    _all_required = {**REQUIRED_VARS, **OPENSEARCH_VARS, **WAZUH_VARS}
    if var_name in _all_required:
        value = os.environ.get(var_name)
        if not value:
            raise ConfigError(
                f"Required environment variable '{var_name}' not set: "
                f"{_all_required[var_name]}"
            )
        return value

    # Optional variables (use safe defaults if provided)
    if var_name in OPTIONAL_VARS:
        default_val, _desc = OPTIONAL_VARS[var_name]
        return os.environ.get(var_name, default_val)

    # Custom variables (use provided default or None)
    return os.environ.get(var_name, default)


def get_int_config(var_name: str, default: int = None) -> int:
    """Get configuration value as integer."""
    value = get_config(var_name, str(default) if default is not None else None)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigError(f"Configuration {var_name}={value} is not a valid integer")


def get_bool_config(var_name: str, default: bool = False) -> bool:
    """Get configuration value as boolean."""
    value = get_config(var_name, None)
    if value is None:
        return default
    return value.lower() in ('true', '1', 'yes', 'on')
