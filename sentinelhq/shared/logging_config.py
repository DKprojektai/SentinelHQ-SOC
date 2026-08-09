"""SentinelHQ logging configuration."""

import logging
import os
import sys


def setup_logging(service_name: str = "sentinelhq"):
    """
    Configure logging consistently across all services.
    Call this at service startup, before any other logging calls.

    Args:
        service_name: Service name for log prefix (e.g., "collector", "analyzer")
    """
    # Get log level from environment
    log_level_str = os.environ.get('LOG_LEVEL', 'WARNING').upper()

    try:
        log_level = getattr(logging, log_level_str)
    except AttributeError:
        log_level = logging.WARNING
        print(
            f"Unknown LOG_LEVEL: {log_level_str}, using WARNING",
            file=sys.stderr
        )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers (avoid duplicates)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler with formatting
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    formatter = logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    root_logger.addHandler(handler)

    # Log startup message
    root_logger.info(f"Logging initialized at {log_level_str} level")

    # Suppress noisy third-party libraries (only show WARNING+)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("psycopg2").setLevel(logging.WARNING)
    logging.getLogger("pyvelociraptor").setLevel(logging.WARNING)
    logging.getLogger("grpc").setLevel(logging.WARNING)

    # Suppress urllib3 InsecureRequestWarning (self-signed certs)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name."""
    return logging.getLogger(name)
