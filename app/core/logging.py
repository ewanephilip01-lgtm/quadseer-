"""Structured logging configuration."""
import logging
import sys


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("quadseer")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)

        # Try JSON formatter, fall back to plain text
        try:
            from pythonjsonlogger import jsonlogger
            formatter = jsonlogger.JsonFormatter(
                "%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d"
            )
        except ImportError:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
