"""
Logging configuration and utilities for the application.
"""
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

# Create logs directory if it doesn't exist
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Default log format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Default log level
DEFAULT_LOG_LEVEL = logging.INFO

# Configure root logger
def setup_logger(name: Optional[str] = None, log_level: int = None):
    """
    Configure and return a logger with the given name.
    
    Args:
        name: Logger name. If None, returns the root logger.
        log_level: Logging level. If None, uses DEFAULT_LOG_LEVEL.
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    
    if log_level is None:
        log_level = DEFAULT_LOG_LEVEL
    
    logger.setLevel(log_level)
    
    # Don't add handlers if they're already configured
    if logger.handlers:
        return logger
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (rotating)
    log_file = Path(LOG_DIR) / "app.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

# Create default logger
logger = setup_logger(__name__)

def log_info(message: str, *args, **kwargs):
    """Log an info message."""
    logger.info(message, *args, **kwargs)

def log_error(message: str, *args, **kwargs):
    """Log an error message."""
    logger.error(message, *args, **kwargs)

def log_warning(message: str, *args, **kwargs):
    """Log a warning message."""
    logger.warning(message, *args, **kwargs)

def log_debug(message: str, *args, **kwargs):
    """Log a debug message."""
    logger.debug(message, *args, **kwargs)

def log_exception(message: str, *args, **kwargs):
    """Log an exception with stack trace."""
    logger.exception(message, *args, **kwargs)

# Create __init__.py in core directory if it doesn't exist
core_init_path = os.path.join(os.path.dirname(__file__), "__init__.py")
if not os.path.exists(core_init_path):
    with open(core_init_path, 'w') as f:
        f.write('"""Core package for the application."""\n')

__all__ = [
    'logger',
    'log_info',
    'log_error',
    'log_warning',
    'log_debug',
    'log_exception',
    'setup_logger'
]
