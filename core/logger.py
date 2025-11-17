"""
Logging configuration and utilities for the application.
"""
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List

# Determine if running as compiled executable
IS_COMPILED = getattr(sys, 'frozen', False)

# Get the application directory
if IS_COMPILED:
    # If compiled, use the directory where the executable is located
    APP_DIR = Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path(sys.executable).parent
else:
    # In development, use the project root
    APP_DIR = Path(__file__).parent.parent

# Logging configuration
LOG_DIR = APP_DIR / "logs"
LOG_FILE_PREFIX = "application"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_LOG_LEVEL = logging.INFO

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def _get_log_file_path() -> str:
    """Get the log file path for the current day.
    
    Returns:
        str: Path to the log file for the current day
    """
    today = datetime.now().strftime('%Y-%m-%d')
    log_file = f'{LOG_FILE_PREFIX}_{today}.log'
    return str(LOG_DIR / log_file)

def set_log_file_prefix(prefix: str) -> None:
    """Set a custom prefix for log files.
    
    Args:
        prefix: Prefix to use for log files
    """
    global LOG_FILE_PREFIX
    LOG_FILE_PREFIX = prefix

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
    
    # Don't add handlers if they're already configured
    if logger.handlers:
        return logger
    
    # Set log level
    logger.setLevel(log_level if log_level is not None else DEFAULT_LOG_LEVEL)
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler with daily rotation
    log_file = _get_log_file_path()
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

def get_log_files() -> List[Path]:
    """Get a list of log files in the log directory.
    
    Returns:
        List of Path objects for log files, sorted by modification time (newest first)
    """
    try:
        log_dir = Path(LOG_DIR)
        if not log_dir.exists():
            return []
            
        # Get all log files with the prefix_*.log pattern
        log_files = [f for f in log_dir.glob(f'{LOG_FILE_PREFIX}_*.log') if f.is_file()]
        
        # Sort by modification time (newest first)
        log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        return log_files
    except Exception as e:
        logger.error(f'Error getting log files: {e}')
        return []

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

# Create __init__.py in core directory if it doesn't exist (development only)
if not IS_COMPILED:
    core_init_path = Path(__file__).parent / "__init__.py"
    if not core_init_path.exists():
        try:
            with open(core_init_path, 'w') as f:
                f.write('"""Core package for OpenPGP application."""\n')
        except Exception as e:
            print(f"Warning: Could not create __init__.py: {e}")

__all__ = [
    'logger',
    'log_info',
    'log_error',
    'log_warning',
    'log_debug',
    'log_exception',
    'setup_logger'
]
