"""
Logging utilities for the OpenPGP application.
Provides functions for logging messages with different severity levels.
"""

import os
import sys
import traceback
from pathlib import Path
from datetime import datetime
from typing import List

# Default log file path
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'application.log')

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def set_log_file(path: str) -> None:
    """Set the log file path.
    
    Args:
        path: Path to the log file (can be relative or absolute)
    """
    global LOG_FILE, LOG_DIR
    
    # Convert to absolute path
    abs_path = os.path.abspath(path)
    LOG_DIR = os.path.dirname(abs_path)
    LOG_FILE = abs_path
    
    # Create the directory if it doesn't exist
    os.makedirs(LOG_DIR, exist_ok=True)

def log_info(msg: str) -> None:
    """Log an informational message.
    
    Args:
        msg: The message to log
    """
    log_message = f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] [INFO] {msg}'
    print(log_message)
    _write_to_log(log_message)

def log_warning(msg: str) -> None:
    """Log a warning message.
    
    Args:
        msg: The warning message to log
    """
    log_message = f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] [WARNING] {msg}'
    print(log_message)
    _write_to_log(log_message)

def log_error(msg: str) -> None:
    """Log an error message.
    
    Args:
        msg: The error message to log
    """
    log_message = f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] [ERROR] {msg}'
    print(log_message, file=sys.stderr)
    _write_to_log(log_message)

def log_exception(e: Exception) -> None:
    """Log an exception with traceback.
    
    Args:
        e: The exception to log
    """
    exc_info = sys.exc_info()
    tb_lines = traceback.format_exception(exc_info[0], exc_info[1], exc_info[2])
    tb_text = ''.join(tb_lines)
    log_message = f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] [EXCEPTION] {str(e)}\n{tb_text}'
    print(log_message, file=sys.stderr)
    _write_to_log(log_message)

def get_log_files() -> List[Path]:
    """Get a list of log files in the log directory.
    
    Returns:
        List of Path objects for log files, sorted by modification time (newest first)
    """
    try:
        log_dir = Path(LOG_DIR)
        if not log_dir.exists():
            return []
            
        # Get all .log files in the log directory
        log_files = list(log_dir.glob('*.log'))
        
        # Sort by modification time (newest first)
        log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        return log_files
    except Exception as e:
        print(f'Error getting log files: {e}', file=sys.stderr)
        return []

def _write_to_log(message: str) -> None:
    """Write a message to the log file.
    
    Args:
        message: The message to write to the log file
    """
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(message + '\n')
    except Exception as e:
        print(f'Failed to write to log file: {e}', file=sys.stderr)
