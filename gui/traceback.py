"""
Traceback Logger (PySide6 Version)

This module provides enhanced exception handling and logging for the OpenPGP application.
It captures uncaught exceptions and logs them to a file with timestamps.

License: GPL v3.0 (see LICENSE)
"""

import sys
import traceback as _std_traceback
import datetime
import os
from pathlib import Path
from typing import Optional, Type, Any

# Define log file path in a platform-appropriate location
LOG_DIR = os.path.join(str(Path.home()), ".openpgp_gui")
LOG_FILE = os.path.join(LOG_DIR, "traceback.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

class ExceptionLogger:
    """A class to handle exception logging with timestamps and formatting."""
    
    @staticmethod
    def log_exception(exc_type: Type[BaseException], 
                     exc_value: BaseException, 
                     exc_tb: Any) -> None:
        """
        Log uncaught exceptions with timestamps to the log file.
        
        Args:
            exc_type: The type of the exception
            exc_value: The exception instance
            exc_tb: The traceback object
        """
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Format the exception
        exc_lines = _std_traceback.format_exception(exc_type, exc_value, exc_tb)
        formatted_exc = ''.join(exc_lines)
        
        # Log to file
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n\n[ERROR] [{timestamp}] Uncaught exception:\n{formatted_exc}")
        except Exception as e:
            # If we can't write to the log file, print to stderr as a fallback
            print(f"Failed to write to log file: {e}", file=sys.stderr)
            print(f"[ERROR] [{timestamp}] Uncaught exception:", file=sys.stderr)
            _std_traceback.print_exception(exc_type, exc_value, exc_tb, file=sys.stderr)
    
    @staticmethod
    def log_info(message: str) -> None:
        """Log an informational message."""
        ExceptionLogger._log_message("INFO", message)
    
    @staticmethod
    def log_warning(message: str) -> None:
        """Log a warning message."""
        ExceptionLogger._log_message("WARNING", message)
    
    @staticmethod
    def log_error(message: str) -> None:
        """Log an error message."""
        ExceptionLogger._log_message("ERROR", message)
    
    @staticmethod
    def _log_message(level: str, message: str) -> None:
        """Internal method to log a message with the specified level."""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"\n[{level}] [{timestamp}] {message}")
        except Exception as e:
            print(f"Failed to write to log file: {e}", file=sys.stderr)
            print(f"[{level}] [{timestamp}] {message}", file=sys.stderr)

# Set up global exception hook
def setup_exception_hook():
    """Set up the global exception hook to use our custom logger."""
    def handle_exception(exc_type, exc_value, exc_tb):
        ExceptionLogger.log_exception(exc_type, exc_value, exc_tb)
        
        # Call the standard exception hook as well
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    
    sys.excepthook = handle_exception

# Initialize the exception handler when this module is imported
setup_exception_hook()

# For backward compatibility
log_exception = ExceptionLogger.log_exception
get_traceback_module = lambda: _std_traceback
