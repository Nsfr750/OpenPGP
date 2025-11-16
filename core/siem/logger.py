# core/siem/logger.py
import logging
import json
import sys
from typing import Dict, Any, Optional
from .config import siem_settings
from .handlers import HTTPSIEMHandler

class SIEMLogger:
    def __init__(self, name: str = "siem"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, siem_settings.LOG_LEVEL))
        self._setup_handlers()
    
    def _setup_handlers(self):
        # Remove existing handlers to avoid duplicates
        self.logger.handlers = []
        
        if "console" in siem_settings.HANDLERS:
            console_handler = logging.StreamHandler(sys.stdout)
            console_formatter = logging.Formatter(siem_settings.CONSOLE_FORMAT)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        if "file" in siem_settings.HANDLERS:
            file_handler = logging.FileHandler(siem_settings.LOG_FILE)
            file_formatter = logging.Formatter(siem_settings.FILE_FORMAT)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        
        if "http" in siem_settings.HANDLERS and siem_settings.HTTP_ENDPOINT:
            http_handler = HTTPSIEMHandler(
                endpoint=siem_settings.HTTP_ENDPOINT,
                auth_token=siem_settings.HTTP_AUTH_TOKEN
            )
            self.logger.addHandler(http_handler)
    
    def log_security_event(
        self,
        event_type: str,
        message: str,
        severity: str = "INFO",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log a security event with structured data."""
        if not siem_settings.ENABLED:
            return
            
        log_data = {
            "event_type": event_type,
            "message": message,
            "severity": severity.upper(),
            "user_id": user_id,
            "ip_address": ip_address,
            "metadata": metadata or {}
        }
        
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(json.dumps(log_data, default=str))

# Create a default instance
siem_logger = SIEMLogger()