# core/siem/config.py
from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class SIEMSettings(BaseSettings):
    ENABLED: bool = os.getenv("SIEM_ENABLED", "true").lower() == "true"
    LOG_LEVEL: str = os.getenv("SIEM_LOG_LEVEL", "INFO").upper()
    HANDLERS: List[str] = os.getenv("SIEM_HANDLERS", "console,file").split(",")
    
    # Console handler settings
    CONSOLE_FORMAT: str = os.getenv(
        "SIEM_CONSOLE_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # File handler settings
    LOG_FILE: str = os.getenv("SIEM_LOG_FILE", "security_events.log")
    FILE_FORMAT: str = os.getenv(
        "SIEM_FILE_FORMAT",
        '{"time": "%(asctime)s", "level": "%(levelname)s", "event": %(message)s}'
    )
    
    # HTTP handler settings
    HTTP_ENDPOINT: Optional[str] = os.getenv("SIEM_HTTP_ENDPOINT")
    HTTP_AUTH_TOKEN: Optional[str] = os.getenv("SIEM_HTTP_AUTH_TOKEN")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

siem_settings = SIEMSettings()