"""
SIEM Event Models

Defines the data models for SIEM events and related entities.
"""
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, HttpUrl, IPvAnyAddress, validator
import uuid

class SIEMEventSeverity(str, Enum):
    """Severity levels for SIEM events."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"
    EMERGENCY = "EMERGENCY"

class SIEMEventCategory(str, Enum):
    """Categories for SIEM events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    DATABASE = "database"
    STORAGE = "storage"
    CRYPTO = "cryptographic"
    FILE = "file"
    USER = "user"
    SECURITY = "security"
    AUDIT = "audit"
    COMPLIANCE = "compliance"

class SIEMEventSource:
    """Source of a SIEM event."""
    
    def __init__(
        self,
        ip_address: Optional[str] = None,
        hostname: Optional[str] = None,
        service: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        self.ip_address = ip_address
        self.hostname = hostname
        self.service = service
        self.user_id = user_id
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "service": self.service,
            "user_id": self.user_id
        }

class SIEMEventTarget:
    """Target of a SIEM event."""
    
    def __init__(
        self,
        type: str,
        id: Optional[str] = None,
        name: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        self.type = type
        self.id = id
        self.name = name
        self.ip_address = ip_address
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address
        }

class SIEMEvent:
    """SIEM event model."""
    
    def __init__(
        self,
        event_type: str,
        message: str,
        severity: SIEMEventSeverity = SIEMEventSeverity.INFO,
        category: SIEMEventCategory = SIEMEventCategory.APPLICATION,
        source: Optional[SIEMEventSource] = None,
        target: Optional[SIEMEventTarget] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        self.event_type = event_type
        self.message = message
        self.severity = severity
        self.category = category
        self.source = source or SIEMEventSource()
        self.target = target
        self.metadata = metadata or {}
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        return {
            "event_type": self.event_type,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "source": self.source.to_dict() if self.source else None,
            "target": self.target.to_dict() if self.target else None,
            "metadata": self.metadata
        }