# core/siem/__init__.py
"""SIEM (Security Information and Event Management) integration for OpenPGP.

This module provides functionality for logging security events and integrating
with SIEM solutions.
"""

from .client import SIEMClient, siem_client
from .logger import SIEMLogger, siem_logger
from .events import SecurityEventType
from .context import SecurityContext
from .middleware import SIEMRequestMiddleware
from .handlers import HTTPSIEMHandler

__all__ = [
    'SIEMClient',
    'siem_client',
    'SIEMLogger',
    'siem_logger',
    'SecurityEventType',
    'SecurityContext',
    'SIEMRequestMiddleware',
    'HTTPSIEMHandler'
]