# core/compliance/__init__.py
"""
Compliance Module

This module provides automated compliance with GDPR, CCPA, and other data protection regulations.
"""

from .gdpr import GDPRCompliance
from .ccpa import CCPACompliance
from .base import DataSubjectRequest, DataProcessingActivity
from .data_sovereignty import DataSovereigntyManager, DataJurisdiction, DataResidencyRule

__all__ = [
    'GDPRCompliance', 
    'CCPACompliance', 
    'DataSubjectRequest', 
    'DataProcessingActivity',
    'DataSovereigntyManager',
    'DataJurisdiction',
    'DataResidencyRule'
]