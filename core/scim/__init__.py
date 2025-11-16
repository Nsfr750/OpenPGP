"""
SCIM 2.0 Provisioning Module for OpenPGP

This module implements the System for Cross-domain Identity Management (SCIM) 2.0 protocol
for user and group provisioning.
"""

__version__ = "1.0.0"

from .client import SCIMClient, scim_client
from .server import SCIMServer
from .router import router as scim_router
from .models import User, Group, ListResponse, SCIMResourceType, ResourceType, ServiceProviderConfig, Schema
from .exceptions import SCIMError, SCIMValidationError, SCIMNotFoundError, SCIMConflictError, SCIMBadRequestError

__all__ = [
    'SCIMClient',
    'scim_client',
    'SCIMServer',
    'scim_router',
    'User',
    'Group',
    'ListResponse',
    'SCIMResourceType',
    'ResourceType',
    'ServiceProviderConfig',
    'Schema',
    'SCIMError',
    'SCIMValidationError',
    'SCIMNotFoundError',
    'SCIMConflictError',
    'SCIMBadRequestError'
]
