"""
Authentication Module

This module provides authentication and authorization functionality.
"""

from .dependencies import (
    get_current_user,
    get_current_active_user,
    get_current_admin_user,
    oauth2_scheme
)

from .models import (
    UserRole,
    UserStatus,
    UserBase,
    UserCreate,
    UserUpdate,
    UserInDB,
    User,
    Group,
    Token,
    TokenData
)

from .oauth2 import OAuth2Config, OAuth2Client

__all__ = [
    'get_current_user',
    'get_current_active_user',
    'get_current_admin_user',
    'oauth2_scheme',
    'UserRole',
    'UserStatus',
    'UserBase',
    'UserCreate',
    'UserUpdate',
    'UserInDB',
    'User',
    'Group',
    'Token',
    'TokenData',
    'OAuth2Config',
    'OAuth2Client'
]