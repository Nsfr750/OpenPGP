"""
Authentication Models

This module defines the core authentication models for the application.
"""
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    """User roles in the system."""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class UserBase(BaseModel):
    """Base user model with common fields."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_-]+$')
    email: EmailStr
    full_name: Optional[str] = None
    disabled: bool = False
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.PENDING

class UserCreate(UserBase):
    """Model for creating a new user (includes password)."""
    password: str = Field(..., min_length=8, max_length=100)

class UserUpdate(BaseModel):
    """Model for updating user information."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None

class UserInDB(UserBase):
    """User model for database storage."""
    id: str
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        orm_mode = True

class User(UserInDB):
    """User model for API responses."""
    pass

class Group(BaseModel):
    """Group model for organizing users."""
    id: str
    name: str
    description: Optional[str] = None
    members: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        orm_mode = True

class Token(BaseModel):
    """Authentication token model."""
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """Token payload model."""
    username: Optional[str] = None
    scopes: List[str] = []
