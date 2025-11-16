# core/scim/server.py
"""
SCIM 2.0 Server Implementation

Implements the SCIM 2.0 protocol server with OAuth 2.0 and API key authentication.
"""
import os
import json
import base64
from typing import Dict, List, Optional, Any, Union
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel, HttpUrl
from .models import User, Group, ListResponse, SCIMResourceType
from .exceptions import SCIMError, SCIMNotFoundError, SCIMValidationError
from core.auth.oauth2 import OAuth2Config, OAuth2Client
from core.auth.models import User as SystemUser, Group as SystemGroup

class SCIMServer:
    """SCIM 2.0 Server implementation with authentication."""
    
    def __init__(self, app: FastAPI, base_url: str, auth_method: str = "oauth2"):
        """
        Initialize the SCIM server.
        
        Args:
            app: FastAPI application instance
            base_url: Base URL for SCIM endpoints
            auth_method: Authentication method ('oauth2' or 'api_key')
        """
        self.app = app
        self.base_url = base_url.rstrip('/')
        self.auth_method = auth_method
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        self.api_key_scheme = APIKeyHeader(name="Authorization")
        
        # Register routes
        self._register_routes()
        
    async def authenticate(self, request: Request) -> bool:
        """Authenticate the request using the configured method."""
        if self.auth_method == "oauth2":
            token = await self.oauth2_scheme(request)
            return await self._validate_oauth2_token(token)
        else:
            api_key = await self.api_key_scheme(request)
            return await self._validate_api_key(api_key)
    
    async def _validate_oauth2_token(self, token: str) -> bool:
        """Validate OAuth 2.0 token."""
        oauth2_config = OAuth2Config()
        oauth2_client = OAuth2Client(oauth2_config)
        return await oauth2_client.validate_token(token)
    
    async def _validate_api_key(self, api_key: str) -> bool:
        """Validate API key."""
        # Implement API key validation logic
        # This is a placeholder - replace with your actual API key validation
        return api_key == os.getenv("SCIM_API_KEY")
    
    def _register_routes(self):
        """Register SCIM API routes."""
        @self.app.get(f"{self.base_url}/.well-known/scim")
        async def service_provider_config():
            """SCIM Service Provider Configuration."""
            return {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 100},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [
                    {
                        "type": "oauth2",
                        "name": "OAuth 2.0",
                        "description": "OAuth 2.0 Bearer Token",
                        "specUri": "https://tools.ietf.org/html/rfc6749"
                    },
                    {
                        "type": "apiKey",
                        "name": "API Key",
                        "description": "API Key Authentication"
                    }
                ]
            }
        
        # User endpoints
        @self.app.post(f"{self.base_url}/Users")
        async def create_user(user: User, _ = Depends(self.authenticate)):
            """Create a new user."""
            return await self._create_user(user)
            
        @self.app.get(f"{self.base_url}/Users/{{user_id}}")
        async def get_user(user_id: str, _ = Depends(self.authenticate)):
            """Get a user by ID."""
            return await self._get_user(user_id)
            
        # Group endpoints
        @self.app.post(f"{self.base_url}/Groups")
        async def create_group(group: Group, _ = Depends(self.authenticate)):
            """Create a new group."""
            return await self._create_group(group)
            
        @self.app.get(f"{self.base_url}/Groups/{{group_id}}")
        async def get_group(group_id: str, _ = Depends(self.authenticate)):
            """Get a group by ID."""
            return await self._get_group(group_id)
    
    # Implementation methods
    async def _create_user(self, user: User) -> Dict[str, Any]:
        """Create a new user in the system."""
        system_user = SystemUser(
            username=user.user_name,
            email=user.emails[0].value if user.emails else None,
            first_name=user.name.given_name if user.name else None,
            last_name=user.name.family_name if user.name else None,
            active=user.active
        )
        await system_user.save()
        return await self._user_to_scim(system_user)
    
    async def _get_user(self, user_id: str) -> Dict[str, Any]:
        """Get a user from the system."""
        user = await SystemUser.get(user_id)
        if not user:
            raise SCIMNotFoundError(f"User {user_id} not found")
        return await self._user_to_scim(user)
    
    async def _create_group(self, group: Group) -> Dict[str, Any]:
        """Create a new group in the system."""
        system_group = SystemGroup(
            name=group.display_name,
            description=group.external_id
        )
        await system_group.save()
        return await self._group_to_scim(system_group)
    
    async def _get_group(self, group_id: str) -> Dict[str, Any]:
        """Get a group from the system."""
        group = await SystemGroup.get(group_id)
        if not group:
            raise SCIMNotFoundError(f"Group {group_id} not found")
        return await self._group_to_scim(group)
    
    async def _user_to_scim(self, user: SystemUser) -> Dict[str, Any]:
        """Convert system user to SCIM format."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(user.id),
            "userName": user.username,
            "name": {
                "givenName": user.first_name,
                "familyName": user.last_name
            },
            "emails": [{"value": user.email, "primary": True}],
            "active": user.active,
            "meta": {
                "resourceType": "User",
                "created": user.created_at.isoformat(),
                "lastModified": user.updated_at.isoformat(),
                "location": f"{self.base_url}/Users/{user.id}"
            }
        }
    
    async def _group_to_scim(self, group: SystemGroup) -> Dict[str, Any]:
        """Convert system group to SCIM format."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": str(group.id),
            "displayName": group.name,
            "members": [],  # Populate with actual members if needed
            "meta": {
                "resourceType": "Group",
                "created": group.created_at.isoformat(),
                "lastModified": group.updated_at.isoformat(),
                "location": f"{self.base_url}/Groups/{group.id}"
            }
        }