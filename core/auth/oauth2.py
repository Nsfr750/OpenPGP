# core/auth/oauth2.py
"""
OAuth 2.0 Client for SCIM Authentication
"""
from typing import Optional
from pydantic import BaseModel, HttpUrl
import httpx

class OAuth2Config(BaseModel):
    """OAuth 2.0 configuration."""
    token_introspection_url: str
    client_id: str
    client_secret: str
    scope: str = "scim"

class OAuth2Client:
    """OAuth 2.0 client for token validation."""
    
    def __init__(self, config: OAuth2Config):
        self.config = config
    
    async def validate_token(self, token: str) -> bool:
        """Validate an OAuth 2.0 token."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {self._basic_auth()}"
        }
        data = {
            "token": token,
            "token_type_hint": "access_token"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.token_introspection_url,
                    headers=headers,
                    data=data
                )
                response.raise_for_status()
                token_info = response.json()
                return token_info.get("active", False)
        except Exception as e:
            return False
    
    def _basic_auth(self) -> str:
        """Generate Basic Auth header value."""
        import base64
        auth_str = f"{self.config.client_id}:{self.config.client_secret}"
        return base64.b64encode(auth_str.encode()).decode()