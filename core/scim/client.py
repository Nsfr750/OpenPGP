"""
SCIM 2.0 Client

A client for interacting with SCIM 2.0 compliant identity providers.
"""
import httpx
from typing import Dict, Any, Optional, List, Union
from .models import User, Group, ListResponse
from .exceptions import SCIMClientError

class SCIMClient:
    """SCIM 2.0 client for interacting with the SCIM server."""
    
    def __init__(
        self,
        base_url: str,
        auth_token: Optional[str] = None,
        timeout: int = 30
    ):
        """Initialize the SCIM client.
        
        Args:
            base_url: Base URL of the SCIM server (e.g., 'https://api.example.com/scim/v2')
            auth_token: Optional authentication token
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get the default headers for requests."""
        headers = {
            "Accept": "application/scim+json",
            "Content-Type": "application/scim+json"
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers
    
    async def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        url = f"{self.base_url}/Users/{user_id}"
        response = await self.client.get(url, headers=self._get_headers())
        response.raise_for_status()
        return User(**response.json())
    
    async def create_user(self, user_data: Dict[str, Any]) -> User:
        """Create a new user."""
        url = f"{self.base_url}/Users"
        response = await self.client.post(
            url,
            json=user_data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return User(**response.json())
    
    async def update_user(self, user_id: str, user_data: Dict[str, Any]) -> User:
        """Update an existing user."""
        url = f"{self.base_url}/Users/{user_id}"
        response = await self.client.put(
            url,
            json=user_data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return User(**response.json())
    
    async def delete_user(self, user_id: str) -> bool:
        """Delete a user by ID."""
        url = f"{self.base_url}/Users/{user_id}"
        response = await self.client.delete(url, headers=self._get_headers())
        return response.status_code == 204
    
    async def search_users(
        self,
        filter: Optional[str] = None,
        start_index: int = 1,
        count: int = 100
    ) -> ListResponse:
        """Search for users with optional filtering."""
        params = {
            "startIndex": start_index,
            "count": count
        }
        if filter:
            params["filter"] = filter
            
        url = f"{self.base_url}/Users"
        response = await self.client.get(
            url,
            params=params,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return ListResponse(**response.json())
    
    async def get_group(self, group_id: str) -> Group:
        """Get a group by ID."""
        url = f"{self.base_url}/Groups/{group_id}"
        response = await self.client.get(url, headers=self._get_headers())
        response.raise_for_status()
        return Group(**response.json())
    
    async def create_group(self, group_data: Dict[str, Any]) -> Group:
        """Create a new group."""
        url = f"{self.base_url}/Groups"
        response = await self.client.post(
            url,
            json=group_data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return Group(**response.json())
    
    async def update_group(self, group_id: str, group_data: Dict[str, Any]) -> Group:
        """Update an existing group."""
        url = f"{self.base_url}/Groups/{group_id}"
        response = await self.client.put(
            url,
            json=group_data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return Group(**response.json())
    
    async def delete_group(self, group_id: str) -> bool:
        """Delete a group by ID."""
        url = f"{self.base_url}/Groups/{group_id}"
        response = await self.client.delete(url, headers=self._get_headers())
        return response.status_code == 204
    
    async def search_groups(
        self,
        filter: Optional[str] = None,
        start_index: int = 1,
        count: int = 100
    ) -> ListResponse:
        """Search for groups with optional filtering."""
        params = {
            "startIndex": start_index,
            "count": count
        }
        if filter:
            params["filter"] = filter
            
        url = f"{self.base_url}/Groups"
        response = await self.client.get(
            url,
            params=params,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return ListResponse(**response.json())
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

# Create a singleton instance
siem_client = SCIMClient("http://localhost:8000/scim/v2")
