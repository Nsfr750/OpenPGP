"""
SIEM Client for OpenPGP

This module provides a client for interacting with SIEM (Security Information and Event Management) systems.
"""
import httpx
from typing import Dict, Any, Optional, List, Union, AsyncGenerator
from datetime import datetime
import json
from .exceptions import SIEMError
import asyncio

class SIEMClient:
    """Client for interacting with SIEM systems."""
    
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """Initialize the SIEM client.
        
        Args:
            base_url: Base URL of the SIEM API
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get the default headers for requests."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send a single security event to the SIEM.
        
        Args:
            event: The security event to send
            
        Returns:
            bool: True if the event was successfully sent
            
        Raises:
            SIEMError: If there was an error sending the event
        """
        url = f"{self.base_url}/api/v1/events"
        try:
            response = await self.client.post(
                url,
                json=event,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return True
        except httpx.HTTPStatusError as e:
            raise SIEMError(f"Failed to send event: {e.response.text}") from e
    
    async def search_events(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search for security events.
        
        Args:
            query: Search query string
            start_time: Optional start time for the search window
            end_time: Optional end time for the search window
            limit: Maximum number of results to return
            
        Returns:
            List of matching security events
            
        Raises:
            SIEMError: If there was an error searching for events
        """
        url = f"{self.base_url}/api/v1/events/search"
        params = {"q": query, "limit": limit}
        
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
            
        try:
            response = await self.client.get(
                url,
                params=params,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json().get("events", [])
        except httpx.HTTPStatusError as e:
            raise SIEMError(f"Failed to search events: {e.response.text}") from e
    
    async def stream_events(
        self,
        query: str,
        batch_size: int = 100,
        poll_interval: int = 5
    ) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Stream security events in real-time.
        
        Args:
            query: Search query string
            batch_size: Number of events to return in each batch
            poll_interval: Time to wait between polls in seconds
            
        Yields:
            Batches of security events
        """
        last_seen = datetime.utcnow().isoformat() + "Z"
        
        while True:
            try:
                events = await self.search_events(
                    query=f"{query} AND timestamp>\"{last_seen}\"",
                    limit=batch_size
                )
                
                if events:
                    last_seen = events[-1].get("timestamp", last_seen)
                    yield events
                
                await asyncio.sleep(poll_interval)
                
            except Exception as e:
                print(f"Error in event stream: {e}")
                await asyncio.sleep(poll_interval * 2)  # Back off on error
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

# Singleton instance
siem_client: Optional[SIEMClient] = None

def init_siem_client(base_url: str, api_key: Optional[str] = None) -> None:
    """Initialize the global SIEM client.
    
    Args:
        base_url: Base URL of the SIEM API
        api_key: Optional API key for authentication
    """
    global siem_client
    siem_client = SIEMClient(base_url, api_key)