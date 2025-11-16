# core/siem/handlers.py
import logging
import json
import httpx
from typing import Dict, Any, Optional

class HTTPSIEMHandler(logging.Handler):
    """Handler that sends logs to a HTTP endpoint."""
    
    def __init__(
        self,
        endpoint: str,
        auth_token: Optional[str] = None,
        timeout: int = 5
    ):
        super().__init__()
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.timeout = timeout
        self._client = None
    
    @property
    def client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client
    
    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers
    
    async def emit(self, record):
        try:
            log_entry = self.format(record)
            log_data = json.loads(log_entry)
            
            await self.client.post(
                self.endpoint,
                json=log_data,
                headers=self.get_headers()
            )
        except Exception as e:
            # Fallback to console if HTTP logging fails
            print(f"Failed to send log to SIEM: {str(e)}")
            print(f"Log entry: {log_entry}")
    
    def close(self):
        if self._client:
            self._client.close()
        super().close()