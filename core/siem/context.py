# core/siem/context.py
import contextvars
from typing import Optional, Dict, Any

# Context variables for request tracking
current_request_id = contextvars.ContextVar("request_id", default=None)
current_user_id = contextvars.ContextVar("user_id", default=None)
current_ip_address = contextvars.ContextVar("ip_address", default=None)

class SecurityContext:
    """Context manager for security event tracking."""
    
    def __init__(
        self,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        self.request_id = request_id
        self.user_id = user_id
        self.ip_address = ip_address
        self._token = None
    
    def __enter__(self):
        if self.request_id:
            self._token = current_request_id.set(self.request_id)
        if self.user_id:
            self._token = current_user_id.set(self.user_id)
        if self.ip_address:
            self._token = current_ip_address.set(self.ip_address)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._token:
            if self.request_id:
                current_request_id.reset(self._token)
            if self.user_id:
                current_user_id.reset(self._token)
            if self.ip_address:
                current_ip_address.reset(self._token)
    
    @classmethod
    def get_current_context(cls) -> Dict[str, Any]:
        """Get the current security context."""
        return {
            "request_id": current_request_id.get(),
            "user_id": current_user_id.get(),
            "ip_address": current_ip_address.get()
        }