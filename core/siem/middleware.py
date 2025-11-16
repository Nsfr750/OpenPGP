# core/siem/middleware.py
import uuid
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from .context import SecurityContext, current_request_id, current_user_id, current_ip_address
from .logger import siem_logger

class SIEMRequestMiddleware(BaseHTTPMiddleware):
    """Middleware to capture request information for SIEM logging."""
    
    async def dispatch(self, request: Request, call_next):
        # Generate a unique request ID if not present
        request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        
        # Get IP address from X-Forwarded-For or remote address
        if 'x-forwarded-for' in request.headers:
            ip_address = request.headers['x-forwarded-for'].split(',')[0]
        else:
            ip_address = request.client.host if request.client else "0.0.0.0"
        
        # Get user ID from request (customize based on your auth system)
        user_id = None
        if hasattr(request.state, 'user') and request.state.user:
            user_id = request.state.user.id
        
        # Set up security context
        with SecurityContext(
            request_id=request_id,
            user_id=user_id,
            ip_address=ip_address
        ):
            # Process the request
            response = await call_next(request)
            
            # Log the request
            siem_logger.log_security_event(
                event_type="api_call",
                message=f"API Request: {request.method} {request.url.path}",
                severity="INFO",
                user_id=user_id,
                ip_address=ip_address,
                metadata={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "query_params": dict(request.query_params),
                    "user_agent": request.headers.get('user-agent')
                }
            )
            
            # Add request ID to response headers
            response.headers['X-Request-ID'] = request_id
            return response