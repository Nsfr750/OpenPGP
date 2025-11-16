"""
SCIM 2.0 Exceptions

Defines custom exceptions for SCIM 2.0 operations.
"""
from typing import Optional, Dict, Any

class SCIMError(Exception):
    """Base exception for all SCIM-related errors."""
    def __init__(
        self,
        detail: str,
        status: int = 400,
        scim_type: Optional[str] = None,
        **kwargs: Any
    ):
        self.detail = detail
        self.status = status
        self.scim_type = scim_type
        self.extra = kwargs
        super().__init__(detail)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the exception to a SCIM error response."""
        error = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": self.detail,
            "status": str(self.status)
        }
        if self.scim_type:
            error["scimType"] = self.scim_type
        if self.extra:
            error.update(self.extra)
        return error

class SCIMClientError(SCIMError):
    """Raised when there is an error in the SCIM client."""
    def __init__(self, detail: str, status: int = 400, **kwargs: Any):
        super().__init__(detail=detail, status=status, **kwargs)

class SCIMValidationError(SCIMError):
    """Raised when SCIM request validation fails."""
    def __init__(self, detail: str = "Request is unparsable, syntactically incorrect, or violates schema", **kwargs: Any):
        super().__init__(
            detail=detail,
            status=400,
            scim_type="invalidSyntax",
            **kwargs
        )

class SCIMBadRequestError(SCIMError):
    """Raised when the request is malformed or invalid."""
    def __init__(self, detail: str = "Bad request", scim_type: Optional[str] = None, **kwargs: Any):
        super().__init__(
            detail=detail,
            status=400,
            scim_type=scim_type,
            **kwargs
        )

class SCIMNotFoundError(SCIMError):
    """Raised when a requested resource is not found."""
    def __init__(self, detail: str = "Resource not found", **kwargs: Any):
        super().__init__(detail=detail, status=404, **kwargs)

class SCIMConflictError(SCIMError):
    """Raised when a resource already exists."""
    def __init__(self, detail: str = "Resource already exists", **kwargs: Any):
        super().__init__(detail=detail, status=409, scim_type="uniqueness", **kwargs)

class SCIMNotImplementedError(SCIMError):
    """Raised when a requested feature is not implemented."""
    def __init__(self, detail: str = "Not implemented", **kwargs: Any):
        super().__init__(detail=detail, status=501, **kwargs)

class SCIMAuthenticationError(SCIMError):
    """Raised when authentication fails."""
    def __init__(self, detail: str = "Authentication failed", **kwargs: Any):
        super().__init__(detail=detail, status=401, **kwargs)

class SCIMAuthorizationError(SCIMError):
    """Raised when authorization fails."""
    def __init__(self, detail: str = "Insufficient permissions", **kwargs: Any):
        super().__init__(detail=detail, status=403, **kwargs)

class SCIMRateLimitExceededError(SCIMError):
    """Raised when rate limits are exceeded."""
    def __init__(self, detail: str = "Rate limit exceeded", retry_after: int = 60, **kwargs: Any):
        headers = {"Retry-After": str(retry_after)}
        if "headers" in kwargs:
            kwargs["headers"].update(headers)
        else:
            kwargs["headers"] = headers
        super().__init__(detail=detail, status=429, **kwargs)
