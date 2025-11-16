"""
SIEM Integration Exceptions

Defines custom exceptions for the SIEM integration module.
"""
from typing import Optional, Dict, Any

class SIEMError(Exception):
    """Base exception for all SIEM-related errors."""
    def __init__(self, message: str, code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.code:
            return f"{self.code}: {self.message}"
        return self.message

class SIEMConfigurationError(SIEMError):
    """Raised when there is a configuration error with the SIEM integration."""
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        if field:
            message = f"Invalid configuration for '{field}': {message}"
        super().__init__(message=message, code="configuration_error", **kwargs)
        self.field = field

class SIEMConnectionError(SIEMError):
    """Raised when there is a connection error with the SIEM system."""
    def __init__(self, message: str, endpoint: Optional[str] = None, **kwargs):
        if endpoint:
            message = f"Failed to connect to {endpoint}: {message}"
        super().__init__(message=message, code="connection_error", **kwargs)
        self.endpoint = endpoint

class SIEMAuthenticationError(SIEMError):
    """Raised when authentication with the SIEM system fails."""
    def __init__(self, message: str, auth_method: Optional[str] = None, **kwargs):
        if auth_method:
            message = f"Authentication failed using {auth_method}: {message}"
        super().__init__(message=message, code="authentication_error", **kwargs)
        self.auth_method = auth_method

class SIEMRateLimitError(SIEMError):
    """Raised when rate limits are exceeded for the SIEM system."""
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        if retry_after:
            message = f"{message} (retry after {retry_after} seconds)"
        super().__init__(message=message, code="rate_limit_exceeded", **kwargs)
        self.retry_after = retry_after

class SIEMValidationError(SIEMError):
    """Raised when event data fails validation."""
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        if field:
            message = f"Validation error in field '{field}': {message}"
        super().__init__(message=message, code="validation_error", **kwargs)
        self.field = field

class SIEMUnsupportedFeatureError(SIEMError):
    """Raised when a requested feature is not supported by the SIEM system."""
    def __init__(self, feature: str, siem_type: Optional[str] = None, **kwargs):
        message = f"Feature '{feature}' is not supported"
        if siem_type:
            message += f" by {siem_type} SIEM"
        super().__init__(message=message, code="unsupported_feature", **kwargs)
        self.feature = feature
        self.siem_type = siem_type

class SIEMTemporaryError(SIEMError):
    """Raised when a temporary error occurs that might be resolved by retrying."""
    def __init__(self, message: str, retry_after: int = 60, **kwargs):
        super().__init__(
            message=f"Temporary error: {message}",
            code="temporary_error",
            details={"retry_after": retry_after, **kwargs}
        )
        self.retry_after = retry_after
