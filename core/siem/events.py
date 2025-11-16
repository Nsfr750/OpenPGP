# core/siem/events.py
from enum import Enum

class SecurityEventType(str, Enum):
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    
    # User management events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    
    # Group management events
    GROUP_CREATED = "group_created"
    GROUP_UPDATED = "group_updated"
    GROUP_DELETED = "group_deleted"
    
    # Key management events
    KEY_GENERATED = "key_generated"
    KEY_REVOKED = "key_revoked"
    KEY_ROTATED = "key_rotated"
    
    # File operations
    FILE_ENCRYPTED = "file_encrypted"
    FILE_DECRYPTED = "file_decrypted"
    FILE_SHARED = "file_shared"
    
    # System events
    CONFIG_CHANGED = "config_changed"
    PERMISSION_CHANGED = "permission_changed"
    SECURITY_ALERT = "security_alert"
    
    # API events
    API_CALL = "api_call"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    @classmethod
    def get_severity(cls, event_type: str) -> str:
        """Get the default severity for an event type."""
        severity_map = {
            # Critical
            cls.SECURITY_ALERT: "CRITICAL",
            # Error
            cls.LOGIN_FAILED: "ERROR",
            cls.USER_LOCKED: "ERROR",
            cls.RATE_LIMIT_EXCEEDED: "ERROR",
            # Warning
            cls.CONFIG_CHANGED: "WARNING",
            cls.PERMISSION_CHANGED: "WARNING",
            # Info (default)
            "DEFAULT": "INFO"
        }
        return severity_map.get(event_type, severity_map["DEFAULT"])