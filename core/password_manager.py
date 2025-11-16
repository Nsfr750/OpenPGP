"""
Secure Password Manager Integration for OpenPGP

This module provides secure password management with encryption and integration
with popular password managers like Bitwarden, 1Password, and KeePass.
"""
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum, auto
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass

logger = logging.getLogger(__name__)

class PasswordManagerType(Enum):
    BITWARDEN = "bitwarden"
    ONEPASSWORD = "1password"
    KEEPASS = "keepass"
    NATIVE = "native"  # Built-in password manager

class PasswordStrength(Enum):
    WEAK = auto()
    MEDIUM = auto()
    STRONG = auto()
    VERY_STRONG = auto()

@dataclass
class PasswordEntry:
    """Represents a single password entry in the password manager."""
    id: str
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = None
    last_modified: Optional[float] = None
    created: Optional[float] = None

class PasswordManagerError(Exception):
    """Base exception for password manager errors."""
    pass

class PasswordManagerNotConfigured(PasswordManagerError):
    """Raised when the password manager is not properly configured."""
    pass

class PasswordManagerAuthError(PasswordManagerError):
    """Raised when authentication with the password manager fails."""
    pass

class SecurePasswordManager:
    """Secure password manager with support for multiple backends."""
    
    def __init__(self, manager_type: PasswordManagerType = PasswordManagerType.NATIVE):
        """
        Initialize the password manager.
        
        Args:
            manager_type: Type of password manager to use
        """
        self.manager_type = manager_type
        self.fernet = None
        self.initialized = False
        
    def initialize(self, master_password: Optional[str] = None) -> None:
        """
        Initialize the password manager with a master password.
        
        Args:
            master_password: Master password for the native password manager.
                           Not required for external managers like Bitwarden.
        """
        if self.manager_type == PasswordManagerType.NATIVE:
            if not master_password:
                master_password = getpass.getpass("Enter master password: ")
            self._init_native_manager(master_password)
        else:
            self._init_external_manager()
        self.initialized = True
    
    def _init_native_manager(self, master_password: str) -> None:
        """Initialize the native password manager with encryption."""
        # Derive a key from the master password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(key)
        
        # Create storage directory if it doesn't exist
        self.storage_dir = Path.home() / ".openpgp" / "password_manager"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Save salt for future use
        with open(self.storage_dir / "salt.bin", "wb") as f:
            f.write(salt)
    
    def _init_external_manager(self) -> None:
        """Initialize connection to an external password manager."""
        if self.manager_type == PasswordManagerType.BITWARDEN:
            # Check if bw CLI is installed and logged in
            try:
                result = subprocess.run(["bw", "status"], capture_output=True, text=True)
                status = json.loads(result.stdout)
                if status.get("status") != "unlocked":
                    raise PasswordManagerAuthError("Bitwarden CLI is not logged in")
            except (subprocess.SubprocessError, json.JSONDecodeError) as e:
                raise PasswordManagerNotConfigured(
                    "Bitwarden CLI is not properly configured"
                ) from e
    
    def add_password(self, entry: PasswordEntry) -> str:
        """
        Add a new password entry.
        
        Args:
            entry: Password entry to add
            
        Returns:
            ID of the created entry
        """
        if not self.initialized:
            raise PasswordManagerError("Password manager not initialized")
            
        if self.manager_type == PasswordManagerType.NATIVE:
            return self._add_native_password(entry)
        elif self.manager_type == PasswordManagerType.BITWARDEN:
            return self._add_bitwarden_password(entry)
        else:
            raise NotImplementedError(
                f"{self.manager_type.value} is not yet implemented"
            )
    
    def _add_native_password(self, entry: PasswordEntry) -> str:
        """Add a password entry to the native password manager."""
        if not entry.id:
            entry.id = os.urandom(16).hex()
        
        # Encrypt sensitive data
        encrypted_data = {
            'id': entry.id,
            'name': entry.name,
            'username': self.fernet.encrypt(entry.username.encode()).decode() if entry.username else None,
            'password': self.fernet.encrypt(entry.password.encode()).decode() if entry.password else None,
            'url': entry.url,
            'notes': self.fernet.encrypt(entry.notes.encode()).decode() if entry.notes else None,
            'tags': entry.tags or [],
            'last_modified': entry.last_modified,
            'created': entry.created or time.time()
        }
        
        # Save to file
        entry_file = self.storage_dir / f"{entry.id}.json"
        with open(entry_file, 'w') as f:
            json.dump(encrypted_data, f)
            
        return entry.id
    
    def _add_bitwarden_password(self, entry: PasswordEntry) -> str:
        """Add a password entry to Bitwarden."""
        try:
            # Prepare the item data for Bitwarden
            item = {
                "organizationId": None,
                "collectionIds": None,
                "folderId": None,
                "type": 1,  # Login type
                "name": entry.name,
                "notes": entry.notes,
                "favorite": False,
                "login": {
                    "uris": [{"match": None, "uri": entry.url}] if entry.url else [],
                    "username": entry.username,
                    "password": entry.password,
                    "totp": None
                }
            }
            
            # Use Bitwarden CLI to create the item
            result = subprocess.run(
                ["bw", "create", "item"],
                input=json.dumps(item),
                text=True,
                capture_output=True
            )
            
            if result.returncode != 0:
                raise PasswordManagerError(f"Failed to add password: {result.stderr}")
                
            # Extract and return the new item ID
            response = json.loads(result.stdout)
            return response["id"]
            
        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError) as e:
            raise PasswordManagerError(f"Failed to add password: {str(e)}") from e
    
    def get_password(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Retrieve a password entry by ID.
        
        Args:
            entry_id: ID of the password entry to retrieve
            
        Returns:
            PasswordEntry if found, None otherwise
        """
        if not self.initialized:
            raise PasswordManagerError("Password manager not initialized")
            
        if self.manager_type == PasswordManagerType.NATIVE:
            return self._get_native_password(entry_id)
        elif self.manager_type == PasswordManagerType.BITWARDEN:
            return self._get_bitwarden_password(entry_id)
        else:
            raise NotImplementedError(
                f"{self.manager_type.value} is not yet implemented"
            )
    
    def _get_native_password(self, entry_id: str) -> Optional[PasswordEntry]:
        """Retrieve a password entry from the native password manager."""
        entry_file = self.storage_dir / f"{entry_id}.json"
        if not entry_file.exists():
            return None
            
        with open(entry_file, 'r') as f:
            encrypted_data = json.load(f)
        
        # Decrypt sensitive data
        try:
            return PasswordEntry(
                id=encrypted_data['id'],
                name=encrypted_data['name'],
                username=self.fernet.decrypt(encrypted_data['username'].encode()).decode() 
                    if encrypted_data.get('username') else None,
                password=self.fernet.decrypt(encrypted_data['password'].encode()).decode() 
                    if encrypted_data.get('password') else None,
                url=encrypted_data.get('url'),
                notes=self.fernet.decrypt(encrypted_data['notes'].encode()).decode() 
                    if encrypted_data.get('notes') else None,
                tags=encrypted_data.get('tags', []),
                last_modified=encrypted_data.get('last_modified'),
                created=encrypted_data.get('created')
            )
        except Exception as e:
            logger.error(f"Failed to decrypt password entry: {e}")
            raise PasswordManagerError("Failed to decrypt password entry") from e
    
    def _get_bitwarden_password(self, entry_id: str) -> Optional[PasswordEntry]:
        """Retrieve a password entry from Bitwarden."""
        try:
            result = subprocess.run(
                ["bw", "get", "item", entry_id],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get password: {result.stderr}")
                return None
                
            item = json.loads(result.stdout)
            login = item.get("login", {})
            
            return PasswordEntry(
                id=item["id"],
                name=item["name"],
                username=login.get("username"),
                password=login.get("password"),
                url=login.get("uris", [{}])[0].get("uri") if login.get("uris") else None,
                notes=item.get("notes"),
                tags=item.get("collectionIds", []),
                last_modified=item.get("revisionDate"),
                created=item.get("creationDate")
            )
            
        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to get password: {e}")
            return None
    
    @staticmethod
    def check_password_strength(password: str) -> PasswordStrength:
        """
        Check the strength of a password.
        
        Args:
            password: Password to check
            
        Returns:
            PasswordStrength enum indicating the password strength
        """
        if not password:
            return PasswordStrength.WEAK
            
        score = 0
        
        # Length check
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
            
        # Character diversity
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(not c.isalnum() for c in password):
            score += 1
            
        # Common password check (simplified)
        common_passwords = [
            'password', '123456', '123456789', '12345', 'qwerty',
            '12345678', '111111', '1234567', '123123', '1234567890'
        ]
        if password.lower() in common_passwords:
            score = 0
            
        # Determine strength
        if score < 3:
            return PasswordStrength.WEAK
        elif score < 5:
            return PasswordStrength.MEDIUM
        elif score < 7:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG
    
    def generate_password(
        self, 
        length: int = 20, 
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_special: bool = True
    ) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Length of the password
            include_upper: Include uppercase letters
            include_lower: Include lowercase letters
            include_digits: Include digits
            include_special: Include special characters
            
        Returns:
            Generated password
        """
        import string
        import random
        
        chars = ""
        if include_lower:
            chars += string.ascii_lowercase
        if include_upper:
            chars += string.ascii_uppercase
        if include_digits:
            chars += string.digits
        if include_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
        if not chars:
            raise ValueError("At least one character set must be selected")
            
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))
