# core/secure_file_sharing.py
"""
Secure File Sharing for OpenPGP

This module provides secure file sharing capabilities with end-to-end encryption,
access control, and integrity verification.
"""
import os
import hashlib
import json
import base64
import logging
from typing import Dict, List, Optional, Tuple, Union, BinaryIO, Any
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, auto
import shutil
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag, InvalidSignature
from .advanced_crypto import AdvancedCrypto, EncryptedData

logger = logging.getLogger(__name__)

class FileSharingError(Exception):
    """Base exception for file sharing errors."""
    pass

class AccessDeniedError(FileSharingError):
    """Raised when access to a file is denied."""
    pass

class FileIntegrityError(FileSharingError):
    """Raised when file integrity verification fails."""
    pass

class FileSharingPermission(Enum):
    """File sharing permission levels."""
    READ = auto()
    WRITE = auto()
    SHARE = auto()
    DELETE = auto()
    ADMIN = auto()

@dataclass
class FileMetadata:
    """Metadata for a shared file."""
    file_id: str
    file_name: str
    file_size: int
    file_type: str
    owner_id: str
    created_at: float
    modified_at: float
    expires_at: Optional[float] = None
    max_downloads: Optional[int] = None
    download_count: int = 0
    is_encrypted: bool = True
    encryption_algorithm: str = 'aes-256-gcm'
    hmac_algorithm: str = 'sha256'
    tags: List[str] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    access_control: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class FileSharingLink:
    """A shareable link for a file."""
    link_id: str
    file_id: str
    created_by: str
    created_at: float
    expires_at: Optional[float] = None
    max_uses: Optional[int] = None
    use_count: int = 0
    password_protected: bool = False
    access_level: str = 'read'
    metadata: Dict[str, Any] = field(default_factory=dict)

class SecureFileSharing:
    """Secure file sharing with encryption and access control."""
    
    def __init__(self, storage_dir: str, crypto: Optional[AdvancedCrypto] = None):
        """
        Initialize the secure file sharing system.
        
        Args:
            storage_dir: Base directory for storing encrypted files and metadata
            crypto: Optional AdvancedCrypto instance
        """
        self.storage_dir = Path(storage_dir)
        self.crypto = crypto or AdvancedCrypto()
        self.metadata_dir = self.storage_dir / 'metadata'
        self.files_dir = self.storage_dir / 'files'
        self.links_dir = self.storage_dir / 'links'
        
        # Create necessary directories
        for directory in [self.metadata_dir, self.files_dir, self.links_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def upload_file(self, file_path: Union[str, Path], owner_id: str,
                   encryption_key: Optional[bytes] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> FileMetadata:
        """
        Upload and encrypt a file for secure sharing.
        
        Args:
            file_path: Path to the file to upload
            owner_id: ID of the file owner
            encryption_key: Optional encryption key (generated if not provided)
            metadata: Optional file metadata
            
        Returns:
            FileMetadata for the uploaded file
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_id = self._generate_file_id()
        encrypted_file_path = self.files_dir / file_id
        metadata_file = self.metadata_dir / f"{file_id}.json"
        
        # Generate encryption key if not provided
        if encryption_key is None:
            encryption_key = os.urandom(32)  # 256-bit key for AES-256
        
        # Read and encrypt the file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt the file
        encrypted_data = self.crypto.encrypt(
            file_data, encryption_key, 'aes-256-gcm'
        )
        
        # Save the encrypted file
        with open(encrypted_file_path, 'wb') as f:
            if encrypted_data.iv:
                f.write(encrypted_data.iv)
            if encrypted_data.tag:
                f.write(encrypted_data.tag)
            f.write(encrypted_data.ciphertext)
        
        # Create file metadata
        now = time.time()
        file_metadata = FileMetadata(
            file_id=file_id,
            file_name=file_path.name,
            file_size=file_path.stat().st_size,
            file_type=self._guess_mime_type(file_path),
            owner_id=owner_id,
            created_at=now,
            modified_at=now,
            is_encrypted=True,
            encryption_algorithm='aes-256-gcm',
            hmac_algorithm='sha256',
            custom_metadata=metadata or {}
        )
        
        # Save metadata
        self._save_metadata(file_metadata)
        
        return file_metadata
    
    def download_file(self, file_id: str, output_path: Union[str, Path],
                     decryption_key: bytes, verify_integrity: bool = True) -> FileMetadata:
        """
        Download and decrypt a shared file.
        
        Args:
            file_id: ID of the file to download
            output_path: Path to save the decrypted file
            decryption_key: Key to decrypt the file
            verify_integrity: Whether to verify file integrity
            
        Returns:
            Updated file metadata
            
        Raises:
            FileSharingError: If decryption or integrity check fails
        """
        output_path = Path(output_path)
        encrypted_file_path = self.files_dir / file_id
        metadata = self.get_file_metadata(file_id)
        
        if not encrypted_file_path.exists():
            raise FileNotFoundError(f"File not found: {file_id}")
        
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(12)  # 96-bit IV for AES-GCM
            tag = f.read(16)  # 128-bit tag for AES-GCM
            ciphertext = f.read()
        
        # Decrypt the file
        try:
            encrypted_data = EncryptedData(
                ciphertext=ciphertext,
                iv=iv,
                tag=tag,
                algorithm='aes-256-gcm'
            )
            
            decrypted_data = self.crypto.decrypt(encrypted_data, decryption_key)
            
            # Verify integrity if requested
            if verify_integrity:
                self._verify_file_integrity(decrypted_data, metadata)
            
            # Save the decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update download count
            metadata.download_count += 1
            metadata.modified_at = time.time()
            self._save_metadata(metadata)
            
            return metadata
            
        except Exception as e:
            raise FileSharingError(f"Failed to decrypt file: {str(e)}") from e
    
    def create_share_link(self, file_id: str, created_by: str,
                         access_level: str = 'read',
                         expires_in: Optional[int] = None,
                         max_uses: Optional[int] = None,
                         password: Optional[str] = None) -> FileSharingLink:
        """
        Create a shareable link for a file.
        
        Args:
            file_id: ID of the file to share
            created_by: ID of the user creating the link
            access_level: Access level ('read', 'write', etc.)
            expires_in: Link expiration time in seconds
            max_uses: Maximum number of times the link can be used
            password: Optional password to protect the link
            
        Returns:
            FileSharingLink object
        """
        # Verify file exists and user has permission to share it
        metadata = self.get_file_metadata(file_id)
        if metadata.owner_id != created_by and 'admin' not in self._get_user_permissions(created_by, file_id):
            raise AccessDeniedError("You don't have permission to share this file")
        
        link_id = self._generate_link_id()
        now = time.time()
        expires_at = now + expires_in if expires_in else None
        
        link = FileSharingLink(
            link_id=link_id,
            file_id=file_id,
            created_by=created_by,
            created_at=now,
            expires_at=expires_at,
            max_uses=max_uses,
            use_count=0,
            password_protected=bool(password),
            access_level=access_level
        )
        
        # Save the link
        link_path = self.links_dir / f"{link_id}.json"
        with open(link_path, 'w') as f:
            json.dump(self._link_to_dict(link), f)
        
        return link
    
    def get_file_metadata(self, file_id: str) -> FileMetadata:
        """
        Get metadata for a file.
        
        Args:
            file_id: ID of the file
            
        Returns:
            FileMetadata object
        """
        metadata_path = self.metadata_dir / f"{file_id}.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Metadata not found for file: {file_id}")
        
        with open(metadata_path, 'r') as f:
            metadata_dict = json.load(f)
        
        return self._dict_to_file_metadata(metadata_dict)
    
    def update_file_metadata(self, file_id: str, updates: Dict[str, Any],
                           updated_by: str) -> FileMetadata:
        """
        Update file metadata.
        
        Args:
            file_id: ID of the file to update
            updates: Dictionary of fields to update
            updated_by: ID of the user making the update
            
        Returns:
            Updated FileMetadata
        """
        metadata = self.get_file_metadata(file_id)
        
        # Check permissions
        if metadata.owner_id != updated_by and 'admin' not in self._get_user_permissions(updated_by, file_id):
            raise AccessDeniedError("You don't have permission to update this file")
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(metadata, key):
                if key == 'access_control' and isinstance(value, dict):
                    # Merge access control updates
                    if not hasattr(metadata, 'access_control'):
                        setattr(metadata, 'access_control', {})
                    metadata.access_control.update(value)
                else:
                    setattr(metadata, key, value)
            else:
                # Add to custom metadata
                metadata.custom_metadata[key] = value
        
        # Update modified timestamp
        metadata.modified_at = time.time()
        
        # Save updated metadata
        self._save_metadata(metadata)
        
        return metadata
    
    def delete_file(self, file_id: str, deleted_by: str) -> None:
        """
        Delete a file and its metadata.
        
        Args:
            file_id: ID of the file to delete
            deleted_by: ID of the user deleting the file
            
        Raises:
            AccessDeniedError: If user doesn't have permission to delete
        """
        metadata = self.get_file_metadata(file_id)
        
        # Check permissions
        if metadata.owner_id != deleted_by and 'admin' not in self._get_user_permissions(deleted_by, file_id):
            raise AccessDeniedError("You don't have permission to delete this file")
        
        # Delete the encrypted file
        encrypted_file = self.files_dir / file_id
        if encrypted_file.exists():
            encrypted_file.unlink()
        
        # Delete metadata
        metadata_file = self.metadata_dir / f"{file_id}.json"
        if metadata_file.exists():
            metadata_file.unlink()
        
        # Delete any share links
        self._cleanup_links(file_id)
    
    def _generate_file_id(self) -> str:
        """Generate a unique file ID."""
        return os.urandom(16).hex()
    
    def _generate_link_id(self) -> str:
        """Generate a unique share link ID."""
        return base64.urlsafe_b64encode(os.urandom(12)).decode('ascii').rstrip('=')
    
    def _guess_mime_type(self, file_path: Path) -> str:
        """Guess the MIME type of a file based on its extension."""
        # This is a simple implementation; in production, use python-magic or similar
        ext = file_path.suffix.lower()
        mime_types = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.zip': 'application/zip',
            '.gz': 'application/gzip',
            '.tar': 'application/x-tar',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.csv': 'text/csv',
        }
        return mime_types.get(ext, 'application/octet-stream')
    
    def _save_metadata(self, metadata: FileMetadata) -> None:
        """Save file metadata to disk."""
        metadata_path = self.metadata_dir / f"{metadata.file_id}.json"
        with open(metadata_path, 'w') as f:
            json.dump(self._file_metadata_to_dict(metadata), f, indent=2)
    
    def _file_metadata_to_dict(self, metadata: FileMetadata) -> Dict[str, Any]:
        """Convert FileMetadata to a dictionary."""
        data = asdict(metadata)
        # Convert datetime objects to timestamps
        for field in ['created_at', 'modified_at', 'expires_at']:
            if field in data and data[field] is not None:
                if hasattr(data[field], 'timestamp'):  # Handle datetime objects
                    data[field] = data[field].timestamp()
        return data
    
    def _dict_to_file_metadata(self, data: Dict[str, Any]) -> FileMetadata:
        """Convert a dictionary to FileMetadata."""
        from datetime import datetime
    
        # Create a copy to avoid modifying the input
        data = data.copy()
    
        # Convert timestamp numbers back to datetime objects
        for field in ['created_at', 'modified_at', 'expires_at']:
            if field in data and data[field] is not None:
                if isinstance(data[field], (int, float)):
                    data[field] = datetime.fromtimestamp(data[field])
    
        # Handle the access_control field specially if it exists
        if 'access_control' in data and isinstance(data['access_control'], dict):
            # Ensure all permission lists are in the correct format
            for user_id, permissions in data['access_control'].items():
                if isinstance(permissions, list):
                    # Convert string permissions to FileSharingPermission enums
                    data['access_control'][user_id] = [
                    p if isinstance(p, FileSharingPermission) 
                    else FileSharingPermission[p.upper()]
                    for p in permissions
                    if isinstance(p, (str, FileSharingPermission))
                ]
    
        # Create the FileMetadata object
        return FileMetadata(**data)                    
        