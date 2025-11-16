"""
Secure File Synchronization for OpenPGP

This module provides secure, encrypted file synchronization across multiple devices
with support for conflict resolution, versioning, and efficient delta transfers.
"""
import os
import json
import hashlib
import logging
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import aiohttp
import aiofiles
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Import other core modules
from .advanced_crypto import AdvancedCrypto
from .secure_file_sharing import SecureFileSharing, FileMetadata

logger = logging.getLogger(__name__)

class SyncConflictError(Exception):
    """Raised when a file synchronization conflict is detected."""
    pass

class SyncAuthenticationError(Exception):
    """Raised when authentication fails during synchronization."""
    pass

class SyncServerError(Exception):
    """Raised when the sync server returns an error."""
    pass

@dataclass
class FileSyncStatus:
    """Represents the synchronization status of a file."""
    file_id: str
    path: str
    status: str  # 'synced', 'conflict', 'error', 'syncing'
    last_synced: Optional[float] = None
    last_modified: float = field(default_factory=time.time)
    version: int = 1
    size: int = 0
    hash: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SyncOperation:
    """Represents a file synchronization operation."""
    operation: str  # 'upload', 'download', 'delete', 'conflict'
    file_id: str
    path: str
    local_path: Optional[Path] = None
    remote_path: Optional[str] = None
    version: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)

class FileSynchronizer:
    """Handles secure file synchronization between local and remote storage."""
    
    def __init__(
        self,
        sync_dir: Union[str, Path],
        server_url: str,
        user_id: str,
        encryption_key: Optional[bytes] = None,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        """
        Initialize the file synchronizer.
        
        Args:
            sync_dir: Local directory to synchronize
            server_url: Base URL of the sync server
            user_id: User ID for authentication
            encryption_key: Optional encryption key (generated if not provided)
            chunk_size: Size of file chunks for transfer
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
        """
        self.sync_dir = Path(sync_dir).expanduser().resolve()
        self.server_url = server_url.rstrip('/')
        self.user_id = user_id
        self.chunk_size = chunk_size
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # Create sync directory if it doesn't exist
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption
        self.crypto = AdvancedCrypto()
        self.encryption_key = encryption_key or self._generate_encryption_key()
        
        # Initialize file sharing for encryption/decryption
        self.file_sharing = SecureFileSharing(str(self.sync_dir))
        
        # Track sync status
        self.status_file = self.sync_dir / '.sync_status.json'
        self.status: Dict[str, FileSyncStatus] = {}
        self._load_status()
        
        # Track pending operations
        self.pending_operations: List[SyncOperation] = []
        
        # HTTP session for server communication
        self.session: Optional[aiohttp.ClientSession] = None
    
    def _generate_encryption_key(self) -> bytes:
        """Generate a secure encryption key."""
        return os.urandom(32)  # 256-bit key
    
    def _load_status(self) -> None:
        """Load synchronization status from disk."""
        if self.status_file.exists():
            try:
                with open(self.status_file, 'r') as f:
                    data = json.load(f)
                    self.status = {
                        file_id: FileSyncStatus(**status)
                        for file_id, status in data.items()
                    }
            except (json.JSONDecodeError, TypeError) as e:
                logger.error(f"Error loading sync status: {e}")
                self.status = {}
    
    def _save_status(self) -> None:
        """Save synchronization status to disk."""
        with open(self.status_file, 'w') as f:
            data = {
                file_id: asdict(status)
                for file_id, status in self.status.items()
            }
            json.dump(data, f, indent=2)
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _get_relative_path(self, path: Union[str, Path]) -> str:
        """Get the path relative to the sync directory."""
        return str(Path(path).resolve().relative_to(self.sync_dir))
    
    async def _ensure_session(self) -> None:
        """Ensure we have an active HTTP session."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                base_url=self.server_url,
                headers={
                    'User-Agent': 'OpenPGP-Sync/1.0',
                    'X-User-Id': self.user_id,
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make an authenticated request to the sync server."""
        await self._ensure_session()
        
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        
        for attempt in range(self.max_retries):
            try:
                async with self.session.request(method, url, **kwargs) as response:
                    if response.status == 401:
                        raise SyncAuthenticationError("Authentication failed")
                    
                    response.raise_for_status()
                    
                    if response.status == 204:  # No content
                        return {}
                        
                    return await response.json()
                    
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    raise SyncServerError(f"Request failed after {self.max_retries} attempts: {e}")
                
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
    
    async def scan_local_changes(self) -> List[SyncOperation]:
        """Scan the local directory for changes that need to be synced."""
        operations = []
        
        # Track which files we've seen in this scan
        seen_files = set()
        
        # Walk through the sync directory
        for root, _, files in os.walk(self.sync_dir):
            # Skip hidden directories (including .sync)
            if os.path.basename(root).startswith('.'):
                continue
                
            for filename in files:
                # Skip hidden files and status files
                if filename.startswith('.') or filename == 'sync_status.json':
                    continue
                
                file_path = Path(root) / filename
                rel_path = self._get_relative_path(file_path)
                seen_files.add(rel_path)
                
                # Get file stats
                try:
                    stat = file_path.stat()
                except OSError as e:
                    logger.error(f"Error accessing {file_path}: {e}")
                    continue
                
                # Check if this is a new or modified file
                file_id = self._get_file_id(rel_path)
                file_status = self.status.get(file_id)
                
                if file_status is None:
                    # New file
                    operations.append(SyncOperation(
                        operation='upload',
                        file_id=file_id,
                        path=rel_path,
                        local_path=file_path,
                        version=1,
                        metadata={
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'created': stat.st_ctime
                        }
                    ))
                elif stat.st_mtime > file_status.last_modified:
                    # Modified file
                    operations.append(SyncOperation(
                        operation='upload',
                        file_id=file_id,
                        path=rel_path,
                        local_path=file_path,
                        version=file_status.version + 1,
                        metadata={
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'previous_version': file_status.version
                        }
                    ))
        
        # Check for deleted files
        for file_id, file_status in list(self.status.items()):
            if file_status.path not in seen_files:
                operations.append(SyncOperation(
                    operation='delete',
                    file_id=file_id,
                    path=file_status.path,
                    version=file_status.version + 1,
                    metadata={'deleted': True}
                ))
        
        return operations
    
    def _get_file_id(self, path: str) -> str:
        """Generate a deterministic file ID from a path."""
        # In a real implementation, this would use a content-addressable hash
        # For now, we'll use a simple hash of the path
        return hashlib.sha256(path.encode('utf-8')).hexdigest()
    
    async def _upload_file(self, operation: SyncOperation) -> None:
        """Upload a file to the sync server."""
        if not operation.local_path or not operation.local_path.exists():
            logger.error(f"Cannot upload non-existent file: {operation.path}")
            return
        
        file_size = operation.local_path.stat().st_size
        chunk_count = (file_size + self.chunk_size - 1) // self.chunk_size
        
        # Start the upload session
        session_data = await self._make_request(
            'POST',
            '/api/v1/uploads/start',
            json={
                'file_id': operation.file_id,
                'path': operation.path,
                'size': file_size,
                'chunk_size': self.chunk_size,
                'version': operation.version,
                'metadata': operation.metadata
            }
        )
        
        upload_id = session_data['upload_id']
        
        try:
            # Upload chunks
            with open(operation.local_path, 'rb') as f:
                for chunk_num in range(chunk_count):
                    chunk = f.read(self.chunk_size)
                    chunk_hash = hashlib.sha256(chunk).hexdigest()
                    
                    # Encrypt the chunk
                    encrypted_chunk = self.crypto.encrypt(
                        chunk,
                        self.encryption_key,
                        algorithm='aes-256-gcm'
                    )
                    
                    # Upload the chunk
                    form_data = aiohttp.FormData()
                    form_data.add_field('chunk', encrypted_chunk.ciphertext)
                    form_data.add_field('chunk_num', str(chunk_num))
                    form_data.add_field('chunk_hash', chunk_hash)
                    
                    if encrypted_chunk.iv:
                        form_data.add_field('iv', base64.b64encode(encrypted_chunk.iv).decode())
                    if encrypted_chunk.tag:
                        form_data.add_field('tag', base64.b64encode(encrypted_chunk.tag).decode())
                    
                    await self._make_request(
                        'POST',
                        f'/api/v1/uploads/{upload_id}/chunk',
                        data=form_data
                    )
            
            # Complete the upload
            await self._make_request(
                'POST',
                f'/api/v1/uploads/{upload_id}/complete'
            )
            
            # Update local status
            self._update_file_status(
                operation.file_id,
                operation.path,
                'synced',
                operation.version,
                file_size,
                operation.metadata.get('modified')
            )
            
        except Exception as e:
            logger.error(f"Failed to upload {operation.path}: {e}")
            await self._make_request(
                'POST',
                f'/api/v1/uploads/{upload_id}/abort'
            )
            raise
    
    async def _download_file(self, operation: SyncOperation) -> None:
        """Download a file from the sync server."""
        if not operation.path:
            logger.error("No path specified for download")
            return
        
        # Ensure the target directory exists
        local_path = self.sync_dir / operation.path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get file metadata
        file_info = await self._make_request(
            'GET',
            f'/api/v1/files/{operation.file_id}'
        )
        
        # Download chunks
        with open(local_path, 'wb') as f:
            for chunk_num in range(file_info['chunk_count']):
                chunk_data = await self._make_request(
                    'GET',
                    f'/api/v1/files/{operation.file_id}/chunk/{chunk_num}'
                )
                
                # Decrypt the chunk
                decrypted_chunk = self.crypto.decrypt(
                    EncryptedData(
                        ciphertext=chunk_data['data'],
                        iv=base64.b64decode(chunk_data.get('iv', '')),
                        tag=base64.b64decode(chunk_data.get('tag', '')),
                        algorithm=chunk_data.get('algorithm', 'aes-256-gcm')
                    ),
                    self.encryption_key
                )
                
                # Verify the chunk hash
                chunk_hash = hashlib.sha256(decrypted_chunk).hexdigest()
                if chunk_hash != chunk_data['hash']:
                    raise SyncServerError(f"Chunk {chunk_num} verification failed")
                
                f.write(decrypted_chunk)
        
        # Update file metadata
        os.utime(local_path, (time.time(), file_info['modified']))
        
        # Update local status
        self._update_file_status(
            operation.file_id,
            operation.path,
            'synced',
            file_info['version'],
            file_info['size'],
            file_info['modified']
        )
    
    def _update_file_status(
        self,
        file_id: str,
        path: str,
        status: str,
        version: int,
        size: int,
        modified: Optional[float] = None
    ) -> None:
        """Update the status of a file."""
        if file_id in self.status:
            file_status = self.status[file_id]
            file_status.status = status
            file_status.version = version
            file_status.size = size
            file_status.last_synced = time.time()
            if modified:
                file_status.last_modified = modified
        else:
            self.status[file_id] = FileSyncStatus(
                file_id=file_id,
                path=path,
                status=status,
                version=version,
                size=size,
                last_synced=time.time(),
                last_modified=modified or time.time()
            )
        
        self._save_status()
    
    async def sync(self) -> Dict[str, Any]:
        """Synchronize files with the remote server."""
        result = {
            'uploaded': 0,
            'downloaded': 0,
            'deleted': 0,
            'conflicts': 0,
            'errors': 0
        }
        
        try:
            # Get local changes
            local_operations = await self.scan_local_changes()
            
            # Get remote changes
            remote_changes = await self._get_remote_changes()
            
            # Process remote changes (download/delete)
            for change in remote_changes:
                op_type = change['type']
                file_id = change['file_id']
                path = change['path']
                version = change['version']
                
                local_status = next(
                    (s for s in self.status.values() if s.path == path),
                    None
                )
                
                if op_type == 'delete':
                    # Delete local file if it exists
                    local_path = self.sync_dir / path
                    if local_path.exists():
                        try:
                            if local_path.is_file():
                                local_path.unlink()
                            else:
                                local_path.rmdir()
                            result['deleted'] += 1
                        except OSError as e:
                            logger.error(f"Failed to delete {path}: {e}")
                            result['errors'] += 1
                    
                    # Remove from status
                    if file_id in self.status:
                        del self.status[file_id]
                    
                elif op_type in ['create', 'update']:
                    # Check for conflicts
                    if local_status and local_status.version > version:
                        # Local version is newer, mark as conflict
                        self._update_file_status(
                            file_id,
                            path,
                            'conflict',
                            max(version, local_status.version) + 1,
                            change.get('size', 0),
                            change.get('modified')
                        )
                        result['conflicts'] += 1
                    else:
                        # Download the file
                        try:
                            await self._download_file(SyncOperation(
                                operation='download',
                                file_id=file_id,
                                path=path,
                                version=version,
                                metadata=change.get('metadata', {})
                            ))
                            result['downloaded'] += 1
                        except Exception as e:
                            logger.error(f"Failed to download {path}: {e}")
                            result['errors'] += 1
            
            # Process local changes (upload)
            for operation in local_operations:
                try:
                    if operation.operation == 'upload':
                        await self._upload_file(operation)
                        result['uploaded'] += 1
                    elif operation.operation == 'delete':
                        await self._delete_remote_file(operation)
                        result['deleted'] += 1
                except Exception as e:
                    logger.error(f"Failed to process {operation.operation} for {operation.path}: {e}")
                    result['errors'] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Synchronization failed: {e}")
            result['error'] = str(e)
            return result
        
        finally:
            # Clean up
            if self.session:
                await self.session.close()
                self.session = None
    
    async def _get_remote_changes(self) -> List[Dict[str, Any]]:
        """Get a list of changes from the remote server."""
        try:
            return await self._make_request(
                'GET',
                '/api/v1/sync/changes',
                params={'since': self._get_last_sync_time()}
            )
        except Exception as e:
            logger.error(f"Failed to get remote changes: {e}")
            return []
    
    def _get_last_sync_time(self) -> float:
        """Get the timestamp of the last successful sync."""
        if not self.status:
            return 0
        
        last_sync = max(
            (s.last_synced or 0 for s in self.status.values()),
            default=0
        )
        
        return last_sync
    
    async def _delete_remote_file(self, operation: SyncOperation) -> None:
        """Delete a file from the remote server."""
        await self._make_request(
            'DELETE',
            f'/api/v1/files/{operation.file_id}',
            params={'version': operation.version}
        )
        
        # Remove from status
        if operation.file_id in self.status:
            del self.status[operation.file_id]
        
        self._save_status()

# Example usage
async def example_usage():
    """Example of how to use the FileSynchronizer."""
    # Initialize the synchronizer
    sync = FileSynchronizer(
        sync_dir='~/Documents/Sync',
        server_url='https://sync.example.com',
        user_id='user123',
        encryption_key=b'your-encryption-key-here'  # In practice, derive this from user's password
    )
    
    # Perform a sync
    result = await sync.sync()
    print(f"Sync complete: {result}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
