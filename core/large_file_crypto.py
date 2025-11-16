"""
Optimized file encryption/decryption for large files.
Uses chunked processing, memory-mapped files, and parallel processing for better performance.
"""
import os
import io
import hashlib
import json
import mmap
import shutil
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import BinaryIO, Optional, Tuple, Dict, Any, Generator, Callable, List
from pathlib import Path
import logging
from datetime import datetime, timezone
from functools import partial

logger = logging.getLogger(__name__)

# Default chunk size (1MB) - will be adjusted based on available memory
DEFAULT_CHUNK_SIZE = 1024 * 1024
# Maximum number of worker threads for parallel processing
MAX_WORKERS = min(32, (os.cpu_count() or 1) * 2 + 4)
# Minimum chunk size (64KB)
MIN_CHUNK_SIZE = 64 * 1024
# Maximum chunk size (16MB)
MAX_CHUNK_SIZE = 16 * 1024 * 1024

class LargeFileCrypto:
    """
    Handles encryption/decryption of large files efficiently using:
    - Chunked processing with dynamic chunk sizing
    - Memory-mapped files for better I/O performance
    - Parallel processing for multi-core systems
    - Progress tracking and cancellation support
    """
    
    def __init__(self, chunk_size: int = None, max_workers: int = None):
        """
        Initialize the LargeFileCrypto instance.
        
        Args:
            chunk_size: Optional fixed chunk size in bytes. If None, will be calculated based on available memory.
            max_workers: Maximum number of worker threads for parallel processing.
        """
        self._chunk_size = chunk_size
        self.max_workers = max_workers or MAX_WORKERS
        self._progress_callback = None
        self._cancel_flag = False
    
    @property
    def chunk_size(self) -> int:
        """Get the current chunk size, calculating it if not set."""
        if self._chunk_size is None:
            self._chunk_size = self._calculate_optimal_chunk_size()
        return self._chunk_size
    
    @chunk_size.setter
    def chunk_size(self, value: int) -> None:
        """Set a fixed chunk size, or None to use dynamic calculation."""
        self._chunk_size = value
    
    def _calculate_optimal_chunk_size(self) -> int:
        """Calculate optimal chunk size based on available memory."""
        try:
            # Get available memory, leave 1GB for system
            available_mem = psutil.virtual_memory().available - (1024**3)
            # Use 1/4 of available memory or 16MB, whichever is smaller
            chunk_size = min(available_mem // 4, MAX_CHUNK_SIZE)
            # Ensure chunk size is within bounds and a multiple of 4KB for alignment
            chunk_size = max(MIN_CHUNK_SIZE, min(chunk_size, MAX_CHUNK_SIZE))
            chunk_size = (chunk_size // 4096) * 4096  # Align to 4KB
            logger.debug(f"Calculated optimal chunk size: {chunk_size} bytes")
            return chunk_size
        except Exception as e:
            logger.warning(f"Failed to calculate optimal chunk size, using default: {e}")
            return DEFAULT_CHUNK_SIZE
    
    def set_progress_callback(self, callback: Optional[Callable[[int, int], None]]) -> None:
        """Set a callback for progress updates.
        
        Args:
            callback: A function that takes (processed_bytes, total_bytes) as arguments
        """
        self._progress_callback = callback
    
    def cancel(self) -> None:
        """Request cancellation of the current operation."""
        self._cancel_flag = True
    
    def _check_cancellation(self) -> None:
        """Raise an exception if cancellation was requested."""
        if self._cancel_flag:
            self._cancel_flag = False
            raise RuntimeError("Operation was cancelled by user")
    
    def _update_progress(self, processed: int, total: int) -> None:
        """Update progress if a callback is set."""
        if self._progress_callback:
            try:
                self._progress_callback(processed, total)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def _process_chunk(
        self,
        chunk: bytes,
        chunk_index: int,
        encrypt_func: Callable[[bytes], bytes]
    ) -> Tuple[int, bytes]:
        """Process a single chunk of data."""
        try:
            return (chunk_index, encrypt_func(chunk))
        except Exception as e:
            logger.error(f"Error processing chunk {chunk_index}: {e}")
            raise
    
    def _process_file_in_parallel(
        self,
        input_path: str,
        output_path: str,
        process_func: Callable[[bytes], bytes],
        file_size: int
    ) -> None:
        """Process a file in parallel using multiple threads."""
        processed_bytes = 0
        chunk_size = self.chunk_size
        
        with (
            open(input_path, 'rb') as src_file,
            open(output_path, 'wb') as dest_file,
            ThreadPoolExecutor(max_workers=self.max_workers) as executor
        ):
            # Process file in chunks
            futures = []
            chunk_index = 0
            
            while True:
                self._check_cancellation()
                
                # Read chunk
                chunk = src_file.read(chunk_size)
                if not chunk:
                    break
                
                # Submit chunk for processing
                future = executor.submit(
                    self._process_chunk,
                    chunk,
                    chunk_index,
                    process_func
                )
                futures.append(future)
                chunk_index += 1
            
            # Process results in order
            for future in as_completed(futures):
                try:
                    idx, processed_chunk = future.result()
                    dest_file.write(processed_chunk)
                    processed_bytes += len(processed_chunk)
                    self._update_progress(processed_bytes, file_size)
                except Exception as e:
                    logger.error(f"Error processing chunk: {e}")
                    raise
    
    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        public_key: bytes,
        chunk_size: Optional[int] = None,
        use_memory_mapping: bool = True
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt a large file efficiently using parallel processing.
        
        Args:
            input_path: Path to the input file
            output_path: Path to save the encrypted file
            public_key: Public key for encryption
            chunk_size: Optional fixed chunk size in bytes
            use_memory_mapping: Whether to use memory mapping for better performance
            
        Returns:
            Tuple of (encrypted_session_key, metadata)
            
        Raises:
            RuntimeError: If the operation is cancelled
            IOError: If there's an error reading/writing files
            Exception: For other encryption-related errors
        """
        self._cancel_flag = False
        start_time = time.time()
        
        if chunk_size is not None:
            self.chunk_size = chunk_size
        
        file_size = os.path.getsize(input_path)
        metadata = self._create_metadata(input_path, file_size)
        
        try:
            # Generate a random session key for symmetric encryption
            session_key = os.urandom(32)
            
            # Encrypt the session key with the public key
            encrypted_session_key = self._encrypt_session_key(session_key, public_key)
            
            # Create a temporary file for the encrypted data
            temp_path = f"{output_path}.tmp"
            
            # Initialize encryption
            cipher = self._create_cipher(session_key)
            
            if use_memory_mapping and file_size > self.chunk_size * 2:
                # Use memory mapping for large files
                self._encrypt_with_memory_mapping(
                    input_path, temp_path, cipher, file_size
                )
            else:
                # Use parallel processing for smaller files or when memory mapping is disabled
                self._process_file_in_parallel(
                    input_path,
                    temp_path,
                    lambda chunk: self._encrypt_chunk(chunk, cipher),
                    file_size
                )
            
            # Finalize the encrypted file
            self._finalize_encrypted_file(temp_path, output_path, metadata)
            
            elapsed = time.time() - start_time
            logger.info(f"Encrypted {file_size} bytes in {elapsed:.2f} seconds "
                       f"({file_size / (1024 * 1024 * elapsed):.2f} MB/s)")
            
            return encrypted_session_key, metadata
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as cleanup_error:
                    logger.error(f"Error cleaning up temp file: {cleanup_error}")
            raise
    
    def _encrypt_with_memory_mapping(
        self,
        input_path: str,
        output_path: str,
        cipher: Any,
        file_size: int
    ) -> None:
        """Encrypt a file using memory mapping for better performance."""
        processed_bytes = 0
        chunk_size = self.chunk_size
        
        with (
            open(input_path, 'rb') as src_file,
            open(output_path, 'wb') as dest_file,
            mmap.mmap(src_file.fileno(), 0, access=mmap.ACCESS_READ) as mm
        ):
            for offset in range(0, file_size, chunk_size):
                self._check_cancellation()
                
                # Process chunk
                chunk = mm[offset:offset + chunk_size]
                encrypted_chunk = self._encrypt_chunk(chunk, cipher)
                dest_file.write(encrypted_chunk)
                
                # Update progress
                processed_bytes += len(chunk)
                self._update_progress(processed_bytes, file_size)
    
    def _encrypt_chunk(self, chunk: bytes, cipher: Any) -> bytes:
        """Encrypt a single chunk of data."""
        # This is a placeholder - implement actual encryption using the cipher
        # For example, using PyCryptodome:
        # return cipher.encrypt(chunk)
        return chunk  # Replace with actual encryption
    
    def _encrypt_session_key(self, session_key: bytes, public_key: bytes) -> bytes:
        """Encrypt the session key with the public key."""
        # Implement RSA or other asymmetric encryption here
        return session_key  # Replace with actual encryption
    
    def _create_cipher(self, session_key: bytes) -> Any:
        """Create a cipher instance for symmetric encryption."""
        # Implement cipher creation (e.g., AES-GCM, ChaCha20-Poly1305)
        return None  # Replace with actual cipher instance
        # Encrypt the session key with the public key
        from .openpgp import hybrid_encrypt
        encrypted_session_key, _ = hybrid_encrypt(public_key, session_key)
        
        # Process the file in chunks
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write metadata at the beginning of the file
            outfile.write(len(metadata).to_bytes(4, 'big'))
            outfile.write(metadata)
            
            # Process file in chunks
            for chunk in self._read_in_chunks(infile, chunk_size):
                encrypted_chunk = self._encrypt_chunk(chunk, session_key)
                outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                outfile.write(encrypted_chunk)
        
        return encrypted_session_key, metadata
    
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        private_key: bytes,
        encrypted_session_key: bytes,
        passphrase: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Decrypt a large file in chunks.
        
        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file
            private_key: Private key for decryption
            encrypted_session_key: Encrypted session key
            passphrase: Passphrase for the private key if encrypted
            
        Returns:
            Dictionary containing file metadata
        """
        # Decrypt the session key
        from .openpgp import hybrid_decrypt
        session_key = hybrid_decrypt(
            private_key=private_key,
            ciphertext=encrypted_session_key,
            encrypted_message=encrypted_session_key,  # This would need adjustment based on your hybrid_encrypt output
            passphrase=passphrase
        )
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Read metadata
            metadata_length = int.from_bytes(infile.read(4), 'big')
            metadata = json.loads(infile.read(metadata_length).decode('utf-8'))
            
            # Process file in chunks
            while True:
                chunk_length_bytes = infile.read(4)
                if not chunk_length_bytes:
                    break
                    
                chunk_length = int.from_bytes(chunk_length_bytes, 'big')
                encrypted_chunk = infile.read(chunk_length)
                
                if not encrypted_chunk:
                    break
                    
                decrypted_chunk = self._decrypt_chunk(encrypted_chunk, session_key)
                outfile.write(decrypted_chunk)
        
        return metadata
    
    def _create_metadata(self, file_path: str, file_size: int) -> bytes:
        """Create metadata for the encrypted file."""
        metadata = {
            "filename": os.path.basename(file_path),
            "size": file_size,
            "created": datetime.now(timezone.utc).isoformat(),
            "chunk_size": self.chunk_size,
            "algorithm": "AES-256-GCM"
        }
        return json.dumps(metadata).encode('utf-8')
    
    def _read_in_chunks(self, file_object: BinaryIO, chunk_size: int) -> Generator[bytes, None, None]:
        """Read file in chunks."""
        while True:
            chunk = file_object.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    def _encrypt_chunk(self, chunk: bytes, key: bytes) -> bytes:
        """Encrypt a single chunk of data."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(chunk) + encryptor.finalize()
        return iv + encryptor.tag + encrypted
    
    def _decrypt_chunk(self, encrypted_chunk: bytes, key: bytes) -> bytes:
        """Decrypt a single chunk of data."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        iv = encrypted_chunk[:16]
        tag = encrypted_chunk[16:32]
        ciphertext = encrypted_chunk[32:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
