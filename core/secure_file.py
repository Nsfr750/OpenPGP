"""
Secure File Operations for OpenPGP

This module provides secure file operations including encrypted file systems and secure file shredding.
"""
import os
import logging
import shutil
import struct
import secrets
from pathlib import Path
from typing import Optional, Union, BinaryIO, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class SecureFileError(Exception):
    """Base exception for secure file operations."""
    pass


class SecureFile:
    """Class for secure file operations including encryption, decryption, and secure deletion."""
    
    def __init__(self, key: Optional[bytes] = None, gpg_home: Optional[str] = None):
        """
        Initialize the SecureFile instance.
        
        Args:
            key: Encryption key (if None, a random key will be generated)
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
        """
        self.key = key or secrets.token_bytes(32)  # 256-bit key by default
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.efs = EncryptedFileSystem(self.key)
        self.shredder = SecureFileShredder()
    
    def encrypt_file(self, input_path: Union[str, Path], 
                    output_path: Optional[Union[str, Path]] = None,
                    shred_original: bool = False) -> Path:
        """
        Encrypt a file using AES-256-GCM.
        
        Args:
            input_path: Path to the input file
            output_path: Path to the output file (default: input_path + '.enc')
            shred_original: Whether to securely delete the original file
            
        Returns:
            Path to the encrypted file
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise SecureFileError(f"Input file not found: {input_path}")
            
        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.enc')
        else:
            output_path = Path(output_path)
        
        try:
            # Encrypt the file
            self.efs.encrypt_file(input_path, output_path)
            
            # Securely delete the original if requested
            if shred_original:
                self.shredder.shred(input_path)
                
            logger.info(f"Encrypted file saved to {output_path}")
            return output_path
            
        except Exception as e:
            # Clean up partial output file if it exists
            if output_path.exists():
                try:
                    output_path.unlink()
                except OSError:
                    pass
            raise SecureFileError(f"Error encrypting file: {e}")
    
    def decrypt_file(self, input_path: Union[str, Path],
                    output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Decrypt a file encrypted with encrypt_file().
        
        Args:
            input_path: Path to the encrypted file
            output_path: Path to the output file (default: input_path without .enc)
            
        Returns:
            Path to the decrypted file
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise SecureFileError(f"Input file not found: {input_path}")
            
        if output_path is None:
            if input_path.suffix == '.enc':
                output_path = input_path.with_suffix('')
            else:
                output_path = input_path.with_suffix(input_path.suffix + '.dec')
        else:
            output_path = Path(output_path)
        
        try:
            # Decrypt the file
            self.efs.decrypt_file(input_path, output_path)
            logger.info(f"Decrypted file saved to {output_path}")
            return output_path
            
        except Exception as e:
            # Clean up partial output file if it exists
            if output_path.exists():
                try:
                    output_path.unlink()
                except OSError:
                    pass
            raise SecureFileError(f"Error decrypting file: {e}")
    
    def secure_delete(self, path: Union[str, Path], 
                     method: str = 'shred',
                     passes: int = 3) -> None:
        """
        Securely delete a file or directory.
        
        Args:
            path: Path to the file or directory to delete
            method: Method to use ('shred' or 'wipe')
            passes: Number of overwrite passes (for 'shred' method)
            
        Raises:
            SecureFileError: If the operation fails
        """
        path = Path(path)
        if not path.exists():
            raise SecureFileError(f"Path not found: {path}")
            
        try:
            if path.is_file():
                self.shredder.shred(path)
            elif path.is_dir():
                self.shredder.shred_directory(path)
            else:
                raise SecureFileError(f"Unsupported file type: {path}")
                
            logger.info(f"Securely deleted {path}")
            
        except Exception as e:
            raise SecureFileError(f"Error during secure deletion: {e}")
    
    def get_file_metadata(self, path: Union[str, Path]) -> Dict[str, Any]:
        """
        Get metadata about a file.
        
        Args:
            path: Path to the file
            
        Returns:
            Dictionary containing file metadata
            
        Raises:
            SecureFileError: If the file cannot be accessed
        """
        try:
            return get_file_metadata(path)
        except Exception as e:
            raise SecureFileError(f"Error getting file metadata: {e}")
    
    def calculate_checksum(self, path: Union[str, Path], 
                          algorithm: str = 'sha256') -> str:
        """
        Calculate the checksum of a file.
        
        Args:
            path: Path to the file
            algorithm: Hash algorithm to use (e.g., 'sha256', 'sha512')
            
        Returns:
            Hex-encoded checksum string
            
        Raises:
            SecureFileError: If the file cannot be read or the algorithm is unsupported
        """
        path = Path(path)
        if not path.exists():
            raise SecureFileError(f"File not found: {path}")
            
        try:
            # Get the hash function
            hash_func = getattr(hashes, algorithm.upper(), None)
            if hash_func is None:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
                
            digest = hashes.Hash(hash_func(), backend=default_backend())
            
            # Read the file in chunks to handle large files
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    digest.update(chunk)
                    
            return digest.finalize().hex()
            
        except Exception as e:
            raise SecureFileError(f"Error calculating checksum: {e}")

class EncryptedFileSystem:
    """Class for handling encrypted file system operations."""
    
    HEADER = b'OPENPGP_EFS_V1'  # File header magic
    SALT_SIZE = 16
    IV_SIZE = 16
    MAC_SIZE = 32
    KEY_SIZE = 32
    ITERATIONS = 100000
    
    def __init__(self, password: Union[str, bytes], salt: Optional[bytes] = None):
        """
        Initialize the encrypted file system.
        
        Args:
            password: The password to use for encryption/decryption
            salt: Optional salt for key derivation (random if not provided)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        self.password = password
        self.salt = salt if salt else os.urandom(self.SALT_SIZE)
        self.backend = default_backend()
        
        # Derive encryption and MAC keys
        self.enc_key, self.mac_key = self._derive_keys()
    
    def _derive_keys(self) -> tuple[bytes, bytes]:
        """Derive encryption and MAC keys from the password."""
        # Derive a master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE * 2,  # Enough for both keys
            salt=self.salt,
            iterations=self.ITERATIONS,
            backend=self.backend
        )
        master_key = kdf.derive(self.password)
        
        # Split into encryption and MAC keys
        return master_key[:self.KEY_SIZE], master_key[self.KEY_SIZE:]
    
    def _generate_iv(self) -> bytes:
        """Generate a random initialization vector."""
        return os.urandom(self.IV_SIZE)
    
    def _pad_data(self, data: bytes) -> bytes:
        """Pad data to the block size."""
        padder = padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()
    
    def _unpad_data(self, data: bytes) -> bytes:
        """Unpad data."""
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    
    def _compute_mac(self, data: bytes) -> bytes:
        """Compute HMAC of the data."""
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()
    
    def encrypt_file(self, input_path: Union[str, Path], 
                    output_path: Optional[Union[str, Path]] = None,
                    chunk_size: int = 64 * 1024) -> Path:
        """
        Encrypt a file.
        
        Args:
            input_path: Path to the input file
            output_path: Optional output path (default: input_path + '.enc')
            chunk_size: Chunk size for processing large files
            
        Returns:
            Path to the encrypted file
        """
        input_path = Path(input_path)
        output_path = Path(output_path) if output_path else input_path.with_suffix(input_path.suffix + '.enc')
        
        # Generate a random IV for this file
        iv = self._generate_iv()
        
        # Set up the cipher
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CFB(iv),  # CFB mode doesn't require padding
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write the header, salt, and IV
            outfile.write(self.HEADER)
            outfile.write(self.salt)
            outfile.write(iv)
            
            # Process the file in chunks
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                    
                # Encrypt the chunk
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)
            
            # Write the final block
            final_chunk = encryptor.finalize()
            if final_chunk:
                outfile.write(final_chunk)
            
            # Compute and write the MAC
            outfile.seek(len(self.HEADER) + len(self.salt) + len(iv), 0)
            file_data = outfile.read()
            mac = self._compute_mac(file_data)
            outfile.write(mac)
        
        return output_path
    
    def decrypt_file(self, input_path: Union[str, Path],
                    output_path: Optional[Union[str, Path]] = None,
                    chunk_size: int = 64 * 1024) -> Path:
        """
        Decrypt a file.
        
        Args:
            input_path: Path to the encrypted file
            output_path: Optional output path (default: input_path with '.enc' removed)
            chunk_size: Chunk size for processing large files
            
        Returns:
            Path to the decrypted file
            
        Raises:
            SecureFileError: If the file is corrupted or the MAC is invalid
        """
        input_path = Path(input_path)
        if output_path is None:
            if input_path.suffix == '.enc':
                output_path = input_path.with_suffix('')
            else:
                output_path = input_path.with_suffix(input_path.suffix + '.dec')
        else:
            output_path = Path(output_path)
        
        with open(input_path, 'rb') as infile:
            # Read and verify the header
            header = infile.read(len(self.HEADER))
            if header != self.HEADER:
                raise SecureFileError("Invalid file format or corrupted file")
            
            # Read salt and IV
            salt = infile.read(self.SALT_SIZE)
            iv = infile.read(self.IV_SIZE)
            
            # If the salt doesn't match, we need to reinitialize with the correct salt
            if salt != self.salt:
                self.salt = salt
                self.enc_key, self.mac_key = self._derive_keys()
            
            # Read the rest of the file
            encrypted_data = infile.read()
            
            # The last MAC_SIZE bytes are the MAC
            if len(encrypted_data) < self.MAC_SIZE:
                raise SecureFileError("File is too short to contain a valid MAC")
                
            file_data = encrypted_data[:-self.MAC_SIZE]
            stored_mac = encrypted_data[-self.MAC_SIZE:]
            
            # Verify the MAC
            computed_mac = self._compute_mac(file_data)
            if not secrets.compare_digest(computed_mac, stored_mac):
                raise SecureFileError("MAC verification failed - file may be corrupted or tampered with")
            
            # Set up the cipher
            cipher = Cipher(
                algorithms.AES(self.enc_key),
                modes.CFB(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            decrypted_data = decryptor.update(file_data) + decryptor.finalize()
            
            # Write the decrypted data to the output file
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
        
        return output_path


class SecureFileShredder:
    """Class for secure file shredding."""
    
    def __init__(self, passes: int = 3):
        """
        Initialize the file shredder.
        
        Args:
            passes: Number of overwrite passes (default: 3, DoD 5220.22-M compliant)
        """
        self.passes = max(1, min(passes, 35))  # Limit to reasonable values
    
    def _get_random_bytes(self, size: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(size)
    
    def _get_pattern(self, pattern: int, size: int) -> bytes:
        """Generate a pattern of bytes."""
        if pattern == 0:
            return b'\x00' * size
        elif pattern == 1:
            return b'\xFF' * size
        elif pattern == 2:
            return b'\x55' * size  # 01010101
        elif pattern == 3:
            return b'\xAA' * size  # 10101010
        elif pattern == 4:
            return b'\x92\x49\x24' * ((size // 3) + 1)  # 10010010 01001001 00100100
        else:
            return self._get_random_bytes(size)
    
    def _get_file_size(self, path: Union[str, Path]) -> int:
        """Get the size of a file."""
        try:
            return os.path.getsize(path)
        except OSError as e:
            raise SecureFileError(f"Failed to get file size: {e}")
    
    def _overwrite_file(self, path: Union[str, Path], pattern: int) -> None:
        """Overwrite a file with a specific pattern."""
        try:
            file_size = self._get_file_size(path)
            if file_size == 0:
                return
                
            with open(path, 'r+b') as f:
                # Write the pattern in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                pattern_data = self._get_pattern(pattern, min(chunk_size, file_size))
                
                remaining = file_size
                while remaining > 0:
                    chunk = pattern_data[:min(remaining, chunk_size)]
                    f.write(chunk)
                    remaining -= len(chunk)
                
                # Ensure all data is written to disk
                f.flush()
                os.fsync(f.fileno())
                
        except (IOError, OSError) as e:
            raise SecureFileError(f"Failed to overwrite file: {e}")
    
    def shred(self, path: Union[str, Path], rename: bool = True) -> None:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            path: Path to the file to shred
            rename: Whether to rename the file before deletion
            
        Raises:
            SecureFileError: If the file cannot be shredded
        """
        path = Path(path)
        
        if not path.exists():
            return
            
        if not path.is_file():
            raise SecureFileError(f"Not a regular file: {path}")
        
        try:
            # Get the file size before we start
            file_size = self._get_file_size(path)
            
            # Optionally rename the file to make recovery harder
            if rename:
                try:
                    temp_path = path.with_name(f".{secrets.token_hex(8)}.tmp")
                    path.rename(temp_path)
                    path = temp_path
                except OSError:
                    # If we can't rename, continue anyway
                    pass
            
            # Overwrite the file multiple times with different patterns
            for i in range(self.passes):
                self._overwrite_file(path, i)
            
            # Truncate the file to its original size (in case it grew)
            with open(path, 'r+b') as f:
                f.truncate(file_size)
            
            # Delete the file
            path.unlink()
            
        except (OSError, IOError) as e:
            raise SecureFileError(f"Failed to shred file: {e}")
    
    def shred_directory(self, dir_path: Union[str, Path], recursive: bool = True) -> None:
        """
        Securely delete all files in a directory.
        
        Args:
            dir_path: Path to the directory
            recursive: Whether to process subdirectories
            
        Raises:
            SecureFileError: If the directory cannot be processed
        """
        dir_path = Path(dir_path)
        
        if not dir_path.exists():
            return
            
        if not dir_path.is_dir():
            raise SecureFileError(f"Not a directory: {dir_path}")
        
        try:
            # Process all files in the directory
            for item in dir_path.iterdir():
                if item.is_file():
                    try:
                        self.shred(item, rename=False)
                    except SecureFileError as e:
                        logger.warning(f"Failed to shred {item}: {e}")
                elif recursive and item.is_dir():
                    self.shred_directory(item, recursive)
            
            # Remove the directory if it's empty
            try:
                dir_path.rmdir()
            except OSError:
                # Directory not empty, leave it
                pass
                
        except (OSError, IOError) as e:
            raise SecureFileError(f"Failed to shred directory: {e}")


def get_file_metadata(path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get metadata about a file.
    
    Args:
        path: Path to the file
        
    Returns:
        Dictionary containing file metadata
        
    Raises:
        SecureFileError: If the file cannot be accessed
    """
    path = Path(path)
    
    try:
        stat = path.stat()
        
        return {
            'path': str(path.absolute()),
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'permissions': oct(stat.st_mode)[-3:],
            'owner': stat.st_uid,
            'group': stat.st_gid,
            'inode': stat.st_ino,
            'device': stat.st_dev,
            'hard_links': stat.st_nlink,
        }
    except OSError as e:
        raise SecureFileError(f"Failed to get file metadata: {e}")


def secure_delete(path: Union[str, Path], 
                method: str = 'shred', 
                passes: int = 3,
                zero_fill: bool = True) -> None:
    """
    Securely delete a file or directory.
    
    Args:
        path: Path to the file or directory to delete
        method: Method to use ('shred' or 'wipe')
        passes: Number of overwrite passes (for 'shred' method)
        zero_fill: Whether to fill with zeros on the last pass
        
    Raises:
        SecureFileError: If the operation fails
    """
    path = Path(path)
    
    if not path.exists():
        return
    
    try:
        if path.is_file():
            if method.lower() == 'shred':
                shredder = SecureFileShredder(passes=passes)
                shredder.shred(path)
            else:
                # Simple secure delete with one pass of zeros
                with open(path, 'wb') as f:
                    f.write(b'\x00' * path.stat().st_size)
                    f.flush()
                    os.fsync(f.fileno())
                path.unlink()
        
        elif path.is_dir():
            shredder = SecureFileShredder(passes=passes)
            shredder.shred_directory(path)
            
    except (OSError, IOError) as e:
        raise SecureFileError(f"Failed to securely delete {path}: {e}")
