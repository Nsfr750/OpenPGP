# OpenPGP API Documentation

## Table of Contents
- [Introduction](#introduction)
- [Core Modules](#core-modules)
  - [Key Management](#key-management)
  - [Cryptography](#cryptography)
  - [File Operations](#file-operations)
  - [Identity Management](#identity-management)
- [Usage Examples](#usage-examples)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)

## Introduction

This document provides comprehensive API documentation for the OpenPGP application. The API is organized into several modules, each responsible for specific functionality.

## Core Modules

### Key Management

#### `key_manager.py`

##### `KeyManager`
```python
class KeyManager:
    """
    Manages PGP keys including generation, import, export, and keyring operations.
    """
    
    def generate_key_pair(self, user_id, key_type='RSA', key_length=4096, passphrase=None):
        """
        Generate a new PGP key pair.
        
        Args:
            user_id (str): User ID in format 'Name <email@example.com>'
            key_type (str): Key type ('RSA', 'DSA', 'ECDSA', 'ED25519')
            key_length (int): Key length in bits
            passphrase (str, optional): Passphrase to protect the private key
            
        Returns:
            dict: Dictionary containing public and private key information
        """
        pass
    
    def import_key(self, key_data, passphrase=None):
        """
        Import a PGP key from ASCII-armored or binary data.
        
        Args:
            key_data (bytes or str): The key data to import
            passphrase (str, optional): Passphrase if the key is encrypted
            
        Returns:
            dict: Information about the imported key
        """
        pass
    
    # Additional methods...
```

### Cryptography

#### `advanced_crypto.py`

##### `PGPCrypto`
```python
class PGPCrypto:
    """
    Provides cryptographic operations for OpenPGP functionality.
    """
    
    def encrypt(self, data, public_keys, sign_key=None, password=None):
        """
        Encrypt data for one or more recipients.
        
        Args:
            data (bytes): Data to encrypt
            public_keys (list): List of recipient public keys
            sign_key (tuple, optional): (private_key, passphrase) for signing
            password (str, optional): Password for symmetric encryption
            
        Returns:
            bytes: Encrypted data
        """
        pass
    
    def decrypt(self, encrypted_data, private_key, passphrase=None):
        """
        Decrypt data using a private key.
        
        Args:
            encrypted_data (bytes): Data to decrypt
            private_key: The private key to use for decryption
            passphrase (str, optional): Passphrase for the private key
            
        Returns:
            tuple: (decrypted_data, was_signed, signature_verified)
        """
        pass
    
    # Additional methods...
```

### File Operations

#### `secure_file.py`

##### `SecureFile`
```python
class SecureFile:
    """
    Handles secure file operations including encryption and decryption.
    """
    
    def encrypt_file(self, input_path, output_path, public_keys, sign_key=None):
        """
        Encrypt a file for one or more recipients.
        
        Args:
            input_path (str): Path to the file to encrypt
            output_path (str): Path to save the encrypted file
            public_keys (list): List of recipient public keys
            sign_key (tuple, optional): (private_key, passphrase) for signing
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    def decrypt_file(self, input_path, output_path, private_key, passphrase=None):
        """
        Decrypt a file using a private key.
        
        Args:
            input_path (str): Path to the encrypted file
            output_path (str): Path to save the decrypted file
            private_key: The private key to use for decryption
            passphrase (str, optional): Passphrase for the private key
            
        Returns:
            tuple: (success, was_signed, signature_verified)
        """
        pass
    
    # Additional methods...
```

### Identity Management

#### `blockchain_identity.py`

##### `BlockchainIdentity`
```python
class BlockchainIdentity:
    """
    Manages blockchain-based identity verification for OpenPGP keys.
    """
    
    def register_identity(self, public_key, identity_data, signature):
        """
        Register a new identity on the blockchain.
        
        Args:
            public_key (str): The public key to register
            identity_data (dict): Identity information
            signature (str): Signature of the identity data
            
        Returns:
            str: Transaction hash of the registration
        """
        pass
    
    def verify_identity(self, public_key):
        """
        Verify an identity on the blockchain.
        
        Args:
            public_key (str): The public key to verify
            
        Returns:
            dict: Verification results
        """
        pass
    
    # Additional methods...
```

## Usage Examples

### Encrypting and Decrypting a Message

```python
from core.key_manager import KeyManager
from core.advanced_crypto import PGPCrypto

# Initialize components
key_manager = KeyManager()
crypto = PGPCrypto()

# Generate a key pair
key_info = key_manager.generate_key_pair(
    user_id="Test User <test@example.com>",
    key_type="RSA",
    key_length=4096,
    passphrase="secure_passphrase"
)

# Encrypt a message
public_key = key_info['public_key']
encrypted = crypto.encrypt(
    b"Hello, World!",
    public_keys=[public_key],
    sign_key=(key_info['private_key'], "secure_passphrase")
)

# Decrypt the message
decrypted, was_signed, sig_verified = crypto.decrypt(
    encrypted,
    private_key=key_info['private_key'],
    passphrase="secure_passphrase"
)
```

## Advanced Features

### Performance Optimizations for Large Files

When working with large files, the following optimizations can significantly improve performance:

#### 1. Chunked Processing
```python
def process_large_file(input_path, output_path, chunk_size=64 * 1024 * 1024):  # 64MB chunks
    """
    Process a large file in chunks to minimize memory usage.
    
    Args:
        input_path (str): Path to the input file
        output_path (str): Path to save the processed file
        chunk_size (int): Size of each chunk in bytes (default: 64MB)
    """
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            # Process chunk here
            f_out.write(processed_chunk)
```

#### 2. Parallel Processing
```python
from concurrent.futures import ThreadPoolExecutor
import os

def parallel_process_file(input_path, output_path, num_workers=4):
    """
    Process file chunks in parallel using multiple threads.
    
    Args:
        input_path (str): Path to the input file
        output_path (str): Path to save the processed file
        num_workers (int): Number of worker threads to use
    """
    file_size = os.path.getsize(input_path)
    chunk_size = (file_size + num_workers - 1) // num_workers
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(num_workers):
            start = i * chunk_size
            end = min((i + 1) * chunk_size, file_size)
            future = executor.submit(
                process_chunk,
                input_path,
                output_path,
                start,
                end
            )
            futures.append(future)
        
        # Wait for all chunks to complete
        for future in futures:
            future.result()
```

#### 3. Memory-Mapped Files
```python
import mmap

def process_with_mmap(input_path, output_path):
    """
    Process file using memory mapping for better I/O performance.
    
    Args:
        input_path (str): Path to the input file
        output_path (str): Path to save the processed file
    """
    with open(input_path, 'r+b') as f:
        # Memory-map the file
        mm = mmap.mmap(f.fileno(), 0)
        try:
            # Process memory-mapped file here
            # Example: Simple XOR operation (replace with actual processing)
            data = bytearray(mm)
            for i in range(len(data)):
                data[i] ^= 0x55  # Simple XOR with 0x55
            
            # Write result to output file
            with open(output_path, 'wb') as out_f:
                out_f.write(data)
        finally:
            mm.close()
```

#### 4. Compression Optimization
When encrypting large files, consider these strategies:
- Enable compression before encryption (default in most PGP implementations)
- Use faster compression algorithms for large files (e.g., ZIP_DEFLATED with level 1)
- Consider disabling compression for already compressed files (e.g., .zip, .jpg, .mp4)

#### 5. Hardware Acceleration
- Utilize AES-NI instructions for faster symmetric encryption
- Offload cryptographic operations to hardware security modules (HSMs) when available
- Use OpenSSL's hardware acceleration features

### Hardware Security Module (HSM) Integration

The `hsm.py` module provides integration with Hardware Security Modules for secure key storage and cryptographic operations.

### Trust Model

The `trust_model.py` implements a flexible trust model for key verification and web of trust functionality.

## Error Handling

### Common Exceptions

- `KeyGenerationError`: Failed to generate a key pair
- `EncryptionError`: Error during encryption
- `DecryptionError`: Error during decryption
- `KeyImportError`: Failed to import a key
- `VerificationError`: Signature verification failed

Example error handling:

```python
from core.exceptions import KeyGenerationError, EncryptionError

try:
    # Code that might raise exceptions
    pass
except KeyGenerationError as e:
    print(f"Key generation failed: {e}")
except EncryptionError as e:
    print(f"Encryption failed: {e}")
```

## License

© Copyright 2024-2025 Nsfr750 - All rights reserved
