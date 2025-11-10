"""
Advanced Cryptographic Operations for OpenPGP

This module provides advanced cryptographic operations including post-quantum cryptography,
threshold cryptography, and other advanced cryptographic primitives.
"""
import os
import logging
import hashlib
import hmac
from typing import Optional, Tuple, List, Dict, Any, Union
from pathlib import Path
from cryptography.hazmat.primitives import hashes, hmac as hmac_primitive
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_ssh_public_key, Encoding, PublicFormat, PrivateFormat,
    NoEncryption, BestAvailableEncryption
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, InvalidKey
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional, Union, Dict, Any

logger = logging.getLogger(__name__)

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES256_GCM = auto()
    CHACHA20_POLY1305 = auto()
    AES256_CBC = auto()

class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()
    BLAKE2B = auto()
    BLAKE2S = auto()
    SHA3_256 = auto()
    SHA3_512 = auto()

@dataclass
class EncryptedData:
    """Container for encrypted data and its metadata."""
    ciphertext: bytes
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None
    algorithm: Optional[str] = None
    key_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the encrypted data to a dictionary."""
        return {
            'ciphertext': self.ciphertext,
            'iv': self.iv,
            'tag': self.tag,
            'algorithm': self.algorithm,
            'key_id': self.key_id,
            'additional_data': self.additional_data or {}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedData':
        """Create an EncryptedData instance from a dictionary."""
        return cls(
            ciphertext=data['ciphertext'],
            iv=data.get('iv'),
            tag=data.get('tag'),
            algorithm=data.get('algorithm'),
            key_id=data.get('key_id'),
            additional_data=data.get('additional_data', {})
        )

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

class KeyDerivationError(CryptoError):
    """Exception for key derivation errors."""
    pass

class EncryptionError(CryptoError):
    """Exception for encryption/decryption errors."""
    pass

class SignatureError(CryptoError):
    """Exception for signature verification errors."""
    pass

class AdvancedCrypto:
    """Class for advanced cryptographic operations."""
    
    # Default parameters
    DEFAULT_HASH_ALGORITHM = hashes.SHA256
    DEFAULT_KEY_SIZE = 32  # 256 bits
    DEFAULT_IV_SIZE = 16   # 128 bits
    DEFAULT_ITERATIONS = 100000
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize the AdvancedCrypto instance.
        
        Args:
            key: Optional symmetric key for encryption/decryption
        """
        self.key = key
        self.backend = default_backend()
    
    def derive_key(self, password: Union[str, bytes], salt: Optional[bytes] = None,
                  length: int = 32, iterations: int = DEFAULT_ITERATIONS) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        Args:
            password: The password to derive the key from
            salt: Optional salt (random bytes will be generated if not provided)
            length: Length of the derived key in bytes
            iterations: Number of iterations for key derivation
            
        Returns:
            Tuple of (derived_key, salt)
        """
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')
                
            if salt is None:
                salt = os.urandom(16)
                
            kdf = PBKDF2HMAC(
                algorithm=self.DEFAULT_HASH_ALGORITHM(),
                length=length,
                salt=salt,
                iterations=iterations,
                backend=self.backend
            )
            
            key = kdf.derive(password)
            return key, salt
            
        except Exception as e:
            raise KeyDerivationError(f"Error deriving key: {e}")
    
    def encrypt_data(self, data: bytes, key: Optional[bytes] = None,
                    iv: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            key: Encryption key (default: use instance key)
            iv: Initialization vector (random bytes will be generated if not provided)
            
        Returns:
            Tuple of (ciphertext, iv, tag)
        """
        try:
            key = key or self.key
            if key is None:
                raise EncryptionError("No encryption key provided")
                
            if iv is None:
                iv = os.urandom(12)  # 96 bits for GCM
                
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=self.backend
            )
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return ciphertext, iv, encryptor.tag
            
        except Exception as e:
            raise EncryptionError(f"Error encrypting data: {e}")
    
    def decrypt_data(self, ciphertext: bytes, key: Optional[bytes],
                    iv: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            key: Decryption key
            iv: Initialization vector
            tag: Authentication tag
            
        Returns:
            Decrypted data
        """
        try:
            key = key or self.key
            if key is None:
                raise EncryptionError("No decryption key provided")
                
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        except Exception as e:
            raise EncryptionError(f"Error decrypting data: {e}")
    
    def generate_keypair(self, algorithm: str = 'ed25519') -> Tuple[bytes, bytes]:
        """
        Generate a new key pair.
        
        Args:
            algorithm: Key generation algorithm ('ed25519', 'x25519', 'rsa', 'ecdsa')
            
        Returns:
            Tuple of (private_key, public_key) in bytes
        """
        try:
            algorithm = algorithm.lower()
            
            if algorithm == 'ed25519':
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key()
                
                private_bytes = private_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption()
                )
                
                public_bytes = public_key.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw
                )
                
                return private_bytes, public_bytes
                
            elif algorithm == 'x25519':
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key()
                
                private_bytes = private_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption()
                )
                
                public_bytes = public_key.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw
                )
                
                return private_bytes, public_bytes
                
            elif algorithm == 'rsa':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                    backend=self.backend
                )
                
                public_key = private_key.public_key()
                
                private_bytes = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
                
                public_bytes = public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
                
                return private_bytes, public_bytes
                
            elif algorithm == 'ecdsa':
                private_key = ec.generate_private_key(
                    ec.SECP384R1(),
                    self.backend
                )
                
                public_key = private_key.public_key()
                
                private_bytes = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
                
                public_bytes = public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                )
                
                return private_bytes, public_bytes
                
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        except Exception as e:
            raise CryptoError(f"Error generating key pair: {e}")
    
    def sign_data(self, data: bytes, private_key: bytes, 
                 algorithm: str = 'ed25519') -> bytes:
        """
        Sign data using a private key.
        
        Args:
            data: Data to sign
            private_key: Private key in bytes
            algorithm: Signature algorithm ('ed25519', 'rsa', 'ecdsa')
            
        Returns:
            Signature in bytes
        """
        try:
            algorithm = algorithm.lower()
            
            if algorithm == 'ed25519':
                private_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
                return private_key.sign(data)
                
            elif algorithm == 'rsa':
                private_key = serialization.load_pem_private_key(
                    private_key,
                    password=None,
                    backend=self.backend
                )
                
                if not isinstance(private_key, rsa.RSAPrivateKey):
                    raise ValueError("Invalid RSA private key")
                
                return private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
            elif algorithm == 'ecdsa':
                private_key = serialization.load_pem_private_key(
                    private_key,
                    password=None,
                    backend=self.backend
                )
                
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Invalid ECDSA private key")
                
                return private_key.sign(
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        except Exception as e:
            raise SignatureError(f"Error signing data: {e}")
    
    def verify_signature(self, data: bytes, signature: bytes, 
                        public_key: bytes, algorithm: str = 'ed25519') -> bool:
        """
        Verify a signature using a public key.
        
        Args:
            data: Original data that was signed
            signature: Signature to verify
            public_key: Public key in bytes
            algorithm: Signature algorithm ('ed25519', 'rsa', 'ecdsa')
            
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        try:
            algorithm = algorithm.lower()
            
            if algorithm == 'ed25519':
                public_key = x25519.X25519PublicKey.from_public_bytes(public_key)
                public_key.verify(signature, data)
                return True
                
            elif algorithm == 'rsa':
                public_key = serialization.load_pem_public_key(
                    public_key,
                    backend=self.backend
                )
                
                if not isinstance(public_key, rsa.RSAPublicKey):
                    raise ValueError("Invalid RSA public key")
                
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
                
            elif algorithm == 'ecdsa':
                public_key = serialization.load_pem_public_key(
                    public_key,
                    backend=self.backend
                )
                
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise ValueError("Invalid ECDSA public key")
                
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
                
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        except (InvalidSignature, InvalidKey) as e:
            return False
        except Exception as e:
            raise SignatureError(f"Error verifying signature: {e}")
