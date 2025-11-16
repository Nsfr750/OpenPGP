"""
Hybrid cryptographic operations combining classical and post-quantum algorithms.
"""
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.exceptions import InvalidSignature
import logging

# Import PQC module if available
try:
    from .pqcrypto import Kyber, Dilithium, HybridCrypto
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

logger = logging.getLogger(__name__)

class HybridEncryption:
    """
    Provides hybrid encryption combining classical and post-quantum cryptography.
    """
    
    def __init__(self, use_pqc: bool = True):
        """
        Initialize hybrid encryption.
        
        Args:
            use_pqc: Whether to enable post-quantum cryptography
        """
        self.use_pqc = use_pqc and PQC_AVAILABLE
        self.kyber = Kyber() if self.use_pqc else None
        self.dilithium = Dilithium() if self.use_pqc else None
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a hybrid keypair (classic ECDH + PQC Kyber).
        
        Returns:
            Tuple of (private_key, public_key) as bytes
        """
        # Generate classic ECDH keypair
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        
        # Serialize keys
        private_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        # If PQC is available, generate Kyber keypair
        if self.use_pqc:
            try:
                pq_private, pq_public = self.kyber.generate_keypair()
                # Combine keys
                private_bytes = b'HYBRID:' + private_bytes + b':' + pq_private
                public_bytes = b'HYBRID:' + public_bytes + b':' + pq_public
            except Exception as e:
                logger.warning(f"Failed to generate PQC keys: {e}")
                logger.warning("Falling back to classic encryption only")
        
        return private_bytes, public_bytes
    
    def encrypt(
        self,
        public_key: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data using hybrid encryption.
        
        Args:
            public_key: Recipient's public key
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Tuple of (ciphertext, encrypted_session_key)
        """
        # Parse the public key
        if public_key.startswith(b'HYBRID:'):
            # Extract classic and PQC public keys
            try:
                _, classic_pub, pq_pub = public_key.split(b':', 2)
                use_hybrid = True
            except ValueError:
                raise ValueError("Invalid hybrid public key format")
        else:
            # Classic key only
            classic_pub = public_key
            use_hybrid = False
        
        # Generate an ephemeral key pair
        eph_private = ec.generate_private_key(ec.SECP384R1())
        eph_public = eph_private.public_key()
        
        # Derive shared secret using ECDH
        try:
            peer_public_key = load_public_key(classic_pub)
            shared_secret = eph_private.exchange(ec.ECDH(), peer_public_key)
        except Exception as e:
            raise ValueError(f"Failed to derive shared secret: {e}")
        
        # If using hybrid mode, add PQC KEM
        if use_hybrid and self.use_pqc:
            try:
                # Generate PQC shared secret and ciphertext
                pq_shared_secret, pq_ciphertext = self.kyber.encapsulate(pq_pub)
                
                # Combine shared secrets
                hkdf = HKDF(
                    algorithm=hashes.SHA512(),
                    length=64,
                    salt=None,
                    info=b'hybrid_kdf'
                )
                key_material = hkdf.derive(shared_secret + pq_shared_secret)
                
                # Use first 32 bytes for encryption, next 32 for HMAC
                enc_key = key_material[:32]
                auth_key = key_material[32:]
                
            except Exception as e:
                logger.warning(f"PQC encryption failed: {e}")
                logger.warning("Falling back to classic encryption")
                key_material = shared_secret
                pq_ciphertext = b''
        else:
            # Classic mode only
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=b'classic_kdf'
            )
            key_material = hkdf.derive(shared_secret)
            enc_key = key_material
            auth_key = b''
            pq_ciphertext = b''
        
        # Encrypt the data
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.GCM(iv)
        )
        encryptor = cipher.encryptor()
        
        # Add associated data if provided
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        # Encrypt the data
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Create the encrypted message structure
        encrypted_message = (
            eph_public.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ) +
            b'|' + iv +
            b'|' + encryptor.tag
        )
        
        # Add PQC ciphertext if using hybrid mode
        if pq_ciphertext:
            encrypted_message += b'|' + pq_ciphertext
        
        return ciphertext, encrypted_message
    
    def decrypt(
        self,
        private_key: bytes,
        ciphertext: bytes,
        encrypted_message: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data using hybrid decryption.
        
        Args:
            private_key: Recipient's private key
            ciphertext: Encrypted data
            encrypted_message: Encrypted session key and metadata
            associated_data: Optional additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        # Parse the private key
        if private_key.startswith(b'HYBRID:'):
            try:
                _, classic_priv, pq_priv = private_key.split(b':', 2)
                use_hybrid = True
            except ValueError:
                raise ValueError("Invalid hybrid private key format")
        else:
            classic_priv = private_key
            use_hybrid = False
        
        # Parse the encrypted message
        try:
            parts = encrypted_message.split(b'|', 3)
            if len(parts) < 3:
                raise ValueError("Invalid encrypted message format")
                
            if len(parts) == 4 and use_hybrid:
                # Hybrid mode with PQC
                eph_public_bytes, iv, tag, pq_ciphertext = parts
            else:
                # Classic mode
                eph_public_bytes, iv, tag = parts[:3]
                pq_ciphertext = None
        except Exception as e:
            raise ValueError(f"Failed to parse encrypted message: {e}")
        
        # Load the ephemeral public key
        try:
            eph_public = load_public_key(eph_public_bytes)
        except Exception as e:
            raise ValueError(f"Invalid ephemeral public key: {e}")
        
        # Load the private key
        try:
            private_key = load_private_key(classic_priv)
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")
        
        # Derive shared secret using ECDH
        try:
            shared_secret = private_key.exchange(ec.ECDH(), eph_public)
        except Exception as e:
            raise ValueError(f"Failed to derive shared secret: {e}")
        
        # If using hybrid mode, add PQC KEM
        if use_hybrid and self.use_pqc and pq_ciphertext:
            try:
                # Decapsulate PQC shared secret
                pq_shared_secret = self.kyber.decapsulate(pq_priv, pq_ciphertext)
                
                # Combine shared secrets
                hkdf = HKDF(
                    algorithm=hashes.SHA512(),
                    length=64,
                    salt=None,
                    info=b'hybrid_kdf'
                )
                key_material = hkdf.derive(shared_secret + pq_shared_secret)
                
                # Use first 32 bytes for encryption, next 32 for HMAC
                enc_key = key_material[:32]
                auth_key = key_material[32:]
                
            except Exception as e:
                logger.warning(f"PQC decryption failed: {e}")
                logger.warning("Falling back to classic decryption")
                key_material = shared_secret
        else:
            # Classic mode only
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=b'classic_kdf'
            )
            key_material = hkdf.derive(shared_secret)
            enc_key = key_material
        
        # Decrypt the data
        try:
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.GCM(iv, tag)
            )
            decryptor = cipher.decryptor()
            
            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            
            # Decrypt the data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

def load_public_key(public_key: bytes):
    """Load a public key from bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(public_key)

def load_private_key(private_key: bytes, password: Optional[bytes] = None):
    """Load a private key from bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(private_key, password=password)

# Singleton instance
_hybrid_crypto = HybridEncryption()

def get_hybrid_crypto() -> HybridEncryption:
    """Get the global HybridEncryption instance."""
    return _hybrid_crypto
