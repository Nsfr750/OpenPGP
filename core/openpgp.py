import os
import sys
import logging
from typing import Optional, Tuple, Dict, Any, Union, List
from enum import Enum, auto
from pathlib import Path

# Import crypto modules
from . import pqcrypto
from .hybrid_crypto import get_hybrid_crypto as _get_hybrid_crypto

logger = logging.getLogger(__name__)

# Try to import pgpy, but handle the imghdr import issue
try:
    from pgpy import PGPKey, PGPMessage, PGPUID, PGPSignature
except ModuleNotFoundError as e:
    if 'imghdr' in str(e):
        # Create a minimal imghdr module
        class ImghdrModule:
            @staticmethod
            def what(file, h=None):
                return None
        
        # Add the minimal imghdr module to sys.modules
        sys.modules['imghdr'] = ImghdrModule()
        
        # Try the import again
        from pgpy import PGPKey, PGPMessage, PGPUID, PGPSignature
    else:
        # Re-raise if it's a different import error
        raise
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, NoEncryption, load_pem_private_key,
    load_pem_public_key, Encoding, PublicFormat, PrivateFormat
)
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import base64
import hashlib

# --- OpenPGP Key Management ---
def get_key_fingerprint(key: PGPKey) -> str:
    """Return the fingerprint of a PGP key."""
    return key.fingerprint if hasattr(key, 'fingerprint') else ''

def export_public_key(key: PGPKey, filename: str) -> None:
    """Export only the public part of a PGP key to file."""
    try:
        pubkey = key.pubkey if hasattr(key, 'pubkey') else key
        with open(filename, 'w') as f:
            f.write(str(pubkey))
    except Exception as e:
        raise IOError(f"Failed to export public key: {e}")
def generate_pqc_keypair(name: str, email: str, algorithm: str = 'KYBER_DILITHIUM', 
                        passphrase: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a new post-quantum key pair.
    
    Args:
        name: User name
        email: User email
        algorithm: Post-quantum algorithm to use ('KYBER', 'DILITHIUM', or 'KYBER_DILITHIUM')
        passphrase: Optional passphrase to protect the private key
        
    Returns:
        Dict containing the generated keys and metadata
    """
    if not hasattr(pqcrypto, 'PQC_AVAILABLE') or not pqcrypto.PQC_AVAILABLE:
        raise RuntimeError("Post-quantum cryptography is not available. Install required libraries.")
    
    result = {
        'name': name,
        'email': email,
        'algorithm': algorithm,
        'created': datetime.utcnow().isoformat(),
    }
    
    try:
        if algorithm == 'KYBER':
            # Generate Kyber key pair for encryption
            public_key, private_key = pqcrypto.PQCrypto.generate_kyber_keypair()
            result.update({
                'public_key': public_key.hex(),
                'private_key': private_key.hex(),
                'key_type': 'kyber1024',
            })
            
        elif algorithm == 'DILITHIUM':
            # Generate Dilithium key pair for signatures
            public_key, private_key = pqcrypto.PQCrypto.generate_dilithium_keypair()
            result.update({
                'public_key': public_key.hex(),
                'private_key': private_key.hex(),
                'key_type': 'dilithium5',
            })
            
        elif algorithm == 'KYBER_DILITHIUM':
            # Generate both Kyber and Dilithium key pairs for hybrid use
            kyber_public, kyber_private = pqcrypto.PQCrypto.generate_kyber_keypair()
            dilithium_public, dilithium_private = pqcrypto.PQCrypto.generate_dilithium_keypair()
            
            result.update({
                'kyber_public_key': kyber_public.hex(),
                'kyber_private_key': kyber_private.hex(),
                'dilithium_public_key': dilithium_public.hex(),
                'dilithium_private_key': dilithium_private.hex(),
                'key_type': 'kyber1024+dilithium5',
            })
        else:
            raise ValueError(f"Unsupported post-quantum algorithm: {algorithm}")
            
        # Optionally encrypt private keys with passphrase
        if passphrase:
            if 'private_key' in result:
                result['private_key'] = _encrypt_private_key(
                    bytes.fromhex(result['private_key']), 
                    passphrase
                ).hex()
            if 'kyber_private_key' in result:
                result['kyber_private_key'] = _encrypt_private_key(
                    bytes.fromhex(result['kyber_private_key']), 
                    passphrase
                ).hex()
            if 'dilithium_private_key' in result:
                result['dilithium_private_key'] = _encrypt_private_key(
                    bytes.fromhex(result['dilithium_private_key']), 
                    passphrase
                ).hex()
                
        return result
        
    except Exception as e:
        logger.error(f"Failed to generate PQC key pair: {str(e)}")
        raise

def _encrypt_private_key(private_key: bytes, passphrase: str) -> bytes:
    """Encrypt a private key with a passphrase."""
    # In a real implementation, use a proper KDF and authenticated encryption
    # This is a simplified example
    key = hashlib.sha256(passphrase.encode()).digest()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(private_key))

def _decrypt_private_key(encrypted_key: bytes, passphrase: str) -> bytes:
    """Decrypt a private key with a passphrase."""
    # This is the inverse of _encrypt_private_key
    key = hashlib.sha256(passphrase.encode()).digest()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted_key))

def generate_pgp_keypair(name: str, email: str, passphrase: Optional[str] = None, 
                        algorithm: str = 'RSA', key_size: int = 2048, curve: str = 'ed25519',
                        key_expiry_days: Optional[int] = None, 
                        enable_pqc: bool = False) -> PGPKey:
    """
    Generate a new PGP keypair.
    
    Args:
        name (str): User name.
        email (str): User email.
        passphrase (Optional[str]): Passphrase to protect the key.
        algorithm (str): 'RSA' or 'ECC'.
        key_size (int): Key size for RSA (ignored for ECC).
        curve (str): Curve name for ECC (e.g., 'ed25519', 'nistp256', etc.).
        
    Returns:
        PGPKey: Generated key.
        
    Raises:
        ValueError: If an unsupported algorithm or curve is provided.
    """
    # Create a new key with the specified algorithm
    if algorithm.upper() == 'RSA':
        if key_size not in [2048, 3072, 4096, 8192]:
            raise ValueError('RSA key size must be 2048, 3072, 4096, or 8192 bits')
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    elif algorithm.upper() == 'ECC':
        # Map curve names to PGP key parameters
        curve_params = {
            'ed25519': (PubKeyAlgorithm.ECDSA, 256, 'ed25519'),
            'nistp256': (PubKeyAlgorithm.ECDSA, 256, 'nistp256'),
            'nistp384': (PubKeyAlgorithm.ECDSA, 384, 'nistp384'),
            'nistp521': (PubKeyAlgorithm.ECDSA, 521, 'nistp521')
        }
        
        if curve not in curve_params:
            raise ValueError(f'Unsupported curve: {curve}. Must be one of: {list(curve_params.keys())}')
            
        pubkey_algo, key_size, curve_name = curve_params[curve]
        key = PGPKey.new(pubkey_algo, key_size, curve=curve_name)
    else:
        raise ValueError(f'Unsupported algorithm: {algorithm}. Must be "RSA" or "ECC"')
    
    # Create user ID
    uid = PGPUID.new(name, email=email)
    
    # Set key usage flags
    usage = {KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
    
    # Add user ID with preferences
    key.add_uid(
        uid, 
        usage=usage,
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed]
    )
    
    # Set key expiration if specified
    if key_expiry_days is not None and key_expiry_days > 0:
        expiry_date = datetime.utcnow() + timedelta(days=key_expiry_days)
        for subkey in key.subkeys.values():
            subkey._key.sig.expires_at = expiry_date
        for uid in key.user_attributes.values():
            for sig in uid.signatures:
                sig.expires_at = expiry_date
    
    # Protect the key with a passphrase if provided
    if passphrase:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    
    return key

def save_pgp_key(key: PGPKey, filename: str) -> None:
    """Save a PGP key to file."""
    try:
        with open(filename, 'w') as f:
            f.write(str(key))
    except Exception as e:
        raise IOError(f"Failed to save key: {e}")

def load_pgp_key(filename: str, passphrase: Optional[str] = None) -> PGPKey:
    """Load a PGP key from file."""
    try:
        with open(filename, 'r') as f:
            key, _ = PGPKey.from_blob(f.read())
        if key.is_protected and passphrase:
            key.unlock(passphrase)
        return key
    except Exception as e:
        raise IOError(f"Failed to load key: {e}")

# --- Hybrid Post-Quantum Encryption/Decryption ---

def generate_hybrid_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a hybrid keypair (classic ECDH + PQC Kyber).
    
    Returns:
        Tuple of (private_key, public_key) in PEM format
    """
    hybrid = _get_hybrid_crypto()
    return hybrid.generate_keypair()

def hybrid_encrypt(
    public_key: Union[bytes, str],
    message: Union[bytes, str],
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using hybrid encryption.
    
    Args:
        public_key: Recipient's public key in PEM format (bytes or str)
        message: Data to encrypt (bytes or str)
        associated_data: Optional additional authenticated data
        
    Returns:
        Tuple of (ciphertext, encrypted_session_key)
    """
    if isinstance(public_key, str):
        public_key = public_key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    hybrid = _get_hybrid_crypto()
    return hybrid.encrypt(public_key, message, associated_data)

def hybrid_decrypt(
    private_key: Union[bytes, str],
    ciphertext: bytes,
    encrypted_message: bytes,
    associated_data: Optional[bytes] = None,
    passphrase: Optional[Union[str, bytes]] = None
) -> bytes:
    """
    Decrypt data using hybrid decryption.
    
    Args:
        private_key: Recipient's private key in PEM format (bytes or str)
        ciphertext: Encrypted data
        encrypted_message: Encrypted session key and metadata
        associated_data: Optional additional authenticated data
        passphrase: Password for private key if encrypted
        
    Returns:
        Decrypted plaintext as bytes
    """
    hybrid = _get_hybrid_crypto()
    
    # Handle private key input
    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')
    
    # If passphrase is provided, decrypt the private key first
    if passphrase:
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf-8')
        private_key = _decrypt_private_key(private_key, passphrase)
    
    try:
        return hybrid.decrypt(private_key, ciphertext, encrypted_message, associated_data)
    except Exception as e:
        logger.error(f"Hybrid decryption failed: {str(e)}")
        raise

# --- OpenPGP Encryption/Decryption ---
def encrypt_message(message: str, pubkey: PGPKey) -> str:
    """Encrypt a message with a public key.
    
    Args:
        message: The message to encrypt
        pubkey: The public key to encrypt with
        
    Returns:
        str: The encrypted message in ASCII armor format
    """
    try:
        # Create a new message with compression disabled
        msg = PGPMessage.new(message, compression=CompressionAlgorithm.Uncompressed)
        
        # Get the key's preferred compression algorithms if available
        prefs = getattr(pubkey, 'preferred_compression', None)
        if prefs and len(prefs) > 0:
            # Use the most preferred compression algorithm
            compression = prefs[0]
        else:
            # Default to ZLIB if no preferences are set
            compression = CompressionAlgorithm.ZLIB
            
        # Set the compression for the message
        msg._compression = compression
        
        # Encrypt the message
        encrypted = pubkey.encrypt(msg)
        return str(encrypted)
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")

def decrypt_message(encrypted_message: str, privkey: PGPKey, passphrase: Optional[str] = None) -> str:
    """Decrypt a message with a private key."""
    try:
        msg = PGPMessage.from_blob(encrypted_message)
        if privkey.is_protected and passphrase:
            with privkey.unlock(passphrase):
                decrypted = privkey.decrypt(msg)
        else:
            decrypted = privkey.decrypt(msg)
        return decrypted.message
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def revoke_key(key: PGPKey, reason: str = 'Key is no longer used', passphrase: Optional[str] = None) -> str:
    """
    Revoke a PGP key.
    
    Args:
        key: The PGP key to revoke (must be a private key)
        reason: Reason for revocation
        passphrase: Passphrase if the key is protected
        
    Returns:
        str: The revocation certificate in ASCII armor format
        
    Raises:
        ValueError: If revocation fails
    """
    try:
        if key.is_public:
            raise ValueError("Cannot revoke a public key. Use the private key instead.")
            
        # Create a revocation certificate
        revoke_sig = key.revoke(reason=reason)
        
        # If key is protected, unlock it first
        if key.is_protected and passphrase:
            with key.unlock(passphrase):
                revoke_sig = key.revoke(reason=reason)
        
        # Return the revocation certificate
        return str(revoke_sig)
    except Exception as e:
        raise ValueError(f"Failed to revoke key: {str(e)}")

def update_key_expiry(key: PGPKey, expiry_days: Optional[int], passphrase: Optional[str] = None) -> None:
    """
    Update the expiration time of a PGP key.
    
    Args:
        key: The PGP key to update (must be a private key)
        expiry_days: Number of days until the key expires (None for no expiration)
        passphrase: Passphrase if the key is protected
        
    Raises:
        ValueError: If the update fails
    """
    try:
        if key.is_public:
            raise ValueError("Cannot update expiration of a public key. Use the private key instead.")
            
        # Calculate expiry date (None means no expiration)
        expiry_date = datetime.utcnow() + timedelta(days=expiry_days) if expiry_days else None
        
        # Update expiration for subkeys
        for subkey in key.subkeys.values():
            subkey._key.sig.expires_at = expiry_date
            
        # Update expiration for user IDs
        for uid in key.user_attributes.values():
            for sig in uid.signatures:
                sig.expires_at = expiry_date
        
        # If key is protected, unlock it first
        if key.is_protected and passphrase:
            with key.unlock(passphrase):
                key.sign(key, expires_in=timedelta(days=expiry_days) if expiry_days else None)
        else:
            key.sign(key, expires_in=timedelta(days=expiry_days) if expiry_days else None)
            
    except Exception as e:
        raise ValueError(f"Failed to update key expiration: {str(e)}")

# --- OpenPGP Signing/Verification ---
def sign_message(message: str, privkey: PGPKey, passphrase: Optional[str] = None) -> str:
    """
    Sign a message with a private key (detached signature).
    
    Args:
        message: The message to sign
        privkey: The private key to sign with
        passphrase: Passphrase to unlock the private key if protected
        
    Returns:
        str: The detached signature in ASCII armor format
        
    Raises:
        ValueError: If signing fails
    """
    try:
        # Create a message object
        msg = PGPMessage.new(message)
        
        # Get the preferred hash algorithm based on key type
        if hasattr(privkey, 'is_primary') and privkey.is_primary:
            # For Ed25519 keys, use SHA-512 as per OpenPGP best practices
            if privkey.key_algorithm == PubKeyAlgorithm.ECDSA and hasattr(privkey, 'curve') and privkey.curve == 'ed25519':
                hash_algo = HashAlgorithm.SHA512
            else:
                # For other key types, use the preferred hash algorithm or default to SHA256
                prefs = getattr(privkey, 'preferred_hash', [HashAlgorithm.SHA256])
                hash_algo = prefs[0] if prefs else HashAlgorithm.SHA256
        else:
            hash_algo = HashAlgorithm.SHA256
        
        # Sign the message
        if privkey.is_protected and passphrase:
            with privkey.unlock(passphrase):
                signature = privkey.sign(msg, hash_algorithm=hash_algo, detached=True)
        else:
            signature = privkey.sign(msg, hash_algorithm=hash_algo, detached=True)
            
        return str(signature)
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def verify_signature(message: str, signature_str: str, pubkey: PGPKey) -> bool:
    """
    Verify a detached signature.
    
    Args:
        message: The original message that was signed
        signature_str: The detached signature in ASCII armor format
        pubkey: The public key to verify the signature
        
    Returns:
        bool: True if the signature is valid, False otherwise
        
    Raises:
        ValueError: If verification fails or the signature is invalid
    """
    try:
        # Create a message object from the original message
        if not isinstance(message, (bytes, bytearray)):
            message = message.encode('utf-8')
            
        # Parse the signature
        signature = PGPSignature.from_blob(signature_str)
        if isinstance(signature, list):
            if not signature:
                raise ValueError("No signature found in the provided data")
            signature = signature[0]
            
        # Create a message object with the correct format for verification
        msg = PGPMessage.new(message, format='utf8')
        
        # Verify the signature
        return pubkey.verify(message, signature) is not False
    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

# --- SSL Certificate Generation ---
def generate_ssl_cert(common_name: str, key_file: str, cert_file: str, passphrase: Optional[str] = None, key_size: int = 2048, days_valid: int = 365) -> None:
    """
    Generate a self-signed SSL certificate and save to file.
    Args:
        common_name (str): Common Name (CN) for the certificate.
        key_file (str): Path to save the private key.
        cert_file (str): Path to save the certificate.
        passphrase (Optional[str]): Passphrase to protect the private key.
        key_size (int): RSA key size.
        days_valid (int): Validity period in days.
    """
    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=days_valid)
        ).sign(key, hashes.SHA256(), default_backend())
        # Save private key
        if passphrase:
            encryption = BestAvailableEncryption(passphrase.encode())
        else:
            encryption = NoEncryption()
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption
            ))
        # Save certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        raise IOError(f"Failed to generate SSL certificate: {e}")
