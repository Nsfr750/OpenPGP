import os
import sys
from typing import Optional

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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

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
def generate_pgp_keypair(name: str, email: str, passphrase: Optional[str] = None, algorithm: str = 'RSA', key_size: int = 2048) -> PGPKey:
    """
    Generate a new PGP keypair.
    Args:
        name (str): User name.
        email (str): User email.
        passphrase (Optional[str]): Passphrase to protect the key.
        algorithm (str): 'RSA' or 'ECC'.
        key_size (int): Key size for RSA (ignored for ECC).
    Returns:
        PGPKey: Generated key.
    """
    if algorithm.upper() == 'RSA':
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    elif algorithm.upper() == 'ECC':
        key = PGPKey.new(PubKeyAlgorithm.ECDSA, 256)  # Curve25519 not supported by pgpy yet
    else:
        raise ValueError('Unsupported algorithm: ' + algorithm)
    uid = PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB])
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

# --- OpenPGP Encryption/Decryption ---
def encrypt_message(message: str, pubkey: PGPKey) -> str:
    """Encrypt a message with a public key."""
    try:
        msg = PGPMessage.new(message)
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

# --- OpenPGP Signing/Verification ---
def sign_message(message: str, privkey: PGPKey, passphrase: Optional[str] = None) -> str:
    """Sign a message with a private key (detached signature)."""
    try:
        if privkey.is_protected and passphrase:
            with privkey.unlock(passphrase):
                signature = privkey.sign(message, detached=True)
        else:
            signature = privkey.sign(message, detached=True)
        return str(signature)
    except Exception as e:
        raise ValueError(f"Signing failed: {e}")

def verify_signature(message: str, signature_str: str, pubkey: PGPKey) -> bool:
    """Verify a detached signature."""
    try:
        signature = PGPSignature.from_blob(signature_str)
        return pubkey.verify(message, signature)
    except Exception as e:
        raise ValueError(f"Verification failed: {e}")

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
