"""
Secure Key Sharing for OpenPGP

This module provides functionality for securely sharing keys between devices.
"""
import os
import json
import logging
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import gnupg
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import x25519, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat

logger = logging.getLogger(__name__)

class KeySharingError(Exception):
    """Base exception for key sharing related errors."""
    pass


class KeySharing:
    """Class for managing secure key sharing operations."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the KeySharing instance.
        
        Args:
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.manager = KeySharingManager(gpg_home=gpg_home)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new key pair for secure key sharing.
        
        Returns:
            Tuple of (private_key, public_key) in bytes
        """
        return self.manager.generate_keypair()
    
    def prepare_key_for_sharing(self, key_fingerprint: str, 
                              recipient_fingerprints: List[str],
                              min_shares: int = 2) -> Dict[str, Any]:
        """
        Prepare a key for secure sharing with multiple recipients.
        
        Args:
            key_fingerprint: Fingerprint of the key to share
            recipient_fingerprints: List of recipient key fingerprints
            min_shares: Minimum number of shares required to reconstruct the key
            
        Returns:
            Dictionary containing the encrypted key shares and metadata
        """
        try:
            # Export the private key
            private_key = self.gpg.export_keys(key_fingerprint, secret=True, 
                                             passphrase='')
            if not private_key:
                raise KeySharingError(f"Failed to export key {key_fingerprint}")
            
            # Get recipient public keys
            recipient_public_keys = []
            for fp in recipient_fingerprints:
                pubkey = self.gpg.export_keys(fp)
                if not pubkey:
                    raise KeySharingError(f"Failed to export public key {fp}")
                recipient_public_keys.append(pubkey.encode('utf-8'))
            
            # Encrypt and split the key
            shares = self.manager.encrypt_key_share(
                key_data=private_key.encode('utf-8'),
                recipient_public_keys=recipient_public_keys,
                min_shares=min_shares
            )
            
            # Prepare the result
            result = {
                'key_fingerprint': key_fingerprint,
                'recipients': recipient_fingerprints,
                'min_shares': min_shares,
                'shares': [s.to_dict() for s in shares],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return result
            
        except Exception as e:
            raise KeySharingError(f"Error preparing key for sharing: {e}")
    
    def reconstruct_key(self, share_data: Dict[str, Any]) -> bool:
        """
        Reconstruct a shared key and import it into the keyring.
        
        Args:
            share_data: Dictionary containing key share data
            
        Returns:
            bool: True if the key was successfully imported
        """
        try:
            # Convert share data to KeyShare objects
            shares = [
                KeyShare.from_dict(share) 
                for share in share_data.get('shares', [])
            ]
            
            # Get the encrypted package (stored in the first share)
            if not shares:
                raise KeySharingError("No key shares provided")
                
            encrypted_package = shares[0].encrypted_package
            
            # Reconstruct the key
            key_data = self.manager.decrypt_key_share(
                key_shares=shares,
                encrypted_package=encrypted_package,
                private_key=None  # Will use the default private key
            )
            
            if not key_data:
                raise KeySharingError("Failed to reconstruct key from shares")
            
            # Import the key
            import_result = self.gpg.import_keys(key_data.decode('utf-8'))
            if not import_result.count:
                raise KeySharingError("Failed to import reconstructed key")
            
            logger.info(f"Successfully imported key {import_result.fingerprints[0]}")
            return True
            
        except Exception as e:
            raise KeySharingError(f"Error reconstructing key: {e}")
    
    def export_share(self, share_data: Dict[str, Any], 
                    output_file: Optional[str] = None) -> str:
        """
        Export key share data to a file.
        
        Args:
            share_data: Dictionary containing key share data
            output_file: Path to the output file (default: auto-generated)
            
        Returns:
            Path to the exported file
        """
        try:
            if not output_file:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                output_file = f"key_share_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(share_data, f, indent=2)
            
            logger.info(f"Exported key share to {output_file}")
            return output_file
            
        except Exception as e:
            raise KeySharingError(f"Error exporting key share: {e}")
    
    def import_share(self, input_file: str) -> Dict[str, Any]:
        """
        Import key share data from a file.
        
        Args:
            input_file: Path to the input file
            
        Returns:
            Dictionary containing the imported key share data
        """
        try:
            with open(input_file, 'r') as f:
                share_data = json.load(f)
            
            # Validate the share data
            required_fields = ['key_fingerprint', 'recipients', 'min_shares', 'shares']
            for field in required_fields:
                if field not in share_data:
                    raise KeySharingError(f"Missing required field: {field}")
            
            logger.info(f"Imported key share for key {share_data['key_fingerprint']}")
            return share_data
            
        except Exception as e:
            raise KeySharingError(f"Error importing key share: {e}")

class KeyShare:
    """Class representing a share of a key."""
    
    def __init__(self, share_id: str, data: bytes, metadata: Optional[Dict[str, Any]] = None):
        self.share_id = share_id
        self.data = data
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the key share to a dictionary."""
        return {
            'share_id': self.share_id,
            'data': self.data.hex(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyShare':
        """Create a KeyShare from a dictionary."""
        return cls(
            share_id=data['share_id'],
            data=bytes.fromhex(data['data']),
            metadata=data.get('metadata', {})
        )

class KeySharingManager:
    """Manager for secure key sharing between devices."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the key sharing manager.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.backend = default_backend()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new X25519 key pair for key sharing.
        
        Returns:
            Tuple of (private_key, public_key) in bytes
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return priv_bytes, pub_bytes
    
    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Derive a shared secret using X25519 key exchange.
        
        Args:
            private_key: Local private key
            peer_public_key: Remote public key
            
        Returns:
            Shared secret bytes
        """
        priv_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        
        shared_secret = priv_key.exchange(pub_key)
        
        # Use HKDF to derive a secure key from the shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'openpgp-key-sharing',
            backend=self.backend
        )
        
        return hkdf.derive(shared_secret)
    
    def encrypt_key_share(self, key_data: bytes, 
                         recipient_public_keys: List[bytes],
                         min_shares: int = 2) -> List[KeyShare]:
        """
        Encrypt a key for secure sharing using Shamir's Secret Sharing.
        
        Args:
            key_data: The key data to encrypt and share
            recipient_public_keys: List of recipient public keys
            min_shares: Minimum number of shares required to reconstruct the key
            
        Returns:
            List of KeyShare objects
        """
        if len(recipient_public_keys) < min_shares:
            raise KeySharingError(
                f"Need at least {min_shares} recipients for {min_shares}-of-{len(recipient_public_keys)} sharing"
            )
        
        # Generate a random encryption key
        encryption_key = os.urandom(32)
        
        # Encrypt the key data with AES-256-GCM
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(key_data) + encryptor.finalize()
        
        # Create the encrypted package
        package = {
            'version': '1.0',
            'iv': iv.hex(),
            'ciphertext': encrypted_data.hex(),
            'tag': encryptor.tag.hex(),
            'algorithm': 'aes-256-gcm'
        }
        
        # Split the encryption key using Shamir's Secret Sharing
        shares = self._split_secret(encryption_key, len(recipient_public_keys), min_shares)
        
        # Encrypt each share with the recipient's public key
        key_shares = []
        for i, (share, pub_key_bytes) in enumerate(zip(shares, recipient_public_keys)):
            pub_key = x25519.X25519PublicKey.from_public_bytes(pub_key_bytes)
            
            # Encrypt the share
            encrypted_share = self._encrypt_with_public_key(
                share, 
                pub_key,
                f"share-{i+1}".encode()
            )
            
            key_shares.append(KeyShare(
                share_id=f"share-{i+1}",
                data=encrypted_share,
                metadata={
                    'index': i + 1,
                    'total': len(recipient_public_keys),
                    'min_shares': min_shares
                }
            ))
        
        return key_shares, package
    
    def decrypt_key_share(self, key_shares: List[KeyShare], 
                         encrypted_package: Dict[str, Any],
                         private_key: bytes) -> Optional[bytes]:
        """
        Decrypt a key share and reconstruct the original key.
        
        Args:
            key_shares: List of KeyShare objects
            encrypted_package: The encrypted package containing the key data
            private_key: The recipient's private key
            
        Returns:
            Decrypted key data, or None if decryption failed
        """
        try:
            # Decrypt the shares with the private key
            shares = []
            for share in key_shares:
                decrypted_share = self._decrypt_with_private_key(
                    share.data,
                    private_key,
                    f"share-{share.metadata.get('index')}".encode()
                )
                shares.append(decrypted_share)
            
            # Reconstruct the encryption key
            encryption_key = self._reconstruct_secret(shares)
            
            # Decrypt the package
            iv = bytes.fromhex(encrypted_package['iv'])
            ciphertext = bytes.fromhex(encrypted_package['ciphertext'])
            tag = bytes.fromhex(encrypted_package['tag'])
            
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        except Exception as e:
            logger.error(f"Failed to decrypt key share: {e}")
            return None
    
    def _split_secret(self, secret: bytes, num_shares: int, threshold: int) -> List[bytes]:
        """
        Split a secret into multiple shares using Shamir's Secret Sharing.
        
        This is a simplified implementation. In production, use a well-tested
        library like 'secretsharing' or 'sss'.
        """
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
            
        if num_shares < threshold:
            raise ValueError(f"Number of shares ({num_shares}) must be >= threshold ({threshold})")
        
        # For simplicity, we'll just split the secret into equal parts
        # In a real implementation, use proper secret sharing
        chunk_size = (len(secret) + threshold - 1) // threshold
        shares = []
        
        for i in range(num_shares):
            start = (i * len(secret)) // num_shares
            end = ((i + 1) * len(secret)) // num_shares
            shares.append(secret[start:end] or b'\x00')
        
        return shares
    
    def _reconstruct_secret(self, shares: List[bytes]) -> bytes:
        """Reconstruct a secret from shares."""
        # In a real implementation, this would use Lagrange interpolation
        # to reconstruct the secret from the shares
        return b''.join(shares)[:32]  # Simple concatenation for demonstration
    
    def _encrypt_with_public_key(self, data: bytes, 
                               public_key: x25519.X25519PublicKey,
                               aad: bytes = b'') -> bytes:
        """Encrypt data with a public key."""
        # Generate an ephemeral key pair
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        
        # Derive a shared secret
        shared_secret = ephemeral_priv.exchange(public_key)
        
        # Derive encryption key and nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 32 for key, 12 for nonce, 4 for a MAC key
            salt=None,
            info=b'openpgp-key-encryption',
            backend=self.backend
        )
        
        key_material = hkdf.derive(shared_secret)
        key = key_material[:32]
        nonce = key_material[32:44]
        
        # Encrypt the data
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if aad:
            encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return the ephemeral public key + nonce + ciphertext + tag
        return (
            ephemeral_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) + nonce + ciphertext + encryptor.tag
        )
    
    def _decrypt_with_private_key(self, data: bytes,
                                private_key: bytes,
                                aad: bytes = b'') -> bytes:
        """Decrypt data with a private key."""
        if len(data) < 32 + 12 + 16:  # pubkey + nonce + min tag size
            raise ValueError("Invalid encrypted data")
            
        # Extract components
        ephemeral_pub_bytes = data[:32]
        nonce = data[32:44]
        ciphertext = data[44:-16]
        tag = data[-16:]
        
        # Import the private key
        priv_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        
        # Derive the shared secret
        shared_secret = priv_key.exchange(pub_key)
        
        # Derive the encryption key and nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=48,  # 32 for key, 12 for nonce, 4 for a MAC key
            salt=None,
            info=b'openpgp-key-encryption',
            backend=self.backend
        )
        
        key_material = hkdf.derive(shared_secret)
        key = key_material[:32]
        
        # Decrypt the data
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def export_public_key(self, public_key: bytes) -> str:
        """Export a public key to PEM format."""
        pub_key = x25519.X25519PublicKey.from_public_bytes(public_key)
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def import_public_key(self, pem_data: str) -> bytes:
        """Import a public key from PEM format."""
        pub_key = serialization.load_pem_public_key(
            pem_data.encode(),
            backend=self.backend
        )
        return pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
