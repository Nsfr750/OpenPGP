"""
Secure Passphrase Handling and Key Recovery

This module provides secure passphrase management and key recovery options.
"""
import os
import json
import base64
import hashlib
import hmac
import secrets
from typing import Dict, Optional, Tuple, List, Union
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
# Argon2 import (using argon2-cffi)
try:
    from argon2 import PasswordHasher, Type as Argon2Type
except ImportError:
    # Fallback if argon2-cffi is not available
    PasswordHasher = None
    Argon2Type = None
import pyotp
import qrcode
import pyqrcode
from PIL import Image, ImageDraw, ImageFont
import io

class PassphraseManager:
    """Manages secure passphrase handling and key recovery options."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the passphrase manager.
        
        Args:
            config_dir: Directory to store recovery configurations (default: ~/.openpgp/recovery)
        """
        self.config_dir = config_dir or os.path.join(Path.home(), '.openpgp', 'recovery')
        os.makedirs(self.config_dir, exist_ok=True, mode=0o700)
        
        # Constants for crypto operations
        self.SALT_SIZE = 32
        self.KEY_SIZE = 32  # 256 bits for AES-256
        self.IV_SIZE = 16   # 128 bits for AES block size
        self.ITERATIONS = 600000  # PBKDF2 iterations
        
    def _derive_key(self, passphrase: str, salt: bytes) -> Tuple[bytes, bytes]:
        """Derive a secure key and IV from a passphrase and salt."""
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE + self.IV_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        key_iv = kdf.derive(passphrase.encode('utf-8'))
        return key_iv[:self.KEY_SIZE], key_iv[self.KEY_SIZE:]
    
    def _get_hmac(self, key: bytes, data: bytes) -> bytes:
        """Generate HMAC for data integrity verification."""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()
    
    def encrypt_with_passphrase(self, data: bytes, passphrase: str) -> bytes:
        """
        Encrypt data with a passphrase using AES-256-CBC with HMAC.
        
        Args:
            data: The data to encrypt
            passphrase: The passphrase to use for encryption
            
        Returns:
            Encrypted data in format: salt (32) + iv (16) + ciphertext (N) + hmac (32)
        """
        # Generate random salt and IV
        salt = os.urandom(self.SALT_SIZE)
        iv = os.urandom(self.IV_SIZE)
        
        # Derive key and IV
        key, _ = self._derive_key(passphrase, salt)
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Generate HMAC for integrity
        hmac_key = hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        hmac_value = self._get_hmac(hmac_key, salt + iv + ciphertext)
        
        # Return salt + iv + ciphertext + hmac
        return salt + iv + ciphertext + hmac_value
    
    def decrypt_with_passphrase(self, encrypted_data: bytes, passphrase: str) -> bytes:
        """
        Decrypt data with a passphrase.
        
        Args:
            encrypted_data: The encrypted data (salt + iv + ciphertext + hmac)
            passphrase: The passphrase used for encryption
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If decryption or verification fails
        """
        if len(encrypted_data) < self.SALT_SIZE + self.IV_SIZE + 32:  # min size: salt + iv + min 1 block + hmac
            raise ValueError("Invalid encrypted data")
            
        # Extract components
        salt = encrypted_data[:self.SALT_SIZE]
        iv = encrypted_data[self.SALT_SIZE:self.SALT_SIZE + self.IV_SIZE]
        hmac_value = encrypted_data[-32:]
        ciphertext = encrypted_data[self.SALT_SIZE + self.IV_SIZE:-32]
        
        # Verify HMAC
        hmac_key = hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        expected_hmac = self._get_hmac(hmac_key, salt + iv + ciphertext)
        
        if not hmac.compare_digest(hmac_value, expected_hmac):
            raise ValueError("HMAC verification failed - data may be corrupted or tampered with")
        
        # Derive key
        key, _ = self._derive_key(passphrase, salt)
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        try:
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except ValueError as e:
            raise ValueError("Decryption failed - incorrect passphrase or corrupted data") from e
    
    def generate_recovery_codes(self, count: int = 5) -> List[str]:
        """
        Generate one-time recovery codes.
        
        Args:
            count: Number of recovery codes to generate
            
        Returns:
            List of recovery codes
        """
        return [secrets.token_urlsafe(16) for _ in range(count)]
    
    def generate_totp_recovery(self, issuer: str, account_name: str) -> Tuple[str, str]:
        """
        Generate a TOTP secret for recovery.
        
        Args:
            issuer: The service name (e.g., "OpenPGP")
            account_name: The account name (e.g., email)
            
        Returns:
            Tuple of (provisioning_uri, secret_key)
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=account_name,
            issuer_name=issuer
        )
        return provisioning_uri, secret
    
    def verify_totp_code(self, secret: str, code: str, valid_window: int = 1) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            secret: The TOTP secret
            code: The code to verify
            valid_window: Number of time steps to check on either side of current time
            
        Returns:
            bool: True if the code is valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=valid_window)
    
    def generate_recovery_qr_code(self, data: str, output_path: Optional[str] = None) -> Image.Image:
        """
        Generate a QR code for recovery data.
        
        Args:
            data: The data to encode in the QR code
            output_path: Optional path to save the QR code image
            
        Returns:
            PIL Image object containing the QR code
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        if output_path:
            img.save(output_path)
            
        return img
    
    def create_key_backup(self, private_key: bytes, passphrase: str, 
                         recovery_methods: Dict[str, Union[str, List[str]]]) -> Dict:
        """
        Create a secure backup of a private key with recovery options.
        
        Args:
            private_key: The private key data to back up
            passphrase: The passphrase to encrypt the backup
            recovery_methods: Dictionary of recovery methods and parameters
                Example: {
                    'recovery_codes': ['code1', 'code2'],
                    'totp_secret': 'TOTP_SECRET',
                    'security_questions': [
                        {'question': 'Q1', 'answer': 'A1'},
                        {'question': 'Q2', 'answer': 'A2'}
                    ]
                }
                
        Returns:
            Dictionary containing backup data and recovery information
        """
        # Generate a random encryption key for the backup
        backup_key = os.urandom(32)
        
        # Encrypt the private key with the backup key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(backup_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(private_key) + padder.finalize()
        encrypted_key = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the backup key with the passphrase
        encrypted_backup_key = self.encrypt_with_passphrase(backup_key, passphrase)
        
        # Generate recovery hashes
        recovery_hashes = {}
        
        # Add recovery codes
        if 'recovery_codes' in recovery_methods:
            recovery_hashes['recovery_codes'] = [
                hashlib.sha256(code.encode('utf-8')).hexdigest()
                for code in recovery_methods['recovery_codes']
            ]
        
        # Add TOTP secret if provided
        if 'totp_secret' in recovery_methods:
            recovery_hashes['totp_secret'] = hashlib.sha256(
                recovery_methods['totp_secret'].encode('utf-8')
            ).hexdigest()
        
        # Add security questions if provided
        if 'security_questions' in recovery_methods:
            recovery_hashes['security_questions'] = [
                {
                    'question': qa['question'],
                    'answer_hash': hashlib.sha256(qa['answer'].lower().encode('utf-8')).hexdigest()
                }
                for qa in recovery_methods['security_questions']
            ]
        
        # Create backup data structure
        backup_data = {
            'version': '1.0',
            'timestamp': datetime.utcnow().isoformat(),
            'encrypted_key': base64.b64encode(encrypted_backup_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_key).decode('utf-8'),
            'recovery_hashes': recovery_hashes,
            'algorithm': 'aes-256-cbc',
            'kdf': 'pbkdf2_hmac_sha256',
            'iterations': self.ITERATIONS
        }
        
        return backup_data
    
    def restore_key_from_backup(self, backup_data: Dict, recovery_data: Dict) -> bytes:
        """
        Restore a private key from backup using recovery data.
        
        Args:
            backup_data: The backup data created by create_key_backup
            recovery_data: Dictionary containing recovery information
                Example: {
                    'recovery_code': 'code1',  # or
                    'totp_code': '123456',     # or
                    'security_answers': ['answer1', 'answer2']
                }
                
        Returns:
            The restored private key data
            
        Raises:
            ValueError: If recovery fails
        """
        # Verify recovery method
        recovery_verified = False
        recovery_hashes = backup_data.get('recovery_hashes', {})
        
        # Check recovery code
        if 'recovery_code' in recovery_data:
            code_hash = hashlib.sha256(recovery_data['recovery_code'].encode('utf-8')).hexdigest()
            if code_hash in recovery_hashes.get('recovery_codes', []):
                recovery_verified = True
        
        # Check TOTP code
        if not recovery_verified and 'totp_code' in recovery_data and 'totp_secret' in recovery_data:
            if self.verify_totp_code(recovery_data['totp_secret'], recovery_data['totp_code']):
                recovery_verified = True
        
        # Check security questions
        if not recovery_verified and 'security_answers' in recovery_data:
            if 'security_questions' in recovery_hashes:
                questions = recovery_hashes['security_questions']
                answers = recovery_data['security_answers']
                
                if len(questions) == len(answers):
                    all_correct = True
                    for q, a in zip(questions, answers):
                        expected_hash = q['answer_hash']
                        actual_hash = hashlib.sha256(a.lower().encode('utf-8')).hexdigest()
                        if expected_hash != actual_hash:
                            all_correct = False
                            break
                    
                    if all_correct:
                        recovery_verified = True
        
        if not recovery_verified:
            raise ValueError("Recovery verification failed")
        
        # Decrypt the backup key using the recovery data
        try:
            # In a real implementation, you would use the recovery data to derive a key
            # For this example, we'll assume the recovery data contains the passphrase
            if 'passphrase' not in recovery_data:
                raise ValueError("Passphrase is required for recovery")
                
            encrypted_backup_key = base64.b64decode(backup_data['encrypted_key'])
            backup_key = self.decrypt_with_passphrase(encrypted_backup_key, recovery_data['passphrase'])
            
            # Decrypt the private key
            iv = base64.b64decode(backup_data['iv'])
            encrypted_data = base64.b64decode(backup_data['encrypted_data'])
            
            cipher = Cipher(algorithms.AES(backup_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad the data
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
            
        except Exception as e:
            raise ValueError(f"Failed to restore key: {str(e)}")


def generate_strong_passphrase(word_count: int = 6, separator: str = '-') -> str:
    """
    Generate a strong, memorable passphrase.
    
    Args:
        word_count: Number of words in the passphrase
        separator: Separator between words
        
    Returns:
        A strong passphrase
    """
    # In a real implementation, you would use a wordlist
    # For simplicity, we'll use a small sample here
    wordlist = [
        'correct', 'horse', 'battery', 'staple', 'turtle', 'umbrella',
        'giraffe', 'elephant', 'keyboard', 'window', 'monitor', 'lamp',
        'chair', 'table', 'book', 'pencil', 'notebook', 'coffee', 'water'
    ]
    
    if word_count < 4:
        word_count = 4
    
    # Add a random number and special character for extra security
    words = [secrets.choice(wordlist) for _ in range(word_count - 1)]
    words.append(str(secrets.randbelow(100)))
    
    # Shuffle the words
    secrets.SystemRandom().shuffle(words)
    
    # Add a special character
    special_chars = '!@#$%^&*'
    words[-1] += secrets.choice(special_chars)
    
    return separator.join(words)
