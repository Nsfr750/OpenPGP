import secrets
import string
import hashlib
import hmac
import base64
from typing import Optional, Dict, Any, Union, Tuple

class PasswordGenerator:
    """
    A secure password generator with customizable character sets and length.
    """
    def __init__(self):
        self.character_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'punctuation': string.punctuation,
        }
    
    def generate_password(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_punctuation: bool = True,
        custom_chars: str = ''
    ) -> str:
        """
        Generate a secure random password with the specified parameters.
        
        Args:
            length: Length of the password to generate (default: 16)
            use_lowercase: Include lowercase letters (a-z)
            use_uppercase: Include uppercase letters (A-Z)
            use_digits: Include digits (0-9)
            use_punctuation: Include punctuation
            custom_chars: Additional custom characters to include
            
        Returns:
            str: Generated password
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        # Build character set based on parameters
        chars = []
        if use_lowercase:
            chars.append(self.character_sets['lowercase'])
        if use_uppercase:
            chars.append(self.character_sets['uppercase'])
        if use_digits:
            chars.append(self.character_sets['digits'])
        if use_punctuation:
            chars.append(self.character_sets['punctuation'])
            
        if not chars and not custom_chars:
            raise ValueError("At least one character set must be selected")
            
        # Add custom characters if provided
        if custom_chars:
            chars.append(custom_chars)
            
        # Combine all selected character sets
        char_set = ''.join(chars)
        
        # Generate password ensuring at least one character from each selected set
        password = []
        
        # Ensure at least one character from each selected set
        if use_lowercase:
            password.append(secrets.choice(self.character_sets['lowercase']))
        if use_uppercase:
            password.append(secrets.choice(self.character_sets['uppercase']))
        if use_digits:
            password.append(secrets.choice(self.character_sets['digits']))
        if use_punctuation:
            password.append(secrets.choice(self.character_sets['punctuation']))
        if custom_chars:
            password.append(secrets.choice(custom_chars))
            
        # Fill the rest of the password with random characters from the full set
        remaining_length = length - len(password)
        password.extend(secrets.choice(char_set) for _ in range(remaining_length))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


def generate_pbkdf2_hash(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = 100000,
    dklen: int = 32,
    hash_name: str = 'sha256'
) -> Dict[str, Any]:
    """
    Generate a PBKDF2 hash of the password.
    
    Args:
        password: The password to hash
        salt: Optional salt (randomly generated if not provided)
        iterations: Number of iterations (default: 100,000)
        dklen: Length of the derived key in bytes (default: 32)
        hash_name: Name of the hash algorithm (default: 'sha256')
        
    Returns:
        Dict containing the hash, salt, and parameters
    """
    if not password:
        raise ValueError("Password cannot be empty")
        
    # Generate a secure random salt if not provided
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate the hash
    dk = hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=dklen
    )
    
    # Return all the information needed to verify the password later
    return {
        'hash': base64.b64encode(dk).decode('ascii'),
        'salt': base64.b64encode(salt).decode('ascii'),
        'iterations': iterations,
        'dklen': dklen,
        'hash_name': hash_name,
        'algorithm': f'pbkdf2_{hash_name}'
    }


def verify_password(password: str, stored_hash: str, salt: str, iterations: int, dklen: int, hash_name: str = 'sha256') -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The password to verify
        stored_hash: The stored hash (base64 encoded)
        salt: The salt used (base64 encoded)
        iterations: Number of iterations used
        dklen: Length of the derived key in bytes
        hash_name: Name of the hash algorithm (default: 'sha256')
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    try:
        salt_bytes = base64.b64decode(salt)
        stored_hash_bytes = base64.b64decode(stored_hash)
        
        # Generate hash with the same parameters
        new_hash = hashlib.pbkdf2_hmac(
            hash_name=hash_name,
            password=password.encode('utf-8'),
            salt=salt_bytes,
            iterations=iterations,
            dklen=dklen
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(new_hash, stored_hash_bytes)
    except Exception:
        return False
