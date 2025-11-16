"""
Cryptography Module

This module provides cryptographic functionality including homomorphic encryption.
"""

# Import homomorphic encryption
from .homomorphic import HomomorphicEncryption, HEMetadata

# Create a default HE context for the application
# This can be overridden by importing and using HomomorphicEncryption directly
he_context = None

def init_homomorphic_encryption(context=None):
    """
    Initialize the default homomorphic encryption context.
    
    Args:
        context: Optional pre-configured TenSEAL context. If None, a default BFV context will be created.
    """
    global he_context
    he_context = HomomorphicEncryption(context)
    return he_context

def get_he_context():
    """
    Get the current homomorphic encryption context.
    If not initialized, initializes with default parameters.
    
    Returns:
        HomomorphicEncryption: The current HE context
    """
    global he_context
    if he_context is None:
        he_context = init_homomorphic_encryption()
    return he_context

# Initialize HE context on module import
init_homomorphic_encryption()

# Export public API
__all__ = [
    'HomomorphicEncryption',
    'HEMetadata',
    'he_context',
    'init_homomorphic_encryption',
    'get_he_context'
]
