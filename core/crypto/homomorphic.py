"""
Homomorphic Encryption Module

This module provides homomorphic encryption functionality using the TenSEAL library,
which is a Python wrapper for Microsoft SEAL.
"""
import tenseal as ts
import numpy as np
from typing import Union, List, Tuple, Optional
from pathlib import Path
import json
import base64
from dataclasses import dataclass, asdict

@dataclass
class HEMetadata:
    """Metadata for homomorphically encrypted data."""
    poly_modulus_degree: int
    plain_modulus: int
    scheme: str
    version: str = "1.0"

class HomomorphicEncryption:
    """
    A class to handle homomorphic encryption operations using Microsoft SEAL via TenSEAL.
    """
    
    def __init__(self, context: Optional[ts.Context] = None):
        """
        Initialize the homomorphic encryption context.
        
        Args:
            context: Optional pre-configured TenSEAL context. If None, a default BFV context will be created.
        """
        self.context = context or self._create_default_context()
        self.public_key = self.context.public_key()
        self.secret_key = self.context.secret_key()
        self.relin_keys = self.context.relin_keys()
        self.galois_keys = self.context.galois_keys()
        
    @staticmethod
    def _create_default_context() -> ts.Context:
        """Create a default BFV context with reasonable parameters."""
        # These parameters provide a good balance between security and performance
        poly_modulus_degree = 4096
        plain_modulus = 1032193  # A 20-bit prime that supports batching
        
        context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree,
            plain_modulus
        )
        
        # Enable required keys and optimizations
        context.generate_galois_keys()
        return context
    
    @classmethod
    def from_serialized(cls, context_data: bytes, secret_key: Optional[bytes] = None) -> 'HomomorphicEncryption':
        """
        Create a HomomorphicEncryption instance from serialized context data.
        
        Args:
            context_data: Serialized context data (public parameters)
            secret_key: Optional serialized secret key (required for decryption)
            
        Returns:
            HomomorphicEncryption: A new instance with the deserialized context
        """
        context = ts.context_from(context_data)
        if secret_key is not None:
            context.secret_key = ts.secret_key_from(secret_key)
        return cls(context)
    
    def serialize(self, include_secret_key: bool = False) -> dict:
        """
        Serialize the homomorphic encryption context.
        
        Args:
            include_secret_key: Whether to include the secret key in the serialization
            
        Returns:
            dict: A dictionary containing the serialized context and metadata
        """
        # Get the context parameters for metadata
        params = self.context.data[0].parms.parms_id()
        poly_modulus_degree = self.context.data[0].parms.poly_modulus_degree()
        plain_modulus = self.context.data[0].parms.plain_modulus().value()
        scheme = str(self.context.scheme).split('.')[-1]
        
        metadata = HEMetadata(
            poly_modulus_degree=poly_modulus_degree,
            plain_modulus=plain_modulus,
            scheme=scheme
        )
        
        return {
            'metadata': asdict(metadata),
            'context': self.context.serialize(),
            'secret_key': self.secret_key.serialize() if include_secret_key else None,
            'public_key': self.public_key.serialize(),
            'relin_keys': self.relin_keys.serialize(),
            'galois_keys': self.galois_keys.serialize()
        }
    
    def encrypt(self, data: Union[int, float, List[Union[int, float]]]) -> ts.CKKSVector:
        """
        Encrypt data using the current context.
        
        Args:
            data: Data to encrypt (can be a number or a list of numbers)
            
        Returns:
            ts.CKKSVector: Encrypted data
        """
        if isinstance(data, (int, float)):
            data = [data]
        return ts.ckks_vector(self.context, data)
    
    def decrypt(self, encrypted: ts.CKKSVector) -> Union[float, List[float]]:
        """
        Decrypt data using the current context.
        
        Args:
            encrypted: Encrypted data
            
        Returns:
            Union[float, List[float]]: Decrypted data
        """
        decrypted = encrypted.decrypt()
        return decrypted[0] if len(decrypted) == 1 else decrypted
    
    def save_keys(self, path: Union[str, Path], include_secret: bool = False):
        """
        Save the encryption keys to files.
        
        Args:
            path: Directory path to save the keys
            include_secret: Whether to save the secret key
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save public key
        with open(path / 'public_key.tenseal', 'wb') as f:
            f.write(self.public_key.serialize())
            
        # Save relinearization keys
        with open(path / 'relin_keys.tenseal', 'wb') as f:
            f.write(self.relin_keys.serialize())
            
        # Save Galois keys
        with open(path / 'galois_keys.tenseal', 'wb') as f:
            f.write(self.galois_keys.serialize())
            
        # Save metadata
        metadata = self.serialize(include_secret_key=False)['metadata']
        with open(path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Save secret key if requested
        if include_secret:
            with open(path / 'secret_key.tenseal', 'wb') as f:
                f.write(self.secret_key.serialize())
    
    @classmethod
    def load_keys(cls, path: Union[str, Path]) -> 'HomomorphicEncryption':
        """
        Load encryption keys from files.
        
        Args:
            path: Directory path containing the key files
            
        Returns:
            HomomorphicEncryption: A new instance with the loaded keys
        """
        path = Path(path)
        
        # Load metadata
        with open(path / 'metadata.json', 'r') as f:
            metadata = json.load(f)
        
        # Load public key
        with open(path / 'public_key.tenseal', 'rb') as f:
            public_key = f.read()
            
        # Load relinearization keys
        with open(path / 'relin_keys.tenseal', 'rb') as f:
            relin_keys = f.read()
            
        # Load Galois keys
        with open(path / 'galois_keys.tenseal', 'rb') as f:
            galois_keys = f.read()
        
        # Create context
        context = ts.context(
            ts.SCHEME_TYPE.BFV,
            metadata['poly_modulus_degree'],
            metadata['plain_modulus']
        )
        
        # Deserialize keys
        context.public_key = ts.public_key_from(public_key)
        context.relin_keys = ts.relinkey_from(relin_keys)
        context.galois_keys = ts.galois_keys_from(galois_keys)
        
        # Load secret key if available
        secret_key_path = path / 'secret_key.tenseal'
        if secret_key_path.exists():
            with open(secret_key_path, 'rb') as f:
                secret_key = f.read()
            context.secret_key = ts.secret_key_from(secret_key)
        
        return cls(context)

# Example usage:
if __name__ == "__main__":
    # Create a new HE context
    he = HomomorphicEncryption()
    
    # Encrypt some data
    data1 = [1.5, 2.3, 3.7]
    data2 = [0.7, 1.2, 2.8]
    
    encrypted1 = he.encrypt(data1)
    encrypted2 = he.encrypt(data2)
    
    # Perform homomorphic operations
    encrypted_sum = encrypted1 + encrypted2
    encrypted_product = encrypted1 * 2.5
    
    # Decrypt results
    print(f"Data 1: {data1}")
    print(f"Data 2: {data2}")
    print(f"Homomorphic sum: {he.decrypt(encrypted_sum)}")
    print(f"Homomorphic product (data1 * 2.5): {he.decrypt(encrypted_product)}")
    
    # Save keys
    he.save_keys('he_keys', include_secret=True)
    
    # Load keys
    he_loaded = HomomorphicEncryption.load_keys('he_keys')
    print(f"Loaded HE context works: {he_loaded.decrypt(encrypted1) == data1}")
