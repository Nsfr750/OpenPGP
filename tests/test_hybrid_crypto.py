"""
Tests for the hybrid crypto module.
"""
import os
import unittest
from typing import Tuple
from unittest.mock import patch, MagicMock

from core.hybrid_crypto import HybridEncryption, get_hybrid_crypto


class TestHybridCrypto(unittest.TestCase):
    """Test cases for hybrid cryptography functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.hybrid = HybridEncryption(use_pqc=True)
        self.test_message = b"This is a test message for hybrid encryption"
        self.associated_data = b"test_associated_data"

    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = self.hybrid.generate_keypair()
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertTrue(len(private_key) > 0)
        self.assertTrue(len(public_key) > 0)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption roundtrip."""
        # Generate a keypair
        private_key, public_key = self.hybrid.generate_keypair()
        
        # Encrypt a message
        ciphertext, encrypted_message = self.hybrid.encrypt(
            public_key, 
            self.test_message,
            self.associated_data
        )
        
        # Decrypt the message
        decrypted = self.hybrid.decrypt(
            private_key,
            ciphertext,
            encrypted_message,
            self.associated_data
        )
        
        # Verify the decrypted message matches the original
        self.assertEqual(decrypted, self.test_message)

    def test_encrypt_decrypt_with_strings(self):
        """Test encryption/decryption with string inputs."""
        private_key, public_key = self.hybrid.generate_keypair()
        str_message = "This is a string message"
        
        # Test with string message and key
        ciphertext, encrypted_message = self.hybrid.encrypt(
            public_key.decode('utf-8'),
            str_message,
            self.associated_data
        )
        
        decrypted = self.hybrid.decrypt(
            private_key.decode('utf-8'),
            ciphertext,
            encrypted_message,
            self.associated_data
        )
        
        self.assertEqual(decrypted, str_message.encode('utf-8'))

    def test_encrypt_decrypt_without_associated_data(self):
        """Test encryption/decryption without associated data."""
        private_key, public_key = self.hybrid.generate_keypair()
        
        # Encrypt without associated data
        ciphertext, encrypted_message = self.hybrid.encrypt(
            public_key,
            self.test_message
        )
        
        # Try to decrypt with wrong associated data - should raise an exception
        with self.assertRaises(ValueError):
            self.hybrid.decrypt(
                private_key,
                ciphertext,
                encrypted_message,
                b"wrong_associated_data"
            )
        
        # Decrypt with correct (no) associated data
        decrypted = self.hybrid.decrypt(
            private_key,
            ciphertext,
            encrypted_message
        )
        
        self.assertEqual(decrypted, self.test_message)

    @patch('core.hybrid_crypto.PQC_AVAILABLE', False)
    def test_pqc_unavailable(self):
        """Test behavior when PQC is not available."""
        hybrid = HybridEncryption(use_pqc=True)
        private_key, public_key = hybrid.generate_keypair()
        
        # Should still work but with classic crypto only
        ciphertext, encrypted_message = hybrid.encrypt(
            public_key,
            self.test_message
        )
        
        decrypted = hybrid.decrypt(
            private_key,
            ciphertext,
            encrypted_message
        )
        
        self.assertEqual(decrypted, self.test_message)

    def test_get_hybrid_crypto_singleton(self):
        """Test that get_hybrid_crypto returns a singleton instance."""
        instance1 = get_hybrid_crypto()
        instance2 = get_hybrid_crypto()
        self.assertIs(instance1, instance2)


if __name__ == '__main__':
    unittest.main()
