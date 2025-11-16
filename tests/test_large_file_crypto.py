"""
Tests for large file encryption/decryption.
"""
import os
import tempfile
import unittest
import filecmp
from pathlib import Path

from core.large_file_crypto import LargeFileCrypto
from core.openpgp import generate_hybrid_keypair

class TestLargeFileCrypto(unittest.TestCase):
    """Test cases for large file encryption/decryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.input_file = os.path.join(self.test_dir, "test_file.bin")
        self.encrypted_file = os.path.join(self.test_dir, "encrypted.bin")
        self.decrypted_file = os.path.join(self.test_dir, "decrypted.bin")
        
        # Generate a test file with random data (5MB)
        self.file_size = 5 * 1024 * 1024
        self._generate_test_file()
        
        # Generate test keys
        self.private_key, self.public_key = generate_hybrid_keypair()
        self.crypto = LargeFileCrypto(chunk_size=1024 * 1024)  # 1MB chunks
    
    def _generate_test_file(self):
        """Generate a test file with random data."""
        with open(self.input_file, 'wb') as f:
            # Write 1MB at a time to be memory efficient
            for _ in range(self.file_size // (1024 * 1024)):
                f.write(os.urandom(1024 * 1024))
            # Write any remaining bytes
            remaining = self.file_size % (1024 * 1024)
            if remaining > 0:
                f.write(os.urandom(remaining))
    
    def test_encrypt_decrypt(self):
        """Test encrypting and decrypting a large file."""
        # Encrypt the file
        encrypted_session_key, metadata = self.crypto.encrypt_file(
            self.input_file,
            self.encrypted_file,
            self.public_key
        )
        
        # Verify the encrypted file exists and has a reasonable size
        self.assertTrue(os.path.exists(self.encrypted_file))
        self.assertGreater(os.path.getsize(self.encrypted_file), 0)
        
        # Decrypt the file
        decrypted_metadata = self.crypto.decrypt_file(
            self.encrypted_file,
            self.decrypted_file,
            self.private_key,
            encrypted_session_key
        )
        
        # Verify the decrypted file matches the original
        self.assertTrue(filecmp.cmp(self.input_file, self.decrypted_file, shallow=False))
        
        # Verify metadata
        self.assertEqual(metadata["size"], self.file_size)
        self.assertEqual(decrypted_metadata["size"], self.file_size)
    
    def test_chunked_processing(self):
        """Test processing with different chunk sizes."""
        chunk_sizes = [64 * 1024, 256 * 1024, 1024 * 1024]  # 64KB, 256KB, 1MB
        
        for chunk_size in chunk_sizes:
            with self.subTest(chunk_size=chunk_size):
                crypto = LargeFileCrypto(chunk_size=chunk_size)
                
                # Encrypt with this chunk size
                encrypted_session_key, _ = crypto.encrypt_file(
                    self.input_file,
                    self.encrypted_file,
                    self.public_key
                )
                
                # Decrypt with the same chunk size
                crypto.decrypt_file(
                    self.encrypted_file,
                    self.decrypted_file,
                    self.private_key,
                    encrypted_session_key
                )
                
                # Verify the files match
                self.assertTrue(filecmp.cmp(self.input_file, self.decrypted_file, shallow=False))
    
    def tearDown(self):
        """Clean up test files."""
        for f in [self.input_file, self.encrypted_file, self.decrypted_file]:
            if os.path.exists(f):
                os.remove(f)
        os.rmdir(self.test_dir)

if __name__ == '__main__':
    unittest.main()
