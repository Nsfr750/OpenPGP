"""
Tests for Verifiable Credentials implementation.
"""
import unittest
import json
from datetime import datetime, timezone

from core.verifiable_credentials import VerifiableCredential
from core.openpgp import generate_hybrid_keypair, PGPKey

class TestVerifiableCredentials(unittest.TestCase):
    """Test cases for Verifiable Credentials."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_hybrid_keypair()
        self.issuer = "did:example:issuer123"
        self.credential_subject = {
            "id": "did:example:user456",
            "name": "Test User",
            "email": "test@example.com"
        }
    
    def test_create_credential(self):
        """Test creating a verifiable credential."""
        vc = VerifiableCredential(
            issuer=self.issuer,
            credential_subject=self.credential_subject
        )
        
        self.assertEqual(vc.issuer, self.issuer)
        self.assertEqual(vc.credential_subject, self.credential_subject)
        self.assertIsNotNone(vc.id)
        self.assertIsNotNone(vc.issuance_date)
        self.assertIsNone(vc.proof)
    
    def test_sign_credential(self):
        """Test signing a verifiable credential."""
        vc = VerifiableCredential(
            issuer=self.issuer,
            credential_subject=self.credential_subject
        )
        
        # Sign the credential
        signed_vc = vc.sign(self.private_key)
        
        # Verify the signature is present
        self.assertIsNotNone(signed_vc.get("proof"))
        self.assertIsNotNone(signed_vc["proof"].get("jws"))
        self.assertEqual(signed_vc["issuer"], self.issuer)
    
    def test_verify_credential(self):
        """Test verifying a signed credential."""
        vc = VerifiableCredential(
            issuer=self.issuer,
            credential_subject=self.credential_subject
        )
        
        # Sign and verify the credential
        vc.sign(self.private_key)
        is_valid = vc.verify(self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_tamper_detection(self):
        """Test that tampering with a credential is detected."""
        vc = VerifiableCredential(
            issuer=self.issuer,
            credential_subject=self.credential_subject
        )
        
        # Sign the credential
        vc.sign(self.private_key)
        
        # Tamper with the credential
        vc.credential_subject["email"] = "hacked@example.com"
        
        # Verification should fail
        is_valid = vc.verify(self.public_key)
        self.assertFalse(is_valid)
    
    def test_serialization_roundtrip(self):
        """Test serializing and deserializing a credential."""
        vc1 = VerifiableCredential(
            issuer=self.issuer,
            credential_subject=self.credential_subject
        )
        vc1.sign(self.private_key)
        
        # Convert to dict and back
        vc_dict = vc1.to_dict()
        vc2 = VerifiableCredential.from_dict(vc_dict)
        
        # Verify the credentials are equivalent
        self.assertEqual(vc1.issuer, vc2.issuer)
        self.assertEqual(vc1.credential_subject, vc2.credential_subject)
        self.assertEqual(vc1.id, vc2.id)
        self.assertEqual(vc1.issuance_date, vc2.issuance_date)
        self.assertEqual(vc1.proof, vc2.proof)
        
        # Verify the signature is still valid
        self.assertTrue(vc2.verify(self.public_key))

if __name__ == '__main__':
    unittest.main()
