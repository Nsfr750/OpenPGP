"""
Demonstration of advanced features:
1. Algorithm migration
2. Verifiable Credentials
3. Large file encryption
"""
import os
import json
from pathlib import Path
import tempfile
from datetime import datetime, timedelta

# Import the new features
from core.crypto_migration import CryptoMigrator
from core.verifiable_credentials import VerifiableCredential
from core.large_file_crypto import LargeFileCrypto
from core.openpgp import generate_hybrid_keypair, hybrid_encrypt, hybrid_decrypt

def demo_algorithm_migration():
    """Demonstrate algorithm migration."""
    print("\n=== Algorithm Migration Demo ===\n")
    
    # Initialize the migrator
    migrator = CryptoMigrator()
    
    # Simulate migrating a key (in a real app, this would be an actual key)
    key_id = "user123_primary"
    print(f"Migrating key {key_id} to post-quantum secure algorithm...")
    
    # In a real app, this would perform the actual migration
    success = migrator.migrate_key(
        key_id=key_id,
        target_algorithm="kyber-768-ecdh-p384-aes256-gcm"
    )
    
    if success:
        print("Migration successful!")
        # View migration history
        history = migrator.get_migration_history(key_id)
        print("\nMigration history:")
        for entry in history:
            print(f"- {entry['timestamp']}: {entry['from_algorithm']} -> {entry['to_algorithm']} ({entry['status']})")
    else:
        print("Migration failed. Check logs for details.")

def demo_verifiable_credentials():
    """Demonstrate Verifiable Credentials."""
    print("\n=== Verifiable Credentials Demo ===\n")
    
    # Generate a key pair for the issuer
    print("Generating issuer key pair...")
    private_key, public_key = generate_hybrid_keypair()
    
    # Create a verifiable credential
    print("Creating a verifiable credential...")
    credential = VerifiableCredential(
        issuer="did:example:issuer123",
        credential_subject={
            "id": "did:example:user456",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "role": "developer"
        }
    )
    
    # Sign the credential
    print("Signing the credential...")
    signed_credential = credential.sign(private_key)
    
    print("\nSigned Credential:")
    print(json.dumps(signed_credential, indent=2))
    
    # Verify the credential
    print("\nVerifying the credential...")
    is_valid = credential.verify(public_key)
    print(f"Credential is {'valid' if is_valid else 'invalid'}!")

def demo_large_file_encryption():
    """Demonstrate large file encryption."""
    print("\n=== Large File Encryption Demo ===\n")
    
    # Generate test keys
    print("Generating encryption keys...")
    private_key, public_key = generate_hybrid_keypair()
    
    # Create a temporary test file (5MB)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        test_file = temp_file.name
        # Write 5MB of random data
        temp_file.write(os.urandom(5 * 1024 * 1024))
    
    try:
        # Initialize the crypto handler
        crypto = LargeFileCrypto()
        
        # Encrypt the file
        print(f"Encrypting {os.path.getsize(test_file) / (1024*1024):.2f}MB file...")
        encrypted_file = test_file + ".enc"
        encrypted_session_key, metadata = crypto.encrypt_file(
            test_file,
            encrypted_file,
            public_key
        )
        
        print(f"Encrypted file saved to: {encrypted_file}")
        print(f"Original size: {metadata['size'] / (1024*1024):.2f}MB")
        print(f"Encrypted size: {os.path.getsize(encrypted_file) / (1024*1024):.2f}MB")
        
        # Decrypt the file
        print("\nDecrypting the file...")
        decrypted_file = test_file + ".dec"
        crypto.decrypt_file(
            encrypted_file,
            decrypted_file,
            private_key,
            encrypted_session_key
        )
        
        # Verify the files match
        with open(test_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
            if f1.read() == f2.read():
                print("Decryption successful! Files match.")
            else:
                print("Error: Decrypted file doesn't match original!")
    
    finally:
        # Clean up
        for f in [test_file, encrypted_file, decrypted_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except:
                pass

if __name__ == "__main__":
    print("=== OpenPGP Advanced Features Demo ===\n")
    
    # Run the demos
    demo_algorithm_migration()
    demo_verifiable_credentials()
    demo_large_file_encryption()
    
    print("\n=== Demo Complete ===")
