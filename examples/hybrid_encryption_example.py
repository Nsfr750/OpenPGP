"""
Example demonstrating the use of hybrid encryption in OpenPGP.

This script shows how to:
1. Generate a hybrid keypair (ECDH + Kyber)
2. Encrypt a message using hybrid encryption
3. Decrypt the message
4. Handle errors and edge cases
"""
import os
import sys
from pathlib import Path

# Add the parent directory to the path so we can import from core
sys.path.append(str(Path(__file__).parent.parent))

from core.openpgp import (
    generate_hybrid_keypair,
    hybrid_encrypt,
    hybrid_decrypt,
    _encrypt_private_key,
    _decrypt_private_key
)

def main():
    print("=== OpenPGP Hybrid Encryption Example ===\n")
    
    # Step 1: Generate a hybrid keypair
    print("1. Generating hybrid keypair...")
    private_key, public_key = generate_hybrid_keypair()
    print(f"   - Private key length: {len(private_key)} bytes")
    print(f"   - Public key length:  {len(public_key)} bytes")
    
    # Optional: Encrypt the private key with a passphrase
    passphrase = b"my_secure_passphrase"
    encrypted_private_key = _encrypt_private_key(private_key, passphrase)
    print("\n2. Encrypted private key with passphrase")
    
    # Original message
    message = "This is a secret message that will be encrypted with hybrid encryption!"
    print(f"\n3. Original message: {message[:50]}...")
    
    # Step 2: Encrypt the message
    print("\n4. Encrypting message...")
    ciphertext, encrypted_message = hybrid_encrypt(
        public_key=public_key,
        message=message,
        associated_data=b"example_context"
    )
    print(f"   - Ciphertext length: {len(ciphertext)} bytes")
    print(f"   - Encrypted message length: {len(encrypted_message)} bytes")
    
    # Step 3: Decrypt the private key (simulating loading from storage)
    print("\n5. Decrypting private key...")
    decrypted_private_key = _decrypt_private_key(encrypted_private_key, passphrase)
    
    # Step 4: Decrypt the message
    print("6. Decrypting message...")
    decrypted = hybrid_decrypt(
        private_key=decrypted_private_key,
        ciphertext=ciphertext,
        encrypted_message=encrypted_message,
        associated_data=b"example_context",
        passphrase=None  # Already decrypted
    )
    
    print(f"\n7. Decrypted message: {decrypted.decode('utf-8')}")
    
    # Verify the decrypted message matches the original
    assert decrypted == message.encode('utf-8'), "Decrypted message doesn't match original!"
    print("\n✅ Success! The decrypted message matches the original.")
    
    # Demonstrate error handling
    print("\n=== Error Handling Examples ===")
    
    # Try to decrypt with wrong associated data
    print("\nAttempting to decrypt with wrong associated data...")
    try:
        hybrid_decrypt(
            private_key=decrypted_private_key,
            ciphertext=ciphertext,
            encrypted_message=encrypted_message,
            associated_data=b"wrong_context"
        )
        print("❌ Error: Decryption with wrong associated data should have failed!")
    except ValueError as e:
        print(f"   ✅ Expected error (as intended): {str(e)[:100]}...")
    
    # Try to decrypt with wrong private key
    print("\nAttempting to decrypt with wrong private key...")
    try:
        wrong_private_key, _ = generate_hybrid_keypair()
        hybrid_decrypt(
            private_key=wrong_private_key,
            ciphertext=ciphertext,
            encrypted_message=encrypted_message
        )
        print("❌ Error: Decryption with wrong private key should have failed!")
    except Exception as e:
        print(f"   ✅ Expected error (as intended): {str(e)[:100]}...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
