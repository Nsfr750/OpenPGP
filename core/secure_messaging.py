# core/secure_messaging.py
"""
Secure Messaging Protocol for OpenPGP

This module implements a secure messaging protocol for end-to-end encrypted
communication using modern cryptographic primitives.
"""
from typing import Dict, List, Optional, Tuple, Union, Any
import os
import json
import msgpack
import base64
import time
import logging
from dataclasses import dataclass, asdict, field
from enum import Enum, auto
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag
from .advanced_crypto import AdvancedCrypto, EncryptionAlgorithm, HashAlgorithm

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """Types of secure messages."""
    TEXT = auto()
    FILE = auto()
    KEY_EXCHANGE = auto()
    KEY_ROTATION = auto()
    ACKNOWLEDGMENT = auto()
    ERROR = auto()

@dataclass
class MessageHeader:
    """Header for secure messages."""
    version: str = "1.0"
    message_id: str = field(default_factory=lambda: os.urandom(16).hex())
    timestamp: float = field(default_factory=lambda: time.time())
    sender_id: Optional[str] = None
    recipient_id: Optional[str] = None
    message_type: MessageType = MessageType.TEXT
    flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecureMessage:
    """A secure message with encrypted content and authentication."""
    header: MessageHeader
    encrypted_content: bytes
    signature: Optional[bytes] = None
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None
    aad: Optional[bytes] = None

class SecureMessaging:
    """Secure messaging protocol implementation."""
    
    def __init__(self, crypto: Optional[AdvancedCrypto] = None):
        self.crypto = crypto or AdvancedCrypto()
        self.session_keys = {}  # {session_id: (enc_key, auth_key, iv)}
        self.pending_messages = {}  # For handling out-of-order messages
        self.message_handlers = {
            MessageType.TEXT: self._handle_text_message,
            MessageType.FILE: self._handle_file_message,
            MessageType.KEY_EXCHANGE: self._handle_key_exchange,
            MessageType.KEY_ROTATION: self._handle_key_rotation,
            MessageType.ACKNOWLEDGMENT: self._handle_acknowledgment,
            MessageType.ERROR: self._handle_error
        }
    
    def create_message(self, content: Union[str, bytes, Dict[str, Any]],
                      recipient_public_key: bytes,
                      sender_private_key: Optional[bytes] = None,
                      message_type: MessageType = MessageType.TEXT,
                      metadata: Optional[Dict[str, Any]] = None) -> SecureMessage:
        """
        Create a new secure message.
        
        Args:
            content: The message content to encrypt
            recipient_public_key: Recipient's public key
            sender_private_key: Optional sender's private key for signing
            message_type: Type of message
            metadata: Additional metadata for the message header
            
        Returns:
            Encrypted and signed SecureMessage
        """
        if isinstance(content, str):
            content = content.encode('utf-8')
        elif isinstance(content, dict):
            content = json.dumps(content).encode('utf-8')
        
        # Generate a random session key for this message
        session_key = os.urandom(32)
        iv = os.urandom(12)
        
        # Encrypt the content
        encrypted_content = self.crypto.encrypt(
            content, session_key, 'aes-256-gcm', iv=iv
        )
        
        # Create the message header
        header = MessageHeader(
            message_type=message_type,
            metadata=metadata or {}
        )
        
        # Encrypt the session key with the recipient's public key
        # (In a real implementation, use hybrid encryption)
        
        # Sign the message if we have the sender's private key
        signature = None
        if sender_private_key:
            try:
                # In a real implementation, sign the message hash
                signer = ed25519.Ed25519PrivateKey.from_private_bytes(sender_private_key)
                signature = signer.sign(encrypted_content.ciphertext)
            except Exception as e:
                logger.error(f"Failed to sign message: {e}")
                raise
        
        return SecureMessage(
            header=header,
            encrypted_content=encrypted_content.ciphertext,
            signature=signature,
            iv=encrypted_content.iv,
            tag=encrypted_content.tag,
            aad=encrypted_content.aad
        )
    
    def process_message(self, message: Union[SecureMessage, Dict[str, Any]],
                       recipient_private_key: Optional[bytes] = None,
                       sender_public_key: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Process a received secure message.
        
        Args:
            message: The received message (SecureMessage or dict)
            recipient_private_key: Private key to decrypt the message
            sender_public_key: Sender's public key to verify the signature
            
        Returns:
            Decrypted message content and metadata
        """
        if isinstance(message, dict):
            message = self._dict_to_secure_message(message)
        
        # Verify the signature if we have the sender's public key
        if sender_public_key and message.signature:
            try:
                verifier = ed25519.Ed25519PublicKey.from_public_bytes(sender_public_key)
                verifier.verify(
                    message.signature,
                    message.encrypted_content
                )
            except InvalidSignature:
                logger.warning("Invalid message signature")
                return {
                    "status": "error",
                    "error": "invalid_signature",
                    "message": "Message signature verification failed"
                }
        
        # Decrypt the content
        # In a real implementation, you would first decrypt the session key
        # with the recipient's private key, then use that to decrypt the content
        try:
            encrypted_data = EncryptedData(
                ciphertext=message.encrypted_content,
                iv=message.iv,
                tag=message.tag,
                aad=message.aad,
                algorithm='aes-256-gcm'
            )
            
            # In a real implementation, decrypt the session key first
            session_key = b''  # This would come from decrypting with recipient_private_key
            
            decrypted_content = self.crypto.decrypt(encrypted_data, session_key)
            
            # Parse the decrypted content based on message type
            handler = self.message_handlers.get(
                message.header.message_type,
                self._handle_unknown_message
            )
            
            return handler(decrypted_content, message.header)
            
        except Exception as e:
            logger.error(f"Failed to process message: {e}")
            return {
                "status": "error",
                "error": "decryption_failed",
                "message": str(e)
            }
    
    def _handle_text_message(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle a text message."""
        try:
            text = content.decode('utf-8')
            return {
                "status": "success",
                "type": "text",
                "content": text,
                "metadata": header.metadata,
                "timestamp": header.timestamp
            }
        except UnicodeDecodeError:
            return {
                "status": "error",
                "error": "invalid_encoding",
                "message": "Failed to decode text message"
            }
    
    def _handle_file_message(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle a file message."""
        try:
            # In a real implementation, you would save the file and return its path
            file_info = header.metadata.get('file_info', {})
            return {
                "status": "success",
                "type": "file",
                "file_name": file_info.get('name', 'unknown'),
                "file_size": len(content),
                "file_type": file_info.get('type', 'application/octet-stream'),
                "save_path": None,  # In a real implementation, save the file
                "metadata": header.metadata,
                "timestamp": header.timestamp
            }
        except Exception as e:
            logger.error(f"Failed to handle file message: {e}")
            return {
                "status": "error",
                "error": "file_handling_failed",
                "message": str(e)
            }
    
    def _handle_key_exchange(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle a key exchange message."""
        try:
            # In a real implementation, process the key exchange
            key_data = json.loads(content.decode('utf-8'))
            return {
                "status": "success",
                "type": "key_exchange",
                "key_data": key_data,
                "metadata": header.metadata,
                "timestamp": header.timestamp
            }
        except Exception as e:
            logger.error(f"Failed to handle key exchange: {e}")
            return {
                "status": "error",
                "error": "key_exchange_failed",
                "message": str(e)
            }
    
    def _handle_key_rotation(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle a key rotation message."""
        try:
            # In a real implementation, rotate the session keys
            key_data = json.loads(content.decode('utf-8'))
            return {
                "status": "success",
                "type": "key_rotation",
                "key_data": key_data,
                "metadata": header.metadata,
                "timestamp": header.timestamp
            }
        except Exception as e:
            logger.error(f"Failed to handle key rotation: {e}")
            return {
                "status": "error",
                "error": "key_rotation_failed",
                "message": str(e)
            }
    
    def _handle_acknowledgment(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle an acknowledgment message."""
        try:
            ack_data = json.loads(content.decode('utf-8'))
            return {
                "status": "success",
                "type": "acknowledgment",
                "acknowledged_message_id": ack_data.get('message_id'),
                "status_code": ack_data.get('status', 'received'),
                "timestamp": header.timestamp
            }
        except Exception as e:
            logger.error(f"Failed to handle acknowledgment: {e}")
            return {
                "status": "error",
                "error": "acknowledgment_failed",
                "message": str(e)
            }
    
    def _handle_error(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle an error message."""
        try:
            error_data = json.loads(content.decode('utf-8'))
            return {
                "status": "error",
                "type": "error",
                "error_code": error_data.get('code', 'unknown_error'),
                "error_message": error_data.get('message', 'An unknown error occurred'),
                "original_message_id": error_data.get('original_message_id'),
                "timestamp": header.timestamp
            }
        except:
            return {
                "status": "error",
                "type": "error",
                "error_code": "invalid_error_format",
                "error_message": "Received malformed error message",
                "timestamp": header.timestamp
            }
    
    def _handle_unknown_message(self, content: bytes, header: MessageHeader) -> Dict[str, Any]:
        """Handle an unknown message type."""
        return {
            "status": "error",
            "type": "unknown",
            "message_type": str(header.message_type),
            "content_length": len(content),
            "timestamp": header.timestamp
        }
    
    def _dict_to_secure_message(self, data: Dict[str, Any]) -> SecureMessage:
        """Convert a dictionary to a SecureMessage."""
        header_data = data.get('header', {})
        header = MessageHeader(
            version=header_data.get('version', '1.0'),
            message_id=header_data.get('message_id', ''),
            timestamp=header_data.get('timestamp', time.time()),
            sender_id=header_data.get('sender_id'),
            recipient_id=header_data.get('recipient_id'),
            message_type=MessageType[header_data.get('message_type', 'TEXT')],
            flags=header_data.get('flags', []),
            metadata=header_data.get('metadata', {})
        )
        
        return SecureMessage(
            header=header,
            encrypted_content=base64.b64decode(data['encrypted_content']),
            signature=base64.b64decode(data['signature']) if data.get('signature') else None,
            iv=base64.b64decode(data['iv']) if data.get('iv') else None,
            tag=base64.b64decode(data['tag']) if data.get('tag') else None,
            aad=base64.b64decode(data['aad']) if data.get('aad') else None
        )

# Example usage
if __name__ == "__main__":
    # Initialize the secure messaging system
    crypto = AdvancedCrypto()
    messaging = SecureMessaging(crypto)
    
    # Generate key pairs for sender and recipient
    sender_private, sender_public = crypto.generate_key_pair('ed25519')
    recipient_private, recipient_public = crypto.generate_key_pair('ed25519')
    
    # Create a secure message
    message_content = "Hello, secure world!"
    secure_message = messaging.create_message(
        content=message_content,
        recipient_public_key=recipient_public,
        sender_private_key=sender_private,
        message_type=MessageType.TEXT,
        metadata={"importance": "high", "tags": ["test", "demo"]}
    )
    
    print(f"Created secure message with ID: {secure_message.header.message_id}")
    
    # Process the received message
    result = messaging.process_message(
        message=secure_message,
        recipient_private_key=recipient_private,
        sender_public_key=sender_public
    )
    
    print(f"Decrypted message: {result}")
