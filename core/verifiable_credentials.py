"""
Verifiable Credentials support for OpenPGP.
Implements W3C Verifiable Credentials standard.
"""
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
import base64
from uuid import uuid4

from .openpgp import sign_message, verify_signature, PGPKey

class VerifiableCredential:
    """W3C Verifiable Credential implementation."""
    
    def __init__(self, issuer: str, credential_subject: Dict[str, Any]):
        self.context = [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ]
        self.type = ["VerifiableCredential"]
        self.issuer = issuer
        self.issuance_date = datetime.now(timezone.utc).isoformat()
        self.credential_subject = credential_subject
        self.id = f"urn:uuid:{uuid4()}"
        self.proof = None
    
    def sign(self, issuer_key: PGPKey, passphrase: Optional[str] = None) -> Dict[str, Any]:
        """Sign the credential with the issuer's private key."""
        # Create a copy of the credential without the proof
        credential_dict = self.to_dict(include_proof=False)
        
        # Create the proof
        proof = {
            "type": "OpenPgpSignature2021",
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": self.issuer,
            "proofPurpose": "assertionMethod"
        }
        
        # Create the payload to sign
        to_sign = {
            **credential_dict,
            "proof": {**proof, "jws": None}  # jws will be the signature
        }
        
        # Convert to canonical JSON for signing
        canonical_json = json.dumps(to_sign, sort_keys=True, separators=(',', ':'))
        
        # Sign the payload
        signature = sign_message(canonical_json, issuer_key, passphrase)
        
        # Add the signature to the proof
        proof["jws"] = signature
        
        # Add the proof to the credential
        self.proof = proof
        return self.to_dict()
    
    def verify(self, issuer_public_key: PGPKey) -> bool:
        """Verify the credential's signature."""
        if not self.proof or "jws" not in self.proof:
            return False
            
        # Get a copy of the proof and remove the JWS
        proof = self.proof.copy()
        signature = proof.pop("jws")
        
        # Recreate the signed payload
        credential_dict = self.to_dict(include_proof=False)
        to_verify = {
            **credential_dict,
            "proof": proof
        }
        
        # Convert to canonical JSON
        canonical_json = json.dumps(to_verify, sort_keys=True, separators=(',', ':'))
        
        # Verify the signature
        return verify_signature(canonical_json, signature, issuer_public_key)
    
    def to_dict(self, include_proof: bool = True) -> Dict[str, Any]:
        """Convert the credential to a dictionary."""
        result = {
            "@context": self.context,
            "type": self.type,
            "id": self.id,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "credentialSubject": self.credential_subject
        }
        
        if include_proof and self.proof:
            result["proof"] = self.proof
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VerifiableCredential':
        """Create a VerifiableCredential from a dictionary."""
        vc = cls(issuer=data["issuer"], credential_subject=data["credentialSubject"])
        vc.context = data.get("@context", vc.context)
        vc.type = data.get("type", vc.type)
        vc.id = data.get("id", f"urn:uuid:{uuid4()}")
        vc.issuance_date = data.get("issuanceDate", vc.issuance_date)
        vc.proof = data.get("proof")
        return vc
