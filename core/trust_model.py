"""
Enhanced Trust Model for OpenPGP

This module provides an advanced trust model for OpenPGP key verification.
"""
import os
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from datetime import datetime, timedelta
import gnupg
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

class TrustModelError(Exception):
    """Base exception for trust model related errors."""
    pass

class KeyTrust:
    """Class representing the trust level of a key."""
    
    # Trust levels
    UNKNOWN = 0
    NEVER = 1
    MARGINAL = 2
    FULL = 3
    ULTIMATE = 4
    
    # Key types and their relative strengths
    KEY_STRENGTHS = {
        'rsa': {
            2048: 1.0,
            3072: 1.5,
            4096: 2.0,
            8192: 2.5
        },
        'dsa': {
            1024: 0.5,
            2048: 1.0,
            3072: 1.2
        },
        'ed25519': {
            256: 2.0  # Ed25519 is considered very strong for its key size
        },
        'ecdsa': {
            256: 1.5,  # P-256
            384: 2.0,  # P-384
            521: 2.5   # P-521
        }
    }
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the key trust model.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.trust_db_path = Path(self.gpg_home) / 'trustdb.gpg'
        self.trust_model_config = Path(self.gpg_home) / 'trust-model.json'
        self._load_trust_model()
    
    def _load_trust_model(self) -> None:
        """Load the trust model configuration."""
        self.trust_model = {
            'version': '1.0',
            'created': datetime.utcnow().isoformat(),
            'modified': datetime.utcnow().isoformat(),
            'policies': {
                'min_trust_level': self.MARGINAL,
                'expiration_days': 365 * 2,  # 2 years
                'min_key_strength': 1.0,     # Minimum key strength factor
                'require_revocation_check': True,
                'require_self_signature': True,
                'require_cross_certification': False,
                'max_issuer_cert_age': 30,   # Days
                'trust_web_of_trust': True,
                'trust_signature_depth': 3,
                'trust_signature_threshold': 3,
                'trust_marginal_threshold': 2,
                'trust_complete_threshold': 0.8,  # 80% of signatures needed
                'trust_marginal_weight': 0.5,     # Weight of marginal trust
                'trust_full_weight': 1.0,         # Weight of full trust
                'trust_ultimate_weight': 1.5,     # Weight of ultimate trust
                'key_usage_weights': {
                    'sign': 1.0,
                    'certify': 1.5,
                    'encrypt': 0.8,
                    'authenticate': 0.8
                },
                'key_algorithm_weights': {
                    'rsa': 1.0,
                    'dsa': 0.8,
                    'ed25519': 1.2,
                    'ecdsa': 1.1,
                    'ed448': 1.3,
                    'elgamal': 0.7
                },
                'key_strength_weights': {
                    'weak': 0.5,
                    'medium': 1.0,
                    'strong': 1.5,
                    'paranoid': 2.0
                }
            },
            'trusted_keys': {},
            'revoked_keys': {},
            'expired_keys': {},
            'key_metadata': {}
        }
        
        # Load existing configuration if it exists
        if self.trust_model_config.exists():
            try:
                with open(self.trust_model_config, 'r') as f:
                    saved_config = json.load(f)
                    # Merge with defaults
                    self.trust_model.update(saved_config)
                    self.trust_model['modified'] = datetime.utcnow().isoformat()
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load trust model config: {e}")
    
    def save_trust_model(self) -> None:
        """Save the trust model configuration."""
        try:
            with open(self.trust_model_config, 'w') as f:
                json.dump(self.trust_model, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save trust model: {e}")
    
    def get_key_trust_level(self, fingerprint: str) -> int:
        """
        Get the trust level of a key.
        
        Args:
            fingerprint: The key fingerprint
            
        Returns:
            int: The trust level (UNKNOWN, NEVER, MARGINAL, FULL, ULTIMATE)
        """
        # Check if the key is explicitly trusted
        if fingerprint in self.trust_model['trusted_keys']:
            return self.trust_model['trusted_keys'][fingerprint].get('trust_level', self.UNKNOWN)
        
        # Check if the key is explicitly distrusted
        if fingerprint in self.trust_model['revoked_keys']:
            return self.NEVER
        
        # Check if the key is expired
        if fingerprint in self.trust_model['expired_keys']:
            return self.NEVER
        
        # Check key metadata for calculated trust
        if fingerprint in self.trust_model['key_metadata']:
            metadata = self.trust_model['key_metadata'][fingerprint]
            if 'calculated_trust' in metadata:
                return self._calculate_trust_level(metadata['calculated_trust'])
        
        return self.UNKNOWN
    
    def _calculate_trust_level(self, trust_score: float) -> int:
        """
        Convert a trust score to a trust level.
        
        Args:
            trust_score: The calculated trust score (0.0 to 1.0)
            
        Returns:
            int: The trust level
        """
        if trust_score >= 0.9:
            return self.ULTIMATE
        elif trust_score >= 0.7:
            return self.FULL
        elif trust_score >= 0.4:
            return self.MARGINAL
        else:
            return self.UNKNOWN
    
    def calculate_key_trust(self, fingerprint: str) -> Dict[str, Any]:
        """
        Calculate the trust score for a key.
        
        Args:
            fingerprint: The key fingerprint
            
        Returns:
            Dict containing trust information
        """
        # Get key information
        keys = self.gpg.list_keys(keys=fingerprint)
        if not keys:
            raise TrustModelError(f"Key {fingerprint} not found")
        
        key = keys[0]
        keyid = key['keyid']
        
        # Initialize trust metrics
        trust_metrics = {
            'fingerprint': fingerprint,
            'keyid': keyid,
            'created': datetime.fromtimestamp(int(key['date'])).isoformat() if key['date'] else None,
            'expires': datetime.fromtimestamp(int(key['expires'])).isoformat() if key['expires'] else None,
            'algorithm': key.get('algo', 0),
            'length': key.get('length', 0),
            'capabilities': key.get('cap', ''),
            'owner_trust': key.get('ownertrust', ''),
            'trust_level': self.UNKNOWN,
            'trust_score': 0.0,
            'signatures': [],
            'uid_trust': {},
            'key_strength': self._calculate_key_strength(key),
            'issues': []
        }
        
        # Check if key is expired
        if key.get('expires') and int(key['expires']) < time.time():
            self.trust_model['expired_keys'][fingerprint] = {
                'expired_at': datetime.utcnow().isoformat(),
                'keyid': keyid
            }
            trust_metrics['trust_level'] = self.NEVER
            trust_metrics['issues'].append('Key has expired')
            return trust_metrics
        
        # Check key strength
        min_strength = self.trust_model['policies']['min_key_strength']
        if trust_metrics['key_strength'] < min_strength:
            trust_metrics['issues'].append(f"Key strength {trust_metrics['key_strength']} is below minimum {min_strength}")
        
        # Check key capabilities
        self._check_key_capabilities(key, trust_metrics)
        
        # Check signatures on the key
        self._check_key_signatures(key, trust_metrics)
        
        # Calculate final trust score
        trust_metrics['trust_score'] = self._calculate_trust_score(trust_metrics)
        trust_metrics['trust_level'] = self._calculate_trust_level(trust_metrics['trust_score'])
        
        # Update key metadata
        self.trust_model['key_metadata'][fingerprint] = {
            'last_checked': datetime.utcnow().isoformat(),
            'calculated_trust': trust_metrics['trust_score'],
            'issues': trust_metrics['issues'],
            'key_strength': trust_metrics['key_strength']
        }
        
        self.save_trust_model()
        
        return trust_metrics
    
    def _calculate_key_strength(self, key: Dict[str, Any]) -> float:
        """
        Calculate the strength of a key based on its algorithm and size.
        
        Args:
            key: The key information from GnuPG
            
        Returns:
            float: The key strength factor
        """
        algo = key.get('algo', 0)
        length = key.get('length', 0)
        
        # Map GnuPG algorithm numbers to names
        algo_map = {
            1: 'rsa',     # RSA (Encrypt or Sign)
            16: 'elgamal', # Elgamal (Encrypt-Only)
            17: 'dsa',     # DSA
            18: 'ecdsa',   # ECDSA
            19: 'ecdsa',   # ECDH
            22: 'ed25519', # EdDSA
            23: 'ed448'    # Ed448
        }
        
        algo_name = algo_map.get(algo, 'unknown')
        
        # Get the base strength for this algorithm
        algo_strength = self.trust_model['policies']['key_algorithm_weights'].get(algo_name, 0.5)
        
        # Adjust based on key size
        if algo_name in self.KEY_STRENGTHS:
            # Find the closest key size in the strengths table
            sizes = sorted(self.KEY_STRENGTHS[algo_name].keys())
            closest_size = min(sizes, key=lambda x: abs(x - length))
            size_factor = self.KEY_STRENGTHS[algo_name][closest_size]
        else:
            # Default strength for unknown algorithms
            size_factor = 0.5 if length < 2048 else 1.0
        
        return algo_strength * size_factor
    
    def _check_key_capabilities(self, key: Dict[str, Any], metrics: Dict[str, Any]) -> None:
        """
        Check the capabilities of a key and update trust metrics.
        
        Args:
            key: The key information from GnuPG
            metrics: The trust metrics to update
        """
        capabilities = key.get('cap', '').lower()
        
        # Check for certification capability
        if 'c' not in capabilities and 'certify' not in capabilities:
            metrics['issues'].append("Key cannot be used for certification")
        
        # Check for signing capability
        if 's' not in capabilities and 'sign' not in capabilities:
            metrics['issues'].append("Key cannot be used for signing")
        
        # Check for encryption capability
        if 'e' not in capabilities and 'encrypt' not in capabilities:
            metrics['issues'].append("Key cannot be used for encryption")
        
        # Check for authentication capability
        if 'a' not in capabilities and 'authenticate' not in capabilities:
            metrics['issues'].append("Key cannot be used for authentication")
    
    def _check_key_signatures(self, key: Dict[str, Any], metrics: Dict[str, Any]) -> None:
        """
        Check the signatures on a key and update trust metrics.
        
        Args:
            key: The key information from GnuPG
            metrics: The trust metrics to update
        """
        # Get detailed key information with signatures
        try:
            detailed_key = self.gpg.export_keys(key['fingerprint'], secret=False, extra_args=['--list-sigs'])
            # In a real implementation, parse the detailed key information
            # to get signature information
            pass
        except Exception as e:
            logger.warning(f"Failed to get detailed key info for {key['fingerprint']}: {e}")
    
    def _calculate_trust_score(self, metrics: Dict[str, Any]) -> float:
        """
        Calculate a trust score based on the collected metrics.
        
        Args:
            metrics: The trust metrics
            
        Returns:
            float: The calculated trust score (0.0 to 1.0)
        """
        score = 0.5  # Start with a neutral score
        
        # Adjust based on key strength
        key_strength = metrics.get('key_strength', 0.5)
        score = (score + key_strength) / 2
        
        # Penalize for issues
        issue_count = len(metrics.get('issues', []))
        if issue_count > 0:
            score *= max(0.1, 1.0 - (issue_count * 0.1))
        
        # Adjust based on owner trust
        owner_trust = metrics.get('owner_trust', '').lower()
        if owner_trust in ['ultimate']:
            score = min(1.0, score + 0.3)
        elif owner_trust in ['full']:
            score = min(1.0, score + 0.2)
        elif owner_trust in ['marginal']:
            score = min(1.0, score + 0.1)
        elif owner_trust in ['never']:
            score = max(0.0, score - 0.3)
        
        # Ensure the score is in the valid range
        return max(0.0, min(1.0, score))
