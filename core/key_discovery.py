"""
Key Discovery and Verification for OpenPGP

This module provides advanced key discovery and verification capabilities.
"""
import os
import logging
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import gnupg
import dns.resolver
import requests
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class KeyDiscoveryError(Exception):
    """Base exception for key discovery related errors."""
    pass

class KeyVerificationError(Exception):
    """Exception for key verification errors."""
    pass

class KeyDiscovery:
    """Class for discovering and verifying PGP keys."""
    
    # Known PGP key servers
    DEFAULT_KEYSERVERS = [
        'hkps://keys.openpgp.org',
        'hkps://keyserver.ubuntu.com',
        'hkps://pgp.mit.edu',
        'hkps://keys.mailvelope.com'
    ]
    
    # WKD (Web Key Directory) well-known locations
    WKD_PATHS = [
        '.well-known/openpgpkey',
        'openpgpkey'
    ]
    
    def __init__(self, gpg_home: Optional[str] = None, timeout: int = 10):
        """
        Initialize the key discovery service.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
            timeout: Timeout for network operations in seconds
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.timeout = timeout
        self.cache_dir = Path(self.gpg_home) / 'key-discovery-cache'
        self.cache_dir.mkdir(exist_ok=True)
    
    def _get_cache_path(self, key: str) -> Path:
        """Get the path to a cache file."""
        return self.cache_dir / f"{hashlib.sha256(key.encode()).hexdigest()}.json"
    
    def _load_from_cache(self, key: str, max_age: int = 86400) -> Optional[Dict]:
        """Load data from the cache."""
        cache_file = self._get_cache_path(key)
        
        if not cache_file.exists():
            return None
            
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                
            # Check if the cache is still valid
            if 'timestamp' in data and (time.time() - data['timestamp']) <= max_age:
                return data.get('data')
                
        except (json.JSONDecodeError, IOError):
            pass
            
        return None
    
    def _save_to_cache(self, key: str, data: Any) -> None:
        """Save data to the cache."""
        cache_file = self._get_cache_path(key)
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': time.time(),
                    'data': data
                }, f)
        except IOError as e:
            logger.warning(f"Failed to save to cache: {e}")
    
    def _query_dns_txt_record(self, domain: str, record_name: str) -> List[str]:
        """Query DNS TXT records."""
        try:
            answers = dns.resolver.resolve(record_name, 'TXT', lifetime=self.timeout)
            return [str(rdata).strip('"') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return []
        except Exception as e:
            logger.warning(f"DNS query failed for {record_name}: {e}")
            return []
    
    def _fetch_url(self, url: str) -> Optional[bytes]:
        """Fetch content from a URL."""
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.content
        except requests.RequestException as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None
    
    def discover_by_email(self, email: str) -> List[Dict[str, Any]]:
        """
        Discover PGP keys by email address using multiple methods.
        
        Args:
            email: The email address to search for
            
        Returns:
            List of discovered keys with metadata
        """
        if '@' not in email:
            raise ValueError("Invalid email address")
            
        # Check cache first
        cache_key = f"email:{email}"
        cached = self._load_from_cache(cache_key)
        if cached is not None:
            return cached
        
        domain = email.split('@', 1)[1]
        results = []
        
        # Method 1: Check WKD (Web Key Directory)
        wkd_keys = self._discover_wkd(email, domain)
        results.extend(wkd_keys)
        
        # Method 2: Check DNS OPENPGPKEY record (RFC 7929)
        dns_keys = self._discover_dns_openpgpkey(email, domain)
        results.extend(dns_keys)
        
        # Method 3: Search key servers
        keyserver_keys = self._search_keyservers(email)
        results.extend(keyserver_keys)
        
        # Cache the results
        self._save_to_cache(cache_key, results)
        
        return results
    
    def _discover_wkd(self, email: str, domain: str) -> List[Dict[str, Any]]:
        """Discover keys using Web Key Directory (WKD)."""
        local_part = email.split('@', 1)[0].lower()
        
        # Calculate the WKD hash (RFC 7929)
        digest = hashlib.sha1(local_part.encode('utf-8')).hexdigest().upper()
        wkd_hash = f"{digest[-8:-4]}{digest[-4:]}={digest[:-8]}"
        
        # Try different WKD paths
        for path in self.WKD_PATHS:
            # Direct method (RFC 7929)
            urls = [
                f"https://{domain}/{path}/hu/{wkd_hash}",
                f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{wkd_hash}"
            ]
            
            for url in urls:
                key_data = self._fetch_url(url)
                if key_data:
                    try:
                        import_result = self.gpg.import_keys(key_data.decode())
                        if import_result.count > 0:
                            return [{
                                'source': 'wkd',
                                'fingerprint': import_result.fingerprints[0],
                                'url': url,
                                'method': 'direct'
                            }]
                    except Exception as e:
                        logger.debug(f"Failed to import WKD key from {url}: {e}")
        
        # Advanced method (check policy file)
        policy_urls = [
            f"https://{domain}/.well-known/openpgpkey/policy",
            f"https://openpgpkey.{domain}/.well-known/openpgpkey/policy"
        ]
        
        for url in policy_urls:
            policy = self._fetch_url(url)
            if policy:
                logger.debug(f"Found WKD policy at {url}")
                # TODO: Parse policy and handle advanced discovery
        
        return []
    
    def _discover_dns_openpgpkey(self, email: str, domain: str) -> List[Dict[str, Any]]:
        """Discover keys using DNS OPENPGPKEY records (RFC 7929)."""
        local_part = email.split('@', 1)[0].lower()
        
        # Calculate the OPENPGPKEY name (RFC 7929)
        digest = hashlib.sha256(f"{email}".encode('utf-8')).hexdigest().lower()
        record_name = f"{digest}._openpgpkey.{domain}."
        
        # Query the DNS record
        records = self._query_dns_txt_record(domain, record_name)
        
        results = []
        for record in records:
            if record.startswith('v=OPENPGPKEY;'):
                try:
                    # Extract the base64-encoded key
                    parts = record.split(';')
                    data = next((p[4:] for p in parts if p.startswith('p=')), None)
                    if data:
                        # TODO: Parse and import the key
                        results.append({
                            'source': 'dns',
                            'record': record_name,
                            'method': 'openpgpkey'
                        })
                except Exception as e:
                    logger.debug(f"Failed to parse OPENPGPKEY record: {e}")
        
        return results
    
    def _search_keyservers(self, query: str) -> List[Dict[str, Any]]:
        """Search for keys on public key servers."""
        results = []
        
        for keyserver in self.DEFAULT_KEYSERVERS:
            try:
                search_results = self.gpg.search_keys(query, keyserver=keyserver)
                for key in search_results:
                    results.append({
                        'source': 'keyserver',
                        'keyserver': keyserver,
                        'keyid': key['keyid'],
                        'uids': key.get('uids', []),
                        'date': key.get('date'),
                        'expires': key.get('expires'),
                        'length': key.get('length')
                    })
            except Exception as e:
                logger.debug(f"Failed to search keyserver {keyserver}: {e}")
        
        return results
    
    def verify_key(self, fingerprint: str) -> Dict[str, Any]:
        """
        Verify the authenticity of a PGP key.
        
        Args:
            fingerprint: The fingerprint of the key to verify
            
        Returns:
            Dictionary with verification results
        """
        if not fingerprint or len(fingerprint) < 8:
            raise ValueError("Invalid key fingerprint")
        
        # Get the key information
        keys = self.gpg.list_keys(keys=fingerprint)
        if not keys:
            raise KeyVerificationError(f"Key {fingerprint} not found in keyring")
        
        key = keys[0]
        result = {
            'fingerprint': fingerprint,
            'keyid': key['keyid'],
            'uids': key.get('uids', []),
            'created': key.get('date'),
            'expires': key.get('expires'),
            'trust': key.get('trust'),
            'validity': key.get('validity'),
            'signatures': [],
            'verification_methods': []
        }
        
        # Check for direct signatures
        try:
            # Get detailed key information with signatures
            detailed = self.gpg.export_keys(fingerprint, secret=False, extra_args=['--list-sigs'])
            # TODO: Parse the detailed output to get signature information
            
            # This is a placeholder - in a real implementation, you would parse the output
            # to get information about signatures on the key
            result['signatures'] = [{
                'keyid': 'UNKNOWN',  # Would be the signer's key ID
                'date': None,        # Signature date
                'valid': None,       # Whether the signature is valid
                'trusted': None      # Whether the signer is trusted
            }]
            
            result['verification_methods'].append('signature')
        except Exception as e:
            logger.debug(f"Failed to check key signatures: {e}")
        
        # Check for WKD verification
        email = next((uid.split('<')[-1].split('>')[0] for uid in key.get('uids', []) if '@' in uid), None)
        if email:
            wkd_keys = self._discover_wkd(email, email.split('@', 1)[1])
            if any(k.get('fingerprint') == fingerprint for k in wkd_keys):
                result['verification_methods'].append('wkd')
        
        # Check for DNS verification
        if email:
            domain = email.split('@', 1)[1]
            dns_keys = self._discover_dns_openpgpkey(email, domain)
            if dns_keys:  # TODO: Better verification against the key
                result['verification_methods'].append('dns')
        
        # Check key server verification
        keyserver_keys = self._search_keyservers(fingerprint)
        if keyserver_keys:
            result['verification_methods'].append('keyserver')
        
        # Calculate a verification score
        verification_methods = set(result['verification_methods'])
        score = 0
        
        if 'signature' in verification_methods:
            score += 2  # Strong verification if signed by trusted keys
        if 'wkd' in verification_methods:
            score += 2  # WKD is a strong verification method
        if 'dns' in verification_methods:
            score += 1  # DNS is a weaker verification method
        if 'keyserver' in verification_methods:
            score += 0.5  # Keyserver presence is a weak signal
        
        result['verification_score'] = min(5, score)  # Cap at 5
        
        # Determine verification status
        if score >= 3:
            result['verification_status'] = 'verified'
        elif score >= 1.5:
            result['verification_status'] = 'partially_verified'
        else:
            result['verification_status'] = 'unverified'
        
        return result
    
    def import_key(self, key_data: str, verify: bool = True) -> Dict[str, Any]:
        """
        Import a key and optionally verify it.
        
        Args:
            key_data: The key data to import (ASCII-armored or binary)
            verify: Whether to verify the key after import
            
        Returns:
            Dictionary with import and verification results
        """
        try:
            # Import the key
            import_result = self.gpg.import_keys(key_data)
            
            if not import_result.count:
                raise KeyVerificationError("No keys were imported")
            
            fingerprint = import_result.fingerprints[0]
            result = {
                'imported': True,
                'fingerprint': fingerprint,
                'keyid': import_result.results[0].get('fingerprint', '')[-16:],
                'user_ids': import_result.results[0].get('user_ids', []),
                'verification': None
            }
            
            # Verify the key if requested
            if verify:
                try:
                    result['verification'] = self.verify_key(fingerprint)
                except Exception as e:
                    logger.warning(f"Verification failed for {fingerprint}: {e}")
                    result['verification'] = {'error': str(e)}
            
            return result
            
        except Exception as e:
            raise KeyVerificationError(f"Failed to import key: {e}")


def verify_file_signature(signature_path: Union[str, Path],
                        data_path: Optional[Union[str, Path]] = None,
                        data: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Verify a file signature.
    
    Args:
        signature_path: Path to the signature file
        data_path: Path to the signed file (if verifying a file)
        data: The signed data (if verifying in-memory data)
        
    Returns:
        Dictionary with verification results
    """
    if data_path is None and data is None:
        raise ValueError("Either data_path or data must be provided")
    
    signature_path = Path(signature_path)
    if not signature_path.exists():
        raise FileNotFoundError(f"Signature file not found: {signature_path}")
    
    gpg = gnupg.GPG()
    
    try:
        if data_path:
            # Verify a file
            with open(signature_path, 'rb') as sig_file, open(data_path, 'rb') as data_file:
                verified = gpg.verify_file(sig_file, data_filename=str(data_path))
        else:
            # Verify in-memory data
            with open(signature_path, 'rb') as sig_file:
                verified = gpg.verify_file(sig_file, data=data)
        
        return {
            'valid': verified.valid,
            'fingerprint': verified.fingerprint,
            'key_id': verified.key_id,
            'username': verified.username,
            'timestamp': verified.timestamp,
            'expire_timestamp': verified.expire_timestamp,
            'status': verified.status,
            'trust_level': verified.trust_level,
            'trust_text': verified.trust_text,
            'signature_id': verified.signature_id,
            'signature_timestamp': verified.sig_timestamp,
            'signature_expires': verified.expire_timestamp
        }
        
    except Exception as e:
        raise KeyVerificationError(f"Failed to verify signature: {e}")
