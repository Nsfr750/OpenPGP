"""
Key Server Integration for OpenPGP

This module provides functionality for interacting with PGP key servers.
"""
import logging
from typing import List, Optional, Dict, Any
import subprocess
import json
from pathlib import Path
import gnupg

logger = logging.getLogger(__name__)

class KeyServerError(Exception):
    """Base exception for key server related errors."""
    pass


class KeyServer:
    """Class for interacting with PGP key servers."""
    
    def __init__(self, server_url: str = 'hkps://keys.openpgp.org', gpg_home: Optional[str] = None):
        """
        Initialize the KeyServer instance.
        
        Args:
            server_url: URL of the key server to connect to
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
        """
        self.server_url = server_url
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
    
    def search_keys(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for keys on the key server.
        
        Args:
            query: Search query (name, email, or key ID)
            
        Returns:
            List of dictionaries containing key information
        """
        try:
            result = self.gpg.search_keys(query, keyserver=self.server_url)
            return result
        except Exception as e:
            raise KeyServerError(f"Failed to search keys: {e}")
    
    def get_key(self, key_id: str) -> str:
        """
        Get a public key from the key server.
        
        Args:
            key_id: Key ID or fingerprint
            
        Returns:
            The public key as a string
        """
        try:
            result = self.gpg.recv_keys(self.server_url, key_id)
            if not result.results or 'ok' not in str(result.results[0]).lower():
                raise KeyServerError(f"Failed to retrieve key {key_id}")
                
            # Export the key to get the ASCII-armored version
            exported = self.gpg.export_keys(key_id)
            if not exported:
                raise KeyServerError(f"Failed to export key {key_id}")
                
            return exported
        except Exception as e:
            raise KeyServerError(f"Error getting key {key_id}: {e}")
    
    def send_key(self, key_id: str) -> bool:
        """
        Send a public key to the key server.
        
        Args:
            key_id: Key ID or fingerprint to send
            
        Returns:
            bool: True if the key was sent successfully
        """
        try:
            result = self.gpg.send_keys(self.server_url, key_id)
            if not result or 'sending key' not in str(result).lower():
                raise KeyServerError(f"Failed to send key {key_id}")
            return True
        except Exception as e:
            raise KeyServerError(f"Error sending key {key_id}: {e}")
    
    def refresh_keys(self, key_ids: List[str]) -> bool:
        """
        Refresh keys from the key server.
        
        Args:
            key_ids: List of key IDs or fingerprints to refresh
            
        Returns:
            bool: True if all keys were refreshed successfully
        """
        try:
            for key_id in key_ids:
                result = self.gpg.recv_keys(self.server_url, key_id)
                if not result.results or 'ok' not in str(result.results[0]).lower():
                    logger.warning(f"Failed to refresh key {key_id}")
            return True
        except Exception as e:
            raise KeyServerError(f"Error refreshing keys: {e}")

class KeyServerManager:
    """Manager for PGP key server operations."""
    
    DEFAULT_KEYSERVERS = [
        'hkps://keys.openpgp.org',
        'hkps://keyserver.ubuntu.com',
        'hkps://pgp.mit.edu'
    ]
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the key server manager.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
    
    def search_keys(self, search_term: str, keyserver: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for keys on a key server.
        
        Args:
            search_term: Email, name, or key ID to search for
            keyserver: Optional keyserver URL (default: first from DEFAULT_KEYSERVERS)
            
        Returns:
            List of matching keys with their information
        """
        keyserver = keyserver or self.DEFAULT_KEYSERVERS[0]
        try:
            result = self.gpg.search_keys(search_term, keyserver=keyserver)
            return result
        except Exception as e:
            logger.error(f"Error searching keys: {e}")
            raise KeyServerError(f"Failed to search keys: {e}")
    
    def receive_keys(self, key_ids: List[str], keyserver: Optional[str] = None) -> bool:
        """
        Import keys from a key server.
        
        Args:
            key_ids: List of key IDs to import
            keyserver: Optional keyserver URL
            
        Returns:
            bool: True if all keys were imported successfully
        """
        keyserver = keyserver or self.DEFAULT_KEYSERVERS[0]
        success = True
        
        for key_id in key_ids:
            try:
                import_result = self.gpg.recv_keys(keyserver, key_id)
                if not import_result.results or not import_result.results[0].get('ok'):
                    logger.warning(f"Failed to import key {key_id}")
                    success = False
            except Exception as e:
                logger.error(f"Error importing key {key_id}: {e}")
                success = False
                
        return success
    
    def send_key(self, key_id: str, keyserver: Optional[str] = None) -> bool:
        """
        Upload a public key to a key server.
        
        Args:
            key_id: ID of the key to upload
            keyserver: Optional keyserver URL
            
        Returns:
            bool: True if the key was uploaded successfully
        """
        keyserver = keyserver or self.DEFAULT_KEYSERVERS[0]
        try:
            result = self.gpg.send_keys(keyserver, key_id)
            return bool(result and not result.stderr)
        except Exception as e:
            logger.error(f"Error uploading key {key_id}: {e}")
            raise KeyServerError(f"Failed to upload key: {e}")
    
    def refresh_keys(self, keyserver: Optional[str] = None) -> bool:
        """
        Refresh all keys from a key server.
        
        Args:
            keyserver: Optional keyserver URL
            
        Returns:
            bool: True if the refresh was successful
        """
        keyserver = keyserver or self.DEFAULT_KEYSERVERS[0]
        try:
            result = subprocess.run(
                ['gpg', '--keyserver', keyserver, '--refresh-keys'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            logger.error(f"Error refreshing keys: {e.stderr}")
            raise KeyServerError(f"Failed to refresh keys: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error refreshing keys: {e}")
            raise KeyServerError(f"Unexpected error: {e}")

    def list_public_keys(self) -> List[Dict[str, Any]]:
        """
        List all public keys in the keyring.
        
        Returns:
            List of public keys with their information
        """
        try:
            return self.gpg.list_keys()
        except Exception as e:
            logger.error(f"Error listing public keys: {e}")
            raise KeyServerError(f"Failed to list public keys: {e}")

    def list_secret_keys(self) -> List[Dict[str, Any]]:
        """
        List all secret keys in the keyring.
        
        Returns:
            List of secret keys with their information
        """
        try:
            return self.gpg.list_keys(secret=True)
        except Exception as e:
            logger.error(f"Error listing secret keys: {e}")
            raise KeyServerError(f"Failed to list secret keys: {e}")
