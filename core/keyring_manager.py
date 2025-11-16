"""
Key Ring Manager for OpenPGP

This module provides functionality for managing multiple key rings.
"""
import os
import shutil
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union
import gnupg
import subprocess

def is_gnupg_installed() -> bool:
    """Check if GnuPG is installed and available in the system PATH."""
    try:
        # Try to get the GnuPG version
        result = subprocess.run(['gpg', '--version'], 
                              capture_output=True, 
                              text=True,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        return result.returncode == 0
    except FileNotFoundError:
        return False

logger = logging.getLogger(__name__)

class KeyRingError(Exception):
    """Base exception for key ring related errors."""
    pass


class KeyringManager:
    """Manager for multiple key rings."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize the key ring manager.
        
        Args:
            base_dir: Base directory for key rings (default: ~/.openpgp/keyrings)
        """
        self.base_dir = base_dir or Path.home() / '.openpgp' / 'keyrings'
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.current_keyring: Optional[KeyRing] = None
        self.keyrings: Dict[str, KeyRing] = {}
        self._load_keyrings()
    
    def _load_keyrings(self):
        """Load all key rings from disk."""
        for entry in self.base_dir.iterdir():
            if entry.is_dir() and (entry / 'pubring.kbx').exists():
                try:
                    self._load_keyring(entry.name)
                except Exception as e:
                    logger.error(f"Failed to load keyring {entry.name}: {e}")
    
    def _load_keyring(self, name: str):
        """Load a single key ring."""
        keyring_dir = self.base_dir / name
        keyring_dir.mkdir(parents=True, exist_ok=True)
        gpg = gnupg.GPG(gnupghome=None, homedir=str(keyring_dir))
        self.keyrings[name] = KeyRing(name, keyring_dir, gpg)
    
    def add_key(self, key_data: Union[str, bytes], key_type: str = 'public') -> bool:
        """
        Add a key to the current keyring.
        
        Args:
            key_data: The key data (ASCII-armored or binary)
            key_type: Type of key ('public' or 'private')
            
        Returns:
            bool: True if the key was added successfully
        """
        if not self.current_keyring:
            # If no keyring is selected, use the default one
            if 'default' not in self.keyrings:
                self.create_keyring('default')
            self.switch_keyring('default')
        
        try:
            if isinstance(key_data, bytes):
                key_data = key_data.decode('utf-8', errors='replace')
            
            # Import the key
            import_result = self.current_keyring.gpg.import_keys(key_data)
            
            if import_result.count == 0:
                logger.error("No keys found in the provided data")
                return False
                
            # Get the fingerprint of the imported key
            fingerprint = import_result.fingerprints[0]
            
            # Update metadata
            if not hasattr(self.current_keyring, '_metadata'):
                self.current_keyring._metadata = self.current_keyring._load_metadata()
                
            self.current_keyring._metadata['keys'][fingerprint] = {
                'type': key_type,
                'imported': self.current_keyring._now(),
                'tags': [],
                'metadata': {}
            }
            
            # Save the updated metadata
            self.current_keyring._save_metadata()
            
            logger.info(f"Successfully imported {import_result.count} key(s)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import key: {e}")
            return False
            self.current_keyring = self.keyrings[name]
    
    def create_keyring(self, name: str, description: str = '') -> bool:
        """
        Create a new key ring.
        
        Args:
            name: Name of the key ring
            description: Optional description
            
        Returns:
            bool: True if the key ring was created successfully
        """
        if name in self.keyrings:
            logger.warning(f"Keyring {name} already exists")
            return False
            
        keyring_dir = self.base_dir / name
        keyring_dir.mkdir(exist_ok=True)
        
        # Set appropriate permissions
        keyring_dir.chmod(0o700)
        
        # Create a new GPG instance for this keyring
        gpg = gnupg.GPG(gnupghome=None, homedir=str(keyring_dir))
        
        # Create the keyring
        self.keyrings[name] = KeyRing(name, keyring_dir, gpg)
        
        # Set as current keyring
        self.current_keyring = self.keyrings[name]
        
        logger.info(f"Created new keyring: {name}")
        return True
    
    def delete_keyring(self, name: str) -> bool:
        """
        Delete a key ring.
        
        Args:
            name: Name of the key ring to delete
            
        Returns:
            bool: True if the key ring was deleted successfully
        """
        if name not in self.keyrings:
            logger.warning(f"Keyring {name} not found")
            return False
            
        if self.current_keyring and self.current_keyring.name == name:
            self.current_keyring = None
            
        keyring_dir = self.base_dir / name
        try:
            shutil.rmtree(keyring_dir)
            del self.keyrings[name]
            logger.info(f"Deleted keyring: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete keyring {name}: {e}")
            return False
    
    def switch_keyring(self, name: str) -> bool:
        """
        Switch to a different key ring.
        
        Args:
            name: Name of the key ring to switch to
            
        Returns:
            bool: True if the switch was successful
        """
        if name not in self.keyrings:
            logger.warning(f"Keyring {name} not found")
            return False
            
        self.current_keyring = self.keyrings[name]
        logger.info(f"Switched to keyring: {name}")
        return True
    
    def list_keyrings(self) -> List[Dict[str, Any]]:
        """
        List all available key rings.
        
        Returns:
            List of key ring information dictionaries
        """
        result = []
        for name, keyring in self.keyrings.items():
            result.append({
                'name': name,
                'path': str(keyring.path),
                'is_current': keyring == self.current_keyring,
                'key_count': len(keyring.list_keys())
            })
        return result
        
    def list_keys(self, key_type: Optional[str] = None, 
                 tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List keys in the current keyring.
        
        Args:
            key_type: Optional filter by key type ('public' or 'private')
            tags: Optional filter by tags
            
        Returns:
            List of key information dictionaries
        """
        if not self.current_keyring:
            # If no keyring is selected, try to use the default one
            if 'default' in self.keyrings:
                self.switch_keyring('default')
            else:
                # If no keyrings exist, create a default one
                self.create_keyring('default')
                
        return self.current_keyring.list_keys(key_type, tags)

class KeyRing:
    """Class representing a key ring."""
    
    def __init__(self, name: str, path: Path, gpg: gnupg.GPG):
        """
        Initialize a key ring.
        
        Args:
            name: Name of the key ring
            path: Path to the key ring directory
            gpg: GPG instance to use
        """
        self.name = name
        self.path = path
        self.gpg = gpg
        self.metadata_file = path / 'metadata.json'
        self._metadata = self._load_metadata()
        
        # Ensure the key ring directory exists
        self.path.mkdir(parents=True, exist_ok=True)
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load metadata from the metadata file."""
        if not self.metadata_file.exists():
            return {
                'name': self.name,
                'created': self._now(),
                'modified': self._now(),
                'keys': {},
                'tags': {},
                'description': ''
            }
            
        try:
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                # Ensure all required fields exist
                metadata.setdefault('name', self.name)
                metadata.setdefault('created', self._now())
                metadata.setdefault('modified', self._now())
                metadata.setdefault('keys', {})
                metadata.setdefault('tags', {})
                metadata.setdefault('description', '')
                return metadata
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load metadata for key ring '{self.name}': {e}")
            return {
                'name': self.name,
                'created': self._now(),
                'modified': self._now(),
                'keys': {},
                'tags': {},
                'description': ''
            }
    
    def _save_metadata(self) -> None:
        """Save metadata to the metadata file."""
        self._metadata['modified'] = self._now()
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self._metadata, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save metadata for key ring '{self.name}': {e}")
            raise KeyRingError(f"Failed to save metadata: {e}")
    
    def _now(self) -> str:
        """Get the current timestamp as a string."""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def add_key(self, key_data: Union[str, bytes], 
               key_type: str = 'public',
               tags: Optional[List[str]] = None,
               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a key to the key ring.
        
        Args:
            key_data: The key data (can be ASCII-armored or binary)
            key_type: Type of key ('public' or 'private')
            tags: Optional list of tags for the key
            metadata: Optional additional metadata
            
        Returns:
            bool: True if the key was added successfully
        """
        try:
            # Import the key
            import_result = self.gpg.import_keys(key_data)
            
            if not import_result.count:
                logger.warning("No keys were imported")
                return False
            
            # Get the fingerprint of the imported key
            fingerprint = import_result.fingerprints[0]
            
            # Update metadata
            self._metadata['keys'][fingerprint] = {
                'type': key_type,
                'imported': self._now(),
                'tags': list(set(tags or [])),
                'metadata': metadata or {}
            }
            
            # Update tags
            for tag in (tags or []):
                self._metadata['tags'].setdefault(tag, []).append(fingerprint)
            
            self._save_metadata()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add key to key ring '{self.name}': {e}")
            return False
    
    def remove_key(self, fingerprint: str) -> bool:
        """
        Remove a key from the key ring.
        
        Args:
            fingerprint: The fingerprint of the key to remove
            
        Returns:
            bool: True if the key was removed successfully
        """
        try:
            # Delete the key
            delete_result = self.gpg.delete_keys(
                fingerprints=fingerprint,
                secret=True,  # Try to delete both public and private keys
                subkeys='delete'
            )
            
            if not delete_result:
                logger.warning(f"Failed to delete key {fingerprint}")
                return False
            
            # Remove from metadata
            if fingerprint in self._metadata['keys']:
                # Remove from tags
                key_info = self._metadata['keys'][fingerprint]
                for tag in key_info.get('tags', []):
                    if tag in self._metadata['tags'] and fingerprint in self._metadata['tags'][tag]:
                        self._metadata['tags'][tag].remove(fingerprint)
                        if not self._metadata['tags'][tag]:
                            del self._metadata['tags'][tag]
                
                # Remove from keys
                del self._metadata['keys'][fingerprint]
                self._save_metadata()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove key {fingerprint} from key ring '{self.name}': {e}")
            return False
    
    def list_keys(self, key_type: Optional[str] = None, 
                 tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List keys in the key ring.
        
        Args:
            key_type: Optional filter by key type ('public' or 'private')
            tags: Optional filter by tags
            
        Returns:
            List of key information dictionaries
        """
        keys = []
        
        # Get all keys or filter by type
        for fp, key_info in self._metadata['keys'].items():
            if key_type and key_info.get('type') != key_type:
                continue
                
            # Filter by tags if specified
            if tags and not any(tag in key_info.get('tags', []) for tag in tags):
                continue
            
            # Get key details from GPG
            key = self.gpg.list_keys(keys=fp, secret=key_type == 'private')
            if key:
                key = key[0]  # Get the first (and should be only) key
                keys.append({
                    'fingerprint': fp,
                    'type': key_type or key_info.get('type'),
                    'uids': key['uids'],
                    'created': key.get('date'),
                    'expires': key.get('expires'),
                    'tags': key_info.get('tags', []),
                    'metadata': key_info.get('metadata', {})
                })
        
        return keys
    
    def add_tag(self, fingerprint: str, tag: str) -> bool:
        """
        Add a tag to a key.
        
        Args:
            fingerprint: The fingerprint of the key
            tag: The tag to add
            
        Returns:
            bool: True if the tag was added successfully
        """
        if fingerprint not in self._metadata['keys']:
            logger.warning(f"Key {fingerprint} not found in key ring '{self.name}'")
            return False
        
        # Add to key's tags
        if 'tags' not in self._metadata['keys'][fingerprint]:
            self._metadata['keys'][fingerprint]['tags'] = []
        
        if tag not in self._metadata['keys'][fingerprint]['tags']:
            self._metadata['keys'][fingerprint]['tags'].append(tag)
        
        # Add to global tags
        self._metadata['tags'].setdefault(tag, []).append(fingerprint)
        
        self._save_metadata()
        return True
    
    def remove_tag(self, fingerprint: str, tag: str) -> bool:
        """
        Remove a tag from a key.
        
        Args:
            fingerprint: The fingerprint of the key
            tag: The tag to remove
            
        Returns:
            bool: True if the tag was removed successfully
        """
        if fingerprint not in self._metadata['keys']:
            return False
        
        # Remove from key's tags
        if 'tags' in self._metadata['keys'][fingerprint]:
            if tag in self._metadata['keys'][fingerprint]['tags']:
                self._metadata['keys'][fingerprint]['tags'].remove(tag)
        
        # Remove from global tags
        if tag in self._metadata['tags'] and fingerprint in self._metadata['tags'][tag]:
            self._metadata['tags'][tag].remove(fingerprint)
            if not self._metadata['tags'][tag]:
                del self._metadata['tags'][tag]
        
        self._save_metadata()
        return True
    
    def get_tags(self) -> List[str]:
        """
        Get all tags in the key ring.
        
        Returns:
            List of tag names
        """
        return list(self._metadata['tags'].keys())
    
    def export_key(self, fingerprint: str, output_file: Optional[Path] = None) -> Optional[bytes]:
        """
        Export a key from the key ring.
        
        Args:
            fingerprint: The fingerprint of the key to export
            output_file: Optional file to save the key to
            
        Returns:
            The key data as bytes, or None if export failed
        """
        try:
            # Check if the key exists in this key ring
            if fingerprint not in self._metadata['keys']:
                logger.warning(f"Key {fingerprint} not found in key ring '{self.name}'")
                return None
            
            # Export the key
            key_type = self._metadata['keys'][fingerprint].get('type', 'public')
            export_result = self.gpg.export_keys(
                fingerprints=fingerprint,
                secret=key_type == 'private',
                armor=True
            )
            
            if not export_result:
                logger.warning(f"Failed to export key {fingerprint}")
                return None
            
            # Save to file if requested
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(export_result)
            
            return export_result.encode()
            
        except Exception as e:
            logger.error(f"Failed to export key {fingerprint}: {e}")
            return None


class KeyRingManager:
    """Manager for multiple key rings."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize the key ring manager.
        
        Args:
            base_dir: Base directory for key rings (default: ~/.openpgp/keyrings)
        """
        self.base_dir = base_dir or Path.home() / '.openpgp' / 'keyrings'
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.current_keyring: Optional[KeyRing] = None
        self.keyrings: Dict[str, KeyRing] = {}
        self._load_keyrings()
    
    def _load_keyrings(self) -> None:
        """Load all key rings from disk."""
        self.keyrings.clear()
        
        # Each subdirectory is a key ring
        for entry in self.base_dir.iterdir():
            if entry.is_dir():
                name = entry.name
                keyring = self._load_keyring(name)
                if keyring:
                    self.keyrings[name] = keyring
    
    def _load_keyring(self, name: str) -> Optional[KeyRing]:
        """Load a single key ring."""
        try:
            keyring_dir = self.base_dir / name
            
            # Create a new GPG instance for this key ring
            gpg = gnupg.GPG(
                gnupghome=str(keyring_dir),
                keyring='pubring.kbx',
                secret_keyring='private-keys-v1.d',
                options=['--no-tty']
            )
            
            return KeyRing(name, keyring_dir, gpg)
            
        except Exception as e:
            logger.error(f"Failed to load key ring '{name}': {e}")
            return None
    
    def create_keyring(self, name: str, description: str = '') -> bool:
        """
        Create a new key ring.
        
        Args:
            name: Name of the key ring
            description: Optional description
            
        Returns:
            bool: True if the key ring was created successfully
        """
        if name in self.keyrings:
            logger.warning(f"Key ring '{name}' already exists")
            return False
        
        try:
            keyring_dir = self.base_dir / name
            keyring_dir.mkdir(parents=True, exist_ok=True)
            
            # Create necessary subdirectories
            (keyring_dir / 'private-keys-v1.d').mkdir(exist_ok=True)
            
            # Create a new GPG instance for this key ring
            gpg = gnupg.GPG(
                gnupghome=str(keyring_dir),
                keyring='pubring.kbx',
                secret_keyring='private-keys-v1.d',
                options=['--no-tty']
            )
            
            # Create the key ring
            keyring = KeyRing(name, keyring_dir, gpg)
            keyring._metadata['description'] = description
            keyring._save_metadata()
            
            self.keyrings[name] = keyring
            
            # Set as current if this is the first key ring
            if self.current_keyring is None:
                self.current_keyring = keyring
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create key ring '{name}': {e}")
            # Clean up if creation failed
            if keyring_dir.exists():
                shutil.rmtree(keyring_dir, ignore_errors=True)
            return False
    
    def delete_keyring(self, name: str) -> bool:
        """
        Delete a key ring.
        
        Args:
            name: Name of the key ring to delete
            
        Returns:
            bool: True if the key ring was deleted successfully
        """
        if name not in self.keyrings:
            logger.warning(f"Key ring '{name}' not found")
            return False
        
        try:
            keyring_dir = self.base_dir / name
            
            # Remove from current key ring if it's the one being deleted
            if self.current_keyring and self.current_keyring.name == name:
                self.current_keyring = None
            
            # Remove from the keyrings dictionary
            del self.keyrings[name]
            
            # Delete the directory
            shutil.rmtree(keyring_dir, ignore_errors=True)
            
            # Set a new current key ring if needed
            if not self.current_keyring and self.keyrings:
                self.current_keyring = next(iter(self.keyrings.values()))
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete key ring '{name}': {e}")
            return False
    
    def switch_keyring(self, name: str) -> bool:
        """
        Switch to a different key ring.
        
        Args:
            name: Name of the key ring to switch to
            
        Returns:
            bool: True if the switch was successful
        """
        if name not in self.keyrings:
            logger.warning(f"Key ring '{name}' not found")
            return False
        
        self.current_keyring = self.keyrings[name]
        return True
    
    def list_keyrings(self) -> List[Dict[str, Any]]:
        """
        List all available key rings.
        
        Returns:
            List of key ring information dictionaries
        """
        keyrings = []
        for name, keyring in self.keyrings.items():
            keyrings.append({
                'name': name,
                'path': str(keyring.path),
                'description': keyring._metadata.get('description', ''),
                'created': keyring._metadata.get('created'),
                'modified': keyring._metadata.get('modified'),
                'key_count': len(keyring._metadata.get('keys', {})),
                'is_current': self.current_keyring and self.current_keyring.name == name
            })
        
        return keyrings
