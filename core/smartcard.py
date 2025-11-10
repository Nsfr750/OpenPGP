"""
OpenPGP Smart Card Support

This module provides support for OpenPGP smart cards for secure key storage and operations.
"""
import os
import logging
import subprocess
from typing import Dict, List, Optional, Tuple, Union, Any
from pathlib import Path
import json
import gnupg
from datetime import datetime

logger = logging.getLogger(__name__)

class SmartCardError(Exception):
    """Base exception for smart card related errors."""
    pass


class SmartCard:
    """Class for managing OpenPGP smart card operations."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the SmartCard instance.
        
        Args:
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.card = OpenPGPCard(self.gpg_home)
        
    def get_card_info(self) -> Dict[str, Any]:
        """
        Get information about the inserted smart card.
        
        Returns:
            Dictionary containing card information
        """
        try:
            return self.card.card_status
        except Exception as e:
            raise SmartCardError(f"Failed to get card info: {e}")
    
    def generate_key_on_card(self, key_type: str = 'RSA', key_length: int = 2048, 
                           name_real: str = '', name_email: str = '') -> bool:
        """
        Generate a new key directly on the smart card.
        
        Args:
            key_type: Type of key to generate (RSA, ECC, etc.)
            key_length: Length of the key in bits
            name_real: Real name for the key
            name_email: Email for the key
            
        Returns:
            bool: True if key generation was successful
        """
        try:
            # Check if card is present and writable
            if not self.card_status.get('card_available', False):
                raise SmartCardError("No smart card found")
                
            if not self.card_status.get('card_writable', False):
                raise SmartCardError("Smart card is not writable")
                
            # Generate key on card
            input_data = self.gpg.gen_key_input(
                key_type=key_type,
                key_length=key_length,
                name_real=name_real,
                name_email=name_email,
                key_usage='sign,encrypt,auth',
                subkey_type=key_type,
                subkey_length=key_length,
                subkey_usage='sign,encrypt',
                expire_date='2y',
                passphrase='',  # No passphrase for card-stored keys
                no_protection=True,
                key_curve='ed25519' if key_type.upper() == 'ECC' else None
            )
            
            result = self.gpg.gen_key(input_data)
            if not result.fingerprint:
                raise SmartCardError(f"Failed to generate key: {result.stderr}")
                
            logger.info(f"Generated new key on smart card: {result.fingerprint}")
            return True
            
        except Exception as e:
            raise SmartCardError(f"Error generating key on card: {e}")
    
    def import_public_key(self, key_data: str) -> bool:
        """
        Import a public key to the smart card.
        
        Args:
            key_data: Public key data as a string
            
        Returns:
            bool: True if import was successful
        """
        try:
            import_result = self.gpg.import_keys(key_data)
            if not import_result.fingerprints:
                raise SmartCardError("Failed to import public key")
                
            logger.info(f"Imported public key: {import_result.fingerprints[0]}")
            return True
            
        except Exception as e:
            raise SmartCardError(f"Error importing public key: {e}")
    
    def change_pin(self, pin_type: str = 'user') -> bool:
        """
        Change the PIN for the smart card.
        
        Args:
            pin_type: Type of PIN to change ('user', 'admin', or 'reset')
            
        Returns:
            bool: True if PIN was changed successfully
        """
        try:
            if pin_type not in ['user', 'admin', 'reset']:
                raise ValueError("Invalid PIN type. Must be 'user', 'admin', or 'reset'")
                
            # This will prompt the user for the current and new PINs
            result = self.gpg.card_edit(
                commands=[f'admin\npasswd\n{self._get_pin_type_code(pin_type)}\nquit\n']
            )
            
            if 'command failed' in str(result).lower():
                raise SmartCardError("Failed to change PIN")
                
            logger.info(f"Successfully changed {pin_type} PIN")
            return True
            
        except Exception as e:
            raise SmartCardError(f"Error changing {pin_type} PIN: {e}")
    
    def _get_pin_type_code(self, pin_type: str) -> str:
        """Get the code for the specified PIN type."""
        pin_types = {
            'user': '1',
            'admin': '3',
            'reset': '4'
        }
        return pin_types.get(pin_type.lower(), '1')
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys on the smart card.
        
        Returns:
            List of dictionaries containing key information
        """
        try:
            keys = []
            public_keys = self.gpg.list_keys()
            secret_keys = self.gpg.list_secret_keys()
            
            for key in public_keys:
                if key.get('keyid') in [k.get('keyid') for k in secret_keys]:
                    key['on_card'] = True
                    keys.append(key)
                    
            return keys
            
        except Exception as e:
            raise SmartCardError(f"Error listing keys: {e}")

class OpenPGPCard:
    """Class representing an OpenPGP smart card."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """Initialize the OpenPGP card interface."""
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.card_status = self._get_card_status()
    
    def _run_gpg_command(self, command: List[str]) -> str:
        """Run a gpg command and return its output."""
        try:
            result = subprocess.run(
                ['gpg'] + command,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"GPG command failed: {e.stderr}")
            raise SmartCardError(f"GPG command failed: {e.stderr}")
    
    def _get_card_status(self) -> Dict[str, str]:
        """Get the status of the OpenPGP card."""
        try:
            output = self._run_gpg_command(['--card-status'])
            return self._parse_card_status(output)
        except Exception as e:
            logger.error(f"Failed to get card status: {e}")
            return {}
    
    def _parse_card_status(self, status_output: str) -> Dict[str, str]:
        """Parse the output of gpg --card-status."""
        status = {}
        for line in status_output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                status[key.strip()] = value.strip()
        return status
    
    def is_connected(self) -> bool:
        """Check if a smart card is connected and ready."""
        return bool(self.card_status)
    
    def get_serial_number(self) -> Optional[str]:
        """Get the serial number of the smart card."""
        return self.card_status.get('Serial number')
    
    def get_key_info(self, key_type: str = 'SIGN') -> Dict[str, str]:
        """Get information about a key on the smart card."""
        key_info = {}
        key_type = key_type.upper()
        
        for line in self._run_gpg_command(['--card-status']).split('\n'):
            line = line.strip()
            if line.startswith(f'{key_type} '):
                parts = line.split()
                if len(parts) >= 5:
                    key_info['keygrip'] = parts[1]
                    key_info['key_type'] = parts[3]
                    key_info['key_size'] = parts[4]
        
        return key_info

class SmartCardManager:
    """Manager for multiple smart cards and their operations."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.cards: Dict[str, OpenPGPCard] = {}
        self._discover_cards()
    
    def _discover_cards(self) -> None:
        """Discover all connected smart cards."""
        try:
            result = subprocess.run(
                ['gpg', '--card-status', '--with-colons'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.warning("Failed to discover smart cards")
                return
                
            serial_numbers = set()
            for line in result.stdout.split('\n'):
                if line.startswith('SERIALNO:'):
                    serial = line.split(':', 1)[1].strip()
                    if serial:
                        serial_numbers.add(serial)
            
            for serial in serial_numbers:
                if serial not in self.cards:
                    self.cards[serial] = OpenPGPCard(self.gpg_home)
            
            for serial in list(self.cards.keys()):
                if serial not in serial_numbers:
                    del self.cards[serial]
                    
        except Exception as e:
            logger.error(f"Error discovering smart cards: {e}")
    
    def get_card(self, serial_number: Optional[str] = None) -> Optional[OpenPGPCard]:
        """Get a smart card by serial number."""
        if not self.cards:
            self._discover_cards()
            
        if not serial_number and self.cards:
            return next(iter(self.cards.values()))
            
        return self.cards.get(serial_number) if serial_number else None

class KeySharingManager:
    """Manager for secure key sharing between devices."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
    
    def export_key_for_sharing(self, key_fingerprint: str, 
                             recipient_fingerprints: List[str],
                             output_file: Optional[str] = None) -> Optional[bytes]:
        """Export a key encrypted for specific recipients."""
        try:
            result = self.gpg.export_keys(
                keyids=key_fipherprint,
                secret=True,
                armor=True,
                passphrase=None,
                encrypt=True,
                recipients=recipient_fingerprints
            )
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result)
                    
            return result.encode() if result else None
            
        except Exception as e:
            logger.error(f"Failed to export key for sharing: {e}")
            return None

class KeyRingManager:
    """Manager for multiple key rings."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
    
    def create_keyring(self, name: str) -> bool:
        """Create a new keyring."""
        keyring_dir = Path(self.gpg_home) / 'keyrings' / name
        keyring_dir.mkdir(parents=True, exist_ok=True)
        return keyring_dir.exists()
    
    def switch_keyring(self, name: str) -> bool:
        """Switch to a different keyring."""
        keyring_dir = Path(self.gpg_home) / 'keyrings' / name
        if not keyring_dir.exists():
            return False
            
        self.gpg = gnupg.GPG(
            gnupghome=str(keyring_dir),
            keyring='pubring.kbx',
            secret_keyring='private-keys-v1.d/'
        )
        return True
    
    def list_keyrings(self) -> List[str]:
        """List all available keyrings."""
        keyrings_dir = Path(self.gpg_home) / 'keyrings'
        if not keyrings_dir.exists():
            return []
            
        return [d.name for d in keyrings_dir.iterdir() if d.is_dir()]
