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
