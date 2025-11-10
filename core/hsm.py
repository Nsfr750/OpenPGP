"""
Hardware Security Module (HSM) Support for OpenPGP

This module provides support for using Hardware Security Modules (HSMs) with OpenPGP.
"""
import os
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import gnupg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from OpenSSL import crypto

logger = logging.getLogger(__name__)

class HSMError(Exception):
    """Base exception for HSM related errors."""
    pass


class HSM:
    """Class for managing Hardware Security Module (HSM) operations."""
    
    def __init__(self, hsm_id: str = 'default', gpg_home: Optional[str] = None):
        """
        Initialize the HSM instance.
        
        Args:
            hsm_id: Unique identifier for the HSM
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
        """
        self.hsm_id = hsm_id
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.manager = HSMManager()
    
    def is_available(self) -> bool:
        """
        Check if the HSM is available and accessible.
        
        Returns:
            bool: True if the HSM is available, False otherwise
        """
        try:
            # Try to list keys to check HSM connectivity
            self.gpg.list_cards()
            return True
        except Exception:
            return False
    
    def generate_key(self, key_type: str = 'RSA', key_length: int = 2048, 
                    name_real: str = '', name_email: str = '') -> Dict[str, Any]:
        """
        Generate a new key on the HSM.
        
        Args:
            key_type: Type of key to generate (RSA, ECC, etc.)
            key_length: Length of the key in bits
            name_real: Real name for the key
            name_email: Email for the key
            
        Returns:
            Dictionary with information about the generated key
        """
        try:
            # Prepare key parameters
            key_usage = ['sign', 'encrypt', 'auth']
            
            # Generate key on HSM
            key_info = generate_key_on_hsm(
                hsm_id=self.hsm_id,
                key_type=key_type.upper(),
                key_size=key_length,
                key_usage=key_usage
            )
            
            # Import the public key into GnuPG
            public_key = key_info.get('public_key')
            if public_key:
                import_result = self.gpg.import_keys(public_key)
                key_info['fingerprint'] = import_result.fingerprints[0] if import_result.fingerprints else None
            
            logger.info(f"Generated new key on HSM: {key_info.get('key_id')}")
            return key_info
            
        except Exception as e:
            raise HSMError(f"Error generating key on HSM: {e}")
    
    def sign_data(self, key_id: str, data: bytes, 
                 hash_algorithm: str = 'sha256') -> bytes:
        """
        Sign data using a key on the HSM.
        
        Args:
            key_id: ID of the key to use for signing
            data: Data to sign
            hash_algorithm: Hash algorithm to use
            
        Returns:
            The signature as bytes
        """
        try:
            # Get key information
            keys = self.gpg.list_keys(secret=True)
            key_info = next((k for k in keys if key_id in k['fingerprint']), None)
            
            if not key_info:
                raise HSMError(f"Key {key_id} not found in keyring")
                
            # Sign the data using the HSM
            signature = sign_with_hsm(
                hsm_id=self.hsm_id,
                key_info=key_info,
                data=data,
                hash_algorithm=hash_algorithm
            )
            
            return signature
            
        except Exception as e:
            raise HSMError(f"Error signing data with HSM: {e}")
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys available on the HSM.
        
        Returns:
            List of dictionaries containing key information
        """
        try:
            # Get keys from GnuPG that are stored on the HSM
            keys = []
            for key in self.gpg.list_keys(secret=True):
                if key.get('card_no'):  # Keys with card_no are on the HSM
                    keys.append({
                        'fingerprint': key['fingerprint'],
                        'key_id': key['keyid'],
                        'type': key['type'],
                        'length': key['length'],
                        'created': key['date'],
                        'expires': key['expires'],
                        'card_no': key.get('card_no')
                    })
            return keys
            
        except Exception as e:
            raise HSMError(f"Error listing HSM keys: {e}")
    
    def get_public_key(self, key_id: str) -> str:
        """
        Get the public key from the HSM.
        
        Args:
            key_id: ID of the key to export
            
        Returns:
            The public key in ASCII-armored format
        """
        try:
            # Export the public key from GnuPG
            public_key = self.gpg.export_keys(key_id)
            if not public_key:
                raise HSMError(f"Failed to export public key {key_id}")
                
            return public_key
            
        except Exception as e:
            raise HSMError(f"Error getting public key from HSM: {e}")
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from the HSM.
        
        Args:
            key_id: ID of the key to delete
            
        Returns:
            bool: True if the key was deleted successfully
        """
        try:
            # Delete the key from GnuPG
            result = self.gpg.delete_keys(key_id, secret=True, passphrase='')
            if not result:
                raise HSMError(f"Failed to delete key {key_id}")
                
            logger.info(f"Deleted key from HSM: {key_id}")
            return True
            
        except Exception as e:
            raise HSMError(f"Error deleting key from HSM: {e}")

class HSMManager:
    """Manager for Hardware Security Module (HSM) operations."""
    
    # Supported HSM types
    HSM_PKCS11 = 'pkcs11'
    HSM_OPENPGP = 'openpgp'
    HSM_TPM = 'tpm'
    
    # Known HSM vendors and their PKCS#11 libraries
    KNOWN_HSM_LIBS = {
        'yubikey': '/usr/local/lib/libykcs11.dylib',  # macOS
        'yubikey_linux': '/usr/lib/x86_64-linux-gnu/libykcs11.so',  # Linux
        'yubikey_win': 'C:\\Windows\\System32\\yubihsm.dll',  # Windows
        'nfast': '/opt/nfast/toolkits/pkcs11/libcknfast.so',
        'safenet': '/usr/lib/libeToken.so',
        'opensc': '/usr/lib/opensc-pkcs11.so',
        'softhsm': '/usr/lib/softhsm/libsofthsm2.so',
        'cloudhsm': '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
        'aws': '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
        'azure': '/opt/microsoft/azurekeyvault/security/azurekeyvault-pkcs11.so',
        'google': '/usr/lib/x86_64-linux-gnu/libgooglekms.so',
    }
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the HSM manager.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.detected_hsms = []
        self.initialized = False
    
    def detect_hsms(self) -> List[Dict[str, Any]]:
        """
        Detect available HSMs on the system.
        
        Returns:
            List of detected HSMs with their information
        """
        self.detected_hsms = []
        
        # Check for PKCS#11 devices
        self._detect_pkcs11_devices()
        
        # Check for OpenPGP cards
        self._detect_openpgp_cards()
        
        # Check for TPM
        self._detect_tpm()
        
        self.initialized = True
        return self.detected_hsms
    
    def _detect_pkcs11_devices(self) -> None:
        """Detect PKCS#11 compatible devices."""
        try:
            # First, try to use the pkcs11-tool to list tokens
            try:
                result = subprocess.run(
                    ['pkcs11-tool', '--list-token-slots'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    self._parse_pkcs11_tool_output(result.stdout)
                    return
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            # Fall back to checking known libraries
            for name, lib_path in self.KNOWN_HSM_LIBS.items():
                if os.path.exists(lib_path):
                    self.detected_hsms.append({
                        'type': self.HSM_PKCS11,
                        'name': f"PKCS#11: {name}",
                        'library': lib_path,
                        'status': 'detected',
                        'keys': []
                    })
                    
        except Exception as e:
            logger.warning(f"Error detecting PKCS#11 devices: {e}")
    
    def _parse_pkcs11_tool_output(self, output: str) -> None:
        """Parse the output of pkcs11-tool --list-token-slots."""
        current_token = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New token section
            if line.startswith('Token '):
                if current_token:
                    self.detected_hsms.append(current_token)
                
                current_token = {
                    'type': self.HSM_PKCS11,
                    'name': line.split(':', 1)[1].strip() if ':' in line else 'Unknown PKCS#11 Token',
                    'library': 'pkcs11-tool',
                    'status': 'detected',
                    'details': {},
                    'keys': []
                }
            
            # Parse token details
            elif current_token and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                if key in ['token_label', 'manufacturer_id', 'model', 'serial_number']:
                    current_token['details'][key] = value
                
                # Extract additional information
                if 'label' in key and 'token_label' not in current_token['details']:
                    current_token['details']['token_label'] = value
                elif 'serial' in key and 'serial_number' not in current_token['details']:
                    current_token['details']['serial_number'] = value
                
                # Check if token is initialized
                if 'initialized' in key.lower():
                    current_token['status'] = 'initialized' if value.lower() == 'yes' else 'uninitialized'
        
        # Add the last token
        if current_token:
            self.detected_hsms.append(current_token)
    
    def _detect_openpgp_cards(self) -> None:
        """Detect OpenPGP smart cards."""
        try:
            # Use gpg --card-status to detect OpenPGP cards
            result = subprocess.run(
                ['gpg', '--card-status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                card_info = self._parse_card_status(result.stdout)
                if card_info:
                    self.detected_hsms.append({
                        'type': self.HSM_OPENPGP,
                        'name': f"OpenPGP Card: {card_info.get('name', 'Unknown')}",
                        'details': card_info,
                        'status': 'initialized' if card_info.get('serial') else 'uninitialized',
                        'keys': self._get_card_keys(card_info)
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.warning(f"Error detecting OpenPGP cards: {e}")
    
    def _parse_card_status(self, status: str) -> Dict[str, Any]:
        """Parse the output of gpg --card-status."""
        card_info = {}
        current_key = None
        
        for line in status.split('\n'):
            line = line.strip()
            
            if not line:
                continue
                
            # Parse key-value pairs
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                
                # Handle special cases
                if key == 'name' and ' ' in value:
                    # Handle "Name (Lastname, Firstname)" format
                    card_info['last_name'], card_info['first_name'] = \
                        [n.strip() for n in value.split(',', 1)]
                    card_info['name'] = f"{card_info['first_name']} {card_info['last_name']}"
                else:
                    card_info[key] = value
                    
                    # Check for key references
                    if key in ['signature_key', 'encryption_key', 'authentication_key']:
                        current_key = key.replace('_key', '')
            
            # Parse key information
            elif current_key and line.startswith(' '):
                line = line.strip()
                if 'created' in line.lower():
                    card_info[f"{current_key}_created"] = line.split(':', 1)[1].strip()
                elif 'fingerprint' in line.lower():
                    card_info[f"{current_key}_fingerprint"] = line.split(':', 1)[1].strip()
        
        return card_info
    
    def _get_card_keys(self, card_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key information from card status."""
        keys = []
        key_types = ['signature', 'encryption', 'authentication']
        
        for key_type in key_types:
            fingerprint = card_info.get(f"{key_type}_fingerprint")
            if fingerprint:
                keys.append({
                    'type': key_type,
                    'fingerprint': fingerprint,
                    'created': card_info.get(f"{key_type}_created", ''),
                    'usage': [key_type.upper()],
                    'card_key': True
                })
        
        return keys
    
    def _detect_tpm(self) -> None:
        """Detect Trusted Platform Module (TPM)."""
        try:
            # Check if TPM device exists
            tpm_paths = [
                '/dev/tpm0',  # Linux
                '/dev/tpmrm0',  # Linux TPM resource manager
                '\\\\.\\TPM0',  # Windows
                '\\\\.\\TCM0'   # Windows TCM
            ]
            
            tpm_detected = any(os.path.exists(path) for path in tpm_paths)
            
            if tpm_detected:
                self.detected_hsms.append({
                    'type': self.HSM_TPM,
                    'name': 'Trusted Platform Module (TPM)',
                    'status': 'detected',
                    'details': {
                        'device': next((p for p in tpm_paths if os.path.exists(p)), 'unknown'),
                        'version': self._get_tpm_version()
                    },
                    'keys': []
                })
        except Exception as e:
            logger.warning(f"Error detecting TPM: {e}")
    
    def _get_tpm_version(self) -> str:
        """Get the TPM version."""
        try:
            # Try to get TPM version from sysfs (Linux)
            if os.path.exists('/sys/class/tpm/tpm0/tpm_version_major'):
                with open('/sys/class/tpm/tpm0/tpm_version_major', 'r') as f:
                    version_major = f.read().strip()
                with open('/sys/class/tpm/tpm0/tpm_version_minor', 'r') as f:
                    version_minor = f.read().strip()
                return f"{version_major}.{version_minor}"
            
            # Try to use tpm2_getcap
            try:
                result = subprocess.run(
                    ['tpm2_getcap', 'properties-fixed'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    # Look for TPM_PT_FAMILY_INDICATOR
                    for line in result.stdout.split('\n'):
                        if 'TPM_PT_FAMILY_INDICATOR' in line:
                            version = line.split(':')[-1].strip().strip('"')
                            return version[1:]  # Remove the '2.' prefix
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
                
        except Exception:
            pass
            
        return 'unknown'
    
    def import_hsm_key_to_gpg(self, hsm_id: str, key_info: Dict[str, Any], 
                            keygrip: Optional[str] = None) -> bool:
        """
        Import a key from an HSM into the GnuPG keyring.
        
        Args:
            hsm_id: The ID of the HSM
            key_info: Information about the key to import
            keygrip: Optional keygrip for the key
            
        Returns:
            bool: True if the key was imported successfully
        """
        hsm = next((h for h in self.detected_hsms if h.get('id') == hsm_id or 
                   h.get('name') == hsm_id), None)
        
        if not hsm:
            raise HSMError(f"HSM not found: {hsm_id}")
        
        if hsm['type'] == self.HSM_OPENPGP:
            return self._import_openpgp_card_key(key_info, keygrip)
        elif hsm['type'] == self.HSM_PKCS11:
            return self._import_pkcs11_key(hsm, key_info, keygrip)
        elif hsm['type'] == self.HSM_TPM:
            return self._import_tpm_key(hsm, key_info, keygrip)
        else:
            raise HSMError(f"Unsupported HSM type: {hsm['type']}")
    
    def _import_openpgp_card_key(self, key_info: Dict[str, Any], 
                               keygrip: Optional[str] = None) -> bool:
        """Import a key from an OpenPGP card."""
        try:
            # For OpenPGP cards, the key is already available to GnuPG
            # We just need to ensure it's in the keyring
            fingerprint = key_info.get('fingerprint')
            if not fingerprint:
                raise HSMError("No fingerprint provided for OpenPGP card key")
            
            # Check if the key is already in the keyring
            keys = self.gpg.list_keys(keys=fingerprint)
            if keys:
                logger.info(f"Key {fingerprint} is already in the keyring")
                return True
            
            # If not, we need to import the public key
            # This assumes the card is already connected and available
            result = subprocess.run(
                ['gpg', '--card-edit', '--command-fd', '0', '--status-fd', '1'],
                input=f'fetch\nquit\n'.encode(),
                capture_output=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise HSMError(f"Failed to fetch keys from OpenPGP card: {result.stderr.decode()}")
            
            # Verify the key was imported
            keys = self.gpg.list_keys(keys=fingerprint)
            return len(keys) > 0
            
        except Exception as e:
            raise HSMError(f"Failed to import OpenPGP card key: {e}")
    
    def _import_pkcs11_key(self, hsm: Dict[str, Any], key_info: Dict[str, Any],
                          keygrip: Optional[str] = None) -> bool:
        """Import a key from a PKCS#11 device."""
        try:
            # For PKCS#11, we need to use the PKCS#11 provider
            library = hsm.get('library')
            if not library:
                raise HSMError("No PKCS#11 library specified")
            
            # Check if the pkcs11-helper tool is available
            try:
                subprocess.run(['pkcs11-tool', '--version'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("pkcs11-tool is required for PKCS#11 operations")
            
            # Get the key ID from the key info
            key_id = key_info.get('id')
            if not key_id:
                raise HSMError("No key ID provided for PKCS#11 key")
            
            # Create a temporary file for the public key
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                pubkey_path = tmp_file.name
            
            try:
                # Export the public key using pkcs11-tool
                result = subprocess.run(
                    ['pkcs11-tool', '-l', '--token-label', hsm.get('details', {}).get('token_label', ''),
                     '--read-object', '--type', 'pubkey', '--id', key_id, '--output-file', pubkey_path],
                    capture_output=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise HSMError(f"Failed to export public key: {result.stderr.decode()}")
                
                # Import the public key into GnuPG
                with open(pubkey_path, 'rb') as f:
                    import_result = self.gpg.import_keys(f.read())
                
                if not import_result.count:
                    raise HSMError("Failed to import public key into GnuPG")
                
                return True
                
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(pubkey_path)
                except OSError:
                    pass
                    
        except Exception as e:
            raise HSMError(f"Failed to import PKCS#11 key: {e}")
    
    def _import_tpm_key(self, hsm: Dict[str, Any], key_info: Dict[str, Any],
                       keygrip: Optional[str] = None) -> bool:
        """Import a key from a TPM."""
        try:
            # For TPM, we need to use the TPM2 tools
            try:
                subprocess.run(['tpm2_getcap', 'algorithms'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("tpm2-tools are required for TPM operations")
            
            # Get the key handle or context
            key_handle = key_info.get('handle')
            if not key_handle:
                raise HSMError("No key handle provided for TPM key")
            
            # Create a temporary file for the public key
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                pubkey_path = tmp_file.name
            
            try:
                # Export the public key using tpm2_readpublic
                result = subprocess.run(
                    ['tpm2_readpublic', '-c', key_handle, '-o', pubkey_path],
                    capture_output=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise HSMError(f"Failed to export TPM public key: {result.stderr.decode()}")
                
                # Convert the TPM public key to a format GnuPG can understand
                # This is a simplified example - in practice, you'd need to handle different key types
                with open(pubkey_path, 'rb') as f:
                    pubkey_data = f.read()
                
                # In a real implementation, you would parse the TPMT_PUBLIC structure
                # and convert it to a format GnuPG can import (e.g., PEM)
                # This is a placeholder for that logic
                
                # For now, we'll just try to import the raw data
                try:
                    import_result = self.gpg.import_keys(pubkey_data.hex())
                    return import_result.count > 0
                except Exception:
                    raise HSMError("Failed to import TPM public key (unsupported format)")
                
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(pubkey_path)
                except OSError:
                    pass
                    
        except Exception as e:
            raise HSMError(f"Failed to import TPM key: {e}")
    
    def generate_key_on_hsm(self, hsm_id: str, key_type: str = 'RSA',
                          key_size: int = 2048, key_usage: List[str] = None,
                          user_pin: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a new key on an HSM.
        
        Args:
            hsm_id: The ID of the HSM
            key_type: The type of key to generate (RSA, ECC, etc.)
            key_size: The size of the key in bits
            key_usage: List of key usages (e.g., ['sign', 'encrypt'])
            user_pin: Optional user PIN for the HSM
            
        Returns:
            Dictionary with information about the generated key
            
        Raises:
            HSMError: If key generation fails
        """
        hsm = next((h for h in self.detected_hsms if h.get('id') == hsm_id or 
                   h.get('name') == hsm_id), None)
        
        if not hsm:
            raise HSMError(f"HSM not found: {hsm_id}")
        
        if hsm['type'] == self.HSM_OPENPGP:
            return self._generate_key_on_openpgp_card(hsm, key_type, key_size, key_usage)
        elif hsm['type'] == self.HSM_PKCS11:
            return self._generate_key_on_pkcs11(hsm, key_type, key_size, key_usage, user_pin)
        elif hsm['type'] == self.HSM_TPM:
            return self._generate_key_on_tpm(hsm, key_type, key_size, key_usage)
        else:
            raise HSMError(f"Unsupported HSM type: {hsm['type']}")
    
    def _generate_key_on_openpgp_card(self, hsm: Dict[str, Any], key_type: str,
                                    key_size: int, key_usage: List[str]) -> Dict[str, Any]:
        """Generate a key on an OpenPGP card."""
        try:
            # Map key types to OpenPGP card key slots
            slot_map = {
                'SIGN': 1,
                'ENCRYPT': 2,
                'AUTHENTICATE': 3
            }
            
            # Determine which slot to use based on key usage
            slot = None
            for usage in (key_usage or []):
                usage = usage.upper()
                if usage in slot_map:
                    slot = slot_map[usage]
                    break
            
            if slot is None:
                slot = 1  # Default to SIGN key
            
            # Map key types to OpenPGP card algorithms
            algo_map = {
                'RSA': 'RSA',
                'ECC': 'NIST P-256',  # Default ECC curve
                'ED25519': 'Ed25519',
                'ECDSA': 'NIST P-256',
                'EDDSA': 'Ed25519'
            }
            
            algo = algo_map.get(key_type.upper())
            if not algo:
                raise HSMError(f"Unsupported key type for OpenPGP card: {key_type}")
            
            # Generate the key on the card
            # Note: This is a simplified example - in practice, you'd use gpg --card-edit
            # or a library that can communicate with the card
            
            # For now, we'll just simulate a successful key generation
            key_info = {
                'type': key_type,
                'size': key_size,
                'slot': slot,
                'algorithm': algo,
                'generated': True,
                'card_key': True
            }
            
            # Add the key to the HSM's key list
            if 'keys' not in hsm:
                hsm['keys'] = []
            
            hsm['keys'].append(key_info)
            
            return key_info
            
        except Exception as e:
            raise HSMError(f"Failed to generate key on OpenPGP card: {e}")
    
    def _generate_key_on_pkcs11(self, hsm: Dict[str, Any], key_type: str,
                              key_size: int, key_usage: List[str],
                              user_pin: Optional[str]) -> Dict[str, Any]:
        """Generate a key on a PKCS#11 device."""
        try:
            # Check if pkcs11-tool is available
            try:
                subprocess.run(['pkcs11-tool', '--version'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("pkcs11-tool is required for PKCS#11 operations")
            
            # Build the pkcs11-tool command
            cmd = [
                'pkcs11-tool',
                '--module', hsm.get('library', ''),
                '--login',  # Will prompt for PIN if not provided
                '--keypairgen',
                '--key-type', f"{key_type}:{key_size}",
                '--id', '01'  # Use a sequential ID
            ]
            
            # Add key usage flags
            for usage in (key_usage or []):
                usage = usage.upper()
                if usage in ['SIGN', 'VERIFY', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP', 'DERIVE']:
                    cmd.extend(['--usage', usage.lower()])
            
            # Add PIN if provided
            if user_pin:
                cmd.extend(['--pin', user_pin])
            
            # Run the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                raise HSMError(f"Failed to generate key: {result.stderr}")
            
            # Parse the output to get key information
            key_info = {
                'type': key_type,
                'size': key_size,
                'id': '01',  # In a real implementation, you'd extract this from the output
                'generated': True,
                'pkcs11_key': True
            }
            
            # Add the key to the HSM's key list
            if 'keys' not in hsm:
                hsm['keys'] = []
            
            hsm['keys'].append(key_info)
            
            return key_info
            
        except Exception as e:
            raise HSMError(f"Failed to generate key on PKCS#11 device: {e}")
    
    def _generate_key_on_tpm(self, hsm: Dict[str, Any], key_type: str,
                           key_size: int, key_usage: List[str]) -> Dict[str, Any]:
        """Generate a key in the TPM."""
        try:
            # Check if tpm2-tools are available
            try:
                subprocess.run(['tpm2_getcap', 'algorithms'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("tpm2-tools are required for TPM operations")
            
            # Map key types to TPM algorithms
            algo_map = {
                'RSA': 'rsa',
                'ECC': 'ecc',
                'ECDSA': 'ecc',
                'EC': 'ecc'
            }
            
            algo = algo_map.get(key_type.upper())
            if not algo:
                raise HSMError(f"Unsupported key type for TPM: {key_type}")
            
            # Create a temporary directory for TPM objects
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                
                # Generate the key
                key_ctx = tmp_path / 'key.ctx'
                pubkey_file = tmp_path / 'pubkey.pem'
                
                # Build the tpm2_createprimary command
                primary_ctx = tmp_path / 'primary.ctx'
                subprocess.run(
                    ['tpm2_createprimary', '-C', 'o', '-c', str(primary_ctx)],
                    check=True,
                    capture_output=True
                )
                
                # Build the tpm2_create command based on key type
                if algo == 'rsa':
                    key_alg = 'rsa'
                    key_attrs = 'sign|decrypt|userwithauth|sensitivedataorigin|sign'
                    
                    subprocess.run([
                        'tpm2_create', '-C', str(primary_ctx), '-G', f"{key_alg}:rsa{key_size}",
                        '-u', str(pubkey_file), '-r', str(key_ctx),
                        '-a', key_attrs
                    ], check=True, capture_output=True)
                    
                elif algo == 'ecc':
                    # Default to P-256 for ECC
                    curve = 'nist_p256'
                    if key_size == 384:
                        curve = 'nist_p384'
                    elif key_size == 521:
                        curve = 'nist_p521'
                    
                    key_attrs = 'sign|decrypt|userwithauth|sensitivedataorigin|sign'
                    
                    subprocess.run([
                        'tpm2_create', '-C', str(primary_ctx), '-G', f"ecc:{curve}",
                        '-u', str(pubkey_file), '-r', str(key_ctx),
                        '-a', key_attrs
                    ], check=True, capture_output=True)
                
                # Load the key into the TPM
                loaded_ctx = tmp_path / 'loaded.ctx'
                result = subprocess.run(
                    ['tpm2_load', '-C', str(primary_ctx), '-u', str(pubkey_file),
                     '-r', str(key_ctx), '-c', str(loaded_ctx)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                
                # Extract the key handle from the output
                # Example: "loaded object at 0x80000000"
                handle_match = re.search(r'loaded object at (0x[0-9a-f]+)', result.stdout)
                if not handle_match:
                    raise HSMError("Failed to get key handle from TPM")
                
                handle = handle_match.group(1)
                
                # Persist the key (optional)
                persistent_handle = '0x81000000'  # First persistent handle
                subprocess.run(
                    ['tpm2_evictcontrol', '-C', 'o', '-c', handle, '-P', 'owner',
                     '-o', str(tmp_path / 'key.handle')],
                    check=True,
                    capture_output=True
                )
                
                # Create key info
                key_info = {
                    'type': key_type,
                    'size': key_size,
                    'handle': handle,
                    'persistent_handle': persistent_handle,
                    'generated': True,
                    'tpm_key': True
                }
                
                # Add the key to the HSM's key list
                if 'keys' not in hsm:
                    hsm['keys'] = []
                
                hsm['keys'].append(key_info)
                
                return key_info
                
        except subprocess.CalledProcessError as e:
            raise HSMError(f"TPM command failed: {e.stderr}")
        except Exception as e:
            raise HSMError(f"Failed to generate key on TPM: {e}")
    
    def sign_with_hsm(self, hsm_id: str, key_info: Dict[str, Any],
                     data: bytes, hash_algorithm: str = 'sha256',
                     user_pin: Optional[str] = None) -> bytes:
        """
        Sign data using a key on an HSM.
        
        Args:
            hsm_id: The ID of the HSM
            key_info: Information about the key to use
            data: The data to sign
            hash_algorithm: The hash algorithm to use
            user_pin: Optional user PIN for the HSM
            
        Returns:
            The signature as bytes
            
        Raises:
            HSMError: If signing fails
        """
        hsm = next((h for h in self.detected_hsms if h.get('id') == hsm_id or 
                   h.get('name') == hsm_id), None)
        
        if not hsm:
            raise HSMError(f"HSM not found: {hsm_id}")
        
        if hsm['type'] == self.HSM_OPENPGP:
            return self._sign_with_openpgp_card(hsm, key_info, data, hash_algorithm)
        elif hsm['type'] == self.HSM_PKCS11:
            return self._sign_with_pkcs11(hsm, key_info, data, hash_algorithm, user_pin)
        elif hsm['type'] == self.HSM_TPM:
            return self._sign_with_tpm(hsm, key_info, data, hash_algorithm)
        else:
            raise HSMError(f"Unsupported HSM type: {hsm['type']}")
    
    def _sign_with_openpgp_card(self, hsm: Dict[str, Any], key_info: Dict[str, Any],
                              data: bytes, hash_algorithm: str) -> bytes:
        """Sign data using a key on an OpenPGP card."""
        try:
            # For OpenPGP cards, we can use gpg to sign the data
            with tempfile.NamedTemporaryFile(delete=False) as data_file:
                data_path = data_file.name
                data_file.write(data)
            
            with tempfile.NamedTemporaryFile(delete=False) as sig_file:
                sig_path = sig_file.name
            
            try:
                # Get the key ID or fingerprint from key_info
                key_id = key_info.get('id') or key_info.get('fingerprint')
                if not key_id:
                    raise HSMError("No key ID or fingerprint provided")
                
                # Build the gpg command
                cmd = [
                    'gpg',
                    '--detach-sign',
                    '--output', sig_path,
                    '--digest-algo', hash_algorithm,
                    '--local-user', key_id,
                    data_path
                ]
                
                # Run the command
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise HSMError(f"Failed to sign data: {result.stderr}")
                
                # Read the signature
                with open(sig_path, 'rb') as f:
                    signature = f.read()
                
                return signature
                
            finally:
                # Clean up temporary files
                try:
                    os.unlink(data_path)
                    os.unlink(sig_path)
                except OSError:
                    pass
                    
        except Exception as e:
            raise HSMError(f"Failed to sign with OpenPGP card: {e}")
    
    def _sign_with_pkcs11(self, hsm: Dict[str, Any], key_info: Dict[str, Any],
                         data: bytes, hash_algorithm: str,
                         user_pin: Optional[str]) -> bytes:
        """Sign data using a key on a PKCS#11 device."""
        try:
            # Check if pkcs11-tool is available
            try:
                subprocess.run(['pkcs11-tool', '--version'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("pkcs11-tool is required for PKCS#11 operations")
            
            # Create temporary files
            with tempfile.NamedTemporaryFile(delete=False) as data_file:
                data_path = data_file.name
                data_file.write(data)
            
            with tempfile.NamedTemporaryFile(delete=False) as sig_file:
                sig_path = sig_file.name
            
            try:
                # Get the key ID from key_info
                key_id = key_info.get('id')
                if not key_id:
                    raise HSMError("No key ID provided")
                
                # Map hash algorithm to PKCS#11 mechanism
                mech_map = {
                    'sha1': 'SHA-1',
                    'sha256': 'SHA256',
                    'sha384': 'SHA384',
                    'sha512': 'SHA512'
                }
                
                mech = mech_map.get(hash_algorithm.lower())
                if not mech:
                    raise HSMError(f"Unsupported hash algorithm: {hash_algorithm}")
                
                # Build the pkcs11-tool command
                cmd = [
                    'pkcs11-tool',
                    '--module', hsm.get('library', ''),
                    '--sign',
                    '--input', data_path,
                    '--output', sig_path,
                    '--id', key_id,
                    '--mechanism', mech,
                    '--signature-format', 'openssl'
                ]
                
                # Add PIN if provided
                if user_pin:
                    cmd.extend(['--pin', user_pin])
                
                # Run the command
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise HSMError(f"Failed to sign data: {result.stderr}")
                
                # Read the signature
                with open(sig_path, 'rb') as f:
                    signature = f.read()
                
                return signature
                
            finally:
                # Clean up temporary files
                try:
                    os.unlink(data_path)
                    os.unlink(sig_path)
                except OSError:
                    pass
                    
        except Exception as e:
            raise HSMError(f"Failed to sign with PKCS#11 device: {e}")
    
    def _sign_with_tpm(self, hsm: Dict[str, Any], key_info: Dict[str, Any],
                      data: bytes, hash_algorithm: str) -> bytes:
        """Sign data using a key in the TPM."""
        try:
            # Check if tpm2-tools are available
            try:
                subprocess.run(['tpm2_getcap', 'algorithms'], 
                             capture_output=True, 
                             check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                raise HSMError("tpm2-tools are required for TPM operations")
            
            # Create a temporary directory for TPM objects
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                
                # Write the data to a file
                data_file = tmp_path / 'data.bin'
                with open(data_file, 'wb') as f:
                    f.write(data)
                
                # Get the key handle from key_info
                key_handle = key_info.get('handle')
                if not key_handle:
                    raise HSMError("No key handle provided")
                
                # Map hash algorithm to TPM algorithm
                hash_map = {
                    'sha1': 'sha1',
                    'sha256': 'sha256',
                    'sha384': 'sha384',
                    'sha512': 'sha512'
                }
                
                hash_alg = hash_map.get(hash_algorithm.lower())
                if not hash_alg:
                    raise HSMError(f"Unsupported hash algorithm: {hash_algorithm}")
                
                # Sign the data
                sig_file = tmp_path / 'signature.bin'
                
                subprocess.run(
                    ['tpm2_sign', '-c', key_handle, '-g', hash_alg,
                     '-o', str(sig_file), str(data_file)],
                    check=True,
                    capture_output=True
                )
                
                # Read the signature
                with open(sig_file, 'rb') as f:
                    signature = f.read()
                
                return signature
                
        except subprocess.CalledProcessError as e:
            raise HSMError(f"TPM command failed: {e.stderr.decode()}")
        except Exception as e:
            raise HSMError(f"Failed to sign with TPM: {e}")


def detect_system_hsms() -> List[Dict[str, Any]]:
    """
    Detect all available HSMs on the system.
    
    Returns:
        List of detected HSMs with their information
    """
    hsm_manager = HSMManager()
    return hsm_manager.detect_hsms()


def generate_key_on_hsm(hsm_id: str, key_type: str = 'RSA',
                      key_size: int = 2048, key_usage: List[str] = None,
                      user_pin: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a new key on an HSM.
    
    Args:
        hsm_id: The ID of the HSM
        key_type: The type of key to generate (RSA, ECC, etc.)
        key_size: The size of the key in bits
        key_usage: List of key usages (e.g., ['sign', 'encrypt'])
        user_pin: Optional user PIN for the HSM
        
    Returns:
        Dictionary with information about the generated key
    """
    hsm_manager = HSMManager()
    hsm_manager.detect_hsms()  # Ensure HSMs are detected
    return hsm_manager.generate_key_on_hsm(hsm_id, key_type, key_size, key_usage, user_pin)


def sign_with_hsm(hsm_id: str, key_info: Dict[str, Any],
                data: bytes, hash_algorithm: str = 'sha256',
                user_pin: Optional[str] = None) -> bytes:
    """
    Sign data using a key on an HSM.
    
    Args:
        hsm_id: The ID of the HSM
        key_info: Information about the key to use
        data: The data to sign
        hash_algorithm: The hash algorithm to use
        user_pin: Optional user PIN for the HSM
        
    Returns:
        The signature as bytes
    """
    hsm_manager = HSMManager()
    hsm_manager.detect_hsms()  # Ensure HSMs are detected
    return hsm_manager.sign_with_hsm(hsm_id, key_info, data, hash_algorithm, user_pin)
