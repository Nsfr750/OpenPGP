"""
Hardware Token and TPM Support for OpenPGP

This module provides support for using hardware security tokens like YubiKey
and TPM (Trusted Platform Module) for PGP operations.
"""
import os
import subprocess
import tempfile
import logging
import json
from typing import Optional, Tuple, List, Dict, Any, Set
from pathlib import Path
import gnupg
from datetime import datetime, timedelta

# TPM support configuration
# Set this to False to disable TPM support even if tpm2-pytss is available
ENABLE_TPM = True
TPM_SUPPORT = False

# Try to import TPM2 support if enabled
if ENABLE_TPM:
    try:
        import tpm2_pytss as tpm
        TPM_SUPPORT = True
    except ImportError:
        import warnings
        warnings.warn("TPM support not available. Install tpm2-pytss for TPM functionality.")
else:
    import logging
    logger = logging.getLogger(__name__)
    logger.info("TPM support is disabled by configuration")

logger = logging.getLogger(__name__)

class HardwareTokenError(Exception):
    """Base exception for hardware token related errors."""
    pass

class HardwareToken:
    """Class for managing hardware token operations."""
    
    def __init__(self, token_id: str = 'default', gpg_home: Optional[str] = None, enable_tpm: Optional[bool] = None):
        """
        Initialize the HardwareToken instance.
        
        Args:
            token_id: Unique identifier for the hardware token
            gpg_home: Path to the GnuPG home directory (default: ~/.gnupg)
            enable_tpm: Override global TPM support setting (None to use global setting)
        """
        self.token_id = token_id
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.manager = HardwareTokenManager(gpg_home=gpg_home)
        
        # Handle TPM support
        self.tpm_support = TPM_SUPPORT
        if enable_tpm is not None:
            self.tpm_support = enable_tpm and TPM_SUPPORT
            if enable_tpm and not TPM_SUPPORT:
                logger.warning("TPM support is not available. Install tpm2-pytss and enable TPM in config.")
    
    def is_available(self) -> bool:
        """
        Check if the hardware token is available and accessible.
        
        Returns:
            bool: True if the token is available, False otherwise
        """
        try:
            # Try to list tokens to check connectivity
            tokens = self.manager.list_tokens()
            return any(t['id'] == self.token_id for t in tokens)
        except Exception:
            return False
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get information about the hardware token.
        
        Returns:
            Dictionary containing token information
        """
        try:
            tokens = self.manager.list_tokens()
            for token in tokens:
                if token.get('id') == self.token_id:
                    return token
            raise HardwareTokenError(f"Token {self.token_id} not found")
        except Exception as e:
            raise HardwareTokenError(f"Error getting token info: {e}")
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys available on the hardware token.
        
        Returns:
            List of dictionaries containing key information
        """
        try:
            token_info = self.get_info()
            return token_info.get('keys', [])
        except Exception as e:
            raise HardwareTokenError(f"Error listing keys: {e}")
    
    def get_public_key(self, keygrip: str) -> str:
        """
        Get the public key from the hardware token.
        
        Args:
            keygrip: The keygrip of the key to export
            
        Returns:
            The public key in ASCII-armored format
        """
        try:
            # Import the key to get the public key
            fingerprint = self.manager.import_key_from_token(keygrip)
            if not fingerprint:
                raise HardwareTokenError(f"Failed to import key {keygrip}")
                
            # Export the public key
            public_key = self.gpg.export_keys(fingerprint)
            if not public_key:
                raise HardwareTokenError(f"Failed to export public key for {keygrip}")
                
            return public_key
            
        except Exception as e:
            raise HardwareTokenError(f"Error getting public key: {e}")
    
    def sign_data(self, data: str, keygrip: str) -> str:
        """
        Sign data using a key on the hardware token.
        
        Args:
            data: The data to sign
            keygrip: The keygrip of the key to use for signing
            
        Returns:
            The signature in ASCII-armored format
        """
        try:
            if not isinstance(data, str):
                data = str(data)
                
            signature = self.manager.sign_with_token(data, keygrip)
            if not signature:
                raise HardwareTokenError(f"Failed to sign data with key {keygrip}")
                
            return signature
            
        except Exception as e:
            raise HardwareTokenError(f"Error signing data: {e}")
    
    def verify_signature(self, data: str, signature: str) -> Tuple[bool, str]:
        """
        Verify a signature using a key on the hardware token.
        
        Args:
            data: The original data that was signed
            signature: The signature in ASCII-armored format
            
        Returns:
            Tuple of (is_valid, status_message)
        """
        try:
            if not isinstance(data, str):
                data = str(data)
                
            return self.manager.verify_with_token(data, signature)
            
        except Exception as e:
            return False, f"Error verifying signature: {e}"

class TPMError(Exception):
    """Exception for TPM-related errors."""
    pass

class KeyGroupManager:
    """Manager for key groups and tags."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the key group manager.
        
        Args:
            config_dir: Directory to store group configuration (default: ~/.config/openpgp)
        """
        self.config_dir = Path(config_dir or Path.home() / '.config' / 'openpgp')
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.groups_file = self.config_dir / 'groups.json'
        self._groups = self._load_groups()
    
    def _load_groups(self) -> Dict[str, Dict[str, Any]]:
        """Load groups from the configuration file."""
        if not self.groups_file.exists():
            return {}
            
        try:
            with open(self.groups_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load groups: {e}")
            return {}
    
    def _save_groups(self) -> None:
        """Save groups to the configuration file."""
        try:
            with open(self.groups_file, 'w') as f:
                json.dump(self._groups, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save groups: {e}")
            raise
    
    def create_group(self, name: str, description: str = "") -> bool:
        """
        Create a new key group.
        
        Args:
            name: Name of the group
            description: Optional description
            
        Returns:
            bool: True if the group was created, False if it already exists
        """
        if name in self._groups:
            return False
            
        self._groups[name] = {
            'description': description,
            'keys': set(),
            'tags': {},
            'created': datetime.utcnow().isoformat(),
            'updated': datetime.utcnow().isoformat()
        }
        self._save_groups()
        return True
    
    def delete_group(self, name: str) -> bool:
        """
        Delete a key group.
        
        Args:
            name: Name of the group to delete
            
        Returns:
            bool: True if the group was deleted, False if it didn't exist
        """
        if name not in self._groups:
            return False
            
        del self._groups[name]
        self._save_groups()
        return True
    
    def add_key_to_group(self, group_name: str, key_fingerprint: str, tags: Optional[List[str]] = None) -> bool:
        """
        Add a key to a group with optional tags.
        
        Args:
            group_name: Name of the group
            key_fingerprint: Fingerprint of the key to add
            tags: Optional list of tags for the key in this group
            
        Returns:
            bool: True if the key was added, False if the group doesn't exist
        """
        if group_name not in self._groups:
            return False
            
        self._groups[group_name]['keys'].add(key_fingerprint)
        if tags:
            self._groups[group_name]['tags'][key_fingerprint] = list(set(tags))  # Remove duplicates
            
        self._groups[group_name]['updated'] = datetime.utcnow().isoformat()
        self._save_groups()
        return True
    
    def remove_key_from_group(self, group_name: str, key_fingerprint: str) -> bool:
        """
        Remove a key from a group.
        
        Args:
            group_name: Name of the group
            key_fingerprint: Fingerprint of the key to remove
            
        Returns:
            bool: True if the key was removed, False if it wasn't in the group
        """
        if group_name not in self._groups:
            return False
            
        if key_fingerprint not in self._groups[group_name]['keys']:
            return False
            
        self._groups[group_name]['keys'].remove(key_fingerprint)
        self._groups[group_name]['tags'].pop(key_fingerprint, None)
        self._groups[group_name]['updated'] = datetime.utcnow().isoformat()
        self._save_groups()
        return True
    
    def get_key_tags(self, group_name: str, key_fingerprint: str) -> List[str]:
        """
        Get tags for a key in a group.
        
        Args:
            group_name: Name of the group
            key_fingerprint: Fingerprint of the key
            
        Returns:
            List of tags for the key, or empty list if not found
        """
        if (group_name not in self._groups or 
            key_fingerprint not in self._groups[group_name]['tags']):
            return []
            
        return self._groups[group_name]['tags'][key_fingerprint]
    
    def get_keys_by_tag(self, group_name: str, tag: str) -> List[str]:
        """
        Get all keys in a group with a specific tag.
        
        Args:
            group_name: Name of the group
            tag: Tag to search for
            
        Returns:
            List of key fingerprints that have the specified tag
        """
        if group_name not in self._groups:
            return []
            
        return [
            fp for fp, tags in self._groups[group_name]['tags'].items()
            if tag in tags
        ]
    
    def list_groups(self) -> List[str]:
        """
        List all key groups.
        
        Returns:
            List of group names
        """
        return list(self._groups.keys())
    
    def get_group_keys(self, group_name: str) -> Set[str]:
        """
        Get all keys in a group.
        
        Args:
            group_name: Name of the group
            
        Returns:
            Set of key fingerprints in the group
        """
        if group_name not in self._groups:
            return set()
            
        return set(self._groups[group_name]['keys'])
    
    def get_key_groups(self, key_fingerprint: str) -> List[str]:
        """
        Get all groups that contain a key.
        
        Args:
            key_fingerprint: Fingerprint of the key
            
        Returns:
            List of group names that contain the key
        """
        return [
            name for name, group in self._groups.items()
            if key_fingerprint in group['keys']
        ]

class HardwareTokenManager:
    """Manager for hardware token and TPM operations."""
    
    def __init__(self, gpg_home: Optional[str] = None):
        """
        Initialize the hardware token and TPM manager.
        
        Args:
            gpg_home: Path to GnuPG home directory (default: ~/.gnupg)
        """
        self.gpg_home = str(gpg_home or Path.home() / '.gnupg')
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home, use_agent=True)
        self.tpm_available = TPM_SUPPORT
        self.tpm_ctx = tpm.ESYS(flags=tpm.TSS2_ESYS_FLAGS_DEFAULT) if TPM_SUPPORT else None
        
    def _get_tpm_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the TPM.
        
        Returns:
            Dictionary with TPM information, or None if TPM is not available
        """
        if not self.tpm_available or not self.tpm_ctx:
            return None
            
        try:
            # Get TPM properties
            tpm_props = {}
            for prop in [
                tpm.TPM2_PT_MANUFACTURER,
                tpm.TPM2_PT_VENDOR_STRING_1,
                tpm.TPM2_PT_VENDOR_STRING_2,
                tpm.TPM2_PT_FIRMWARE_VERSION_1,
                tpm.TPM2_PT_FIRMWARE_VERSION_2,
            ]:
                prop_data = self.tpm_ctx.get_capability(
                    tpm.TPM2_CAP_TPM_PROPERTIES,
                    prop,
                    1
                )
                if prop_data:
                    tpm_props[prop] = prop_data[0].value
            
            return {
                'type': 'tpm',
                'manufacturer': tpm_props.get(tpm.TPM2_PT_MANUFACTURER, 'Unknown'),
                'vendor': (
                    f"{tpm_props.get(tpm.TPM2_PT_VENDOR_STRING_1, '')} "
                    f"{tpm_props.get(tpm.TPM2_PT_VENDOR_STRING_2, '')}"
                ).strip(),
                'firmware': (
                    f"{tpm_props.get(tpm.TPM2_PT_FIRMWARE_VERSION_1, 0):08x}."
                    f"{tpm_props.get(tpm.TPM2_PT_FIRMWARE_VERSION_2, 0):08x}"
                ),
                'status': 'active' if tpm_props else 'inactive',
                'supported_algorithms': ['RSA', 'ECC']  # TPM 2.0 supports both
            }
            
        except Exception as e:
            logger.warning(f"Failed to get TPM info: {e}")
            return None
    
    def list_tokens(self) -> List[Dict[str, Any]]:
        """
        List available hardware tokens and TPM.
        
        Returns:
            List of dictionaries containing token/TPM information
        """
        tokens = []
        
        # Add TPM if available
        if self.tpm_available:
            tpm_info = self._get_tpm_info()
            if tpm_info:
                tokens.append(tpm_info)
        
        try:
            # Use gpg --card-status to get token information
            result = subprocess.run(
                ['gpg', '--card-status'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to extract token information
            current_token = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Reader'):
                    if current_token:
                        tokens.append(current_token)
                    current_token = {'reader': line.split(':', 1)[1].strip()}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    current_token[key.strip()] = value.strip()
            
            if current_token:
                tokens.append(current_token)
                
            return tokens
            
        except subprocess.CalledProcessError as e:
            raise HardwareTokenError(f"Failed to list hardware tokens: {e.stderr}")
    
    def import_key_from_token(self, keygrip: str) -> str:
        """
        Import a public key from a hardware token.
        
        Args:
            keygrip: The keygrip of the key to import
            
        Returns:
            The fingerprint of the imported key
        """
        try:
            # Export the public key from the token
            result = subprocess.run(
                ['gpg', '--export', '--armor', keygrip],
                capture_output=True,
                text=True,
                check=True
            )
            
            if not result.stdout:
                raise HardwareTokenError("No key found with the specified keygrip")
                
            # Import the key into the keyring
            import_result = self.gpg.import_keys(result.stdout)
            
            if not import_result.fingerprints:
                raise HardwareTokenError("Failed to import key from token")
                
            return import_result.fingerprints[0]
            
        except subprocess.CalledProcessError as e:
            raise HardwareTokenError(f"Failed to import key from token: {e.stderr}")
    
    def sign_with_token(self, message: str, keygrip: str) -> str:
        """
        Sign a message using a key on a hardware token.
        
        Args:
            message: The message to sign
            keygrip: The keygrip of the key to use for signing
            
        Returns:
            The detached signature in ASCII armor format
        """
        try:
            # Create a temporary file for the message
            with tempfile.NamedTemporaryFile(delete=False, mode='w+') as msg_file:
                msg_file.write(message)
                msg_file_path = msg_file.name
                
            # Create a temporary file for the signature
            with tempfile.NamedTemporaryFile(delete=False) as sig_file:
                sig_file_path = sig_file.name
            
            try:
                # Sign the message using the hardware token
                result = subprocess.run(
                    [
                        'gpg',
                        '--detach-sign',
                        '--armor',
                        '--local-user', keygrip,
                        '--output', sig_file_path,
                        msg_file_path
                    ],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Read the signature
                with open(sig_file_path, 'r') as f:
                    signature = f.read()
                    
                return signature
                
            finally:
                # Clean up temporary files
                os.unlink(msg_file_path)
                os.unlink(sig_file_path)
                
        except subprocess.CalledProcessError as e:
            raise HardwareTokenError(f"Failed to sign with hardware token: {e.stderr}")
    
    def verify_with_token(self, message: str, signature: str) -> Tuple[bool, str]:
        """
        Verify a signature using a key on a hardware token.
        
        Args:
            message: The original message that was signed
            signature: The detached signature in ASCII armor format
            
        Returns:
            A tuple of (is_valid, status_message)
        """
        try:
            # Create a temporary file for the message
            with tempfile.NamedTemporaryFile(delete=False, mode='w+') as msg_file:
                msg_file.write(message)
                msg_file_path = msg_file.name
                
            # Create a temporary file for the signature
            with tempfile.NamedTemporaryFile(delete=False, mode='w+') as sig_file:
                sig_file.write(signature)
                sig_file_path = sig_file.name
            
            try:
                # Verify the signature
                result = subprocess.run(
                    [
                        'gpg',
                        '--verify',
                        sig_file_path,
                        msg_file_path
                    ],
                    capture_output=True,
                    text=True
                )
                
                # Check the verification result
                if result.returncode == 0:
                    return True, "Signature is valid"
                else:
                    return False, result.stderr or "Signature verification failed"
                    
            finally:
                # Clean up temporary files
                os.unlink(msg_file_path)
                os.unlink(sig_file_path)
                
        except Exception as e:
            raise HardwareTokenError(f"Failed to verify signature with hardware token: {str(e)}")
    


def detect_hardware_token() -> bool:
    """
    Check if a hardware token or TPM is available.
    
    Returns:
        bool: True if a hardware token or TPM is detected, False otherwise
    """
    # Check for TPM
    if TPM_SUPPORT:
        try:
            with tpm.ESYS() as ctx:
                # Try to get TPM properties
                ctx.get_capability(
                    tpm.TPM2_CAP_TPM_PROPERTIES,
                    tpm.TPM2_PT_MANUFACTURER,
                    1
                )
                return True
        except Exception:
            pass

    # Check for smart card
    try:
        result = subprocess.run(
            ['gpg', '--card-status'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
