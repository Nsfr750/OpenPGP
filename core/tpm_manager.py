"""
TPM 2.0 Manager for OpenPGP

This module provides comprehensive TPM 2.0 support including:
- Secure key storage and management
- TPM-based encryption/decryption
- Platform attestation
- Sealed storage
"""
import platform
import logging
import hashlib
import json
from typing import Optional, Dict, Any, Tuple, Union, List
from pathlib import Path

# Try to import TPM libraries
try:
    import tpm2_pytss as tpm2
    from tpm2_pytss import TCTI, TPMT_PUBLIC, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPM2B_PRIVATE
    from tpm2_pytss.types import TPM2_ALG, TPM2_RH, TPM2_CC, TPM2B_DATA, TPM2B_PUBLIC
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("TPM 2.0 libraries not available. TPM features will be disabled.")

class TPMKey:
    """Represents a key stored in the TPM."""
    
    def __init__(self, public_blob: bytes, private_blob: bytes, key_type: str, key_name: str):
        """
        Initialize a TPM key.
        
        Args:
            public_blob: The public portion of the key
            private_blob: The private portion of the key (encrypted by the TPM)
            key_type: Type of key (e.g., 'RSA', 'ECC', 'AES')
            key_name: User-friendly name for the key
        """
        self.public_blob = public_blob
        self.private_blob = private_blob
        self.key_type = key_type
        self.key_name = key_name
        self.loaded_handle = None

class TPMManager:
    """Manages TPM 2.0 operations for OpenPGP."""
    
    def __init__(self, tcti: Optional[str] = None):
        """
        Initialize the TPM manager.
        
        Args:
            tcti: TPM Command Transmission Interface (default: platform-specific)
        """
        self.ctx = None
        self._initialize_tpm(tcti)
        self._keys: Dict[str, TPMKey] = {}
        self._sessions = {}
        
    def _initialize_tpm(self, tcti: Optional[str] = None) -> None:
        """Initialize the TPM context."""
        if not TPM_AVAILABLE:
            raise RuntimeError("TPM 2.0 is not available on this system")
            
        try:
            if tcti is None:
                if platform.system() == 'Windows':
                    tcti = 'tbs'
                else:
                    tcti = 'device:/dev/tpmrm0'
                    
            self.ctx = tpm2.ESAPI(tcti)
            logger.info("TPM 2.0 initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize TPM: {str(e)}")
            raise RuntimeError(f"TPM initialization failed: {str(e)}")
    
    def is_available(self) -> bool:
        """Check if TPM is available and accessible."""
        try:
            if not TPM_AVAILABLE:
                return False
                
            # Try to read the TPM's random number generator
            self.ctx.get_random(1)
            return True
            
        except Exception:
            return False
    
    def create_primary_key(self, hierarchy: str = 'owner', key_type: str = 'RSA', 
                         key_bits: int = 2048, key_auth: Optional[str] = None) -> TPMKey:
        """
        Create a primary key in the TPM.
        
        Args:
            hierarchy: The hierarchy to create the key in ('owner', 'endorsement', 'platform', 'null')
            key_type: Type of key to create ('RSA', 'ECC')
            key_bits: Key size in bits
            key_auth: Optional authorization value for the key
            
        Returns:
            TPMKey: The created key
        """
        if not self.ctx:
            raise RuntimeError("TPM not initialized")
            
        # Map hierarchy to TPM handle
        hierarchy_map = {
            'owner': TPM2_RH.OWNER,
            'endorsement': TPM2_RH.ENDORSEMENT,
            'platform': TPM2_RH.PLATFORM,
            'null': TPM2_RH.NULL
        }
        hierarchy_handle = hierarchy_map.get(hierarchy.lower(), TPM2_RH.OWNER)
        
        # Configure key parameters
        if key_type.upper() == 'RSA':
            if key_bits not in [1024, 2048, 3072, 4096]:
                raise ValueError("RSA key size must be 1024, 2048, 3072, or 4096 bits")
                
            public = TPM2B_PUBLIC(
                publicArea=TPMT_PUBLIC(
                    type=TPM2_ALG.RSA,
                    nameAlg=TPM2_ALG.SHA256,
                    objectAttributes=(
                        tpm2.types.TPMA_OBJECT.FIXEDTPM |
                        tpm2.types.TPMA_OBJECT.FIXEDPARENT |
                        tpm2.types.TPMA_OBJECT.SIGN_ENCRYPT |
                        tpm2.types.TPMA_OBJECT.USERWITHAUTH |
                        tpm2.types.TPMA_OBJECT.SENSITIVEDATAORIGIN
                    ),
                    parameters=tpm2.types.TPMS_RSA_PARMS(
                        symmetric=tpm2.types.TPMT_SYM_DEF_OBJECT(
                            algorithm=TPM2_ALG.NULL
                        ),
                        scheme=tpm2.types.TPMT_RSA_SCHEME(
                            scheme=TPM2_ALG.RSASSA,
                            details=tpm2.types.TPMU_ASYM_SCHEME(
                                rsassa=tpm2.types.TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA256)
                            )
                        ),
                        keyBits=key_bits,
                        exponent=65537
                    )
                )
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Create the primary key
        try:
            auth = TPM2B_SENSITIVE_CREATE()
            if key_auth:
                auth.sensitive.userAuth = key_auth.encode()
                
            result = self.ctx.create_primary(
                hierarchy_handle,
                auth,
                public,
                None,
                []
            )
            
            # Create a TPMKey object
            key = TPMKey(
                public_blob=result.outPublic,
                private_blob=result.outPrivate,
                key_type=key_type,
                key_name=f"{key_type}_{key_bits}"
            )
            
            # Store the key handle
            key.loaded_handle = result.objectHandle
            
            # Flush the context to free the handle
            self.ctx.flush_context(result.objectHandle)
            
            return key
            
        except Exception as e:
            logger.error(f"Failed to create primary key: {str(e)}")
            raise
    
    def seal_data(self, data: bytes, auth_value: Optional[str] = None) -> Dict[str, bytes]:
        """
        Seal data to the TPM.
        
        Args:
            data: The data to seal
            auth_value: Optional authorization value
            
        Returns:
            Dict containing the sealed data and related information
        """
        if not self.ctx:
            raise RuntimeError("TPM not initialized")
            
        try:
            # Create a primary key for sealing
            primary = self.create_primary_key('null', 'RSA', 2048)
            
            # Create a sealing object
            in_sensitive = tpm2.types.TPM2B_SENSITIVE_CREATE()
            if auth_value:
                in_sensitive.sensitive.userAuth = auth_value.encode()
                
            # Seal the data
            result = self.ctx.create(
                primary.loaded_handle,
                in_sensitive,
                tpm2.types.TPM2B_PUBLIC(
                    publicArea=tpm2.types.TPMT_PUBLIC(
                        type=TPM2_ALG.KEYEDHASH,
                        nameAlg=TPM2_ALG.SHA256,
                        objectAttributes=(
                            tpm2.types.TPMA_OBJECT.FIXEDTPM |
                            tpm2.types.TPMA_OBJECT.FIXEDPARENT |
                            tpm2.types.TPMA_OBJECT.USERWITHAUTH
                        ),
                        parameters=tpm2.types.TPMS_KEYEDHASH_PARMS(
                            scheme=tpm2.types.TPMT_KEYEDHASH_SCHEME(
                                scheme=TPM2_ALG.NULL
                            )
                        )
                    )
                ),
                tpm2.types.TPM2B_DATA(data),
                []
            )
            
            return {
                'public': result.outPublic,
                'private': result.outPrivate,
                'encrypted_data': result.outData,
                'primary_public': primary.public_blob,
                'primary_private': primary.private_blob
            }
            
        except Exception as e:
            logger.error(f"Failed to seal data: {str(e)}")
            raise
    
    def unseal_data(self, sealed_data: Dict[str, bytes], auth_value: Optional[str] = None) -> bytes:
        """
        Unseal data from the TPM.
        
        Args:
            sealed_data: The sealed data from seal_data()
            auth_value: Optional authorization value
            
        Returns:
            The unsealed data
        """
        if not self.ctx:
            raise RuntimeError("TPM not initialized")
            
        try:
            # Load the primary key
            primary_public = tpm2.types.TPM2B_PUBLIC(sealed_data['primary_public'])
            primary_private = tpm2.types.TPM2B_PRIVATE(sealed_data['primary_private'])
            
            primary_handle = self.ctx.load(
                TPM2_RH.NULL,
                primary_private,
                primary_public
            )
            
            # Load the sealed data object
            sealed_public = tpm2.types.TPM2B_PUBLIC(sealed_data['public'])
            sealed_private = tpm2.types.TPM2B_PRIVATE(sealed_data['private'])
            
            sealed_handle = self.ctx.load(
                primary_handle,
                sealed_private,
                sealed_public
            )
            
            # Unseal the data
            result = self.ctx.unseal(
                sealed_handle,
                auth_value.encode() if auth_value else None
            )
            
            # Clean up
            self.ctx.flush_context(sealed_handle)
            self.ctx.flush_context(primary_handle)
            
            return bytes(result.outData.buffer)
            
        except Exception as e:
            logger.error(f"Failed to unseal data: {str(e)}")
            raise
    
    def get_tpm_info(self) -> Dict[str, Any]:
        """
        Get information about the TPM.
        
        Returns:
            Dict containing TPM information
        """
        if not self.ctx:
            raise RuntimeError("TPM not initialized")
            
        try:
            # Get TPM properties
            properties = self.ctx.get_capability(
                TPM2_CAP.TPM_PROPERTIES,
                TPM2_PT.TOTAL_COMMANDS,
                1
            )
            
            # Get TPM version
            version = self.ctx.get_capability(
                TPM2_CAP.TPM_PROPERTIES,
                TPM2_PT.FAMILY_INDICATOR,
                1
            )
            
            return {
                'manufacturer': self._get_tpm_manufacturer(),
                'firmware_version': self._get_tpm_firmware_version(),
                'spec_version': '2.0',
                'properties': properties,
                'version': version
            }
            
        except Exception as e:
            logger.error(f"Failed to get TPM info: {str(e)}")
            return {}
    
    def _get_tpm_manufacturer(self) -> str:
        """Get the TPM manufacturer ID."""
        if not self.ctx:
            return "Unknown"
            
        try:
            # Get the TPM manufacturer ID
            manufacturer_id = self.ctx.get_capability(
                TPM2_CAP.TPM_PROPERTIES,
                TPM2_PT.MANUFACTURER,
                1
            )
            
            # Convert to ASCII
            if manufacturer_id and hasattr(manufacturer_id, 'tpmProperty'):
                prop = manufacturer_id.tpmProperty[0].value
                return f"{chr((prop >> 24) & 0xFF)}{chr((prop >> 16) & 0xFF)}{chr((prop >> 8) & 0xFF)}{chr(prop & 0xFF)}"
                
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def _get_tpm_firmware_version(self) -> str:
        """Get the TPM firmware version."""
        if not self.ctx:
            return "0.0.0.0"
            
        try:
            # Get the TPM firmware version
            fw_ver = self.ctx.get_capability(
                TPM2_CAP.TPM_PROPERTIES,
                TPM2_PT.FIRMWARE_VERSION_1,
                2
            )
            
            if fw_ver and hasattr(fw_ver, 'tpmProperty') and len(fw_ver.tpmProperty) >= 2:
                ver1 = fw_ver.tpmProperty[0].value
                ver2 = fw_ver.tpmProperty[1].value
                return f"{(ver1 >> 16) & 0xFFFF}.{ver1 & 0xFFFF}.{(ver2 >> 16) & 0xFFFF}.{ver2 & 0xFFFF}"
                
            return "0.0.0.0"
            
        except Exception:
            return "0.0.0.0"

# Singleton instance
_tpm_manager = None

def get_tpm_manager() -> TPMManager:
    """
    Get the global TPM manager instance.
    
    Returns:
        TPMManager: The TPM manager instance
    """
    global _tpm_manager
    if _tpm_manager is None and TPM_AVAILABLE:
        try:
            _tpm_manager = TPMManager()
        except Exception as e:
            logger.error(f"Failed to initialize TPM manager: {str(e)}")
            _tpm_manager = None
    return _tpm_manager
