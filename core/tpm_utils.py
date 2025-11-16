"""
TPM (Trusted Platform Module) utility functions with enhanced Windows TPM 2.0 support.
"""
import platform
import subprocess
import sys
import ctypes
import os
import logging
from typing import Optional, Dict, Any, List, Tuple, Union
from pathlib import Path

# Try to import TPM libraries
try:
    import tpm2_pytss as tpm2
    from tpm2_pytss.types import TPM2_ALG, TPM2_RH, TPM2_CC, TPM2B_PUBLIC
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False

logger = logging.getLogger(__name__)

# Windows TBS (TPM Base Services) constants
TBS_SUCCESS = 0x00000000
TBS_CONTEXT_VERSION_ONE = 1
TBS_TCGLOG_DRIVER_CONFIG = 0x00000001
TBS_TCGLOG_SERVICES_DRIVER = 0x00000002
TBS_TCGLOG_SERVICES_TCG = 0x00000004
TBS_TCGLOG_SERVICES_ALL = 0x00000007

# Windows TBS structures
class TBS_CONTEXT_PARAMS(ctypes.Structure):
    _fields_ = [("version", ctypes.c_ulong)]

class TBS_CONTEXT_PARAMS2(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_ulong),
        ("includeTpm12", ctypes.c_ulong),
        ("includeTpm20", ctypes.c_ulong),
    ]

# Load Windows TBS DLL
try:
    if platform.system() == 'Windows':
        tbs = ctypes.WinDLL('Tbs')
        TBS_AVAILABLE = True
    else:
        TBS_AVAILABLE = False
except Exception as e:
    logger.warning(f"Failed to load TBS DLL: {str(e)}")
    TBS_AVAILABLE = False

def check_tpm_requirements() -> Dict[str, Any]:
    """
    Check if the system meets TPM requirements with enhanced Windows TPM 2.0 support.
    
    Returns:
        Dict containing detailed TPM status information
    """
    result = {
        'system': platform.system(),
        'tpm_available': False,
        'tpm_version': None,
        'tpm2_supported': False,
        'dependencies_met': False,
        'missing_dependencies': [],
        'python_package_available': TPM_AVAILABLE,
        'tpm_tools_available': False,
        'tpm_details': {},
        'windows_tbs_available': TBS_AVAILABLE if platform.system() == 'Windows' else False,
        'tpm_manufacturer': None,
        'tpm_firmware_version': None,
        'tpm_spec_family': None,
        'tpm_spec_level': None,
        'tpm_spec_revision': None
    }
    
    if not TPM_AVAILABLE:
        result['missing_dependencies'].append('tpm2-pytss')
    
    # Platform-specific checks
    if platform.system() == 'Windows':
        result.update(_check_windows_tpm())
    elif platform.system() == 'Linux':
        result.update(_check_linux_tpm())
    
    # Additional TPM details if available
    if result['tpm_available'] and TPM_AVAILABLE:
        try:
            from .tpm_manager import get_tpm_manager
            tpm = get_tpm_manager()
            if tpm and tpm.is_available():
                tpm_info = tpm.get_tpm_info()
                result['tpm_details'] = tpm_info
                
                # Extract manufacturer and version if available
                if 'manufacturer' in tpm_info:
                    result['tpm_manufacturer'] = tpm_info['manufacturer']
                if 'firmware_version' in tpm_info:
                    result['tpm_firmware_version'] = tpm_info['firmware_version']
                    
                    # Parse TPM spec info from firmware version
                    try:
                        parts = result['tpm_firmware_version'].split('.')
                        if len(parts) >= 4:
                            result['tpm_spec_family'] = f"{parts[0]}.{parts[1]}"
                            result['tpm_spec_level'] = int(parts[2])
                            result['tpm_spec_revision'] = int(parts[3])
                    except (ValueError, IndexError):
                        pass
                        
        except Exception as e:
            logger.warning(f"Failed to get detailed TPM info: {str(e)}")
    
    # Check if all dependencies are met
    result['dependencies_met'] = all([
        result['python_package_available'],
        result.get('windows_tbs_available', False) or platform.system() != 'Windows',
        not result['missing_dependencies']
    ])
    
    return result

def _check_windows_tpm() -> Dict[str, Any]:
    """
    Check TPM status on Windows with enhanced TPM 2.0 support.
    
    Returns:
        Dict containing detailed Windows TPM status
    """
    result = {
        'tpm_available': False,
        'tpm_version': None,
        'tpm2_supported': False,
        'tpm_tools_available': TBS_AVAILABLE,
        'tpm_manufacturer': None,
        'tpm_firmware_version': None,
        'tbs_available': TBS_AVAILABLE,
        'wmi_details': {}
    }
    
    # First, try WMI for basic TPM info
    try:
        import wmi  # type: ignore[import]
        c = wmi.WMI()
        tpm = c.Win32_Tpm()
        
        if tpm:
            result['tpm_available'] = True
            tpm_obj = tpm[0]
            
            # Get TPM version
            if hasattr(tpm_obj, 'SpecVersion'):
                spec_version = tpm_obj.SpecVersion
                result['tpm_version'] = spec_version
                
                # Check for TPM 2.0
                if spec_version and '2.0' in spec_version:
                    result['tpm2_supported'] = True
                    
                    # Get TPM manufacturer and firmware version if available
                    if hasattr(tpm_obj, 'Manufacturer'):
                        manufacturer_id = tpm_obj.Manufacturer
                        if manufacturer_id:
                            # Convert manufacturer ID to string (4 characters)
                            try:
                                result['tpm_manufacturer'] = ''.join(
                                    chr((manufacturer_id >> (8 * i)) & 0xFF) 
                                    for i in range(3, -1, -1)
                                ).strip('\x00')
                            except (TypeError, ValueError):
                                pass
                    
                    if hasattr(tpm_obj, 'SpecVersionInfo'):
                        result['tpm_spec_info'] = tpm_obj.SpecVersionInfo
                        
                    # Get firmware version if available
                    if hasattr(tpm_obj, 'Manufacturer') and hasattr(tpm_obj, 'FirmwareVersion'):
                        try:
                            fw_version = tpm_obj.FirmwareVersion
                            if fw_version:
                                # Format as major.minor.rev.build
                                major = (fw_version >> 48) & 0xFFFF
                                minor = (fw_version >> 32) & 0xFFFF
                                rev_major = (fw_version >> 16) & 0xFFFF
                                rev_minor = fw_version & 0xFFFF
                                result['tpm_firmware_version'] = f"{major}.{minor}.{rev_major}.{rev_minor}"
                        except Exception:
                            pass
            
            # Store raw WMI properties for debugging
            result['wmi_details'] = {prop: getattr(tpm_obj, prop) 
                                   for prop in dir(tpm_obj) 
                                   if not prop.startswith('_') and not callable(getattr(tpm_obj, prop))}
    
    except ImportError:
        logger.warning("WMI module not available, falling back to TBS API")
    except Exception as e:
        logger.warning(f"Error checking Windows TPM via WMI: {str(e)}")
    
    # If WMI failed or TPM not found, try TBS API
    if not result['tpm_available'] and TBS_AVAILABLE:
        try:
            # Try to open a TBS context
            context = ctypes.c_void_p()
            params = TBS_CONTEXT_PARAMS()
            params.version = TBS_CONTEXT_VERSION_ONE
            
            # First try TPM 2.0
            if hasattr(tbs, 'Tbsi_Context_Create'):
                params2 = TBS_CONTEXT_PARAMS2()
                params2.version = 2
                params2.includeTpm12 = 0  # Only TPM 2.0
                params2.includeTpm20 = 1
                
                tbs.Tbsi_Context_Create.argtypes = [
                    ctypes.POINTER(ctypes.c_ulong),
                    ctypes.POINTER(ctypes.c_void_p)
                ]
                
                tbs.Tbsi_Context_Create.restype = ctypes.c_ulong
                
                result_code = tbs.Tbsi_Context_Create(
                    ctypes.byref(ctypes.c_ulong(2)),  # TBS_CONTEXT_VERSION_TWO
                    ctypes.byref(context)
                )
                
                if result_code == TBS_SUCCESS:
                    result['tpm_available'] = True
                    result['tpm2_supported'] = True
                    result['tpm_version'] = '2.0'
                    
                    # Try to get TPM manufacturer
                    try:
                        manufacturer = ctypes.c_uint32()
                        manufacturer_size = ctypes.c_uint32(ctypes.sizeof(manufacturer))
                        
                        tbs.Tbsi_Get_TCG_Log_Ex.argtypes = [
                            ctypes.c_void_p,
                            ctypes.c_ulong,
                            ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_uint32)
                        ]
                        
                        tbs.Tbsi_Get_TCG_Log_Ex.restype = ctypes.c_ulong
                        
                        result_code = tbs.Tbsi_Get_TCG_Log_Ex(
                            context,
                            TBS_TCGLOG_SERVICES_TCG,
                            ctypes.byref(manufacturer),
                            ctypes.byref(manufacturer_size)
                        )
                        
                        if result_code == TBS_SUCCESS:
                            # Convert manufacturer ID to string (4 characters)
                            manufacturer_id = manufacturer.value
                            result['tpm_manufacturer'] = ''.join(
                                chr((manufacturer_id >> (8 * i)) & 0xFF) 
                                for i in range(3, -1, -1)
                            ).strip('\x00')
                    
                    except Exception as e:
                        logger.warning(f"Failed to get TPM manufacturer: {str(e)}")
                    
                    # Clean up
                    tbs.Tbsip_Context_Close.argtypes = [ctypes.c_void_p]
                    tbs.Tbsip_Context_Close.restype = ctypes.c_ulong
                    tbs.Tbsip_Context_Close(context)
        
        except Exception as e:
            logger.warning(f"Error checking Windows TPM via TBS: {str(e)}")
    
    return result

def _check_linux_tpm() -> Dict[str, Any]:
    """
    Check TPM status on Linux with enhanced TPM 2.0 support.
    
    Returns:
        Dict containing detailed Linux TPM status
    """
    result = {
        'tpm_available': False,
        'tpm_version': None,
        'tpm2_supported': False,
        'tpm_tools_available': False,
        'missing_dependencies': [],
        'tpm_devices': [],
        'tpm2_tools': {}
    }
    
    # Check for TPM devices
    try:
        tpm_devices = []
        tpm_base = Path('/sys/class/tpm')
        
        if tpm_base.exists():
            for tpm_dir in tpm_base.iterdir():
                if tpm_dir.is_dir() and tpm_dir.name.startswith('tpm'):
                    device_info = {
                        'device': tpm_dir.name,
                        'path': str(tpm_dir),
                        'version': None,
                        'active': False,
                        'enabled': True,
                        'owned': False
                    }
                    
                    # Check device status
                    active_path = tpm_dir / 'active'
                    enabled_path = tpm_dir / 'enabled'
                    owned_path = tpm_dir / 'owned'
                    
                    if active_path.exists():
                        try:
                            with open(active_path, 'r', encoding='utf-8') as f:
                                device_info['active'] = f.read().strip() == '1'
                        except (IOError, ValueError):
                            pass
                    
                    if enabled_path.exists():
                        try:
                            with open(enabled_path, 'r', encoding='utf-8') as f:
                                device_info['enabled'] = f.read().strip() == '1'
                        except (IOError, ValueError):
                            pass
                    
                    if owned_path.exists():
                        try:
                            with open(owned_path, 'r', encoding='utf-8') as f:
                                device_info['owned'] = f.read().strip() == '1'
                        except (IOError, ValueError):
                            pass
                    
                    # Get TPM version
                    version_major = tpm_dir / 'tpm_version_major'
                    version_minor = tpm_dir / 'tpm_version_minor'
                    
                    if version_major.exists():
                        try:
                            with open(version_major, 'r', encoding='utf-8') as f:
                                major = f.read().strip()
                                device_info['version'] = f"{major}.0"
                                
                                if major == '2':
                                    result['tpm2_supported'] = True
                                    
                                    # Get more details for TPM 2.0
                                    caps_path = tpm_dir / 'caps'
                                    if caps_path.exists():
                                        try:
                                            with open(caps_path, 'r', encoding='utf-8') as f:
                                                device_info['capabilities'] = f.read().strip()
                                        except (IOError, ValueError):
                                            pass
                            
                            if version_minor.exists():
                                try:
                                    with open(version_minor, 'r', encoding='utf-8') as f:
                                        minor = f.read().strip()
                                        device_info['version'] = f"{major}.{minor}"
                                except (IOError, ValueError):
                                    pass
                                    
                        except (IOError, ValueError):
                            pass
                    
                    tpm_devices.append(device_info)
        
        result['tpm_devices'] = tpm_devices
        result['tpm_available'] = any(dev['active'] and dev['enabled'] for dev in tpm_devices)
        
        # Set the highest available TPM version
        versions = [dev['version'] for dev in tpm_devices if dev.get('version')]
        if versions:
            result['tpm_version'] = max(versions)
    
    except Exception as e:
        logger.warning(f"Error checking Linux TPM devices: {str(e)}")
    
    # Check for TPM 2.0 tools
    try:
        tpm2_tools = {}
        
        # Check for tpm2-tools
        try:
            tpm2_tools_ver = subprocess.check_output(
                ['tpm2_getcap', '--version'],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            ).strip()
            tpm2_tools['tpm2-tools'] = tpm2_tools_ver.split('\n')[0].split()[-1]
        except (subprocess.CalledProcessError, FileNotFoundError):
            result['missing_dependencies'].append('tpm2-tools')
        
        # Check for tpm2-tss
        try:
            tpm2_tss_ver = subprocess.check_output(
                ['pkg-config', '--modversion', 'tss2-esys'],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            ).strip()
            tpm2_tools['tpm2-tss'] = tpm2_tss_ver
        except (subprocess.CalledProcessError, FileNotFoundError):
            result['missing_dependencies'].append('tpm2-tss')
        
        # Check for tpm2-abrmd (optional)
        try:
            tpm2_abrmd_ver = subprocess.check_output(
                ['tpm2_abrmd', '--version'],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            ).strip()
            tpm2_tools['tpm2-abrmd'] = tpm2_abrmd_ver.split()[-1]
        except (subprocess.CalledProcessError, FileNotFoundError):
            # tpm2-abrmd is optional
            pass
        
        result['tpm2_tools'] = tpm2_tools
        result['tpm_tools_available'] = len(tpm2_tools) >= 2  # At least tpm2-tools and tpm2-tss
        
    except Exception as e:
        logger.warning(f"Error checking TPM 2.0 tools: {str(e)}")
        result['missing_dependencies'].extend(['tpm2-tools', 'tpm2-tss'])
    
    return result

def get_tpm_status_message() -> str:
    """
    Get a detailed, user-friendly message about TPM status.
    
    Returns:
        str: Formatted status message
    """
    status = check_tpm_requirements()
    lines = []
    
    # Basic TPM status
    if status['tpm_available']:
        lines.append("✅ TPM is available")
        lines.append(f"  • Version: {status.get('tpm_version', 'Unknown')}")
        
        # Show TPM 2.0 specific info
        if status.get('tpm2_supported', False):
            lines.append("  • TPM 2.0: Supported")
            
            # Show manufacturer and firmware version if available
            if status.get('tpm_manufacturer'):
                lines.append(f"  • Manufacturer: {status['tpm_manufacturer']}")
            
            if status.get('tpm_firmware_version'):
                lines.append(f"  • Firmware: {status['tpm_firmware_version']}")
            
            # Show TPM spec info if available
            spec_parts = []
            if 'tpm_spec_family' in status:
                spec_parts.append(f"Family {status['tpm_spec_family']}")
            if 'tpm_spec_level' in status:
                spec_parts.append(f"Level {status['tpm_spec_level']}")
            if 'tpm_spec_revision' in status:
                spec_parts.append(f"Rev {status['tpm_spec_revision']}")
                
            if spec_parts:
                lines.append(f"  • Spec: {' '.join(spec_parts)}")
    else:
        lines.append("❌ TPM is not available or not enabled")
    
    # Dependencies status
    if status.get('dependencies_met'):
        lines.append("✅ All dependencies are installed")
    else:
        lines.append("❌ Missing dependencies: " + ", ".join(status.get('missing_dependencies', [])))
    
    # Platform-specific details
    if platform.system() == 'Windows':
        if status.get('windows_tbs_available', False):
            lines.append("✅ Windows TPM Base Services (TBS) is available")
        else:
            lines.append("❌ Windows TPM Base Services (TBS) is not available")
    
    # TPM tools status
    if status.get('tpm2_supported', False):
        if status.get('tpm_tools_available', False):
            lines.append("✅ TPM 2.0 tools are available")
            
            # List available tools
            if 'tpm2_tools' in status and status['tpm2_tools']:
                lines.append("  • Installed tools:")
                for tool, version in status['tpm2_tools'].items():
                    lines.append(f"    - {tool}: {version}")
        else:
            lines.append("❌ TPM 2.0 tools are not fully installed")
    
    # Add any additional details
    if 'wmi_details' in status and status['wmi_details']:
        lines.append("\nAdditional TPM details:")
        for key, value in status['wmi_details'].items():
            if not key.startswith('_') and not callable(value):
                lines.append(f"  • {key}: {value}")
    
    return "\n".join(lines)
