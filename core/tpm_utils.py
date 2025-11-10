"""
TPM (Trusted Platform Module) utility functions.
"""
import platform
import subprocess
import sys
from typing import Optional, Dict, Any, List
import logging
import os

logger = logging.getLogger(__name__)

def check_tpm_requirements() -> Dict[str, Any]:
    """
    Check if the system meets TPM requirements.
    
    Returns:
        Dict containing TPM status information
    """
    result = {
        'system': platform.system(),
        'tpm_available': False,
        'dependencies_met': False,
        'missing_dependencies': [],
        'tpm_version': None,
        'python_package_available': False,
        'tpm_tools_available': False
    }
    
    # Check Python package
    try:
        import tpm2_pytss  # noqa: F401
        result['python_package_available'] = True
    except ImportError:
        result['missing_dependencies'].append('tpm2-pytss')
    
    # Platform-specific checks
    if platform.system() == 'Windows':
        result.update(_check_windows_tpm())
    elif platform.system() == 'Linux':
        result.update(_check_linux_tpm())
    
    # Check if all dependencies are met
    result['dependencies_met'] = all([
        result['python_package_available'],
        result['tpm_tools_available'] or platform.system() == 'Windows',
        not result['missing_dependencies']
    ])
    
    return result

def _check_windows_tpm() -> Dict[str, Any]:
    """Check TPM status on Windows."""
    result = {
        'tpm_available': False,
        'tpm_version': None,
        'tpm_tools_available': True  # Windows has built-in TPM tools
    }
    
    try:
        # Check TPM using Windows Management Instrumentation (WMI)
        import wmi  # type: ignore[import]
        c = wmi.WMI()
        tpm = c.Win32_Tpm()
        
        if tpm:
            result['tpm_available'] = True
            result['tpm_version'] = tpm[0].SpecVersion if hasattr(tpm[0], 'SpecVersion') else '1.2+'
    except Exception as e:
        logger.warning("Error checking Windows TPM: %s", e)
    
    return result

def _check_linux_tpm() -> Dict[str, Any]:
    """Check TPM status on Linux."""
    result = {
        'tpm_available': False,
        'tpm_version': None,
        'tpm_tools_available': False,
        'missing_dependencies': []
    }
    
    # Check for TPM device
    try:
        if os.path.exists('/dev/tpm0') or os.path.exists('/dev/tpmrm0'):
            result['tpm_available'] = True
            
            # Try to get TPM version
            try:
                with open('/sys/class/tpm/tpm0/tpm_version_major', 'r', encoding='utf-8') as f:
                    major = f.read().strip()
                    result['tpm_version'] = f"{major}.0"
            except (IOError, FileNotFoundError):
                result['tpm_version'] = '1.2 or 2.0'
    except Exception as e:
        logger.warning("Error checking Linux TPM: %s", e)
    
    # Check for TPM tools
    try:
        result['tpm_tools_available'] = (
            subprocess.run(
                ['which', 'tpm2_getrandom'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            ).returncode == 0
        )
        if not result['tpm_tools_available']:
            result['missing_dependencies'].append('tpm2-tools')
    except Exception as e:
        logger.warning("Error checking TPM tools: %s", e)
    
    return result

def get_tpm_status_message() -> str:
    """Get a user-friendly message about TPM status."""
    status = check_tpm_requirements()
    
    if not status['tpm_available']:
        return "TPM not detected on this system."
    
    messages = [f"TPM {status.get('tpm_version', '')} detected."]
    
    if not status['dependencies_met']:
        messages.append("Some TPM dependencies are missing:")
        if not status['python_package_available']:
            messages.append("- Python package: tpm2-pytss")
        if not status['tpm_tools_available'] and platform.system() == 'Linux':
            messages.append("- System package: tpm2-tools")
    
    return "\n".join(messages)
