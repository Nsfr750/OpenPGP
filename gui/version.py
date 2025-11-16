"""
Version information for OpenPGP.
"""

# Version as a tuple (major, minor, patch)
VERSION = (2, 1, 0)

# String version
__version__ = ".".join(map(str, VERSION))

# Detailed version information
__status__ = "stable"
__author__ = "Nsfr750"
__maintainer__ = "Nsfr750"
__organization__ = 'Tuxxle'
__copyright__ = '© 2024-2025 Nsfr750 - All Rights Reserved'
__email__ = "nsfr750@yandex.com"
__license__ = "GPL-3.0"

# Build information
__build__ = ""
__date__ = "2025-11-10"

# Version description
__description__ = "A modern PySide6-based graphical user interface for OpenPGP with enhanced encryption, key management, and security features."

# Dependencies
__requires__ = [
    "PySide6>=6.4.0",
    "PGPy>=0.6.0",
    "cryptography>=3.4.0",
    "pyperclip>=1.8.2",
    "wand>=0.6.10",
    "python-gnupg>=0.5.0",
    "pycryptodome>=3.12.0",
    "argon2-cffi>=21.3.0"
]

# Version as a tuple for comparison
version_info = tuple(map(int, __version__.split('.')))

# Changelog
__changelog__ = """
## [2.1.0] - 2025-11-10
### Added
- Support for ECC and Ed25519 key generation
- Hardware token support (YubiKey and compatible devices)
- Drag and drop functionality for files and keys
- Enhanced passphrase strength indicators
- Key backup and recovery options
- Key expiration and revocation support
- Modernized interface with improved theming
- Better keyboard navigation and shortcuts
- File encryption/decryption support
- Message signing and verification
- Multiple language support

### Improved
- Faster key generation and operations
- Reduced memory usage
- Enhanced error handling and recovery
- Better cross-platform compatibility
- Improved key import/export functionality
- More intuitive user interface
- Comprehensive tooltips and help documentation

## [2.0.0] - 2025-10-30
### Added
- Migrated UI from tkinter/ttkbootstrap to PySide6
- Added dark theme support with consistent styling
- Enhanced password generation and hashing features
- Improved PGP key management interface
- Added comprehensive logging system
- Improved error handling and user feedback

## [1.0.0] - 2025-09-25
### Added
- Initial release
"""

def get_version():
    """Return the current version as a string."""
    return __version__

def get_version_info():
    """Return the version as a tuple for comparison."""
    return VERSION

def get_version_history():
    """Return the version history."""
    return [
        {
            "version": "2.1.0",
            "date": "2025-11-10",
            "changes": [
                "Added support for ECC and Ed25519 key generation",
                "Implemented hardware token support (YubiKey and compatible devices)",
                "Added drag and drop functionality for files and keys",
                "Enhanced passphrase strength indicators",
                "Added key backup and recovery options",
                "Implemented key expiration and revocation support",
                "Modernized interface with improved theming and navigation",
                "Added file encryption/decryption support",
                "Implemented message signing and verification",
                "Added multiple language support",
                "Improved performance and memory usage",
                "Enhanced error handling and recovery"
            ]
        },
        {
            "version": "2.0.0",
            "date": "2025-10-30",
            "changes": [
                "Migrated UI from tkinter/ttkbootstrap to PySide6",
                "Added dark theme support with consistent styling",
                "Enhanced password generation and hashing features",
                "Improved PGP key management interface",
                "Added comprehensive logging system",
                "Improved error handling and user feedback"
            ]
        },
        {
            "version": "1.0.0",
            "date": "2025-09-25",
            "changes": [
                "Initial release with basic PGP functionality"
            ]
        }
    ]

def get_latest_changes():
    """Get the changes in the latest version."""
    if get_version_history():
        return get_version_history()[0]['changes']
    return []

def is_development():
    """Check if this is a development version."""
    return "dev" in __version__ or "a" in __version__ or "b" in __version__

def get_codename():
    """Get the codename for this version."""
    # Simple codename based on version number
    major, minor, patch = VERSION
    codenames = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel"]
    return codenames[minor % len(codenames)]
