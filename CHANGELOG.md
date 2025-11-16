# Changelog

## [2.2.0] - 2025-11-17

### 🚀 New Features

#### 🔌 SIEM Integration
- Added SIEM client for security event monitoring
- Implemented secure connection to SIEM servers
- Added support for API key authentication
- Real-time security event logging

#### 🔄 SCIM 2.0 Server
- Implemented SCIM 2.0 protocol support
- Added user and group provisioning
- Support for OAuth2 and API key authentication
- Built-in service provider configuration

#### 🛠️ System Management
- Added server management interface
- Improved error handling and logging
- Enhanced security controls

### 🐛 Bug Fixes
- Fixed keyring initialization issues
- Resolved TPM detection warnings
- Improved error messages and user feedback

## [2.1.0] - 2025-11-10

### 🚀 New Features

#### 🔑 Enhanced Key Management

- Added support for blockchain-based identity verification
- Implemented secure key sharing with fine-grained permissions
- Added hardware token support (YubiKey and compatible devices)
- Enhanced key backup and recovery options
- Added key expiration and revocation support

#### 🔒 Advanced Security

- Implemented end-to-end encryption for files and messages
- Added secure file sharing with access control
- Enhanced passphrase strength indicators
- Improved secure key storage with hardware protection
- Added support for multiple encryption algorithms

#### 🖥️ Modern Interface

- Redesigned UI with dark/light theme support
- Added drag and drop functionality for files and keys
- Improved key and file management interface
- Enhanced keyboard navigation and accessibility
- Added comprehensive help and documentation

#### 🔄 File Operations

- Added secure file sharing with access control
- Implemented file versioning and history
- Added batch processing for multiple files
- Improved file encryption/decryption performance

### 🛠️ Improvements

- Optimized memory usage for large files
- Improved error handling and recovery
- Enhanced logging and debugging capabilities
- Updated dependencies to latest secure versions
- Improved multi-language support

### 🐛 Bug Fixes

- Fixed issues with key import/export
- Resolved UI layout problems on high-DPI displays
- Fixed memory leaks in file operations
- Addressed security vulnerabilities in crypto operations
- File encryption/decryption support
- Message signing and verification
- Log viewer with advanced filtering
- Multiple language support

#### ⚡ Performance & Stability

- Faster key generation and operations
- Reduced memory usage
- Improved error handling and recovery
- Better cross-platform compatibility

## [2.0.0] - 2025-08-08

### Major Changes

- **Complete UI Migration to PySide6**

  - Modern, responsive interface with dark theme
  - Improved window management and dialog handling
  - Better cross-platform compatibility

- **New Password Management Features**

  - Secure password generation with customizable options
  - PBKDF2-SHA256 password hashing
  - Password strength validation
  - Clipboard integration with error handling

- **Enhanced PGP Tools**

  - Streamlined key generation and management
  - Improved message encryption/decryption workflow
  - Better error handling and user feedback

- **Code Quality & Maintenance**

  - Updated dependencies to latest stable versions
  - Improved code organization and documentation
  - Better error handling and logging

## [1.2.0] - 2025-05-25

- Centralized logging system: info, warning, error, uncaught exceptions
- Added log_info, log_warning, log_error for custom log entries
- Log Viewer: now supports real-time filtering (ALL, INFO, WARNING, ERROR)
- Automatic traceback capture and display in log viewer
- Bugfix: import di SECONDARY in sponsor.py
- Migliorata Help dialog (nuova sezione Logging)
- Sponsor dialog grafica migliorata

## [1.1.0] - 2025-05-25

- Export public key in ASCII-armored format (.asc)
- Visualize and display key fingerprint
- Generate SSL certificates with custom CN
- Improved GUI with ttkbootstrap (Superhero theme)
- Updated About and Help dialogs
- Menu: added 'Esporta chiave pubblica' under File
- Version info and author in About
- Bugfix: style/theme initialization

## [Unreleased]

- Fixed relative imports in struttura package
- Fixed indentation errors in gui/main_window.py
- Updated requirements.txt and README.md for clarity and troubleshooting
- Improved modularity and project documentation

---
This project is licensed under the GNU General Public License v3.0 (GPLv3). See LICENSE for details.
