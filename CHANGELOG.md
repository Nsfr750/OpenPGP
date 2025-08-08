# Changelog

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
