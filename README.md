# OpenPGP GUI App

**Version:** 2.1.0 (Stable)  
**Author:** Nsfr750  
**License:** GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.

## 🚀 Key Features

### 🔑 Enhanced Key Management

- Generate ECC and Ed25519 key pairs
- Import/export keys in multiple formats
- Secure key backup and recovery
- Key expiration and revocation support
- Hardware token support (YubiKey, etc.)
- Key sharing with fine-grained permissions

### 🔒 Advanced Security

- End-to-end encryption for files and messages
- Hardware token support (YubiKey, etc.)
- Visual passphrase strength indicators
- Secure key storage with hardware protection
- Blockchain-based identity verification
- Secure file sharing with access control

### 🖥️ Modern Interface

- Dark/light theme support
- Drag and drop functionality
- Intuitive key and file management
- Multi-language support

### 🖥️ Modern UI/UX

- Drag and drop support for files and keys
- Dark/light theme support
- Intuitive keyboard navigation
- Comprehensive tooltips and help

### 🔄 PGP Tools

- Generate, load, and export OpenPGP key pairs
- Encrypt/decrypt files and messages
- Sign and verify messages with detached signatures
- Support for multiple key algorithms (RSA, ECC, Ed25519)
- Key fingerprint visualization
- SSL certificate generation

## 🛡️ Security Features

- Secure password generation with PBKDF2-SHA256
- Hardware token integration (YubiKey, etc.)
- Centralized logging system with multiple log levels
- Real-time log viewer with advanced filtering
- Automatic error reporting and traceback capture
- Clear/reset all sensitive data with one click

## ✨ User Experience

- Modern, responsive interface with dark/light themes
- Drag and drop functionality for files and keys
- Dynamic menu system with keyboard shortcuts
- Real-time status updates and notifications
- Comprehensive help system with tooltips
- Support for multiple languages

## 📋 Requirements

- Python 3.9+
- PySide6 >= 6.4.0 (Qt for Python)
- PGPy >= 0.6.0 (for PGP functionality)
- cryptography >= 3.4.0 (for cryptographic operations)
- pyperclip >= 1.8.2 (for clipboard operations)
- wand >= 0.6.10 (for image processing)
- python-gnupg >= 0.5.0 (for hardware token support)
- pycryptodome >= 3.12.0 (for additional crypto functions)
- argon2-cffi >= 21.3.0 (for secure password hashing)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Nsfr750/OpenPGP.git
   cd OpenPGP
   ```

2. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On macOS/Linux
   ```

3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Application

```bash
python main.py
```

### Password Tools

1. Generate secure passwords with customizable options
2. Create password hashes with PBKDF2-SHA256
3. Verify passwords against stored hashes
4. Copy passwords and hashes to clipboard

### PGP Tools

1. **Generate Keys**: Create new PGP key pairs
2. **Load Keys**: Import existing PGP keys
3. **Encrypt/Decrypt**: Secure message encryption and decryption
4. **Sign/Verify**: Digital signatures for message authentication
5. **Export Keys**: Save public keys for sharing

## Project Structure

- `main.py` — Main entry point
- `gui/` — PySide6 GUI components
  - `main_window.py` — Main application window
  - `menu.py` — Menu bar implementation
  - `about.py` — About dialog
  - `help.py` — Help documentation
  - `sponsor.py` — Sponsor information
  - `log_viewer.py` — Log viewing interface
  - `traceback.py` — Error display
  - `widgets/` — Custom widgets
- `utils/` — Utility functions
  - `password_utils.py` — Password generation and hashing
- `lang/` — Language and translations
- `docs/` — Documentation
- `tests/` — Test suite

## Troubleshooting

- **Missing Dependencies**: Install all requirements with `pip install -r requirements.txt`
- **Import Errors**: Ensure you're running from the project root directory
- **UI Issues**: Try resizing the window if any elements appear misaligned
- **Logs**: Check the log viewer for detailed error information

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support

For support, please:

- Open an issue on GitHub
- Check out the [documentation](docs/)

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the LICENSE file for full terms.
