# OpenPGP GUI App

**Version:** 2.0.0  
**Author:** Nsfr750  
**License:** GNU General Public License v3.0 (GPLv3). See LICENSE for details.

## Features
- Modern UI with PySide6 and dark theme
- **Password Management:**
  - Generate secure, customizable passwords
  - PBKDF2-SHA256 password hashing
  - Password strength validation
  - Copy to clipboard with error handling
- **PGP Tools:**
  - Generate, load, and export OpenPGP key pairs
  - Set key name, email, and passphrase
  - Encrypt and decrypt messages
  - Sign and verify messages (detached signatures)
  - Export public key in ASCII-armored format (.asc)
  - Visualize key fingerprint for security checks
  - Generate SSL certificates with custom CN
- **Security Features:**
  - Secure password generation and hashing
  - Clear/reset all fields with one click
  - Centralized logging system (info, warning, error, and uncaught exceptions)
  - Log Viewer with real-time filtering (ALL, INFO, WARNING, ERROR)
  - Automatic traceback capture and display
- **User Experience:**
  - Dark theme for better visibility
  - Responsive and intuitive interface
  - Dynamic menu system
  - Status bar feedback
  - Tooltips and help text

## Requirements
- Python 3.9+
- PySide6 (Qt for Python)
- PGPy (for PGP functionality)
- cryptography (for cryptographic operations)
- pyperclip (for clipboard operations)
- wand (for image processing)

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
- Join our [Discord](https://discord.gg/ryqNeuRYjD)
- Check out the [documentation](docs/)

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the LICENSE file for full terms.
