# OpenPGP GUI App

**Version:** 1.2.0  
**Author:** Nsfr750  
**License:** GNU General Public License v3.0 (GPLv3). See LICENSE for details.

## Features
- Modern UI with ttkbootstrap (Superhero theme)
- Generate, load, and export OpenPGP key pairs
- Set key name, email, passphrase, and view fingerprint
- Encrypt and decrypt messages
- Sign and verify messages (detached signatures)
- Export public key in ASCII-armored format (.asc)
- Visualize key fingerprint for security checks
- Generate SSL certificates with custom CN
- Clear/reset all fields with one click
- **Centralized logging system:** info, warning, error, and uncaught exceptions
- **Log Viewer with real-time filtering** (ALL, INFO, WARNING, ERROR)
- Use `log_info`, `log_warning`, `log_error` in your code for custom log entries
- Automatic traceback capture and display in the log viewer
- Dynamic menu bar with About, Help, Log Viewer, Sponsor, Version dialogs
- Semantic versioning and version info
- Modular structure (`struttura`, `gui`, etc.)
- Easy extensibility and theming (via ttkbootstrap)

## Requirements
- Python 3.x
- Tkinter (comes with standard Python)
- Pillow (`pip install pillow`)  # For PNG icon support
- ttkbootstrap (`pip install ttkbootstrap`)  # Optional for custom themes

## Usage
1. Always run from the project root directory:
   ```
   python main.py
   ```
   or, if using a virtual environment:
   ```
   .venv\Scripts\python.exe main.py
   ```
2. If you see import errors, ensure you are running from the root and not from within a subfolder.

## Project Structure
- `main.py` — Main entry point
- `gui/` — GUI components (windows, widgets)
- `struttura/` — Core logic, dialogs, and utilities

## Troubleshooting
- If you see `ModuleNotFoundError` for a module in `struttura`, make sure you are running from the root and not from inside a subfolder.
- All sibling imports in `struttura` use relative imports (e.g., `from .about import About`).

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the LICENSE file for full terms.
