# OpenPGP Project Structure

This document outlines the structure of the OpenPGP project, a modern PySide6-based graphical user interface for OpenPGP with enhanced encryption, key management, and security features.

## Root Directory

```
OpenPGP/
├── assets/               # Static assets (images, icons, etc.)
├── core/                 # Core functionality
│   ├── api/              # API endpoints and handlers
│   ├── auth/             # Authentication and authorization
│   ├── compliance/       # Compliance-related code
│   ├── crypto/           # Core cryptographic operations
│   ├── scim/             # System for Cross-domain Identity Management
│   ├── siem/             # Security Information and Event Management
│   └── storage/          # Data storage and persistence
├── data/                 # Application data
│   └── compliance/       # Compliance-related data
│       ├── activities/   # Activity logs
│       ├── audit_logs/   # Audit trail logs
│       └── requests/     # Compliance requests
├── docs/                 # Documentation
├── examples/             # Example scripts and usage
├── gui/                  # Graphical user interface
│   ├── dialogs/          # Dialog windows
│   ├── key_management/   # Key management UI components
│   └── security/         # Security-related UI components
├── lang/                 # Language and localization files
├── logs/                 # Application logs
├── sample/               # Sample files and test data
├── setup/                # Build and installation scripts
├── spec/                 # Build specifications
├── tests/                # Test suite
├── ui/                   # UI templates and resources
├── venv/                 # Python virtual environment
├── .gitignore            # Git ignore rules
├── CHANGELOG.md          # Version history
├── LICENSE               # License file
├── main.py               # Application entry point
├── pyproject.toml        # Project metadata and build configuration
├── README.md             # Project overview
└── requirements.txt      # Python dependencies
```

## Key Components

### Core Functionality (`core/`)
- `advanced_crypto.py`: Advanced cryptographic operations
- `blockchain_identity.py`: Blockchain-based identity management
- `config.py`: Configuration management
- `logger.py`: Logging configuration and utilities
- `openpgp.py`: Main OpenPGP implementation
- `password_utils.py`: Password handling utilities
- `pqcrypto.py`: Post-quantum cryptography support
- `tpm_manager.py`: Trusted Platform Module integration
- `verifiable_credentials.py`: Digital credential management

### GUI Components (`gui/`)
- `main_window.py`: Main application window
- `about.py`: About dialog
- `help.py`: Help system
- `settings_dialog.py`: Application settings
- `log_viewer.py`: Log viewing interface
- `security.py`: Security-related UI components
- `version.py`: Version information

### Build and Deployment (`setup/`)
- `comp.py`: Compilation script
- `setup.py`: Package installation script
- `clear_cache.py`: Cache cleaning utility

## Data Storage

- Application data is stored in the `data/` directory
- Logs are stored in the `logs/` directory
- Temporary files follow system conventions

## Development

### Dependencies
- Python 3.8+
- PySide6
- PGPy
- cryptography
- pycryptodome
- argon2-cffi

### Building

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Build the application:
   ```bash
   python setup/comp.py
   ```

3. The compiled executable will be available in the `dist/` directory.

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

---
*Last updated: 2025-11-17*
