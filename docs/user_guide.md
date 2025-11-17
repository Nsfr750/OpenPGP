# User Guide

## Main Window Overview

- Enter your name, email, and passphrase for key generation.
- Select the algorithm (currently RSA; more coming soon).
- Use the buttons to generate, load, or export keys.
- The fingerprint of the loaded/generated key is shown for verification.
- Use the text area to input messages for encryption, decryption, signing, or verification.
- Export your public key to share it securely.
- Generate SSL certificates from the GUI.
- Use the 'Clear' button to reset all fields.

## Menu Bar

- **File**: Export public key, Exit

- **Log**: View log (with filters for ALL, INFO, WARNING, ERROR)

- **Help**: Help, About, Sponsor

## Logging & Log Viewer (v2.1.0+)

### Logging Features

- All info, warnings, errors, and uncaught exceptions are logged automatically
- Custom logging functions: `log_info(msg)`, `log_warning(msg)`, `log_error(msg)`, `log_exception(e)`
- Logs are stored in the `logs/` directory with timestamps
- Automatic log rotation and file management

### Using the Log Viewer

Access the Log Viewer from the menu: **Log** > **View Log**

#### Main Features

- **File Selection**: Choose from multiple log files in the dropdown

- **Filter by Level**: Show only specific log levels (ALL, DEBUG, INFO, WARNING, ERROR, OTHER)

- **Text Search**: Find specific text within logs

- **Keyboard Shortcuts**:

  - `F1`: Open Help
  - `F2`: Show About
  - `F3`: Open Wiki Pages
  - `F4`: Show Sponsor info
  - `F5`: Open Log Viewer
  - `Ctrl+F`: Focus search box

#### Log File Management

- Logs are automatically rotated
- View file size and last modified time in the status bar
- Open the logs folder directly from the toolbar

### Troubleshooting

- If you encounter issues, check the log files in the `logs/` directory
- The most recent error traceback is displayed if the application crashes
- Log files are named with timestamps for easy identification

## Tips

- All cryptographic operations are local (no cloud).
- For best results, use strong passphrases.
- The log window provides feedback and error details.
