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

## Logging & Log Viewer
- All info, warnings, errors, and uncaught exceptions are logged automatically.
- Use `log_info(msg)`, `log_warning(msg)`, `log_error(msg)` in your scripts for custom logging.
- The Log Viewer (Log > View Log) allows you to filter and view logs by level.
- If the log file is missing, the last runtime traceback is shown if available.

## Tips
- All cryptographic operations are local (no cloud).
- For best results, use strong passphrases.
- The log window provides feedback and error details.
