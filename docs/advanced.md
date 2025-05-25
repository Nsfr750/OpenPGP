# Advanced Usage

## Exporting Public Keys
- Use the 'Export Public Key' button or menu item to save your public key in ASCII-armored format (.asc).

## Fingerprint Verification
- Always check the fingerprint before sharing your public key for added security.

## SSL Certificate Generation
- Enter the desired Common Name (CN) in the name field.
- Click the 'Generate SSL Certificate' button to create a self-signed certificate.

## Extending the App
- You can add support for more algorithms (ECC, Ed25519) by extending the key generation logic in `main_window.py`.
- The GUI uses ttkbootstrap for easy theming and customization.

## Logging & Debugging
- All actions, warnings, errors, and uncaught exceptions are logged to `traceback.log`.
- Use `log_info`, `log_warning`, `log_error` for custom log entries in your code.
- The Log Viewer supports filtering by ALL, INFO, WARNING, ERROR.
- If the log file is missing, the last runtime traceback is displayed.

## Troubleshooting
- If you encounter import errors, ensure you are running from the project root.
- For issues with dependencies, check `requirements.txt` or reinstall the needed packages.
