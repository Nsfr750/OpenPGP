# Developer Guide

Welcome, developer! This guide provides the essentials for contributing to and extending the OpenPGP GUI App.

---

## Project Structure
- `main.py` — Entry point, launches the main window.
- `gui/` — All GUI components (main window, widgets, dialogs).
- `struttura/` — Core logic, dialogs, utilities, versioning, help/about, etc.
- `docs/` — Documentation.
- `requirements.txt` — Python dependencies.

## Key Technologies
- **Python 3.x**
- **Tkinter** — GUI framework (with ttkbootstrap for theming)
- **pgpy** — OpenPGP cryptography
- **cryptography** — SSL certificate generation
- **Pillow** — (optional) for icons

## How to Contribute
1. Fork and clone the repository.
2. Create a virtual environment and install dependencies.
3. Follow PEP8 and keep code modular.
4. Document new features and update `CHANGELOG.md`.
5. Add or update tests if possible.
6. Open a pull request with a clear description.

## Adding Features
- To add new algorithms (e.g., ECC), extend the key generation logic in `main_window.py`.
- For new GUI components, add widgets in `gui/` and keep logic separate from UI.
- Use `ttkbootstrap` styles for a consistent look.

## Testing
- Add tests for new features and bugfixes.
- Manual testing: run `python main.py` and use all GUI functions.
- (Optional) Integrate with CI/CD for automated tests.

## Code Style
- Follow PEP8.
- Use docstrings for public functions/classes.
- Keep UI and logic as separate as possible.

## Logging & Debugging
- Use `log_info(msg)`, `log_warning(msg)`, `log_error(msg)` anywhere in the code for custom log entries.
- All logs are saved in `traceback.log` and shown in the Log Viewer.
- The Log Viewer supports filtering by ALL, INFO, WARNING, ERROR.
- Uncaught exceptions are automatically logged and shown in the Log Viewer (with traceback).

## Support & Questions
- Open issues on GitHub for bugs or feature requests.
- See `README.md` for contact and contribution info.

---

## Advanced Topics

### API Reference

The application is modular: core logic is in `struttura/`, GUI in `gui/`.

**Main classes and functions:**
- `MainWindow` (`gui/main_window.py`): Main GUI logic and event handling.
- `gen_key`, `export_pubkey`, `clear_fields`, etc.: Methods for cryptographic operations.
- `Help`, `About`, `LogViewer`, etc.: Dialogs and utilities in `struttura/`.
- `get_version()` (`struttura/version.py`): Returns current version string.

For more, read the docstrings in the code and see `docs/user_guide.md` for usage flow.

### Extension Examples

#### Adding a New Key Algorithm
1. In `gui/main_window.py`, locate the algorithm selection dropdown.
2. Add your new algorithm (e.g., ECC, Ed25519) to the dropdown options.
3. In the key generation logic, implement the handling for the new algorithm using `pgpy`.
4. Test thoroughly and update the documentation.

#### Adding a Custom Widget
1. Create your widget in `gui/widgets.py` or a new file.
2. Import and use it in `main_window.py` where needed.
3. Follow ttkbootstrap style conventions for consistency.

### Architectural Diagram

Below is a simple textual architecture overview:

```
OpenPGP GUI App
│
├── main.py (entry point)
│
├── gui/
│   ├── main_window.py (MainWindow class, event logic)
│   ├── widgets.py (custom widgets)
│   └── ...
│
├── struttura/
│   ├── help.py, about.py, version.py (dialogs, versioning)
│   ├── menu.py (menu bar logic)
│   └── ...
│
├── docs/ (documentation)
├── requirements.txt
└── ...
```

For a visual diagram, see [docs/architecture.png](architecture.png) (add your own PNG for more detail).

---

Happy coding!
