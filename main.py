# Add imghdr shim for Python 3.9+ compatibility
import sys
import builtins
if 'imghdr' not in sys.modules:
    from imghdr_shim import imghdr
    sys.modules['imghdr'] = imghdr
    builtins.imghdr = imghdr

import traceback
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from gui.main_window import MainWindow

# Global exception hook to log all uncaught exceptions
LOG_FILE = 'traceback.log'

def log_info(msg):
    print(f'[INFO] {msg}')
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f'[INFO] {msg}\n')
    except Exception as e:
        print(f'Failed to write to log file: {e}')

def log_warning(msg):
    print(f'[WARNING] {msg}')
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f'[WARNING] {msg}\n')
    except Exception as e:
        print(f'Failed to write to log file: {e}')

def log_error(msg):
    print(f'[ERROR] {msg}')
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f'[ERROR] {msg}\n')
    except Exception as e:
        print(f'Failed to write to log file: {e}')

def global_exception_hook(exc_type, exc_value, exc_tb):
    # Save last traceback for LogViewer
    sys.last_type = exc_type
    sys.last_value = exc_value
    sys.last_traceback = exc_tb
    
    # Write to log file
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write('\n--- Uncaught Exception ---\n')
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception as e:
        print(f'Failed to write exception to log file: {e}')
    
    # Call default hook (prints to stderr)
    sys.__excepthook__(exc_type, exc_value, exc_tb)

# Set the exception hook
sys.excepthook = global_exception_hook

def main():
    # Create the Qt Application
    app = QApplication(sys.argv)
    
    # Apply Fusion style for a modern look
    app.setStyle('Fusion')
    
    # Set application information
    app.setApplicationName("OpenPGP")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("OpenPGP")
    
    # Create and show the main window
    try:
        window = MainWindow()
        window.show()
        
        # Log application start
        log_info("Application started successfully")
        
        # Run the main Qt loop
        return app.exec()
        
    except Exception as e:
        log_error(f"Fatal error: {str(e)}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
