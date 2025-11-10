# Add imghdr shim for Python 3.9+ compatibility
import sys
import traceback
import builtins
if 'imghdr' not in sys.modules:
    from core.imghdr_shim import imghdr
    sys.modules['imghdr'] = imghdr
    builtins.imghdr = imghdr

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from gui.main_window import MainWindow
from utils.logger import log_error, log_info, log_warning, log_exception, set_log_file

# Set up logging
LOG_FILE = 'logs/application.log'
set_log_file(LOG_FILE)

def global_exception_hook(exc_type, exc_value, exc_tb):
    """Global exception handler that logs uncaught exceptions."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Call the default excepthook for keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    # Log the exception
    log_exception(exc_value)

# Set the exception hook
sys.excepthook = global_exception_hook

def main():
    # Create the Qt Application
    app = QApplication(sys.argv)
    
    # Set application icon
    app_icon = QIcon("assets/icon.png")
    app.setWindowIcon(app_icon)
    
    # Apply Fusion style for a modern look
    app.setStyle('Fusion')
    
    # Set application information
    app.setApplicationName("OpenPGP")
    app.setApplicationVersion("2.1.0")
    app.setOrganizationName("Tuxxle")
    
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
