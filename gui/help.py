"""
Help Dialog Module (PySide6 Version)

This module provides the Help dialog for the OpenPGP application.
Displays usage instructions and feature highlights in a tabbed interface.

License: GPL v3.0 (see LICENSE)
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QLabel, 
    QPushButton, QTextBrowser, QApplication
)
from PySide6.QtCore import Qt

class HelpWindow(QDialog):
    """A dialog window that displays help information in a tabbed interface."""
    
    def __init__(self, parent=None):
        """Initialize the Help dialog."""
        super().__init__(parent)
        self.setWindowTitle("Help")
        self.resize(800, 600)
        self.setMinimumSize(600, 400)
        self.setWindowModality(Qt.ApplicationModal)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Create tabs
        self.create_usage_tab()
        self.create_features_tab()
        self.create_advanced_tab()
        self.create_logging_tab()
        
        # Add tabs to the tab widget
        main_layout.addWidget(self.tabs)
        
        # Add Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(100)
        
        btn_layout = QVBoxLayout()
        btn_layout.addWidget(close_btn, 0, Qt.AlignCenter)
        btn_layout.setContentsMargins(0, 10, 0, 10)
        
        main_layout.addLayout(btn_layout)
        
        # Center the window
        self.center_window()
    
    def create_usage_tab(self):
        """Create the Usage tab with basic instructions."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        text = (
            'To start the application, run main.py from the project root.\n\n'
            'Use the menu bar for Help, About, Log Viewer, and more.\n\n'
            'Log Viewer lets you see all info, warnings, errors, and tracebacks.\n\n'
            'If you see import errors, ensure you are running from the root directory.\n\n'
            'If you get an error, check the Application Log for details and traceback.'
        )
        
        text_browser = QTextBrowser()
        text_browser.setPlainText(text)
        text_browser.setOpenExternalLinks(True)
        text_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
                border-radius: 3px;
                color: #EFF0F1;
                padding: 10px;
            }
        """)
        
        layout.addWidget(text_browser)
        self.tabs.addTab(tab, "Usage")
    
    def create_features_tab(self):
        """Create the Features tab with application features."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        features = [
            "- Modern UI with dark theme",
            "- Generate, load, and export OpenPGP key pairs",
            "- Set key name, email, passphrase, and view fingerprint",
            "- Encrypt and decrypt messages",
            "- Sign and verify messages (detached signatures)",
            "- Export public key",
            "- Generate SSL certificates",
            "- Clear/reset all fields with one click",
            "- Full log and error feedback"
        ]
        
        text_browser = QTextBrowser()
        text_browser.setPlainText("\n".join(features))
        text_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
                border-radius: 3px;
                color: #EFF0F1;
                padding: 10px;
            }
        """)
        
        layout.addWidget(text_browser)
        self.tabs.addTab(tab, "Features")
    
    def create_advanced_tab(self):
        """Create the Advanced tab with technical details."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        advanced = [
            "Advanced Features:",
            "- Export public key in ASCII-armored format (.asc)",
            "- Visualize key fingerprint for security checks",
            "- Choose key algorithm (currently RSA, extensible)",
            "- Generate SSL certificates with custom CN",
            "- All cryptographic operations are performed locally (no cloud)",
            "- Modern error handling and user feedback",
            "- Centralized logging: info, warning, error, uncaught exceptions",
            "- Application Log Viewer with real-time filtering"
        ]
        
        text_browser = QTextBrowser()
        text_browser.setPlainText("\n".join(advanced))
        text_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
                border-radius: 3px;
                color: #EFF0F1;
                padding: 10px;
            }
        """)
        
        layout.addWidget(text_browser)
        self.tabs.addTab(tab, "Advanced")
    
    def create_logging_tab(self):
        """Create the Logging & Debug tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        logging_info = [
            "Logging and Debugging:",
            "- All info, warnings, errors, and uncaught exceptions are logged.",
            "- Logs are stored in the application's data directory.",
            "- Use the Log Viewer to filter and search through logs.",
            "- Logs include timestamps and severity levels for easy debugging."
        ]
        
        text_browser = QTextBrowser()
        text_browser.setPlainText("\n\n".join(logging_info))
        text_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
                border-radius: 3px;
                color: #EFF0F1;
                padding: 10px;
            }
        """)
        
        layout.addWidget(text_browser)
        self.tabs.addTab(tab, "Logging & Debug")
    
    def center_window(self):
        """Center the window on the screen."""
        frame = self.frameGeometry()
        center_point = QApplication.primaryScreen().availableGeometry().center()
        frame.moveCenter(center_point)
        self.move(frame.topLeft())
