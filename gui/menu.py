import os
from PySide6.QtWidgets import QMenu, QMenuBar, QMessageBox
from PySide6.QtGui import QAction, QKeySequence, QIcon
from PySide6.QtCore import Qt, Signal, QObject

from .about import AboutDialog as AboutWindow
from .help import HelpDialog as HelpWindow
from .sponsor import SponsorDialog as SponsorWindow
from .log_viewer import LogViewerDialog as LogViewerWindow

class MenuSignals(QObject):
    export_pubkey = Signal()
    quit_app = Signal()

class MenuBar(QMenuBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signals = MenuSignals()
        self.setup_ui()
    
    def setup_ui(self):
        # File menu
        file_menu = self.addMenu("🗃️ &File")
        
        # Export key action
        export_action = QAction("&Export Public Key", self)
        export_action.triggered.connect(self.signals.export_pubkey)
        
        # Exit action
        exit_action = QAction("E&xit", self)
        
        # Add actions to menu
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.signals.quit_app)
        file_menu.addAction(exit_action)
        
        # Log menu
        log_menu = self.addMenu("📜 &Log")
        
        view_log_action = QAction("&View Log", self)
        view_log_action.triggered.connect(self.show_log_viewer)
        view_log_action.setShortcut(QKeySequence("F4"))
        log_menu.addAction(view_log_action)
        
        # Help menu
        help_menu = self.addMenu("❓ &Help")
        
        help_action = QAction("&Help", self)
        help_action.triggered.connect(self.show_help)
        help_action.setShortcut(QKeySequence("F1"))
        help_menu.addAction(help_action)
        
        help_menu.addSeparator()
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        about_action.setShortcut(QKeySequence("F2"))
        help_menu.addAction(about_action)
        
        sponsor_action = QAction("&Sponsor", self)
        sponsor_action.triggered.connect(self.show_sponsor)
        sponsor_action.setShortcut(QKeySequence("F3"))
        help_menu.addAction(sponsor_action)
    
    def show_about(self):
        """Show the About dialog."""
        self.about_window = AboutWindow()
        self.about_window.show()
    
    def show_help(self):
        """Show the Help window."""
        self.help_window = HelpWindow()
        self.help_window.show()
        
    def show_log_viewer(self):
        """Show the Log Viewer window."""
        try:
            # Ensure logs directory exists
            logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            
            # Default log file path
            log_file = os.path.join(logs_dir, 'application.log')
            
            # Create and show the log viewer
            self.log_viewer = LogViewerWindow(log_file=log_file)
            self.log_viewer.show()
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Error",
                f"Failed to open log viewer: {str(e)}"
            )
    
    def show_sponsor(self):
        """Show the Sponsor window."""
        self.sponsor_window = SponsorWindow()
        self.sponsor_window.show()

def create_menu_bar(parent):
    """Create and return a menu bar with all the necessary menus and actions."""
    return MenuBar(parent)
