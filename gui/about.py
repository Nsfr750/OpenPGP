from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QApplication
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt, QSize

from .version import get_version

class AboutWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.setMinimumSize(400, 300)
        self.setWindowModality(Qt.ApplicationModal)
        
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Title
        title = QLabel("OpenPGP GUI App")
        title_font = title.font()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        
        # Version
        version = QLabel(f"Version {get_version()}")
        version.setAlignment(Qt.AlignCenter)
        
        # Description
        description = QLabel(
            "A modern Python GUI for OpenPGP encryption, signature, key management "
            "and SSL certificate generation.\n\n"
            "All operations are local and privacy-friendly."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        
        # Author and copyright
        author = QLabel("Author: Nsfr750")
        author.setAlignment(Qt.AlignCenter)
        
        copyright = QLabel("© 2025 Nsfr750, GPL v3.0")
        copyright.setAlignment(Qt.AlignCenter)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        close_btn.setFixedWidth(100)
        
        # Add widgets to layout
        layout.addSpacing(20)
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(version)
        layout.addSpacing(20)
        layout.addWidget(description)
        layout.addSpacing(20)
        layout.addWidget(author)
        layout.addWidget(copyright)
        layout.addSpacing(20)
        layout.addWidget(close_btn, 0, Qt.AlignCenter)
        layout.addSpacing(10)
        
        # Set layout
        self.setLayout(layout)
        
        # Center the window
        screen = QApplication.primaryScreen().availableGeometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
