from PySide6 import QtWidgets
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QTextBrowser, QScrollArea, 
    QWidget, QFrame, QHBoxLayout, QApplication, QSizePolicy
)
from PySide6.QtCore import Qt, QSize, QUrl
from PySide6 import __version__ as QT_VERSION_STR
# PYQT_VERSION_STR is not available in PySide6, using PySide6 version instead
from PySide6.QtGui import QPixmap, QIcon, QDesktopServices

# Import version information
from gui.version import get_version, get_version_info

def get_codename():
    """
    Get the codename for the current version.
    
    Returns:
        str: Version codename or 'unknown' if not available
    """
    try:
        version_info = get_version_info()
        return version_info.get('codename', 'unknown')
    except Exception:
        return 'unknown'

def is_development():
    """
    Check if this is a development version.
    
    Returns:
        bool: True if this is a development version, False otherwise
    """
    try:
        version_info = get_version_info()
        return version_info.get('is_dev', False)
    except Exception:
        return False

# Import language manager
import os
import sys
import platform
from pathlib import Path
import logging

# Try to import psutil, but handle gracefully if not available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False
    logging.debug("psutil not available - some system info may be limited")

try:
    from wand.image import Image as WandImage
except ImportError:
    WandImage = None
    logging.warning("Wand library not found. Some features may be limited.")

logger = logging.getLogger(__name__)

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About OpenPGP")
        self.resize(600, 400)
        
        layout = QVBoxLayout(self)
        
        # App logo and title
        header = QHBoxLayout()
        
        # Load application logo
        logo_paths = [
            Path("assets/about.png"),  # Relative to project root
            Path(__file__).parent.parent / "assets" / "about.png",  # Project root/assets
            Path(__file__).parent / "assets" / "about.png"  # gui/assets
        ]
        
        logo_found = False
        logo_label = QLabel()
        
        for logo_path in logo_paths:
            if logo_path.exists():
                try:
                    pixmap = QPixmap(str(logo_path))
                    if not pixmap.isNull():
                        # Scale logo to a reasonable size while maintaining aspect ratio
                        scaled_pixmap = pixmap.scaled(
                            128, 128, 
                            Qt.AspectRatioMode.KeepAspectRatio, 
                            Qt.TransformationMode.SmoothTransformation
                        )
                        logo_label.setPixmap(scaled_pixmap)
                        logo_found = True
                        break
                except Exception as e:
                    logging.warning(f"Error loading logo from {logo_path}: {e}")
        
        if not logo_found:
            # Add a placeholder label with app name if logo not found
            logo_label.setText("OpenPGP")
            logo_label.setStyleSheet("""
                QLabel {
                    font-size: 24px;
                    font-weight: bold;
                    color: #2c3e50;
                    padding: 20px;
                }
            """)
            
        # Add some spacing and alignment
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setFixedSize(128, 128)
        logo_label.setContentsMargins(0, 0, 20, 0)
        header.addWidget(logo_label)
        
        # App info
        app_info = QVBoxLayout()
        
        # Application title
        title = QLabel("OpenPGP")
        title.setStyleSheet("""
            font-size: 24px; 
            font-weight: bold;
            color: white;
            margin-bottom: 5px;
        """)
        
        # Description
        description = QLabel(
            "A modern GUI for OpenPGP.\n" 
            "- Encryption\n"
            "- Signature\n"
            "- Key management\n"
            "- SSL cert generation\n\n"
            "All operations are local and privacy-friendly."
        )
        description.setWordWrap(True)
        description.setStyleSheet("""
            color: white;
            font-size: 14px;
            margin: 10px 0;
            padding: 10px;
            border-radius: 5px;
        """)

        # Version information
        try:
            version = get_version()
            version_text = f"Version {version}"
            
            # Try to get additional version info if available
            try:
                if callable(get_codename):
                    codename = get_codename()
                    if codename and codename != 'unknown':
                        version_text += f" {codename}"
                
                if callable(is_development):
                    status = "Development" if is_development() else "Stable"
                    version_text += f" ({status})"
                    
            except Exception as e:
                logger.debug(f"Could not get extended version info: {e}")
                
        except Exception as e:
            logger.error(f"Error getting version info: {e}")
            version_text = "Version Unknown"  # Final fallback
        version = QLabel(version_text)
        version.setStyleSheet("""
            color: white;
            font-size: 14px;
            margin-bottom: 10px;
        """)
        version.setAlignment(Qt.AlignmentFlag.AlignLeft)
        
        app_info.addWidget(title)
        app_info.addWidget(version)
        app_info.addWidget(description)
        app_info.addStretch()
        
        header.addLayout(app_info)
        header.addStretch()
        
        layout.addLayout(header)
        
        # Add some spacing before the copyright
        layout.addSpacing(20)
        
        # Copyright and license
        copyright = QLabel(
            "© Copyright 2024-2025 Nsfr750 - All rights reserved\n"
            "Licensed under the GPL v3.0 License"
        )
        copyright.setStyleSheet("""
            color: white;
            font-size: 11px;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #dee2e6;
        """)
        copyright.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(copyright)
        
        # Buttons
        buttons = QHBoxLayout()
        
        # GitHub button
        github_btn = QPushButton("GitHub")
        github_btn.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl("https://github.com/Nsfr750/OpenPGP")))
        # Style GitHub button with blue background and white text
        github_btn.setStyleSheet("""
            QPushButton {
                background-color: #0366d6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #004494;
            }
        """)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        # Style Close button with red background and white text
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        
        # Add buttons to layout with proper spacing
        buttons.addStretch()
        buttons.addWidget(github_btn)
        buttons.addWidget(close_btn)
        
        # Add buttons layout to main layout with some spacing
        layout.addLayout(buttons)
        layout.setContentsMargins(20, 20, 20, 20)