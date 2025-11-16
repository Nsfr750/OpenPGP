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
        self.resize(600, 700)
        
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
                
        # Create a scrollable area for system info
        # Set up scroll area
        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        # System info widget
        sys_info_widget = QWidget()
        sys_info_layout = QVBoxLayout(sys_info_widget)
        
        # System info title
        sys_info_title = QLabel("<h3>System Information</h3>")
        sys_info_title.setStyleSheet("margin-top: 10px;")
        sys_info_layout.addWidget(sys_info_title)
        
        # System info content
        sys_info = QTextBrowser()
        sys_info.setOpenLinks(True)
        sys_info.setStyleSheet("""
            QTextBrowser {
                background-color: #f0f0f0;
                border: 1px solid #d0d0d0;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        sys_info.setHtml(self.get_system_info())
        sys_info_layout.addWidget(sys_info)
        
        # Set the widget to the scroll area
        scroll.setWidget(sys_info_widget)
        scroll.setWidgetResizable(True)
        
        # Add scroll area to the main layout
        layout.addWidget(scroll, 1)  # The 1 makes it take up remaining space
        sys_info.setStyleSheet("""
            QTextBrowser {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
                font-family: monospace;
                font-size: 12px;
                color: black;
            }
        """)
        sys_info_layout.addWidget(sys_info)
        
        # Set the widget to the scroll area
        scroll.setWidget(sys_info_widget)
        layout.addWidget(scroll, 1)  # The '1' makes it take available space
        
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
            
    def get_system_info(self):
        """Generate HTML-formatted system information."""
        try:
            # Get system information
            system = platform.system()
            release = platform.release()
            version = platform.version()
            machine = platform.machine()
            processor = platform.processor()
            
            # Get Python information
            python_version = platform.python_version()
            python_implementation = platform.python_implementation()
            
            # Get PySide6 version
            from PySide6 import __version__ as pyside_version
            pyside6_version = QT_VERSION_STR
            
            # Get application information
            app_version = get_version()
            try:
                app_codename = get_codename()
                app_status = "Development" if is_development() else "Stable"
            except Exception as e:
                logger.warning(f"Could not get version details: {e}")
                app_codename = ""
                app_status = ""
            
            # Format the information as HTML
            info = f"""
            <html>
            <body>
                <h3>Application</h3>
                <table>
                    <tr><td><b>Name:</b></td><td>OpenPGP</td></tr>
                    <tr><td><b>Version:</b></td><td>{app_version} {app_codename} ({app_status})</td></tr>
                </table>            
                <h3>System</h3>
                <table>
                    <tr><td><b>OS:</b></td><td>{system} {release}</td></tr>
                    <tr><td><b>Version:</b></td><td>{version}</td></tr>
                    <tr><td><b>Machine:</b></td><td>{machine}</td></tr>
                    <tr><td><b>Processor:</b></td><td>{processor}</td></tr>
                </table>
                <h3>Python</h3>
                <table>
                    <tr><td><b>Version:</b></td><td>{python_implementation} {python_version}</td></tr>
                    <tr><td><b>PySide6:</b></td><td>{pyside6_version}</td></tr>
                </table>
            </body>
            </html>
            """
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return "<p>Error retrieving system information.</p>"
    