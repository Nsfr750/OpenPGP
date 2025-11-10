"""
Help Dialog for OpenPGP Application

This module provides a help dialog for the OpenPGP application.
It includes documentation and usage instructions for the application.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextBrowser, 
    QPushButton, QWidget, QFrame, QLabel, QTabWidget,
    QApplication, QScrollArea, QSizePolicy, QMessageBox
)
from PySide6.QtCore import Qt, QUrl, QSize
from PySide6.QtGui import QDesktopServices, QFont, QTextCursor, QPixmap, QIcon

import os
import sys
import platform
import logging

# Get version information
try:
    from ..version import get_version
    VERSION = get_version()
except ImportError:
    VERSION = "1.0.0"

logger = logging.getLogger('OpenPGP')

class HelpDialog(QDialog):
    """Help dialog for the OpenPGP application."""
    
    def __init__(self, parent=None):
        """Initialize the help dialog."""
        super().__init__(parent)
        self.setWindowTitle("OpenPGP Help")
        self.resize(800, 600)
        self.setMinimumSize(600, 400)
        
        # Set window flags
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        
        try:
            # Set up UI
            self.init_ui()
            logger.debug("Help dialog initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing help dialog: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to initialize help dialog: {str(e)}")

    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Add tabs
        self.tabs.addTab(self._create_welcome_tab(), "Welcome")
        self.tabs.addTab(self._create_encryption_tab(), "Encryption")
        self.tabs.addTab(self._create_decryption_tab(), "Decryption")
        self.tabs.addTab(self._create_keys_tab(), "Key Management")
        self.tabs.addTab(self._create_support_tab(), "Support")
        self.tabs.addTab(self._create_about_tab(), "About")
        
        main_layout.addWidget(self.tabs)
        
        # Close button
        button_box = QHBoxLayout()
        button_box.addStretch()
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        self.close_btn.setMinimumWidth(120)
        
        # Style the close button
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
        """)
        
        button_box.addWidget(self.close_btn)
        main_layout.addLayout(button_box)
    
    def _create_welcome_tab(self):
        """Create the welcome tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Welcome message
        welcome_text = """
        <h2>Welcome to OpenPGP</h2>
        <p>Thank you for using OpenPGP, a secure and easy-to-use application for PGP encryption, 
        decryption, and key management.</p>
        
        <h3>Getting Started</h3>
        <ol>
            <li>Generate a new key pair or import existing keys</li>
            <li>Encrypt files or messages with public keys</li>
            <li>Decrypt received files with your private key</li>
            <li>Manage your keys and contacts</li>
        </ol>
        
        <h3>Quick Tips</h3>
        <ul>
            <li>Always keep your private key secure and never share it</li>
            <li>Regularly back up your keys</li>
            <li>Verify the fingerprint of public keys before using them</li>
        </ul>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(welcome_text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_encryption_tab(self):
        """Create the encryption tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        text = """
        <h2>Encrypting Files and Messages</h2>
        
        <h3>Encrypting Files</h3>
        <ol>
            <li>Click on the 'Encrypt' tab in the main window</li>
            <li>Select the file you want to encrypt</li>
            <li>Choose the recipient's public key</li>
            <li>Click 'Encrypt' and save the encrypted file</li>
        </ol>
        
        <h3>Encrypting Text</h3>
        <ol>
            <li>Go to the 'Encrypt' tab</li>
            <li>Type or paste your message in the text area</li>
            <li>Select the recipient's public key</li>
            <li>Click 'Encrypt' and copy the encrypted message</li>
        </ol>
        
        <h3>Options</h3>
        <ul>
            <li><b>Sign Message:</b> Add your digital signature to verify your identity</li>
            <li><b>ASCII Armor:</b> Output in ASCII format for email compatibility</li>
            <li><b>Compress:</b> Reduce the size of the encrypted output</li>
        </ul>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_decryption_tab(self):
        """Create the decryption tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        text = """
        <h2>Decrypting Files and Messages</h2>
        
        <h3>Decrypting Files</h3>
        <ol>
            <li>Click on the 'Decrypt' tab in the main window</li>
            <li>Select the encrypted file (.gpg, .asc, etc.)</li>
            <li>Enter your private key passphrase if prompted</li>
            <li>Click 'Decrypt' and choose where to save the decrypted file</li>
        </ol>
        
        <h3>Decrypting Text</h3>
        <ol>
            <li>Go to the 'Decrypt' tab</li>
            <li>Paste the encrypted message in the text area</li>
            <li>Enter your private key passphrase if prompted</li>
            <li>Click 'Decrypt' to view the decrypted message</li>
        </ol>
        
        <h3>Verifying Signatures</h3>
        <p>When a message is signed, the application will automatically verify the signature 
        and show you the result. Make sure you have the sender's public key in your keyring 
        to verify their signature.</p>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_keys_tab(self):
        """Create the key management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        text = """
        <h2>Key Management</h2>
        
        <h3>Generating a New Key Pair</h3>
        <ol>
            <li>Go to the 'Keys' tab</li>
            <li>Click 'Generate New Key'</li>
            <li>Enter your name and email address</li>
            <li>Choose a strong passphrase</li>
            <li>Click 'Generate' and wait for the process to complete</li>
        </ol>
        
        <h3>Importing Keys</h3>
        <p>You can import public keys from files or by pasting them directly. 
        Always verify the fingerprint of any key before importing it.</p>
        
        <h3>Exporting Keys</h3>
        <p>You can export your public key to share with others or back up your private key. 
        Keep your private key secure and never share it.</p>
        
        <h3>Key Trust and Verification</h3>
        <p>Always verify the fingerprint of any key before trusting it. 
        You can sign other people's keys to indicate that you trust they are who they claim to be.</p>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_support_tab(self):
        """Create the support tab with donation information."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        monero_address = "47Jc6MC47WJVFhiQFYwHyBNQP5BEsjUPG6tc8R37FwcTY8K5Y3LvFzveSXoGiaDQSxDrnCUBJ5WBj6Fgmsfix8VPD4w3gXF"
        
        support_text = f"""
        <h2>Support OpenPGP Development</h2>
        <p>Thank you for considering supporting the development of OpenPGP! Your contribution helps ensure the continued improvement and maintenance of this open-source project.</p>
        
        <h3>Monero (XMR) Donation</h3>
        <p>You can support the project by donating Monero (XMR) to the following address:</p>
        
        <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; margin: 10px 0; font-family: monospace; word-break: break-all;">
            {monero_address}
        </div>
        
        <p>To copy the address, simply click on it and press Ctrl+C.</p>
        
        <h3>Other Ways to Contribute</h3>
        <ul>
            <li>Star the project on <a href="https://github.com/Nsfr750/OpenPGP">GitHub</a></li>
            <li>Report bugs and suggest new features</li>
            <li>Share the application with others</li>
            <li>Contribute code or documentation</li>
        </ul>
        
        <p>Your support is greatly appreciated!</p>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(support_text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_about_tab(self):
        """Create the about tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Get system information
        system = platform.system()
        release = platform.release()
        python_version = platform.python_version()
        
        about_text = f"""
        <div style="text-align: center;">
            <h2>OpenPGP</h2>
            <p>Version {VERSION}</p>
            <p>A secure and easy-to-use application for PGP encryption, decryption, and key management.</p>
            
            <h3>System Information</h3>
            <table style="margin: 0 auto; text-align: left;">
                <tr><td><b>Operating System:</b></td><td>{system} {release}</td></tr>
                <tr><td><b>Python Version:</b></td><td>{python_version}</td></tr>
            </table>
            
            <h3>License</h3>
            <p>© 2024-2025 Nsfr750 - All rights reserved</p>
            <p>Licensed under the GPL v3.0 License</p>
            
            <p>
                <a href="https://github.com/Nsfr750/OpenPGP">GitHub Repository</a> | 
                <a href="https://github.com/Nsfr750/OpenPGP/issues">Report Issues</a>
            </p>
        </div>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(about_text)
        
        layout.addWidget(text_browser)
        return widget
    
    def accept(self):
        """Handle dialog acceptance."""
        super().accept()
    
    def reject(self):
        """Handle dialog rejection."""
        super().reject()            
   
    def show_dialog(self):
        """Show the help dialog."""
        self.show()
        return self.exec_()
    
    def open_link(self, url):
        """
        Open a link in the default web browser.
        
        Args:
            url: QUrl of the link to open
        """
        try:
            QDesktopServices.openUrl(url)
        except Exception as e:
            logger.error(self.tr(
                "help.link_open_error",
                "Error opening link {url}: {error}"
            ).format(url=url.toString(), error=str(e)))
