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
    from .version import get_version
    VERSION = get_version()
except ImportError:
    VERSION = "2.2.0"

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
        self.tabs.addTab(self._create_security_tab(), "Security")
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
        decryption, and key management with advanced security features.</p>
        
        <h3>What's New in 2.2.0</h3>
        <h4>🔌 SIEM Integration</h4>
        <ul>
            <li><b>Real-time Monitoring</b>: Connect to Security Information and Event Management systems</li>
            <li><b>Centralized Logging</b>: Send security events to your SIEM for analysis</li>
            <li><b>Secure Authentication</b>: API key and OAuth2 support for SIEM connections</li>
            <li><b>Event Forwarding</b>: Forward security events in real-time</li>
        </ul>
        
        <h4>🔄 SCIM 2.0 Server</h4>
        <ul>
            <li><b>User Provisioning</b>: Automate user and group management</li>
            <li><b>Standard Compliance</b>: Full SCIM 2.0 protocol implementation</li>
            <li><b>Secure Authentication</b>: OAuth2 and API key support</li>
            <li><b>Audit Logging</b>: Track all provisioning events</li>
        </ul>
        
        <h4>🔒 Enhanced Security</h4>
        <ul>
            <li><b>Improved TPM 2.0 Support</b>: Better hardware security module integration</li>
            <li><b>Key Management</b>: Enhanced key rotation and lifecycle management</li>
            <li><b>Audit Logging</b>: Comprehensive security event tracking</li>
        </ul>
        
        <h3>Getting Started</h3>
        <ol>
            <li>Generate a new key pair (RSA, ECC, or Ed25519) or import existing keys</li>
            <li>Encrypt files or messages with public keys</li>
            <li>Decrypt received files with your private key or hardware token</li>
            <li>Manage your keys, contacts, and security settings</li>
        </ol>
        
        <h3>Quick Tips</h3>
        <ul>
            <li>Always keep your private key and hardware tokens secure</li>
            <li>Regularly back up your keys using the built-in backup feature</li>
            <li>Verify the fingerprint of public keys before using them</li>
            <li>Use hardware tokens for enhanced security of your private keys</li>
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
            <li>Go to the 'PGP Tools' tab</li>
            <li>Click 'Generate New Key'</li>
            <li>Select key type (RSA, ECC, or Ed25519)</li>
            <li>Enter your name and email address</li>
            <li>Choose a strong passphrase (use the strength meter as a guide)</li>
            <li>For hardware tokens, select 'Use Hardware Token' and follow the prompts</li>
            <li>Click 'Generate' and wait for the process to complete</li>
        </ol>
        
        <h3>Key Types</h3>
        <ul>
            <li><b>RSA</b>: Compatible with most PGP implementations</li>
            <li><b>ECC</b>: More efficient than RSA with similar security</li>
            <li><b>Ed25519</b>: Modern, high-security elliptic curve algorithm</li>
        </ul>
        
        <h3>Hardware Token Support</h3>
        <p>OpenPGP supports hardware security keys like YubiKey for storing your private keys securely.
        To use a hardware token:</p>
        <ol>
            <li>Insert your hardware token</li>
            <li>Select 'Use Hardware Token' when generating a new key</li>
            <li>Follow the on-screen instructions to set up your token</li>
            <li>Your private key will be stored securely on the token</li>
        </ol>
        
        <h3>Importing Keys</h3>
        <p>You can import public keys by:</p>
        <ul>
            <li>Clicking 'Import' and selecting a key file</li>
            <li>Pasting the key directly into the text area</li>
            <li>Dropping a key file into the application window</li>
        </ul>
        <p>Always verify the fingerprint of any key before importing it.</p>
        
        <h3>Exporting Keys</h3>
        <p>You can export your public key to share with others or back up your private key. 
        Keep your private key secure and never share it. For hardware tokens, the private key 
        cannot be exported - only the public key can be shared.</p>
        
        <h3>Key Backup and Recovery</h3>
        <p>Use the 'Backup Key' feature to create a secure backup of your key pair. 
        You can back up to a file or print a paper copy. Store backups in a secure location.</p>
        
        <h3>Key Trust and Verification</h3>
        <p>Always verify the fingerprint of any key before trusting it. 
        You can sign other people's keys to indicate that you trust they are who they claim to be.</p>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(text)
        
        layout.addWidget(text_browser)
        return widget
    
    def _create_security_tab(self):
        """Create the security features tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        text = """
        <h2>Security Features in OpenPGP</h2>
        
        <h3>🔌 SIEM Integration</h3>
        <p>Monitor and analyze security events in real-time with Security Information and Event Management integration.</p>
        <ul>
            <li><b>Real-time Monitoring</b>: Connect to SIEM solutions like Splunk, ELK, or Graylog</li>
            <li><b>Security Event Logging</b>: Track all security-relevant operations</li>
            <li><b>API Integration</b>: Secure API key and OAuth2 authentication</li>
            <li><b>Custom Alerts</b>: Configure alerts for suspicious activities</li>
        </ul>
        
        <h3>🔄 SCIM 2.0 Server</h3>
        <p>Automated user and group management with System for Cross-domain Identity Management.</p>
        <ul>
            <li><b>User Provisioning</b>: Automate user lifecycle management</li>
            <li><b>Group Management</b>: Synchronize group memberships</li>
            <li><b>Standard Protocol</b>: Full SCIM 2.0 compliance</li>
            <li><b>Secure Authentication</b>: OAuth2 and API key support</li>
        </ul>
        
        <h3>🔒 Hardware Security Module (HSM) Support</h3>
        <p>Enterprise-grade key protection with hardware security modules.</p>
        <ul>
            <li>Support for YubiKey and other PKCS#11 compatible devices</li>
            <li>Secure key generation directly on the hardware token</li>
            <li>PIN and touch protection for private key operations</li>
            <li>Hardware-backed encryption and signing operations</li>
        </ul>
        
        <h3>Secure File Operations</h3>
        <p>Enhanced file encryption with advanced security options:</p>
        <ul>
            <li>Multiple encryption algorithms (AES-256, ChaCha20, Twofish)</li>
            <li>File integrity verification with HMAC</li>
            <li>Automatic compression before encryption</li>
            <li>Secure file wiping after operations</li>
        </ul>
        
        <h3>Secure Messaging</h3>
        <p>End-to-end encrypted messaging with the following features:</p>
        <ul>
            <li>Asymmetric encryption using recipient's public key</li>
            <li>Digital signatures for message authentication</li>
            <li>Support for both text and file attachments</li>
            <li>Perfect Forward Secrecy (PFS) for enhanced security</li>
        </ul>
        
        <h3>Secure File Sharing</h3>
        <p>Securely share files with fine-grained access control:</p>
        <ul>
            <li>Password protection for shared files</li>
            <li>Expiration dates for shared links</li>
            <li>Recipient-based access control</li>
            <li>Download limits for shared files</li>
        </ul>
        
        <h3>Trust Model</h3>
        <p>Advanced trust management for PGP keys:</p>
        <ul>
            <li>Visual representation of trust relationships</li>
            <li>Web of Trust (WOT) visualization</li>
            <li>Trust level assignment for keys</li>
            <li>Automatic trust path validation</li>
        </ul>
        
        <h3>Best Practices</h3>
        <ul>
            <li>Always use hardware tokens for storing private keys when possible</li>
            <li>Regularly update your software to get the latest security patches</li>
            <li>Verify the identity of the people you communicate with</li>
            <li>Use strong, unique passphrases for your keys</li>
            <li>Regularly back up your keys and important data</li>
            <li>Enable SIEM integration for centralized security monitoring</li>
            <li>Use SCIM for automated user and group management</li>
            <li>Review audit logs regularly for suspicious activities</li>
        </ul>
        """
        
        text_browser = QTextBrowser()
        text_browser.setOpenExternalLinks(True)
        text_browser.setHtml(text)
        
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
            <h2>OpenPGP v{VERSION}</h2>
            <p>A secure and easy-to-use application for PGP encryption, decryption, and key management.</p>
            
            <h3>System Information</h3>
            <table style="margin: 0 auto; text-align: left;">
                <tr><td><b>Operating System:</b></td><td>{system} {release}</td></tr>
                <tr><td><b>Python Version:</b></td><td>{python_version}</td></tr>
                <tr><td><b>Key Types:</b></td><td>RSA, ECC, Ed25519</td></tr>
                <tr><td><b>Hardware Tokens:</b></td><td>YubiKey and compatible</td></tr>
            </table>
            
            <h3>Features</h3>
            <ul style="text-align: left; display: inline-block;">
                <li>Secure key generation and management</li>
                <li>File and message encryption/decryption</li>
                <li>Digital signatures and verification</li>
                <li>Hardware token support</li>
                <li>Drag and drop interface</li>
                <li>Key backup and recovery</li>
            </ul>
            
            <h3>License</h3>
            <p>© Copyright 2024-2025 Nsfr750. All Rights Reserved</p>
            <p>Licensed under the GPL v3.0 License</p>
            
            <p>
                <a href="https://github.com/Nsfr750/OpenPGP">GitHub Repository</a> | 
                <a href="https://github.com/Nsfr750/OpenPGP/wiki">Wiki Pages</a> | 
                <a href="https://github.com/Nsfr750/OpenPGP/issues">Report Issues</a> |
                <a href="https://github.com/Nsfr750/OpenPGP/releases">Release Notes</a>
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
