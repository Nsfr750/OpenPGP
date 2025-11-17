import sys
import os
from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
    QMessageBox, QFileDialog, QApplication, QSizePolicy, QFrame, 
    QSpinBox, QGroupBox, QFormLayout, QSplitter, QInputDialog, QProgressBar,
    QDialog
)
from PySide6.QtCore import Qt, QSize, Signal, Slot, QSettings, QMimeData, QUrl
from PySide6.QtGui import (
    QFont, QTextCursor, QClipboard, QGuiApplication, 
    QPalette, QColor, QIcon, QAction, QKeySequence,
    QPixmap
)

from .menu import MenuBar
from .key_backup_dialog import KeyBackupDialog
from .identity_tab import IdentityTab
from .key_management import KeyManagementTab
from .security import SecurityTab
from .verifiable_credentials_tab import VerifiableCredentialsTab
from .dialogs.tpm_settings_dialog import TpmSettingsDialog

from core.password_utils import PasswordGenerator, generate_pbkdf2_hash, verify_password
from pgpy import PGPKey
from core.openpgp import (
    generate_pgp_keypair, save_pgp_key, load_pgp_key,
    encrypt_message, decrypt_message, sign_message, 
    verify_signature, generate_ssl_cert
)
from core.scim.server import SCIMServer
from core.siem.client import SIEMClient
import logging

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpenPGP - Secure Password Manager")
        self.setMinimumSize(1024, 768)
        
        # Enable drag and drop
        self.setAcceptDrops(True)
        
        # Initialize password generator
        self.pw_generator = PasswordGenerator()
        self.current_hash_details = None
        
        # PGP related attributes
        self.private_key = None
        self.public_key = None
        self.key_loaded = False
        
        # Server management
        self.scim_server = None
        self.scim_running = False
        self.siem_client = None
        self.siem_connected = False
        
        # Track the last active tab for drag and drop
        self.last_active_tab_index = 0
        
        # Set up the main widget and layout
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout()
        self.main_widget.setLayout(self.main_layout)
        self.setCentralWidget(self.main_widget)
        
        # Create menu bar
        self.create_menu()
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create and add tabs
        self.password_tab = self.create_password_tab()
        self.pgp_tab = self.create_pgp_tab()
        self.identity_tab = IdentityTab()
        self.key_management_tab = KeyManagementTab()
        self.security_tab = SecurityTab()
        self.verifiable_credentials_tab = VerifiableCredentialsTab()
        
        self.tabs.addTab(self.password_tab, "Password Tools")
        self.tabs.addTab(self.pgp_tab, "PGP Tools")
        self.tabs.addTab(self.identity_tab, "Identity")
        self.tabs.addTab(self.key_management_tab, "Key Management")
        self.tabs.addTab(self.security_tab, "Security")
        self.tabs.addTab(self.verifiable_credentials_tab, "Verifiable Credentials")
        self.tabs.addTab(self.create_tpm_tab(), "TPM Settings")
        
        # Connect tab changed signal
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Load settings
        self.settings = QSettings("OpenPGP", "OpenPGP")
        self.load_settings()
        
    def create_menu(self):
        """Create the menu bar."""
        # Create and set the custom menu bar
        self.menu_bar = MenuBar(self)
        self.setMenuBar(self.menu_bar)
        
        # Connect menu signals
        self.menu_bar.signals.export_pubkey.connect(self.export_public_key)
        self.menu_bar.signals.backup_key.connect(self.backup_key)
        self.menu_bar.signals.recover_key.connect(self.recover_key)
        self.menu_bar.signals.quit_app.connect(self.close)
        
        # Connect server management signals
        self.menu_bar.signals.start_scim.connect(self.start_scim_server)
        self.menu_bar.signals.stop_scim.connect(self.stop_scim_server)
        self.menu_bar.signals.connect_siem.connect(self.connect_siem)
        self.menu_bar.signals.disconnect_siem.connect(self.disconnect_siem)
        
    def export_public_key(self):
        """Export the public key to a file."""
        if not self.key_loaded or not self.public_key:
            QMessageBox.warning(self, "Warning", "No public key available to export")
            return
            
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Public Key",
                "",
                "PGP Public Key (*.asc *.gpg *.pgp);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(str(self.public_key))
                self.statusBar().showMessage(f"Public key exported to {file_path}", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export public key: {str(e)}")
            
    def backup_key(self):
        """Back up the private key with recovery options."""
        if not self.key_loaded or not self.private_key:
            QMessageBox.warning(self, "Warning", "No private key available to back up")
            return
            
        try:
            dialog = KeyBackupDialog(self, self.private_key)
            dialog.backup_created.connect(self.on_backup_created)
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create key backup: {str(e)}")
    
    def on_backup_created(self, backup_info):
        """Handle successful backup creation."""
        self.statusBar().showMessage(
            f"Key backup created successfully at {backup_info['timestamp']}", 
            5000
        )
    
    def recover_key(self):
        """Recover a private key from backup."""
        try:
            dialog = KeyBackupDialog(self)
            if dialog.exec_() == QDialog.Accepted and hasattr(dialog, 'private_key'):
                self.private_key = dialog.private_key
                self.public_key = self.private_key.pubkey
                self.key_loaded = True
                
                # Update key info
                key_fingerprint = self.public_key.fingerprint
                formatted_fingerprint = ' '.join([key_fingerprint[i:i+4] for i in range(0, len(key_fingerprint), 4)])
                key_info = f"Recovered Key:\nFingerprint: {formatted_fingerprint}"
                self.key_info.setText(key_info)
                
                self.statusBar().showMessage("Key recovered successfully", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to recover key: {str(e)}")
    
    def update_passphrase_strength(self, text):
        """Update the passphrase strength indicator."""
        from core.passphrase_manager import PassphraseManager
        
        if not text:
            self.strength_bar.setValue(0)
            self.strength_label.clear()
            return
            
        try:
            pm = PassphraseManager()
            strength, feedback = pm.check_passphrase_strength(text)
            
            # Update progress bar
            self.strength_bar.setValue(int(strength * 100))
            
            # Set color based on strength
            if strength < 0.4:
                color = "#ff4444"  # Red
                label = "Weak"
            elif strength < 0.7:
                color = "#ffaa00"  # Orange
                label = "Moderate"
            else:
                color = "#44aa44"  # Green
                label = "Strong"
                
            # Add feedback if any
            if feedback:
                label += f" - {feedback}"
                
            self.strength_bar.setStyleSheet(f"""
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 2px;
                }}
            """)
            
            self.strength_label.setText(label)
            
        except Exception as e:
            self.strength_bar.setValue(0)
            self.strength_label.setText("Error checking strength")
        
    def load_settings(self):
        """Load application settings."""
        # Restore window geometry
        self.restoreGeometry(self.settings.value("geometry", self.saveGeometry()))
        self.restoreState(self.settings.value("windowState", self.saveState()))
        
    def start_scim_server(self):
        """Start the SCIM server."""
        try:
            if not self.scim_server:
                from fastapi import FastAPI
                from uvicorn import Config, Server
                import asyncio
                
                # Create FastAPI app
                app = FastAPI(title="OpenPGP SCIM Server")
                base_url = "/scim/v2"  # Standard SCIM 2.0 base URL
                
                # Initialize SCIM server
                self.scim_server = SCIMServer(app=app, base_url=base_url)
                
                # Store the server instance
                self.scim_uvicorn_config = Config(
                    app=app,
                    host="127.0.0.1",
                    port=8000,
                    log_level="info"
                )
                self.scim_server_instance = Server(self.scim_uvicorn_config)
                
                # Start the server in a separate thread
                import threading
                self.scim_server_thread = threading.Thread(
                    target=lambda: asyncio.run(self.scim_server_instance.serve()),
                    daemon=True
                )
                self.scim_server_thread.start()
                
            self.scim_running = True
            self.update_server_ui()
            self.statusBar().showMessage("SCIM server started on http://127.0.0.1:8000", 3000)
            logging.info("SCIM server started successfully")
            
        except Exception as e:
            self.scim_running = False
            error_msg = f"Failed to start SCIM server: {str(e)}"
            QMessageBox.critical(self, "Error", error_msg)
            logging.error(error_msg, exc_info=True)
            self.update_server_ui()

    def stop_scim_server(self):
        """Stop the SCIM server."""
        try:
            if hasattr(self, 'scim_server_instance') and self.scim_server_instance:
                self.scim_server_instance.should_exit = True
                if hasattr(self, 'scim_server_thread') and self.scim_server_thread.is_alive():
                    self.scim_server_thread.join(timeout=5)
                    
            self.scim_running = False
            self.update_server_ui()
            self.statusBar().showMessage("SCIM server stopped", 3000)
            logging.info("SCIM server stopped")
        except Exception as e:
            error_msg = f"Failed to stop SCIM server: {str(e)}"
            QMessageBox.critical(self, "Error", error_msg)
            logging.error(error_msg, exc_info=True)

    def connect_siem(self):
        """Connect to SIEM."""
        try:
            if not self.siem_client:
                # Get SIEM configuration from user
                from PySide6.QtWidgets import QInputDialog, QLineEdit
                base_url, ok = QInputDialog.getText(
                    self,
                    "Connect to SIEM",
                    "Enter SIEM server URL:",
                    QLineEdit.EchoMode.Normal,
                    "https://"
                )
                
                if not ok or not base_url:
                    return
                    
                api_key, ok = QInputDialog.getText(
                    self,
                    "SIEM Authentication",
                    "Enter API Key (leave empty if not required):",
                    QLineEdit.EchoMode.Password
                )
                
                if not ok:  # User cancelled
                    return
                    
                # Import the global SIEM client
                from core.siem.client import init_siem_client, siem_client
                init_siem_client(base_url=base_url, api_key=api_key if api_key else None)
                self.siem_client = siem_client
                
            # Test the connection
            import asyncio
            from core.siem.client import siem_client
            
            async def test_connection():
                try:
                    # Try to make a simple request to test the connection
                    async with siem_client.client:
                        response = await siem_client.client.get(
                            f"{siem_client.base_url}/api/v1/health",
                            headers=siem_client._get_headers()
                        )
                        response.raise_for_status()
                        return True
                except Exception as e:
                    return False
                    
            # Run the async test in the event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            connection_ok = loop.run_until_complete(test_connection())
            loop.close()
            
            if not connection_ok:
                raise Exception("Failed to connect to SIEM server")
                
            self.siem_connected = True
            self.update_server_ui()
            self.statusBar().showMessage("Connected to SIEM", 3000)
            logging.info("Successfully connected to SIEM")
            
        except Exception as e:
            self.siem_connected = False
            error_msg = f"Failed to connect to SIEM: {str(e)}"
            QMessageBox.critical(self, "Error", error_msg)
            logging.error(error_msg, exc_info=True)
            self.update_server_ui()

    def disconnect_siem(self):
        """Disconnect from SIEM."""
        try:
            if self.siem_client:
                # Close the HTTP client
                import asyncio
                
                async def close_client():
                    await self.siem_client.client.aclose()
                    
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(close_client())
                loop.close()
                
            self.siem_connected = False
            self.siem_client = None
            self.update_server_ui()
            self.statusBar().showMessage("Disconnected from SIEM", 3000)
            logging.info("Disconnected from SIEM")
        except Exception as e:
            error_msg = f"Error disconnecting from SIEM: {str(e)}"
            QMessageBox.critical(self, "Error", error_msg)
            logging.error(error_msg, exc_info=True)

    def update_server_ui(self):
        """Update the UI based on server and SIEM connection states."""
        if hasattr(self, 'menu_bar'):
            # Update SCIM server menu items
            self.menu_bar.start_scim_action.setEnabled(not self.scim_running)
            self.menu_bar.stop_scim_action.setEnabled(self.scim_running)
            
            # Update SIEM connection menu items
            self.menu_bar.connect_siem_action.setEnabled(not self.siem_connected)
            self.menu_bar.disconnect_siem_action.setEnabled(self.siem_connected)
            
            # Update status bar
            scim_status = "Running" if self.scim_running else "Stopped"
            siem_status = "Connected" if self.siem_connected else "Disconnected"
            self.statusBar().showMessage(f"SCIM: {scim_status} | SIEM: {siem_status}")

    def closeEvent(self, event):
        """Handle window close event."""
        try:
            # Stop SCIM server if running
            if hasattr(self, 'scim_running') and self.scim_running:
                self.stop_scim_server()
                
            # Disconnect from SIEM if connected
            if hasattr(self, 'siem_connected') and self.siem_connected:
                self.disconnect_siem()
                
            # Save window state and geometry
            self.settings.setValue("windowState", self.saveState())
            self.settings.setValue("geometry", self.saveGeometry())
            
            # Save splitter state if it exists
            if hasattr(self, 'splitter') and self.splitter:
                self.settings.setValue("splitterState", self.splitter.saveState())
                
        except Exception as e:
            logging.error(f"Error during application shutdown: {str(e)}", exc_info=True)
            
        # Proceed with normal close
        event.accept()
        
    def on_tab_changed(self, index):
        """Handle tab changes to track the active tab for drag and drop."""
        self.last_active_tab_index = index
    
    def dragEnterEvent(self, event):
        """Handle drag enter event."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dragMoveEvent(self, event):
        """Handle drag move event."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        """Handle drop event."""
        if not event.mimeData().hasUrls():
            return
            
        urls = event.mimeData().urls()
        if not urls:
            return
            
        # Get the first file path
        file_path = urls[0].toLocalFile()
        if not file_path:
            return
            
        # Handle based on current tab
        if self.last_active_tab_index == 0:  # Password Tools tab
            self.handle_password_tab_drop(file_path)
        else:  # PGP Tools tab
            self.handle_pgp_tab_drop(file_path, event.pos())
    
    def handle_password_tab_drop(self, file_path):
        """Handle file drop on Password Tools tab."""
        # Check if the file is a password file or hash file
        if file_path.lower().endswith(('.txt', '.hash', '.json')):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Set the content to the appropriate field based on context
                if hasattr(self, 'password_input') and self.password_input:
                    self.password_input.setText(content)
                elif hasattr(self, 'message_input') and self.message_input:
                    self.message_input.setPlainText(content)
                    
                self.statusBar().showMessage(f"Loaded content from {file_path}", 3000)
                
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Error Loading File",
                    f"Could not load file: {str(e)}"
                )
    
    def handle_pgp_tab_drop(self, file_path, drop_position):
        """Handle file drop on PGP Tools tab."""
        try:
            # Check if it's a key file
            if file_path.lower().endswith(('.asc', '.gpg', '.pgp', '.key')):
                self.load_key_from_file(file_path)
            # Check if it's a file to encrypt/decrypt
            elif os.path.isfile(file_path):
                # Determine if we should encrypt or decrypt based on file extension
                if file_path.lower().endswith(('.pgp', '.gpg', '.asc')):
                    self.decrypt_file(file_path)
                else:
                    self.encrypt_file(file_path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error Processing File",
                f"Could not process {file_path}: {str(e)}"
            )
    
    def load_key_from_file(self, file_path):
        """Load a PGP key from a file."""
        try:
            # Read the key file
            with open(file_path, 'r', encoding='utf-8') as f:
                key_data = f.read().strip()
            
            from pgpy import PGPKey
            
            # Try to load as private key first
            try:
                self.private_key, _ = PGPKey.from_blob(key_data)
                self.public_key = self.private_key.pubkey
                key_type = "private"
            except Exception as e1:
                # If loading as private key fails, try as public key
                try:
                    self.private_key = None
                    self.public_key, _ = PGPKey.from_blob(key_data)
                    key_type = "public"
                except Exception as e2:
                    # Try one more time with the raw key data
                    try:
                        if 'PRIVATE KEY' in key_data:
                            self.private_key = PGPKey()
                            self.private_key.parse(key_data)
                            self.public_key = self.private_key.pubkey
                            key_type = "private"
                        else:
                            self.private_key = None
                            self.public_key = PGPKey()
                            self.public_key.parse(key_data)
                            key_type = "public"
                    except Exception as e3:
                        raise ValueError(f"Failed to parse key: {e1}\n{e2}\n{e3}")
            
            if not hasattr(self, 'public_key') or self.public_key is None:
                raise ValueError("Failed to load any valid PGP key from the file")
            
            self.key_loaded = True
            
            # Update UI
            key_fingerprint = self.public_key.fingerprint
            if key_fingerprint:
                formatted_fingerprint = ' '.join([key_fingerprint[i:i+4] for i in range(0, len(key_fingerprint), 4)])
                key_info = f"Loaded {key_type} key:\nFingerprint: {formatted_fingerprint}"
            else:
                key_info = f"Loaded {key_type} key (no fingerprint available)"
            
            if hasattr(self, 'key_info'):
                self.key_info.setText(key_info)
                
            self.statusBar().showMessage(f"Successfully loaded {key_type} key from {file_path}", 3000)
            return True
            
        except Exception as e:
            error_msg = f"Could not load key from {file_path}.\n\nError: {str(e)}"
            logger.error(f"Failed to load key: {error_msg}")
            QMessageBox.warning(
                self,
                "Error Loading Key",
                error_msg
            )
            return False
    
    def encrypt_file(self, file_path):
        """Encrypt a file using the loaded public key."""
        if not self.key_loaded or not self.public_key:
            QMessageBox.warning(
                self,
                "No Key Loaded",
                "Please load a public key before encrypting files."
            )
            return
            
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Encrypt the content
            encrypted_data = encrypt_message(file_content.decode('utf-8'), self.public_key)
            
            # Save the encrypted file
            output_path = f"{file_path}.gpg"
            with open(output_path, 'w') as f:
                f.write(str(encrypted_data))
                
            self.statusBar().showMessage(f"File encrypted and saved as {output_path}", 5000)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Encryption Failed",
                f"Failed to encrypt file: {str(e)}"
            )
    
    def decrypt_file(self, file_path):
        """Decrypt a file using the loaded private key."""
        if not self.key_loaded or not self.private_key:
            QMessageBox.warning(
                self,
                "No Private Key",
                "Please load a private key before decrypting files."
            )
            return
            
        try:
            # Read the encrypted file
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            
            # Get passphrase if key is protected
            passphrase = None
            if self.private_key.is_protected:
                passphrase, ok = QInputDialog.getText(
                    self,
                    "Enter Passphrase",
                    "The private key is protected. Please enter the passphrase:",
                    QLineEdit.Password
                )
                
                if not ok or not passphrase:
                    return
            
            # Decrypt the content
            decrypted_data = decrypt_message(encrypted_data, self.private_key, passphrase or None)
            
            # Determine output path
            output_path = file_path
            for ext in ['.pgp', '.gpg', '.asc']:
                if output_path.lower().endswith(ext):
                    output_path = output_path[:-len(ext)]
                    break
            
            # Save the decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data.encode('utf-8'))
                
            self.statusBar().showMessage(f"File decrypted and saved as {output_path}", 5000)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to decrypt file: {str(e)}"
            )
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItem("RSA", "RSA")
        self.key_type_combo.addItem("ECC (EdDSA)", "ECC")
        self.key_type_combo.currentIndexChanged.connect(self.update_key_size_options)
        form_layout.addRow("Key Type:", self.key_type_combo)
        
        # Key Size Selection
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItem("2048 bits", 2048)
        self.key_size_combo.addItem("3072 bits", 3072)
        self.key_size_combo.addItem("4096 bits", 4096)
        form_layout.addRow("Key Size:", self.key_size_combo)
        
        # Curve Selection (initially hidden)
        self.curve_combo = QComboBox()
        self.curve_combo.addItem("ed25519", "ed25519")
        self.curve_combo.addItem("nistp256", "nistp256")
        self.curve_combo.addItem("nistp384", "nistp384")
        self.curve_combo.addItem("nistp521", "nistp521")
        self.curve_combo.setVisible(False)
        form_layout.addRow("Curve:", self.curve_combo)
        
        # Passphrase with strength indicator
        passphrase_widget = QWidget()
        passphrase_layout = QVBoxLayout(passphrase_widget)
        passphrase_layout.setContentsMargins(0, 0, 0, 0)
        passphrase_layout.setSpacing(2)
        
        # Create a container widget for the passphrase field
        passphrase_container = QWidget()
        passphrase_container_layout = QVBoxLayout(passphrase_container)
        passphrase_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setPlaceholderText("Enter a strong passphrase")
        self.passphrase_edit.setEchoMode(QLineEdit.Password)
        self.passphrase_edit.textChanged.connect(self.update_passphrase_strength)
        
        # Strength indicator
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(4)
        
        self.strength_label = QLabel()
        self.strength_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.strength_label.setStyleSheet("font-size: 9px; color: #888;")
        
        # Add widgets to the container
        passphrase_container_layout.addWidget(self.passphrase_edit)
        passphrase_container_layout.addWidget(self.strength_bar)
        passphrase_container_layout.addWidget(self.strength_label)
        
        # Add container to the main layout
        passphrase_layout.addWidget(passphrase_container)
        
        # Add to form
        form_layout.addRow("Passphrase:", passphrase_widget)
        
        key_layout.addLayout(form_layout)
        
        # Key Actions
        btn_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate Key")
        self.generate_btn.clicked.connect(self.generate_key)
        btn_layout.addWidget(self.generate_btn)
        
        self.load_btn = QPushButton("Load Key")
        self.load_btn.clicked.connect(self.load_key)
        btn_layout.addWidget(self.load_btn)
        
        key_layout.addLayout(btn_layout)
        
        # Key Info
        self.key_info = QTextEdit()
        self.key_info.setReadOnly(True)
        self.key_info.setMaximumHeight(100)
        key_layout.addWidget(QLabel("Key Information:"))
        key_layout.addWidget(self.key_info)
        
        key_group.setLayout(key_layout)
        
        # Message Group
        msg_group = QGroupBox("Message")
        msg_layout = QVBoxLayout()
        
        # Message input with drag and drop support
        class MessageTextEdit(QTextEdit):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.setAcceptDrops(True)
                self.setPlaceholderText("Enter message to encrypt/decrypt or sign/verify here...\n\nYou can also drag and drop a file here to load its content.")
                self.setToolTip("Drag and drop a file to load its content")
            
            def dragEnterEvent(self, event):
                if event.mimeData().hasUrls():
                    event.acceptProposedAction()
            
            def dropEvent(self, event):
                urls = event.mimeData().urls()
                if urls:
                    file_path = urls[0].toLocalFile()
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            self.setPlainText(content)
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Could not load file: {str(e)}")
        
        self.message_input = MessageTextEdit()
        msg_layout.addWidget(self.message_input)
        
        # Buttons
        btn_layout2 = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_message)
        btn_layout2.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_message)
        btn_layout2.addWidget(self.decrypt_btn)
        
        self.sign_btn = QPushButton("Sign")
        self.sign_btn.clicked.connect(self.sign_message)
        btn_layout2.addWidget(self.sign_btn)
        
        self.verify_btn = QPushButton("Verify")
        self.verify_btn.clicked.connect(self.verify_message)
        btn_layout2.addWidget(self.verify_btn)
        
        msg_layout.addLayout(btn_layout2)
        
        # Output
        self.message_output = QTextEdit()
        self.message_output.setReadOnly(True)
        self.message_output.setPlaceholderText("Results will appear here...")
        msg_layout.addWidget(self.message_output)
        
        msg_group.setLayout(msg_layout)
        
        # Add groups to layout
        layout.addWidget(key_group)
        layout.addWidget(msg_group)
        layout.addStretch()
        
        return tab
        
    def create_pgp_tab(self):
        """Create the PGP tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Key Management Group
        key_group = QGroupBox("PGP Key Management")
        key_layout = QVBoxLayout()
        
        # Key Generation
        gen_group = QGroupBox("Key Generation")
        gen_layout = QFormLayout()
        
        # Name and Email
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Your Name")
        gen_layout.addRow("Name:", self.name_edit)
        
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("your.email@example.com")
        gen_layout.addRow("Email:", self.email_edit)
        
        # Key Type Selection
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItem("RSA", "RSA")
        self.key_type_combo.addItem("ECC (EdDSA)", "ECC")
        self.key_type_combo.currentIndexChanged.connect(self.update_key_size_options)
        gen_layout.addRow("Key Type:", self.key_type_combo)
        
        # Key Size Selection
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItem("2048 bits", 2048)
        self.key_size_combo.addItem("3072 bits", 3072)
        self.key_size_combo.addItem("4096 bits", 4096)
        gen_layout.addRow("Key Size:", self.key_size_combo)
        
        # Curve Selection (initially hidden)
        self.curve_combo = QComboBox()
        self.curve_combo.addItem("ed25519", "ed25519")
        self.curve_combo.addItem("ed448", "ed448")
        self.curve_combo.addItem("nistp256", "nistp256")
        self.curve_combo.addItem("nistp384", "nistp384")
        self.curve_combo.addItem("nistp521", "nistp521")
        gen_layout.addRow("Curve:", self.curve_combo)
        self.curve_combo.setVisible(False)  # Hidden by default
        
        # Key Generation Button
        self.generate_btn = QPushButton("Generate Key Pair")
        self.generate_btn.clicked.connect(self.generate_key)
        gen_layout.addRow(self.generate_btn)
        
        gen_group.setLayout(gen_layout)
        key_layout.addWidget(gen_group)
        
        # Key Loading
        load_group = QGroupBox("Load Existing Keys")
        load_layout = QVBoxLayout()
        
        self.load_btn = QPushButton("Load Key Pair")
        self.load_btn.clicked.connect(self.load_key)
        load_layout.addWidget(self.load_btn)
        
        self.key_status = QLabel("No key loaded")
        self.key_status.setWordWrap(True)
        load_layout.addWidget(self.key_status)
        
        load_group.setLayout(load_layout)
        key_layout.addWidget(load_group)
        
        key_group.setLayout(key_layout)
        
        # Message Group
        msg_group = QGroupBox("Message Operations")
        msg_layout = QVBoxLayout()
        
        # Message Input
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Enter message to encrypt/decrypt or sign/verify here...")
        self.message_input.setAcceptDrops(True)
        
        # Operation Buttons
        btn_layout = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_message)
        btn_layout.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_message)
        btn_layout.addWidget(self.decrypt_btn)
        
        self.sign_btn = QPushButton("Sign")
        self.sign_btn.clicked.connect(self.sign_message)
        btn_layout.addWidget(self.sign_btn)
        
        self.verify_btn = QPushButton("Verify")
        self.verify_btn.clicked.connect(self.verify_message)
        btn_layout.addWidget(self.verify_btn)
        
        # Add widgets to message group
        msg_layout.addWidget(self.message_input)
        msg_layout.addLayout(btn_layout)
        msg_group.setLayout(msg_layout)
        
        # Add groups to main layout
        layout.addWidget(key_group)
        layout.addWidget(msg_group)
        layout.addStretch()
        
        # Initialize key loaded state
        self.key_loaded = False
        self.private_key = None
        self.public_key = None
        
        # Set initial key size options
        self.update_key_size_options()
        
        return tab
        
    def create_password_tab(self):
        """Create the password tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Password Generation Group
        gen_group = QFrame()
        gen_group.setFrameShape(QFrame.StyledPanel)
        gen_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        gen_layout = QVBoxLayout(gen_group)
        
        # Title
        title = QLabel("Password Generator")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        gen_layout.addWidget(title)
        
        # Password length
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        
        # Character sets
        self.lower_check = QCheckBox("a-z")
        self.lower_check.setChecked(True)
        self.upper_check = QCheckBox("A-Z")
        self.upper_check.setChecked(True)
        self.digits_check = QCheckBox("0-9")
        self.digits_check.setChecked(True)
        self.symbols_check = QCheckBox("!@#$")
        self.symbols_check.setChecked(True)
        
        # Custom characters
        custom_layout = QHBoxLayout()
        custom_label = QLabel("Custom:")
        self.custom_chars = QLineEdit()
        self.custom_chars.setPlaceholderText("Custom characters")
        custom_layout.addWidget(custom_label)
        custom_layout.addWidget(self.custom_chars)
        
        # Generate button
        gen_btn = QPushButton("Generate Password")
        gen_btn.clicked.connect(self.generate_password)
        
        # Password input with drag and drop support
        class PasswordLineEdit(QLineEdit):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.setAcceptDrops(True)
                self.setPlaceholderText("Enter password to hash or drop a text file here")
                self.setEchoMode(QLineEdit.Password)
                self.setToolTip("Drag and drop a text file to load its content")
            
            def dragEnterEvent(self, event):
                if event.mimeData().hasUrls():
                    urls = event.mimeData().urls()
                    if urls and urls[0].toLocalFile().lower().endswith(('.txt', '.hash', '.json')):
                        event.acceptProposedAction()
            
            def dropEvent(self, event):
                urls = event.mimeData().urls()
                if urls:
                    file_path = urls[0].toLocalFile()
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            self.setText(content)
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Could not load file: {str(e)}")
        
        self.password_input = PasswordLineEdit()
        form_layout = QFormLayout()
        form_layout.addRow("Password:", self.password_input)
        
        gen_layout.addLayout(length_layout)
        
        char_layout = QHBoxLayout()
        char_layout.addWidget(self.lower_check)
        char_layout.addWidget(self.upper_check)
        char_layout.addWidget(self.digits_check)
        char_layout.addWidget(self.symbols_check)
        
        gen_layout.addLayout(char_layout)
        gen_layout.addLayout(custom_layout)
        gen_layout.addWidget(gen_btn)
        gen_layout.addLayout(form_layout)
        
        # Password display
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setEchoMode(QLineEdit.Password)
        self.password_display.setStyleSheet("font-family: 'Courier New'; font-size: 12pt;")
        
        # Password actions
        btn_layout = QHBoxLayout()
        self.show_btn = QPushButton("Show")
        self.show_btn.setCheckable(True)
        self.show_btn.toggled.connect(self.toggle_password_visibility)
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy_password)
        
        btn_layout.addWidget(self.show_btn)
        btn_layout.addWidget(copy_btn)
        
        # Add widgets to generation layout
        gen_layout.addLayout(length_layout)
        
        char_layout = QHBoxLayout()
        char_layout.addWidget(self.lower_check)
        char_layout.addWidget(self.upper_check)
        char_layout.addWidget(self.digits_check)
        char_layout.addWidget(self.symbols_check)
        
        gen_layout.addLayout(char_layout)
        gen_layout.addLayout(custom_layout)
        gen_layout.addWidget(gen_btn)
        gen_layout.addWidget(self.password_display)
        gen_layout.addLayout(btn_layout)
        
        # Hash Generation Group
        hash_group = QFrame()
        hash_group.setFrameShape(QFrame.StyledPanel)
        hash_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        hash_layout = QVBoxLayout(hash_group)
        
        hash_title = QLabel("Password Hashing")
        hash_title.setFont(QFont("Arial", 12, QFont.Bold))
        hash_layout.addWidget(hash_title)
        
        # Password to hash
        hash_pw_layout = QHBoxLayout()
        hash_pw_label = QLabel("Password:")
        self.hash_password = QLineEdit()
        self.hash_password.setEchoMode(QLineEdit.Password)
        hash_pw_layout.addWidget(hash_pw_label)
        hash_pw_layout.addWidget(self.hash_password)
        
        # Hash button
        hash_btn = QPushButton("Generate Hash")
        hash_btn.clicked.connect(self.generate_hash)
        
        # Hash display
        self.hash_display = QTextEdit()
        self.hash_display.setReadOnly(True)
        self.hash_display.setMaximumHeight(80)
        
        # Copy hash button
        copy_hash_btn = QPushButton("Copy Hash")
        copy_hash_btn.clicked.connect(self.copy_hash)
        
        # Hash details
        self.hash_details = QLabel()
        self.hash_details.setWordWrap(True)
        self.hash_details.setStyleSheet("color: #666; font-size: 10pt;")
        
        # Add widgets to hash layout
        hash_layout.addLayout(hash_pw_layout)
        hash_layout.addWidget(hash_btn)
        hash_layout.addWidget(self.hash_display)
        hash_layout.addWidget(copy_hash_btn)
        hash_layout.addWidget(self.hash_details)
        
        # Verification Group
        verify_group = QFrame()
        verify_group.setFrameShape(QFrame.StyledPanel)
        verify_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        verify_layout = QVBoxLayout(verify_group)
        
        verify_title = QLabel("Verify Password")
        verify_title.setFont(QFont("Arial", 12, QFont.Bold))
        verify_layout.addWidget(verify_title)
        
        # Password to verify
        verify_pw_layout = QHBoxLayout()
        verify_pw_label = QLabel("Password:")
        self.verify_password = QLineEdit()
        self.verify_password.setEchoMode(QLineEdit.Password)
        verify_pw_layout.addWidget(verify_pw_label)
        verify_pw_layout.addWidget(self.verify_password)
        
        # Verify button
        verify_btn = QPushButton("Verify")
        verify_btn.clicked.connect(self.verify_password_handler)
        
        # Verification result
        self.verify_result = QLabel()
        self.verify_result.setStyleSheet("font-weight: bold;")
        
        # Add widgets to verify layout
        verify_layout.addLayout(verify_pw_layout)
        verify_layout.addWidget(verify_btn)
        verify_layout.addWidget(self.verify_result)
        
        # Add all groups to main layout
        layout.addWidget(gen_group)
        layout.addWidget(hash_group)
        layout.addWidget(verify_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return tab
    
    def apply_dark_theme(self):
        """Apply dark theme to the application."""
        # Set the style to Fusion for better theming support
        from PySide6.QtWidgets import QStyleFactory
        app = QApplication.instance()
        app.setStyle(QStyleFactory.create('Fusion'))
        
        # Create a dark palette
        dark_palette = QPalette()
        
        # Base colors
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.white)
        
        # Disabled colors
        dark_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(127, 127, 127))
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(127, 127, 127))
        
        # Apply the palette
        QApplication.setPalette(dark_palette)
        
        # Additional styling
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #232629;
            }
            QTabWidget::pane {
                border: 1px solid #2A2D32;
                border-radius: 3px;
                padding: 0px;
                background: #2A2D32;
                margin-top: 2px;
            }
            QTabBar {
                background: #31363B;
                border: none;
            }
            QTabBar::tab {
                background: #31363B;
                color: #EFF0F1;
                padding: 8px 20px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                border: 1px solid #2A2D32;
                margin-right: 2px;
            }
            QTabBar::tab:selected, QTabBar::tab:hover {
                background: #3DAEE9;
                color: #FCFCFC;
                border-bottom: 2px solid #3DAEE9;
            }
            QTabBar::tab:!selected {
                margin-top: 2px;
            }
            QGroupBox {
                border: 1px solid #3A3F44;
                border-radius: 4px;
                margin-top: 1.5em;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTextEdit, QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
                background-color: #31363B;
                color: #EFF0F1;
                border: 1px solid #3A3F44;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #3DAEE9;
            }
            QPushButton {
                background-color: #3A3F44;
                color: #EFF0F1;
                border: 1px solid #2A2D32;
                border-radius: 3px;
                padding: 5px 10px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #4D5257;
                border: 1px solid #6D6F73;
            }
            QPushButton:pressed {
                background-color: #2A2D32;
            }
            QPushButton:disabled {
                background-color: #2A2D32;
                color: #6D6F73;
            }
            QLabel {
                color: #EFF0F1;
            }
            QStatusBar {
                background: #2A2D32;
                color: #EFF0F1;
            }
            QToolTip {
                color: #EFF0F1;
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
            }
        """)
    
    # Password Generation Methods
    def generate_password(self):
        """Generate a random password based on user preferences."""
        try:
            password = self.pw_generator.generate_password(
                length=self.length_spin.value(),
                use_lowercase=self.lower_check.isChecked(),
                use_uppercase=self.upper_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_punctuation=self.symbols_check.isChecked(),
                custom_chars=self.custom_chars.text()
            )
            self.password_display.setText(password)
            # Auto-copy to clipboard
            self.copy_to_clipboard(password, "Password")
            # Auto-fill the hash password field
            self.hash_password.setText(password)
            self.statusBar().showMessage("Password generated successfully", 3000)
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))
    
    def toggle_password_visibility(self, checked):
        """Toggle password visibility in the password field."""
        if checked:
            self.password_display.setEchoMode(QLineEdit.Normal)
            self.show_btn.setText("Hide")
        else:
            self.password_display.setEchoMode(QLineEdit.Password)
            self.show_btn.setText("Show")
    
    def copy_password(self):
        """Copy the generated password to the clipboard."""
        password = self.password_display.text()
        self.copy_to_clipboard(password, "Password")
    
    # Hashing Methods
    def generate_hash(self):
        """Generate a PBKDF2 hash of the password."""
        password = self.hash_password.text()
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password to hash")
            return
            
        try:
            # Generate the hash
            result = generate_pbkdf2_hash(password)
            
            # Update the UI
            self.hash_display.setPlainText(result['hash'])
            
            # Store the hash details for verification
            self.current_hash_details = result
            
            # Update hash details label
            details = (
                f"Algorithm: {result['algorithm']} | "
                f"Iterations: {result['iterations']:,} | "
                f"Salt: {result['salt'][:10]}... | "
                f"Key length: {result['dklen']*8} bits"
            )
            self.hash_details.setText(details)
            
            # Auto-copy hash to clipboard
            self.copy_to_clipboard(result['hash'], "Hash")
            
            self.statusBar().showMessage("Hash generated successfully", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate hash: {str(e)}")
    
    def verify_password_handler(self):
        """Verify a password against the stored hash."""
        if not hasattr(self, 'current_hash_details') or not self.current_hash_details:
            QMessageBox.warning(self, "Warning", "Please generate a hash first")
            return
            
        password = self.verify_password.text()
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password to verify")
            return
            
        try:
            is_valid = verify_password(
                password=password,
                stored_hash=self.current_hash_details['hash'],
                salt=self.current_hash_details['salt'],
                iterations=self.current_hash_details['iterations'],
                dklen=self.current_hash_details['dklen'],
                hash_name=self.current_hash_details['hash_name']
            )
            
            if is_valid:
                self.verify_result.setText("✓ Password is valid")
                self.verify_result.setStyleSheet("color: #27ae60; font-weight: bold;")
                self.statusBar().showMessage("Password verification successful", 3000)
            else:
                self.verify_result.setText("✗ Password does not match")
                self.verify_result.setStyleSheet("color: #e74c3c; font-weight: bold;")
                self.statusBar().showMessage("Password verification failed", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification failed: {str(e)}")
            
    # PGP Methods
    def update_key_size_options(self):
        """Update the key size options based on the selected key type."""
        if not hasattr(self, 'key_type_combo') or not hasattr(self, 'key_size_combo') or not hasattr(self, 'curve_combo'):
            return  # UI elements not initialized yet
            
        key_type = self.key_type_combo.currentData()
        
        # Store current selection if any
        current_size = self.key_size_combo.currentData() if self.key_size_combo.count() > 0 else None
        
        # Clear existing items
        self.key_size_combo.blockSignals(True)  # Prevent signal emission during updates
        self.key_size_combo.clear()
        
        if key_type == "RSA":
            # Show key size combo, hide curve combo
            self.key_size_combo.setVisible(True)
            if hasattr(self, 'curve_combo'):
                self.curve_combo.setVisible(False)
            
            # Add RSA key sizes
            rsa_sizes = [2048, 3072, 4096]
            for size in rsa_sizes:
                self.key_size_combo.addItem(f"{size} bits", size)
            
            # Restore or set default selection
            if current_size in rsa_sizes:
                index = self.key_size_combo.findData(current_size)
                if index >= 0:
                    self.key_size_combo.setCurrentIndex(index)
            elif self.key_size_combo.count() > 0:
                self.key_size_combo.setCurrentIndex(0)  # Default to first item
                
        else:  # ECC
            # Hide key size combo, show curve combo if it exists
            self.key_size_combo.setVisible(False)
            if hasattr(self, 'curve_combo'):
                self.curve_combo.setVisible(True)
                
                # Ensure curve combo is properly populated
                if self.curve_combo.count() == 0:
                    curves = [
                        ("ed25519 (256 bits)", "ed25519"),
                        ("nistp256 (256 bits)", "nistp256"),
                        ("nistp384 (384 bits)", "nistp384"),
                        ("nistp521 (521 bits)", "nistp521")
                    ]
                    for name, curve in curves:
                        self.curve_combo.addItem(name, curve)
        
        self.key_size_combo.blockSignals(False)  # Re-enable signals  # Default to ed25519
    
    def generate_key(self):
        """Generate a new PGP key pair."""
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        passphrase = self.passphrase_edit.text() or None
        key_type = self.key_type_combo.currentData()
        
        if not name or not email:
            QMessageBox.warning(self, "Warning", "Please enter both name and email")
            return
            
        try:
            self.statusBar().showMessage("Generating PGP key pair (this may take a few minutes)...")
            QApplication.processEvents()  # Update UI
            
            # Get key parameters based on selection
            if key_type == "RSA":
                key_size = self.key_size_combo.currentData()
                algorithm = "RSA"
                curve = None
            else:  # ECC
                curve = self.curve_combo.currentData()
                key_size = 256  # Default, will be overridden by curve
                if curve == "nistp384":
                    key_size = 384
                elif curve == "nistp521":
                    key_size = 521
                algorithm = "ECC"
            
            # Generate the PGP key pair
            self.private_key = generate_pgp_keypair(
                name=name,
                email=email,
                passphrase=passphrase,
                algorithm=algorithm,
                key_size=key_size,
                curve=curve
            )
            
            # Get the public key from the private key
            self.public_key = self.private_key.pubkey
            
            self.key_loaded = True
            # Use fingerprint instead of key_id and format it for better readability
            key_fingerprint = self.public_key.fingerprint
            formatted_fingerprint = ' '.join([key_fingerprint[i:i+4] for i in range(0, len(key_fingerprint), 4)])
            key_info = f"Name: {name}\nEmail: {email}\nKey ID: {formatted_fingerprint[-16:].upper()}\nFingerprint: {formatted_fingerprint}"
            self.key_info.setPlainText(key_info)
            self.statusBar().showMessage("PGP key pair generated successfully", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate PGP key: {str(e)}")
            self.statusBar().clearMessage()
    
    def load_key(self):
        """Load an existing PGP key pair from files."""
        try:
            key_file, _ = QFileDialog.getOpenFileName(
                self,
                "Select Private Key File",
                "",
                "PGP Keys (*.asc *.gpg *.pgp);;All Files (*)"
            )
            
            if key_file:
                passphrase, ok = QInputDialog.getText(
                    self, 
                    "Passphrase", 
                    "Enter passphrase (leave empty if none):",
                    QLineEdit.Password
                )
                
                if ok is not False:  # User didn't press Cancel
                    self.statusBar().showMessage("Loading PGP key...")
                    QApplication.processEvents()
                    
                    with open(key_file, 'r') as f:
                        key_data = f.read()
                    
                    self.private_key = load_pgp_key(key_data, passphrase or None)
                    self.public_key = self.private_key.pubkey
                    
                    self.key_loaded = True
                    key_info = f"Key ID: {self.public_key.key_id}\n"
                    key_info += f"Created: {self.public_key.created.strftime('%Y-%m-%d %H:%M:%S')}"
                    self.key_info.setPlainText(key_info)
                    self.statusBar().showMessage("PGP key loaded successfully", 3000)
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load PGP key: {str(e)}")
            self.statusBar().clearMessage()
    
    def encrypt_message(self):
        """Encrypt a message using the loaded public key."""
        if not self.key_loaded:
            QMessageBox.warning(self, "Warning", "Please load or generate a key first")
            return
            
        message = self.message_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to encrypt")
            return
            
        try:
            encrypted = encrypt_message(message, self.public_key)
            self.message_output.setPlainText(encrypted)
            self.statusBar().showMessage("Message encrypted successfully", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message(self):
        """Decrypt a message using the loaded private key."""
        if not self.key_loaded or not self.private_key:
            QMessageBox.warning(self, "Warning", "Please load a private key first")
            return
            
        message = self.message_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to decrypt")
            return
            
            try:
                if self.private_key.is_protected:
                    passphrase, ok = QInputDialog.getText(
                        self,
                        "Passphrase",
                        "Enter passphrase:",
                        QLineEdit.Password
                    )
                    if not ok:
                        return  # User cancelled
                    
                    # Use a context manager to handle the unlocked key
                    with self.private_key.unlock(passphrase):
                        decrypted = decrypt_message(message, self.private_key, passphrase=passphrase)
                else:
                    decrypted = decrypt_message(message, self.private_key)
                self.message_output.setPlainText(decrypted)
                self.statusBar().showMessage("Message decrypted successfully", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
    
    def sign_message(self):
        """Sign a message using the loaded private key."""
        if not self.key_loaded or not self.private_key:
            QMessageBox.warning(self, "Warning", "Please load a private key first")
            return
            
        message = self.message_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to sign")
            return
            
        try:
            if self.private_key.is_protected:
                passphrase, ok = QInputDialog.getText(
                    self,
                    "Passphrase",
                    "Enter passphrase:",
                    QLineEdit.Password
                )
                if not ok:
                    return  # User cancelled
                
                # Use a context manager to handle the unlocked key
                with self.private_key.unlock(passphrase):
                    signature = sign_message(message, self.private_key)
            else:
                signature = sign_message(message, self.private_key)
            self.message_output.setPlainText(signature)
            self.statusBar().showMessage("Message signed successfully", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signing failed: {str(e)}")
    
    def verify_message(self):
        """Verify a signed message using the loaded public key.
        
        The message should be in the format:
        -----BEGIN PGP SIGNED MESSAGE-----
        <message>
        -----BEGIN PGP SIGNATURE-----
        <signature>
        -----END PGP SIGNATURE-----
        """
        if not self.key_loaded or not self.public_key:
            QMessageBox.warning(self, "Warning", "Please load a public key first")
            return
            
        signed_message = self.message_input.toPlainText().strip()
        if not signed_message:
            QMessageBox.warning(self, "Warning", "Please enter a signed message to verify")
            return
            
        try:
            # Try to parse the message and signature
            if "-----BEGIN PGP SIGNED MESSAGE-----" in signed_message:
                # Extract the message and signature from the signed message
                parts = signed_message.split("-----BEGIN PGP SIGNATURE-----")
                if len(parts) != 2:
                    raise ValueError("Invalid signed message format")
                    
                message = parts[0].replace("-----BEGIN PGP SIGNED MESSAGE-----\n", "").strip()
                signature_str = "-----BEGIN PGP SIGNATURE-----\n" + parts[1].strip()
                
                is_valid = verify_signature(message, signature_str, self.public_key)
                
                if is_valid:
                    self.message_output.setPlainText(f"✓ Signature is valid\n\nMessage:\n{message}")
                    self.statusBar().showMessage("Signature verified successfully", 3000)
                else:
                    self.message_output.setPlainText("✗ Invalid signature")
                    self.statusBar().showMessage("Signature verification failed", 3000)
            else:
                QMessageBox.warning(self, "Warning", "The message doesn't appear to be a valid PGP signed message")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification failed: {str(e)}")
    
    def copy_hash(self):
        """Copy the generated hash to the clipboard."""
        hash_value = self.hash_display.toPlainText()
        self.copy_to_clipboard(hash_value, "Hash")
    
    # Utility Methods
    def copy_to_clipboard(self, text: str, label: str):
        """Copy text to clipboard with error handling."""
        try:
            if not text:
                QMessageBox.warning(self, "Warning", f"No {label.lower()} to copy")
                return
                
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(text)
            self.statusBar().showMessage(f"{label} copied to clipboard", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to copy to clipboard: {str(e)}")
            
    # TPM Methods
    def create_tpm_tab(self):
        """Create the TPM settings tab."""
        # Create a container widget for the TPM settings
        tpm_tab = QWidget()
        layout = QVBoxLayout(tpm_tab)
        
        # Add a group box for TPM settings
        tpm_group = QGroupBox("Trusted Platform Module (TPM) Settings")
        tpm_layout = QVBoxLayout()
        
        # Add a button to open TPM settings dialog
        tpm_button = QPushButton("Configure TPM Settings...")
        tpm_button.clicked.connect(self.show_tpm_settings)
        
        # Add a label for status
        self.tpm_status_label = QLabel("TPM Status: Checking...")
        self.tpm_status_label.setWordWrap(True)
        
        # Add widgets to layout
        tpm_layout.addWidget(tpm_button)
        tpm_layout.addWidget(self.tpm_status_label)
        tpm_layout.addStretch()
        
        tpm_group.setLayout(tpm_layout)
        
        # Add to main layout
        layout.addWidget(tpm_group)
        layout.addStretch()
        
        # Update initial status
        self.update_tpm_status()
        
        return tpm_tab
        
    def update_tpm_status(self):
        """Update the TPM status label."""
        try:
            from core.tpm_utils import check_tpm_requirements, get_tpm_status_message
            status = check_tpm_requirements()
            if status.get('tpm_available', False):
                if status.get('dependencies_met', False):
                    self.tpm_status_label.setText("TPM Status: Available and Ready")
                    self.tpm_status_label.setStyleSheet("color: green;")
                else:
                    self.tpm_status_label.setText(
                        "TPM Status: Available (dependencies missing)\n"
                        "Please install the required TPM libraries."
                    )
                    self.tpm_status_label.setStyleSheet("color: orange;")
            else:
                self.tpm_status_label.setText(
                    "TPM Status: Not Available\n"
                    "TPM is either not present or not enabled in your system BIOS."
                )
                self.tpm_status_label.setStyleSheet("color: red;")
        except ImportError:
            self.tpm_status_label.setText(
                "TPM Status: TPM support not installed\n"
                "The required TPM libraries are not installed."
            )
            self.tpm_status_label.setStyleSheet("color: red;")
        except Exception as e:
            self.tpm_status_label.setText(f"TPM Status: Error\n{str(e)}")
            self.tpm_status_label.setStyleSheet("color: red;")
    
    def show_tpm_settings(self):
        """Show the TPM settings dialog."""
        try:
            dialog = TpmSettingsDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.update_tpm_status()
                QMessageBox.information(
                    self,
                    "TPM Settings",
                    "TPM settings have been updated successfully."
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open TPM settings: {str(e)}"
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

