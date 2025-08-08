import sys
import os
from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox,
    QMessageBox, QFileDialog, QApplication, QSizePolicy, QFrame, 
    QSpinBox, QGroupBox, QFormLayout, QSplitter, QInputDialog
)
from PySide6.QtCore import Qt, QSize, Signal, Slot, QSettings
from PySide6.QtGui import (
    QFont, QTextCursor, QClipboard, QGuiApplication, 
    QPalette, QColor, QIcon, QAction, QKeySequence
)

from .menu import MenuBar

from utils.password_utils import PasswordGenerator, generate_pbkdf2_hash, verify_password
from openpgp import (
    generate_pgp_keypair, save_pgp_key, load_pgp_key,
    encrypt_message, decrypt_message, sign_message, 
    verify_signature, generate_ssl_cert
)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpenPGP - Secure Password Manager")
        self.setMinimumSize(1024, 768)
        
        # Initialize password generator
        self.pw_generator = PasswordGenerator()
        self.current_hash_details = None
        
        # PGP related attributes
        self.private_key = None
        self.public_key = None
        self.key_loaded = False
        
        # Set up the main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        
        # Create menu bar
        self.create_menu()
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create and add tabs
        self.password_tab = self.create_password_tab()
        self.pgp_tab = self.create_pgp_tab()
        
        self.tabs.addTab(self.password_tab, "Password Tools")
        self.tabs.addTab(self.pgp_tab, "PGP Tools")
        
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
        self.menu_bar.signals.quit_app.connect(self.close)
        
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
        
    def load_settings(self):
        """Load application settings."""
        # Restore window geometry
        self.restoreGeometry(self.settings.value("geometry", self.saveGeometry()))
        self.restoreState(self.settings.value("windowState", self.saveState()))
        
    def closeEvent(self, event):
        """Handle window close event."""
        # Save settings
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
        event.accept()
    
    def create_pgp_tab(self):
        """Create the PGP tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Key Generation Group
        key_group = QGroupBox("PGP Key Generation")
        key_layout = QVBoxLayout()
        
        # Name and Email
        form_layout = QFormLayout()
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Your Name")
        form_layout.addRow("Name:", self.name_edit)
        
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("your.email@example.com")
        form_layout.addRow("Email:", self.email_edit)
        
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setPlaceholderText("Leave empty for no passphrase")
        self.passphrase_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Passphrase:", self.passphrase_edit)
        
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
        
        # Input
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Enter message to encrypt/decrypt or sign/verify here...")
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
    def generate_key(self):
        """Generate a new PGP key pair."""
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        passphrase = self.passphrase_edit.text() or None
        
        if not name or not email:
            QMessageBox.warning(self, "Warning", "Please enter both name and email")
            return
            
        try:
            self.statusBar().showMessage("Generating PGP key pair (this may take a few minutes)...")
            QApplication.processEvents()  # Update UI
            
            self.public_key, self.private_key = generate_pgp_keypair(
                name=name,
                email=email,
                passphrase=passphrase
            )
            
            self.key_loaded = True
            key_info = f"Name: {name}\nEmail: {email}\nKey ID: {self.public_key.key_id}"
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
                
                self.private_key.decrypt(passphrase)
            
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
                
                self.private_key.decrypt(passphrase)
            
            signature = sign_message(message, self.private_key)
            self.message_output.setPlainText(signature)
            self.statusBar().showMessage("Message signed successfully", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signing failed: {str(e)}")
    
    def verify_message(self):
        """Verify a signed message using the loaded public key."""
        if not self.key_loaded or not self.public_key:
            QMessageBox.warning(self, "Warning", "Please load a public key first")
            return
            
        message = self.message_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to verify")
            return
            
        try:
            is_valid = verify_signature(message, self.public_key)
            if is_valid:
                self.message_output.setPlainText("✓ Signature is valid")
                self.statusBar().showMessage("Signature verified successfully", 3000)
            else:
                self.message_output.setPlainText("✗ Invalid signature")
                self.statusBar().showMessage("Signature verification failed", 3000)
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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
