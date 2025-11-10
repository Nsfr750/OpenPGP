"""
Key Backup and Recovery Dialog

This module provides a dialog for backing up and recovering PGP keys.
"""
import os
import json
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QLineEdit, QTextEdit, QGroupBox, QFormLayout, QFileDialog, QMessageBox,
    QCheckBox, QTabWidget, QWidget, QSizePolicy, QSpacerItem, QApplication, QSpinBox
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QPixmap, QFont, QIcon

from core.passphrase_manager import PassphraseManager, generate_strong_passphrase
from core.openpgp import PGPKey

class KeyBackupDialog(QDialog):
    """Dialog for backing up and recovering PGP keys."""
    
    backup_created = Signal(dict)  # Signal emitted when a backup is created
    
    def __init__(self, parent=None, private_key=None):
        """Initialize the dialog."""
        super().__init__(parent)
        self.private_key = private_key
        self.passphrase_manager = PassphraseManager()
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("PGP Key Backup & Recovery")
        self.setMinimumSize(600, 500)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Add tabs
        self.backup_tab = self.create_backup_tab()
        self.recovery_tab = self.create_recovery_tab()
        
        self.tabs.addTab(self.backup_tab, "Backup Key")
        self.tabs.addTab(self.recovery_tab, "Recover Key")
        
        layout.addWidget(self.tabs)
        
        # Button box
        button_box = QHBoxLayout()
        button_box.addStretch()
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        
        button_box.addWidget(self.close_button)
        layout.addLayout(button_box)
        
        # Set tab order
        self.setTabOrder(self.tabs, self.close_button)
    
    def create_backup_tab(self) -> QWidget:
        """Create the backup tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Backup options group
        options_group = QGroupBox("Backup Options")
        options_layout = QVBoxLayout()
        
        # Recovery method selection
        self.recovery_method_combo = QComboBox()
        self.recovery_method_combo.addItem("Recovery Codes", "recovery_codes")
        self.recovery_method_combo.addItem("Security Questions", "security_questions")
        self.recovery_method_combo.addItem("TOTP (Authenticator App)", "totp")
        
        # Number of recovery codes
        self.num_recovery_codes = QSpinBox()
        self.num_recovery_codes.setRange(3, 10)
        self.num_recovery_codes.setValue(5)
        
        # Security questions
        self.security_questions = []
        self.answers = []
        
        # TOTP setup
        self.totp_secret = None
        self.totp_uri = None
        
        # Form layout for options
        form_layout = QFormLayout()
        form_layout.addRow("Recovery Method:", self.recovery_method_combo)
        form_layout.addRow("Number of Recovery Codes:", self.num_recovery_codes)
        
        # Recovery codes display
        self.recovery_codes_display = QTextEdit()
        self.recovery_codes_display.setReadOnly(True)
        self.recovery_codes_display.setPlaceholderText("Recovery codes will appear here after backup creation.")
        
        # Security questions form
        self.security_questions_widget = QWidget()
        self.security_questions_layout = QVBoxLayout(self.security_questions_widget)
        self.security_questions_layout.setContentsMargins(0, 0, 0, 0)
        
        # TOTP setup widget
        self.totp_widget = QWidget()
        totp_layout = QVBoxLayout(self.totp_widget)
        totp_layout.addWidget(QLabel("Scan the QR code with your authenticator app:"))
        
        self.totp_qr_label = QLabel()
        self.totp_qr_label.setAlignment(Qt.AlignCenter)
        self.totp_secret_label = QLabel()
        self.totp_secret_label.setAlignment(Qt.AlignCenter)
        self.totp_secret_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        
        totp_layout.addWidget(self.totp_qr_label)
        totp_layout.addWidget(QLabel("Or enter this secret manually:"))
        totp_layout.addWidget(self.totp_secret_label)
        
        # Stacked widget for recovery method specific UI
        self.recovery_method_stack = QStackedWidget()
        self.recovery_method_stack.addWidget(self.recovery_codes_display)
        self.recovery_method_stack.addWidget(self.security_questions_widget)
        self.recovery_method_stack.addWidget(self.totp_widget)
        
        # Connect signals
        self.recovery_method_combo.currentIndexChanged.connect(self.update_recovery_ui)
        
        # Add widgets to layout
        options_layout.addLayout(form_layout)
        options_group.setLayout(options_layout)
        
        layout.addWidget(options_group)
        layout.addWidget(QLabel("Recovery Information:"))
        layout.addWidget(self.recovery_method_stack)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.generate_backup_button = QPushButton("Generate Backup")
        self.generate_backup_button.clicked.connect(self.generate_backup)
        
        self.save_backup_button = QPushButton("Save Backup to File...")
        self.save_backup_button.clicked.connect(self.save_backup_to_file)
        self.save_backup_button.setEnabled(False)
        
        button_layout.addWidget(self.generate_backup_button)
        button_layout.addWidget(self.save_backup_button)
        
        layout.addLayout(button_layout)
        
        # Backup data
        self.backup_data = None
        
        return tab
    
    def create_recovery_tab(self) -> QWidget:
        """Create the recovery tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Load backup group
        load_group = QGroupBox("Load Backup")
        load_layout = QVBoxLayout()
        
        # Backup file selection
        file_layout = QHBoxLayout()
        self.backup_file_edit = QLineEdit()
        self.backup_file_edit.setPlaceholderText("Select a backup file...")
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_backup_file)
        
        file_layout.addWidget(self.backup_file_edit)
        file_layout.addWidget(browse_button)
        
        load_layout.addLayout(file_layout)
        load_group.setLayout(load_layout)
        
        # Recovery method selection
        self.recovery_method_combo_recover = QComboBox()
        self.recovery_method_combo_recover.addItem("Recovery Code", "recovery_code")
        self.recovery_method_combo_recover.addItem("Security Questions", "security_answers")
        self.recovery_method_combo_recover.addItem("TOTP Code", "totp_code")
        
        # Recovery input
        self.recovery_input = QLineEdit()
        self.recovery_input.setPlaceholderText("Enter recovery code")
        
        # Security answers
        self.security_answers_widget = QWidget()
        self.security_answers_layout = QVBoxLayout(self.security_answers_widget)
        
        # TOTP input
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("Enter TOTP code")
        
        # Stacked widget for recovery method input
        self.recovery_input_stack = QStackedWidget()
        self.recovery_input_stack.addWidget(self.recovery_input)  # Recovery code
        self.recovery_input_stack.addWidget(self.security_answers_widget)  # Security answers
        self.recovery_input_stack.addWidget(self.totp_input)  # TOTP code
        
        # Connect signals
        self.recovery_method_combo_recover.currentIndexChanged.connect(
            self.update_recovery_input_ui
        )
        
        # Add widgets to layout
        form_layout = QFormLayout()
        form_layout.addRow("Recovery Method:", self.recovery_method_combo_recover)
        form_layout.addRow("Recovery Input:", self.recovery_input_stack)
        
        # Passphrase
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.Password)
        self.passphrase_edit.setPlaceholderText("Enter your passphrase")
        
        form_layout.addRow("Passphrase:", self.passphrase_edit)
        
        layout.addWidget(load_group)
        layout.addLayout(form_layout)
        
        # Recover button
        self.recover_button = QPushButton("Recover Key")
        self.recover_button.clicked.connect(self.recover_key)
        
        layout.addWidget(self.recover_button)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        # Recovered key info
        self.recovered_key_info = QTextEdit()
        self.recovered_key_info.setReadOnly(True)
        self.recovered_key_info.setPlaceholderText("Recovered key information will appear here.")
        layout.addWidget(self.recovered_key_info)
        
        return tab
    
    def update_recovery_ui(self, index: int):
        """Update the UI based on the selected recovery method."""
        self.recovery_method_stack.setCurrentIndex(index)
        
        if index == 1:  # Security questions
            self.setup_security_questions()
        elif index == 2:  # TOTP
            self.setup_totp()
    
    def update_recovery_input_ui(self, index: int):
        """Update the recovery input UI based on the selected method."""
        self.recovery_input_stack.setCurrentIndex(index)
        
        if index == 1:  # Security answers
            self.setup_security_answers()
    
    def setup_security_questions(self, questions=None):
        """Set up the security questions UI."""
        # Clear existing widgets
        while self.security_questions_layout.count():
            item = self.security_questions_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        self.security_questions = questions or [
            "What was your first pet's name?",
            "What city were you born in?",
            "What is your mother's maiden name?"
        ]
        
        self.answer_edits = []
        
        for i, question in enumerate(self.security_questions):
            group = QGroupBox(f"Question {i+1}")
            layout = QVBoxLayout()
            
            question_edit = QLineEdit(question)
            question_edit.setReadOnly(questions is not None)  # Read-only if loading from backup
            
            answer_edit = QLineEdit()
            answer_edit.setPlaceholderText("Your answer")
            answer_edit.setEchoMode(QLineEdit.Password)
            
            layout.addWidget(QLabel("Question:"))
            layout.addWidget(question_edit)
            layout.addWidget(QLabel("Answer:"))
            layout.addWidget(answer_edit)
            
            group.setLayout(layout)
            self.security_questions_layout.addWidget(group)
            
            self.answer_edits.append((question_edit, answer_edit))
        
        self.security_questions_widget.updateGeometry()
    
    def setup_security_answers(self):
        """Set up the security answers UI for recovery."""
        # Clear existing widgets
        while self.security_answers_layout.count():
            item = self.security_answers_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        if not hasattr(self, 'backup_data') or 'recovery_hashes' not in self.backup_data:
            return
        
        recovery_hashes = self.backup_data['recovery_hashes']
        if 'security_questions' not in recovery_hashes:
            return
        
        self.answer_edits_recover = []
        
        for i, qa in enumerate(recovery_hashes['security_questions']):
            group = QGroupBox(f"Question {i+1}")
            layout = QVBoxLayout()
            
            question_label = QLabel(qa['question'])
            answer_edit = QLineEdit()
            answer_edit.setPlaceholderText("Your answer")
            answer_edit.setEchoMode(QLineEdit.Password)
            
            layout.addWidget(question_label)
            layout.addWidget(QLabel("Answer:"))
            layout.addWidget(answer_edit)
            
            group.setLayout(layout)
            self.security_answers_layout.addWidget(group)
            
            self.answer_edits_recover.append((qa['question'], answer_edit))
        
        self.security_answers_widget.updateGeometry()
    
    def setup_totp(self):
        """Set up TOTP for the first time."""
        if not hasattr(self, 'totp_uri') or not self.totp_uri:
            # Generate a new TOTP secret
            from core.passphrase_manager import PassphraseManager
            
            pm = PassphraseManager()
            self.totp_uri, self.totp_secret = pm.generate_totp_recovery(
                "OpenPGP",
                "user@example.com"  # TODO: Get actual user email
            )
            
            # Generate QR code
            import qrcode
            from io import BytesIO
            from PySide6.QtGui import QPixmap
            
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(self.totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to QPixmap
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue())
            
            # Scale the pixmap if it's too large
            max_size = 200
            if pixmap.width() > max_size or pixmap.height() > max_size:
                pixmap = pixmap.scaled(
                    max_size, max_size,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
            
            self.totp_qr_label.setPixmap(pixmap)
            self.totp_secret_label.setText(self.totp_secret)
    
    def generate_backup(self):
        """Generate a backup of the private key."""
        if not self.private_key:
            QMessageBox.warning(self, "Error", "No private key available for backup.")
            return
        
        # Get recovery method
        method = self.recovery_method_combo.currentData()
        
        try:
            pm = PassphraseManager()
            
            # Prepare recovery methods
            recovery_methods = {}
            
            if method == "recovery_codes":
                # Generate recovery codes
                num_codes = self.num_recovery_codes.value()
                recovery_codes = pm.generate_recovery_codes(num_codes)
                recovery_methods['recovery_codes'] = recovery_codes
                
                # Display recovery codes
                self.recovery_codes_display.setPlainText("\n".join(recovery_codes))
                
            elif method == "security_questions":
                # Get security questions and answers
                questions = []
                answers = []
                
                for q_edit, a_edit in self.answer_edits:
                    question = q_edit.text().strip()
                    answer = a_edit.text().strip()
                    
                    if not question or not answer:
                        QMessageBox.warning(
                            self,
                            "Error",
                            "Please provide both questions and answers."
                        )
                        return
                    
                    questions.append({
                        'question': question,
                        'answer': answer
                    })
                
                recovery_methods['security_questions'] = questions
                
            elif method == "totp":
                if not hasattr(self, 'totp_secret') or not self.totp_secret:
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Please set up TOTP first by scanning the QR code."
                    )
                    return
                
                recovery_methods['totp_secret'] = self.totp_secret
            
            # Get passphrase
            from PySide6.QtWidgets import QInputDialog
            
            passphrase, ok = QInputDialog.getText(
                self,
                "Enter Passphrase",
                "Enter a strong passphrase to encrypt the backup:",
                QLineEdit.Password
            )
            
            if not ok or not passphrase:
                return
            
            # Confirm passphrase
            confirm_passphrase, ok = QInputDialog.getText(
                self,
                "Confirm Passphrase",
                "Re-enter the passphrase to confirm:",
                QLineEdit.Password
            )
            
            if not ok or passphrase != confirm_passphrase:
                QMessageBox.warning(
                    self,
                    "Error",
                    "Passphrases do not match or are empty."
                )
                return
            
            # Create backup
            self.backup_data = pm.create_key_backup(
                private_key=str(self.private_key).encode('utf-8'),
                passphrase=passphrase,
                recovery_methods=recovery_methods
            )
            
            # Enable save button
            self.save_backup_button.setEnabled(True)
            
            QMessageBox.information(
                self,
                "Backup Created",
                "Key backup has been created successfully. "
                "Please save it to a secure location."
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to create backup: {str(e)}"
            )
    
    def save_backup_to_file(self):
        """Save the backup to a file."""
        if not self.backup_data:
            QMessageBox.warning(self, "Error", "No backup data to save.")
            return
        
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Backup",
                "",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                # Ensure the file has the correct extension
                if not file_path.lower().endswith('.json'):
                    file_path += '.json'
                
                with open(file_path, 'w') as f:
                    json.dump(self.backup_data, f, indent=2)
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"Backup saved to:\n{file_path}"
                )
                
                # Emit signal with backup info
                self.backup_created.emit({
                    'file_path': file_path,
                    'method': self.recovery_method_combo.currentText(),
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save backup: {str(e)}"
            )
    
    def browse_backup_file(self):
        """Open a file dialog to select a backup file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Backup File",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            self.backup_file_edit.setText(file_path)
            self.load_backup_file(file_path)
    
    def load_backup_file(self, file_path):
        """Load a backup file."""
        try:
            with open(file_path, 'r') as f:
                self.backup_data = json.load(f)
            
            # Update UI based on backup data
            if 'recovery_hashes' in self.backup_data:
                recovery_hashes = self.backup_data['recovery_hashes']
                
                if 'security_questions' in recovery_hashes:
                    # Set up security questions
                    questions = [
                        qa['question'] for qa in recovery_hashes['security_questions']
                    ]
                    self.setup_security_questions(questions)
                    
                    # Switch to security questions tab
                    self.recovery_method_combo_recover.setCurrentIndex(1)
                
                # TODO: Handle other recovery methods
                
            self.status_label.setText(f"Loaded backup from: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load backup file: {str(e)}"
            )
    
    def recover_key(self):
        """Recover a key from backup."""
        if not hasattr(self, 'backup_data') or not self.backup_data:
            QMessageBox.warning(self, "Error", "No backup data loaded.")
            return
        
        method_index = self.recovery_method_combo_recover.currentIndex()
        method = self.recovery_method_combo_recover.currentData()
        
        try:
            pm = PassphraseManager()
            recovery_data = {}
            
            # Get recovery data based on method
            if method == "recovery_code":
                recovery_code = self.recovery_input.text().strip()
                if not recovery_code:
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Please enter a recovery code."
                    )
                    return
                
                recovery_data['recovery_code'] = recovery_code
                
            elif method == "security_answers":
                if not hasattr(self, 'answer_edits_recover'):
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Security questions not loaded properly."
                    )
                    return
                
                answers = []
                for question, answer_edit in self.answer_edits_recover:
                    answer = answer_edit.text().strip()
                    if not answer:
                        QMessageBox.warning(
                            self,
                            "Error",
                            "Please answer all security questions."
                        )
                        return
                    
                    answers.append(answer)
                
                recovery_data['security_answers'] = answers
                
            elif method == "totp_code":
                totp_code = self.totp_input.text().strip()
                if not totp_code:
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Please enter a TOTP code."
                    )
                    return
                
                recovery_data['totp_code'] = totp_code
            
            # Get passphrase
            passphrase = self.passphrase_edit.text()
            if not passphrase:
                QMessageBox.warning(
                    self,
                    "Error",
                    "Please enter the backup passphrase."
                )
                return
            
            recovery_data['passphrase'] = passphrase
            
            # Attempt recovery
            private_key_data = pm.restore_key_from_backup(
                self.backup_data,
                recovery_data
            )
            
            # If we get here, recovery was successful
            try:
                # Try to load the private key
                from pgpy import PGPKey
                private_key = PGPKey()
                private_key.parse(private_key_data.decode('utf-8'))
                
                # Display key information
                key_info = []
                key_info.append("Key recovered successfully!\n")
                
                if private_key.is_public and private_key.is_private:
                    key_info.append("Type: Private Key")
                elif private_key.is_public:
                    key_info.append("Type: Public Key")
                
                if hasattr(private_key, 'fingerprint'):
                    key_info.append(f"Fingerprint: {private_key.fingerprint}")
                
                if hasattr(private_key, 'created'):
                    key_info.append(f"Created: {private_key.created}")
                
                if hasattr(private_key, 'expires_at'):
                    key_info.append(f"Expires: {private_key.expires_at}")
                
                self.recovered_key_info.setPlainText("\n".join(key_info))
                
                # Emit signal with recovered key
                self.accept()
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to parse recovered key: {str(e)}"
                )
                return
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Recovery Failed",
                f"Failed to recover key: {str(e)}"
            )
    
    def get_recovered_key(self):
        """Get the recovered private key."""
        return self.private_key
