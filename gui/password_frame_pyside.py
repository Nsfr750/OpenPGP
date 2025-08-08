"""
Password Frame Module (PySide6 Version)

This module provides a password generation and hashing interface.

License: GPL v3.0 (see LICENSE)
"""

import json
import pyperclip
from typing import Optional, Dict, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QCheckBox, QSpinBox, QFrame, QSizePolicy, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QFont, QIcon, QPixmap

from utils.password_utils import PasswordGenerator, generate_pbkdf2_hash, verify_password
from .widgets import LabeledInput, create_section_header, create_horizontal_line

class PasswordFrame(QWidget):
    """A frame containing password generation and hashing functionality."""
    
    def __init__(self, parent: QWidget = None):
        """Initialize the password frame.
        
        Args:
            parent: The parent widget
        """
        super().__init__(parent)
        self.pw_generator = PasswordGenerator()
        self.show_password = False
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Password Generation Section
        gen_section = create_section_header("Password Generation", self)
        main_layout.addWidget(gen_section)
        
        # Password length and options
        options_layout = QHBoxLayout()
        
        # Length
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.setFixedWidth(60)
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        
        # Character set checkboxes
        self.lower_check = QCheckBox("a-z")
        self.lower_check.setChecked(True)
        self.upper_check = QCheckBox("A-Z")
        self.upper_check.setChecked(True)
        self.digits_check = QCheckBox("0-9")
        self.digits_check.setChecked(True)
        self.punct_check = QCheckBox("!@#$")
        self.punct_check.setChecked(True)
        
        # Custom characters
        custom_layout = QHBoxLayout()
        custom_label = QLabel("Custom:")
        self.custom_edit = QLineEdit()
        self.custom_edit.setPlaceholderText("Custom characters")
        self.custom_edit.setFixedWidth(100)
        custom_layout.addWidget(custom_label)
        custom_layout.addWidget(self.custom_edit)
        
        # Add options to layout
        options_layout.addLayout(length_layout)
        options_layout.addWidget(self.lower_check)
        options_layout.addWidget(self.upper_check)
        options_layout.addWidget(self.digits_check)
        options_layout.addWidget(self.punct_check)
        options_layout.addLayout(custom_layout)
        options_layout.addStretch()
        
        main_layout.addLayout(options_layout)
        
        # Password display and actions
        display_layout = QHBoxLayout()
        
        self.password_edit = QLineEdit()
        self.password_edit.setReadOnly(True)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Generated password will appear here")
        self.password_edit.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                border: 1px solid #3A3F44;
                border-radius: 4px;
                background-color: #2A2D32;
                color: #EFF0F1;
            }
        """)
        
        # Toggle password visibility
        self.toggle_btn = QPushButton()
        self.toggle_btn.setIcon(self.style().standardIcon("SP_FileDialogDetailedView"))
        self.toggle_btn.setToolTip("Show/Hide Password")
        self.toggle_btn.setFixedSize(30, 30)
        self.toggle_btn.clicked.connect(self.toggle_password_visibility)
        
        # Copy to clipboard
        copy_btn = QPushButton()
        copy_btn.setIcon(self.style().standardIcon("SP_DialogSaveButton"))
        copy_btn.setToolTip("Copy to Clipboard")
        copy_btn.setFixedSize(30, 30)
        copy_btn.clicked.connect(self.copy_to_clipboard)
        
        # Generate button
        generate_btn = QPushButton("Generate")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:pressed {
                background-color: #219653;
            }
        """)
        generate_btn.clicked.connect(self.generate_password)
        
        display_layout.addWidget(self.password_edit, 1)
        display_layout.addWidget(self.toggle_btn)
        display_layout.addWidget(copy_btn)
        display_layout.addWidget(generate_btn)
        
        main_layout.addLayout(display_layout)
        
        # Add a separator
        main_layout.addWidget(create_horizontal_line(self))
        
        # Password Hashing Section
        hash_section = create_section_header("Password Hashing", self)
        main_layout.addWidget(hash_section)
        
        # Password input
        self.password_input = LabeledInput("Password:")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.update_hash)
        
        # Salt input
        self.salt_input = LabeledInput("Salt (optional):")
        self.salt_input.textChanged.connect(self.update_hash)
        
        # Hash display
        self.hash_display = LabeledInput("Hash:")
        self.hash_display.setReadOnly(True)
        
        # Hash options
        hash_options = QHBoxLayout()
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1000, 1000000)
        self.iterations_spin.setValue(100000)
        self.iterations_spin.setToolTip("Number of iterations (higher is more secure but slower)")
        
        hash_options.addWidget(QLabel("Iterations:"))
        hash_options.addWidget(self.iterations_spin)
        hash_options.addStretch()
        
        # Hash actions
        hash_actions = QHBoxLayout()
        
        copy_hash_btn = QPushButton("Copy Hash")
        copy_hash_btn.clicked.connect(self.copy_hash_to_clipboard)
        
        reset_btn = QPushButton("Reset All")
        reset_btn.clicked.connect(self.reset_fields)
        reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
        """)
        
        hash_actions.addWidget(copy_hash_btn)
        hash_actions.addWidget(reset_btn)
        
        # Add hash widgets to main layout
        main_layout.addWidget(self.password_input)
        main_layout.addWidget(self.salt_input)
        main_layout.addLayout(hash_options)
        main_layout.addWidget(create_horizontal_line(self))
        main_layout.addWidget(self.hash_display)
        main_layout.addLayout(hash_actions)
        main_layout.addStretch()
        
        # Set initial state
        self.update_hash()
    
    def generate_password(self):
        """Generate a random password based on user preferences."""
        try:
            # Get character sets
            chars = ""
            if self.lower_check.isChecked():
                chars += "abcdefghijklmnopqrstuvwxyz"
            if self.upper_check.isChecked():
                chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if self.digits_check.isChecked():
                chars += "0123456789"
            if self.punct_check.isChecked():
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            # Add custom characters
            custom_chars = self.custom_edit.text().strip()
            if custom_chars:
                chars += custom_chars
            
            if not chars:
                QMessageBox.warning(self, "Error", "Please select at least one character set.")
                return
            
            # Generate password
            length = self.length_spin.value()
            password = self.pw_generator.generate_password(length, chars)
            
            # Update UI
            self.password_edit.setText(password)
            self.password_input.setText(password)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate password: {str(e)}")
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        self.show_password = not self.show_password
        if self.show_password:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setIcon(self.style().standardIcon("SP_DialogNoButton"))
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.toggle_btn.setIcon(self.style().standardIcon("SP_FileDialogDetailedView"))
    
    def copy_to_clipboard(self):
        """Copy the generated password to the clipboard."""
        password = self.password_edit.text()
        if password:
            try:
                pyperclip.copy(password)
                QMessageBox.information(self, "Success", "Password copied to clipboard!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to copy to clipboard: {str(e)}")
        else:
            QMessageBox.warning(self, "Warning", "No password to copy!")
    
    def update_hash(self):
        """Update the hash display based on the current password and salt."""
        password = self.password_input.text()
        if not password:
            self.hash_display.setText("")
            return
        
        try:
            salt = self.salt_input.text().encode() or None
            iterations = self.iterations_spin.value()
            
            # Generate hash
            hash_result = generate_pbkdf2_hash(password, salt, iterations)
            
            # Update display
            self.hash_display.setText(hash_result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate hash: {str(e)}")
    
    def copy_hash_to_clipboard(self):
        """Copy the generated hash to the clipboard."""
        hash_text = self.hash_display.text()
        if hash_text:
            try:
                pyperclip.copy(hash_text)
                QMessageBox.information(self, "Success", "Hash copied to clipboard!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to copy hash: {str(e)}")
        else:
            QMessageBox.warning(self, "Warning", "No hash to copy!")
    
    def reset_fields(self):
        """Reset all input fields to their default values."""
        self.password_input.setText("")
        self.salt_input.setText("")
        self.hash_display.setText("")
        self.password_edit.clear()
        self.length_spin.setValue(16)
        self.lower_check.setChecked(True)
        self.upper_check.setChecked(True)
        self.digits_check.setChecked(True)
        self.punct_check.setChecked(True)
        self.custom_edit.clear()
        self.iterations_spin.setValue(100000)
        self.show_password = False
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.toggle_btn.setIcon(self.style().standardIcon("SP_FileDialogDetailedView"))
