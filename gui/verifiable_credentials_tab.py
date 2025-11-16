"""
Verifiable Credentials Tab

This module provides a tab for managing W3C Verifiable Credentials.
"""
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QComboBox, QFileDialog, QMessageBox,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QTabWidget, QFormLayout,
    QGroupBox, QListWidget, QListWidgetItem, QInputDialog, QSplitter
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QIcon, QFont

from core.verifiable_credentials import VerifiableCredential
from core.keyring_manager import KeyringManager
from core.openpgp import PGPKey

class VerifiableCredentialsTab(QWidget):
    """Tab for managing Verifiable Credentials."""
    
    def __init__(self, parent=None):
        """Initialize the Verifiable Credentials tab."""
        super().__init__(parent)
        self.keyring_manager = KeyringManager()
        self.current_credential: Optional[VerifiableCredential] = None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Credentials list and actions
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Credentials list
        creds_group = QGroupBox("Verifiable Credentials")
        creds_layout = QVBoxLayout()
        
        self.credentials_list = QTreeWidget()
        self.credentials_list.setHeaderLabels(["ID", "Type", "Issuer", "Issuance Date"])
        self.credentials_list.setSelectionMode(QTreeWidget.SingleSelection)
        self.credentials_list.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.credentials_list.itemSelectionChanged.connect(self.on_credential_selected)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        self.new_btn = QPushButton("New")
        self.import_btn = QPushButton("Import")
        self.export_btn = QPushButton("Export")
        self.delete_btn = QPushButton("Delete")
        
        btn_layout.addWidget(self.new_btn)
        btn_layout.addWidget(self.import_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.delete_btn)
        
        # Add to left layout
        creds_layout.addWidget(self.credentials_list)
        creds_layout.addLayout(btn_layout)
        creds_group.setLayout(creds_layout)
        left_layout.addWidget(creds_group)
        
        # Right panel - Credential details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Credential details
        details_group = QGroupBox("Credential Details")
        details_layout = QFormLayout()
        
        self.credential_id = QLabel()
        self.credential_type = QLabel()
        self.issuer = QLabel()
        self.issuance_date = QLabel()
        self.expiration_date = QLabel()
        
        details_layout.addRow("ID:", self.credential_id)
        details_layout.addRow("Type:", self.credential_type)
        details_layout.addRow("Issuer:", self.issuer)
        details_layout.addRow("Issuance Date:", self.issuance_date)
        details_layout.addRow("Expiration Date:", self.expiration_date)
        
        # Credential subject
        self.subject_view = QTextEdit()
        self.subject_view.setReadOnly(True)
        details_layout.addRow("Subject:", self.subject_view)
        
        # Proof section
        proof_group = QGroupBox("Proof")
        proof_layout = QFormLayout()
        
        self.proof_type = QLabel()
        self.proof_created = QLabel()
        self.proof_verification_method = QLabel()
        self.proof_purpose = QLabel()
        
        proof_layout.addRow("Type:", self.proof_type)
        proof_layout.addRow("Created:", self.proof_created)
        proof_layout.addRow("Verification Method:", self.proof_verification_method)
        proof_layout.addRow("Purpose:", self.proof_purpose)
        
        proof_group.setLayout(proof_layout)
        details_layout.addRow(proof_group)
        
        # Verification status
        self.verification_status = QLabel()
        self.verification_status.setAlignment(Qt.AlignCenter)
        self.verification_status.setStyleSheet("font-weight: bold;")
        details_layout.addRow("Status:", self.verification_status)
        
        # Action buttons
        action_layout = QHBoxLayout()
        self.verify_btn = QPushButton("Verify")
        self.sign_btn = QPushButton("Sign")
        self.share_btn = QPushButton("Share")
        
        action_layout.addWidget(self.verify_btn)
        action_layout.addWidget(self.sign_btn)
        action_layout.addWidget(self.share_btn)
        
        details_layout.addRow(action_layout)
        details_group.setLayout(details_layout)
        right_layout.addWidget(details_group)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 500])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        
        # Connect signals
        self.new_btn.clicked.connect(self.new_credential)
        self.import_btn.clicked.connect(self.import_credential)
        self.export_btn.clicked.connect(self.export_credential)
        self.delete_btn.clicked.connect(self.delete_credential)
        self.verify_btn.clicked.connect(self.verify_credential)
        self.sign_btn.clicked.connect(self.sign_credential)
        self.share_btn.clicked.connect(self.share_credential)
        
        # Disable buttons initially
        self.update_buttons()
    
    def update_buttons(self, has_selection: bool = False):
        """Update button states based on current selection."""
        self.export_btn.setEnabled(has_selection)
        self.delete_btn.setEnabled(has_selection)
        self.verify_btn.setEnabled(has_selection)
        self.sign_btn.setEnabled(has_selection)
        self.share_btn.setEnabled(has_selection)
    
    def new_credential(self):
        """Create a new verifiable credential."""
        # TODO: Implement credential creation dialog
        QMessageBox.information(self, "Not Implemented", "Credential creation will be implemented in a future version")
    
    def import_credential(self):
        """Import a verifiable credential from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Verifiable Credential",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                credential = VerifiableCredential.from_dict(data)
                self.add_credential_to_list(credential)
                
                QMessageBox.information(
                    self,
                    "Import Successful",
                    f"Successfully imported credential: {credential.id}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Import Failed",
                    f"Failed to import credential: {str(e)}"
                )
    
    def export_credential(self):
        """Export the selected credential to a file."""
        if not self.current_credential:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Verifiable Credential",
            f"credential_{self.current_credential.id[:8]}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_credential.to_dict(), f, indent=2)
                
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Successfully exported credential to {file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Export Failed",
                    f"Failed to export credential: {str(e)}"
                )
    
    def delete_credential(self):
        """Delete the selected credential."""
        if not self.current_credential:
            return
            
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete credential {self.current_credential.id}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # TODO: Implement actual deletion from storage
            self.credentials_list.takeTopLevelItem(
                self.credentials_list.indexOfTopLevelItem(
                    self.credentials_list.currentItem()
                )
            )
            self.current_credential = None
            self.clear_credential_details()
    
    def verify_credential(self):
        """Verify the selected credential's signature."""
        if not self.current_credential:
            return
            
        try:
            # TODO: Implement actual verification with issuer's public key
            is_valid = True  # Placeholder
            
            if is_valid:
                self.verification_status.setText("✅ Valid")
                self.verification_status.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.verification_status.setText("❌ Invalid")
                self.verification_status.setStyleSheet("color: red; font-weight: bold;")
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Verification Failed",
                f"Failed to verify credential: {str(e)}"
            )
    
    def sign_credential(self):
        """Sign the selected credential."""
        if not self.current_credential:
            return
            
        # TODO: Implement credential signing with private key
        QMessageBox.information(
            self,
            "Not Implemented",
            "Credential signing will be implemented in a future version"
        )
    
    def share_credential(self):
        """Share the selected credential."""
        if not self.current_credential:
            return
            
        # TODO: Implement credential sharing
        QMessageBox.information(
            self,
            "Not Implemented",
            "Credential sharing will be implemented in a future version"
        )
    
    def on_credential_selected(self):
        """Handle credential selection change."""
        selected = self.credentials_list.selectedItems()
        if not selected:
            self.current_credential = None
            self.clear_credential_details()
            self.update_buttons(False)
            return
            
        # Get the credential from the selected item
        item = selected[0]
        credential = item.data(0, Qt.UserRole)
        
        if not credential:
            return
            
        self.current_credential = credential
        self.update_credential_details(credential)
        self.update_buttons(True)
    
    def add_credential_to_list(self, credential: VerifiableCredential):
        """Add a credential to the list view."""
        item = QTreeWidgetItem()
        item.setText(0, credential.id)
        item.setText(1, ", ".join(credential.type) if isinstance(credential.type, list) else credential.type)
        item.setText(2, credential.issuer)
        item.setText(3, credential.issuance_date)
        item.setData(0, Qt.UserRole, credential)
        
        self.credentials_list.addTopLevelItem(item)
        self.credentials_list.setCurrentItem(item)
    
    def update_credential_details(self, credential: VerifiableCredential):
        """Update the credential details view."""
        self.credential_id.setText(credential.id)
        self.credential_type.setText(", ".join(credential.type) if isinstance(credential.type, list) else credential.type)
        self.issuer.setText(credential.issuer)
        self.issuance_date.setText(credential.issuance_date)
        
        # Set subject data as pretty-printed JSON
        subject_text = json.dumps(credential.credential_subject, indent=2)
        self.subject_view.setPlainText(subject_text)
        
        # Update proof information if available
        if credential.proof:
            self.proof_type.setText(credential.proof.get('type', 'N/A'))
            self.proof_created.setText(credential.proof.get('created', 'N/A'))
            self.proof_verification_method.setText(credential.proof.get('verificationMethod', 'N/A'))
            self.proof_purpose.setText(credential.proof.get('proofPurpose', 'N/A'))
        
        # Reset verification status
        self.verification_status.clear()
    
    def clear_credential_details(self):
        """Clear the credential details view."""
        self.credential_id.clear()
        self.credential_type.clear()
        self.issuer.clear()
        self.issuance_date.clear()
        self.expiration_date.clear()
        self.subject_view.clear()
        self.proof_type.clear()
        self.proof_created.clear()
        self.proof_verification_method.clear()
        self.proof_purpose.clear()
        self.verification_status.clear()
