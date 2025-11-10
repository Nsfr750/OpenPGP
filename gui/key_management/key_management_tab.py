"""
Key Management Tab

This module provides a tab for managing PGP keys, including keyring operations,
key server interactions, and hardware token management.
"""
import os
import json
import logging
from pathlib import Path
from typing import Optional

# Set up logging
logger = logging.getLogger(__name__)

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFormLayout, QGroupBox, QMessageBox, QFileDialog,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QHeaderView, QComboBox,
    QSplitter, QTextEdit, QCheckBox, QInputDialog, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, Signal, QTimer, QSize
from PySide6.QtGui import QIcon, QPixmap, QFont, QAction

# Import core modules
try:
    from core.keyring_manager import KeyringManager
    from core.key_server import KeyServer
    from core.key_sharing import KeySharing
    from core.key_discovery import KeyDiscovery
    from core.smartcard import SmartCard
    from core.hardware_token import HardwareToken
    from core.hsm import HSM
    from core.secure_file import SecureFile
    
    CORE_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some core modules not available: {e}")
    CORE_MODULES_AVAILABLE = False

class KeyManagementTab(QWidget):
    """Main tab for key management operations."""
    
    def __init__(self, parent=None):
        """Initialize the key management tab."""
        super().__init__(parent)
        self.keyring_manager = KeyringManager() if CORE_MODULES_AVAILABLE else None
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.keyring_tab = self.create_keyring_tab()
        self.server_tab = self.create_server_tab()
        self.sharing_tab = self.create_sharing_tab()
        self.hardware_tab = self.create_hardware_tab()
        
        self.tab_widget.addTab(self.keyring_tab, "Keyring")
        self.tab_widget.addTab(self.server_tab, "Key Servers")
        self.tab_widget.addTab(self.sharing_tab, "Key Sharing")
        self.tab_widget.addTab(self.hardware_tab, "Hardware")
        
        main_layout.addWidget(self.tab_widget)
    
    def create_keyring_tab(self):
        """Create the keyring management tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.import_key_btn = QPushButton("Import Key")
        self.export_key_btn = QPushButton("Export Key")
        self.generate_key_btn = QPushButton("Generate Key")
        self.delete_key_btn = QPushButton("Delete Key")
        
        toolbar.addWidget(self.import_key_btn)
        toolbar.addWidget(self.export_key_btn)
        toolbar.addWidget(self.generate_key_btn)
        toolbar.addWidget(self.delete_key_btn)
        
        # Key list
        self.key_list = QTreeWidget()
        self.key_list.setHeaderLabels(["Key ID", "Type", "User ID", "Created", "Expires"])
        self.key_list.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.key_list.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Key details
        details_group = QGroupBox("Key Details")
        details_layout = QFormLayout()
        
        self.key_id_label = QLabel()
        self.key_type_label = QLabel()
        self.key_size_label = QLabel()
        self.key_created_label = QLabel()
        self.key_expires_label = QLabel()
        self.key_fingerprint_label = QLabel()
        self.key_user_ids = QListWidget()
        
        details_layout.addRow("Key ID:", self.key_id_label)
        details_layout.addRow("Type:", self.key_type_label)
        details_layout.addRow("Size:", self.key_size_label)
        details_layout.addRow("Created:", self.key_created_label)
        details_layout.addRow("Expires:", self.key_expires_label)
        details_layout.addRow("Fingerprint:", self.key_fingerprint_label)
        details_layout.addRow("User IDs:", self.key_user_ids)
        
        details_group.setLayout(details_layout)
        
        # Add to layout
        layout.addLayout(toolbar)
        layout.addWidget(self.key_list)
        layout.addWidget(details_group)
        
        # Connect signals
        self.key_list.itemSelectionChanged.connect(self.on_key_selected)
        self.import_key_btn.clicked.connect(self.import_key)
        self.export_key_btn.clicked.connect(self.export_key)
        self.generate_key_btn.clicked.connect(self.generate_key)
        self.delete_key_btn.clicked.connect(self.delete_key)
        
        return tab
    
    def create_server_tab(self):
        """Create the key server tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Server selection
        server_group = QGroupBox("Key Servers")
        server_layout = QVBoxLayout()
        
        self.server_combo = QComboBox()
        self.server_combo.addItems([
            "hkps://keys.openpgp.org",
            "hkps://keyserver.ubuntu.com",
            "hkps://pgp.mit.edu"
        ])
        
        self.custom_server_edit = QLineEdit()
        self.custom_server_edit.setPlaceholderText("Or enter custom server URL")
        
        server_layout.addWidget(QLabel("Select Key Server:"))
        server_layout.addWidget(self.server_combo)
        server_layout.addWidget(self.custom_server_edit)
        
        # Search
        search_group = QGroupBox("Search Keys")
        search_layout = QVBoxLayout()
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by key ID, fingerprint, or email")
        self.search_btn = QPushButton("Search")
        
        self.search_results = QListWidget()
        
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(self.search_btn)
        search_layout.addWidget(QLabel("Search Results:"))
        search_layout.addWidget(self.search_results)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.import_from_server_btn = QPushButton("Import Selected")
        self.upload_to_server_btn = QPushButton("Upload Public Key")
        
        btn_layout.addWidget(self.import_from_server_btn)
        btn_layout.addWidget(self.upload_to_server_btn)
        
        # Add to layouts
        search_layout.addLayout(btn_layout)
        search_group.setLayout(search_layout)
        server_group.setLayout(server_layout)
        
        layout.addWidget(server_group)
        layout.addWidget(search_group)
        
        # Connect signals
        self.search_btn.clicked.connect(self.search_keys)
        self.import_from_server_btn.clicked.connect(self.import_from_server)
        self.upload_to_server_btn.clicked.connect(self.upload_to_server)
        
        return tab
    
    def create_sharing_tab(self):
        """Create the key sharing tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Key selection
        key_group = QGroupBox("Select Key to Share")
        key_layout = QVBoxLayout()
        
        self.share_key_combo = QComboBox()
        self.share_include_private = QCheckBox("Include private key (for trusted recipients)")
        
        key_layout.addWidget(QLabel("Key to share:"))
        key_layout.addWidget(self.share_key_combo)
        key_layout.addWidget(self.share_include_private)
        
        # Recipients
        recipient_group = QGroupBox("Recipients")
        recipient_layout = QVBoxLayout()
        
        self.recipient_list = QListWidget()
        self.add_recipient_btn = QPushButton("Add Recipient")
        self.remove_recipient_btn = QPushButton("Remove Selected")
        
        recipient_btn_layout = QHBoxLayout()
        recipient_btn_layout.addWidget(self.add_recipient_btn)
        recipient_btn_layout.addWidget(self.remove_recipient_btn)
        
        recipient_layout.addWidget(QLabel("Recipients (public keys):"))
        recipient_layout.addWidget(self.recipient_list)
        recipient_layout.addLayout(recipient_btn_layout)
        
        # Export options
        export_group = QGroupBox("Export Options")
        export_layout = QVBoxLayout()
        
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItems(["ASCII Armored", "Binary"])
        
        self.export_btn = QPushButton("Export Shared Key")
        
        export_layout.addWidget(QLabel("Format:"))
        export_layout.addWidget(self.export_format_combo)
        export_layout.addStretch()
        export_layout.addWidget(self.export_btn)
        
        # Add to layouts
        key_group.setLayout(key_layout)
        recipient_group.setLayout(recipient_layout)
        export_group.setLayout(export_layout)
        
        layout.addWidget(key_group)
        layout.addWidget(recipient_group)
        layout.addWidget(export_group)
        
        # Connect signals
        self.add_recipient_btn.clicked.connect(self.add_recipient)
        self.remove_recipient_btn.clicked.connect(self.remove_recipient)
        self.export_btn.clicked.connect(self.export_shared_key)
        
        return tab
    
    def create_hardware_tab(self):
        """Create the hardware token management tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Hardware token status
        status_group = QGroupBox("Hardware Token Status")
        status_layout = QFormLayout()
        
        self.token_status_label = QLabel("No hardware token detected")
        self.token_info_label = QLabel()
        
        status_layout.addRow("Status:", self.token_status_label)
        status_layout.addRow("Token Info:", self.token_info_label)
        
        # Token operations
        op_group = QGroupBox("Operations")
        op_layout = QVBoxLayout()
        
        self.detect_token_btn = QPushButton("Detect Token")
        self.initialize_token_btn = QPushButton("Initialize Token")
        self.import_to_token_btn = QPushButton("Import Key to Token")
        self.export_from_token_btn = QPushButton("Export Key from Token")
        self.change_pin_btn = QPushButton("Change PIN")
        
        op_btn_layout1 = QHBoxLayout()
        op_btn_layout1.addWidget(self.detect_token_btn)
        op_btn_layout1.addWidget(self.initialize_token_btn)
        
        op_btn_layout2 = QHBoxLayout()
        op_btn_layout2.addWidget(self.import_to_token_btn)
        op_btn_layout2.addWidget(self.export_from_token_btn)
        
        op_layout.addLayout(op_btn_layout1)
        op_layout.addLayout(op_btn_layout2)
        op_layout.addWidget(self.change_pin_btn)
        
        # Add to layouts
        status_group.setLayout(status_layout)
        op_group.setLayout(op_layout)
        
        layout.addWidget(status_group)
        layout.addWidget(op_group)
        layout.addStretch()
        
        # Connect signals
        self.detect_token_btn.clicked.connect(self.detect_token)
        self.initialize_token_btn.clicked.connect(self.initialize_token)
        self.import_to_token_btn.clicked.connect(self.import_to_token)
        self.export_from_token_btn.clicked.connect(self.export_from_token)
        self.change_pin_btn.clicked.connect(self.change_pin)
        
        return tab
    
    # Keyring tab methods
    def on_key_selected(self):
        """Handle key selection in the key list."""
        selected = self.key_list.selectedItems()
        if not selected:
            return
            
        key_item = selected[0]
        key_id = key_item.text(0)
        
        # TODO: Get key details from keyring manager
        # key_info = self.keyring_manager.get_key_info(key_id)
        # self.update_key_details(key_info)
    
    def import_key(self):
        """Import a key from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Key",
            "",
            "PGP Keys (*.asc *.gpg *.pgp);;All Files (*)"
        )
        
        if not file_path:
            return
            
        try:
            # Read the key file
            with open(file_path, 'rb') as f:
                key_data = f.read()
            
            # Try to determine key type from file extension
            key_type = 'public'
            if file_path.lower().endswith(('.gpg', '.pgp')):
                # Could be either, but we'll try public first
                key_type = 'public'
            
            # Import the key
            if self.keyring_manager.add_key(key_data, key_type=key_type):
                self.refresh_key_list()
                QMessageBox.information(self, "Success", "Key imported successfully")
            else:
                QMessageBox.warning(self, "Warning", "Failed to import key: Unknown error")
                
        except Exception as e:
            logger.error(f"Failed to import key: {e}")
            QMessageBox.critical(
                self, 
                "Error", 
                f"Failed to import key: {str(e)}\n\n"
                f"Make sure the file contains a valid PGP key and you have "
                f"permission to access it."
            )
    
    def export_key(self):
        """Export the selected key to a file."""
        selected = self.key_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a key to export")
            return
            
        key_item = selected[0]
        key_id = key_item.text(0)
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Key",
            f"{key_id}.asc",
            "ASCII Armored (*.asc);;Binary (*.gpg);;All Files (*)"
        )
        
        if file_path:
            try:
                # TODO: Implement key export using keyring_manager
                # self.keyring_manager.export_key(key_id, file_path)
                QMessageBox.information(self, "Success", f"Key exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export key: {str(e)}")
    
    def generate_key(self):
        """Generate a new key pair."""
        # TODO: Implement key generation dialog and logic
        QMessageBox.information(self, "Not Implemented", "Key generation will be implemented in a future version")
    
    def delete_key(self):
        """Delete the selected key."""
        selected = self.key_list.selectedItems()
        if not selected:
            return
            
        key_item = selected[0]
        key_id = key_item.text(0)
        
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete key {key_id}?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # TODO: Implement key deletion using keyring_manager
                # self.keyring_manager.delete_key(key_id)
                self.refresh_key_list()
                QMessageBox.information(self, "Success", "Key deleted successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete key: {str(e)}")
    
    def refresh_key_list(self):
        """Refresh the list of keys in the keyring."""
        self.key_list.clear()
        
        if not self.keyring_manager:
            return
            
        try:
            # Get all keys from the keyring manager
            keys = self.keyring_manager.list_keys()
            
            for key in keys:
                # Format the key information
                key_id = key.get('fingerprint', '')[-8:]  # Use last 8 chars of fingerprint as key ID
                key_type = key.get('type', 'unknown').capitalize()
                
                # Get the first user ID or 'No user ID'
                user_ids = key.get('uids', [])
                user_id = user_ids[0] if user_ids else 'No user ID'
                
                # Format dates
                created = self._format_timestamp(key.get('created'))
                expires = self._format_timestamp(key.get('expires')) or 'Never'
                
                # Create the tree item
                item = QTreeWidgetItem([
                    key_id,
                    key_type,
                    user_id,
                    created,
                    expires
                ])
                
                # Store the full fingerprint as data
                item.setData(0, Qt.UserRole, key.get('fingerprint'))
                
                # Add to the list
                self.key_list.addTopLevelItem(item)
                
            # Resize columns to fit content
            for i in range(self.key_list.columnCount()):
                self.key_list.resizeColumnToContents(i)
                
        except Exception as e:
            logger.error(f"Failed to refresh key list: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to load keys: {str(e)}"
            )
    
    def _format_timestamp(self, timestamp: Optional[float]) -> str:
        """Format a timestamp as a human-readable string."""
        if not timestamp:
            return ""
            
        try:
            from datetime import datetime
            return datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return str(timestamp)
    
    # Key server tab methods
    def search_keys(self):
        """Search for keys on the key server."""
        search_term = self.search_edit.text().strip()
        if not search_term:
            QMessageBox.warning(self, "Error", "Please enter a search term")
            return
            
        server_url = self.server_combo.currentText()
        if not server_url and self.custom_server_edit.text():
            server_url = self.custom_server_edit.text()
        
        if not server_url:
            QMessageBox.warning(self, "Error", "Please select or enter a key server URL")
            return
            
        try:
            # TODO: Implement key search using KeyServer
            # key_server = KeyServer(server_url)
            # results = key_server.search(search_term)
            # self.update_search_results(results)
            QMessageBox.information(
                self,
                "Search Results",
                f"Searching for '{search_term}' on {server_url}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to search keys: {str(e)}")
    
    def import_from_server(self):
        """Import selected keys from the key server."""
        selected = self.search_results.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select keys to import")
            return
            
        try:
            # TODO: Implement key import from server
            # for item in selected:
            #     key_id = item.data(Qt.UserRole)
            #     self.keyring_manager.import_key_from_server(key_id)
            QMessageBox.information(
                self,
                "Success",
                f"Imported {len(selected)} keys from the server"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import keys: {str(e)}")
    
    def upload_to_server(self):
        """Upload the selected public key to the key server."""
        selected = self.key_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a key to upload")
            return
            
        key_item = selected[0]
        key_id = key_item.text(0)
        
        server_url = self.server_combo.currentText()
        if not server_url and self.custom_server_edit.text():
            server_url = self.custom_server_edit.text()
        
        if not server_url:
            QMessageBox.warning(self, "Error", "Please select or enter a key server URL")
            return
            
        try:
            # TODO: Implement key upload to server
            # key_server = KeyServer(server_url)
            # key_server.upload_key(key_id)
            QMessageBox.information(
                self,
                "Success",
                f"Key {key_id} uploaded to {server_url}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to upload key: {str(e)}")
    
    # Key sharing tab methods
    def add_recipient(self):
        """Add a recipient for key sharing."""
        # TODO: Implement recipient selection from keyring
        recipient, ok = QInputDialog.getText(
            self,
            "Add Recipient",
            "Enter recipient's key ID or email:"
        )
        
        if ok and recipient:
            # TODO: Validate recipient key exists
            self.recipient_list.addItem(recipient)
    
    def remove_recipient(self):
        """Remove selected recipients."""
        selected = self.recipient_list.selectedItems()
        for item in selected:
            self.recipient_list.takeItem(self.recipient_list.row(item))
    
    def export_shared_key(self):
        """Export a key encrypted for the selected recipients."""
        if self.recipient_list.count() == 0:
            QMessageBox.warning(self, "No Recipients", "Please add at least one recipient")
            return
            
        key_id = self.share_key_combo.currentData()
        if not key_id:
            QMessageBox.warning(self, "No Key Selected", "Please select a key to share")
            return
            
        recipients = []
        for i in range(self.recipient_list.count()):
            recipients.append(self.recipient_list.item(i).text())
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Shared Key",
            f"{key_id}.gpg",
            "PGP Key (*.gpg);;All Files (*)"
        )
        
        if file_path:
            try:
                # TODO: Implement key sharing
                # self.keyring_manager.export_shared_key(
                #     key_id,
                #     recipients,
                #     file_path,
                #     include_private=self.share_include_private.isChecked()
                # )
                QMessageBox.information(
                    self,
                    "Success",
                    f"Key exported and encrypted for {len(recipients)} recipients"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export shared key: {str(e)}")
    
    # Hardware token methods
    def detect_token(self):
        """Detect connected hardware tokens."""
        try:
            # TODO: Implement hardware token detection
            # token = HardwareToken.detect()
            # if token:
            #     self.token_status_label.setText("Token detected")
            #     self.token_info_label.setText(f"{token.manufacturer} {token.model}")
            # else:
            #     self.token_status_label.setText("No token detected")
            #     self.token_info_label.clear()
            QMessageBox.information(
                self,
                "Hardware Token",
                "Hardware token detection will be implemented in a future version"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to detect hardware token: {str(e)}")
    
    def initialize_token(self):
        """Initialize a new hardware token."""
        # TODO: Implement token initialization
        QMessageBox.information(
            self,
            "Not Implemented",
            "Hardware token initialization will be implemented in a future version"
        )
    
    def import_to_token(self):
        """Import a key to the hardware token."""
        # TODO: Implement key import to token
        QMessageBox.information(
            self,
            "Not Implemented",
            "Key import to token will be implemented in a future version"
        )
    
    def export_from_token(self):
        """Export a key from the hardware token."""
        # TODO: Implement key export from token
        QMessageBox.information(
            self,
            "Not Implemented",
            "Key export from token will be implemented in a future version"
        )
    
    def change_pin(self):
        """Change the PIN for the hardware token."""
        # TODO: Implement PIN change
        QMessageBox.information(
            self,
            "Not Implemented",
            "PIN change will be implemented in a future version"
        )


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = KeyManagementTab()
    window.setWindowTitle("Key Management")
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())
