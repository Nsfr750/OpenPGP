"""
Identity Management UI for OpenPGP

This module provides a user interface for managing blockchain-based identities.
"""
from typing import Optional, Dict, Any, List
from pathlib import Path
import json
import asyncio
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QTabWidget,
    QFormLayout, QComboBox, QFileDialog, QProgressBar, QSizePolicy,
    QInputDialog, QMenu, QToolBar, QSplitter, QTextEdit, QGroupBox
)
from PyQt6.QtCore import Qt, QSize, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QPixmap, QColor, QFont

from ..core.blockchain_identity import (
    BlockchainIdentityManager, BlockchainIdentity, IdentityClaim,
    BlockchainType, VerificationStatus, BlockchainIdentityError
)
from ..core.secure_messaging import SecureMessaging
from ..core.advanced_crypto import AdvancedCrypto

class IdentityTab(QWidget):
    """Tab for managing blockchain identities and verifiable credentials."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.identity_manager = None
        self.current_identity = None
        self.verification_requests = []
        self.setup_ui()
        self.load_identities()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QHBoxLayout()
        
        # Left sidebar for identity list
        sidebar = QWidget()
        sidebar.setMaximumWidth(300)
        sidebar_layout = QVBoxLayout(sidebar)
        
        # Identity list
        self.identity_list = QTableWidget()
        self.identity_list.setColumnCount(2)
        self.identity_list.setHorizontalHeaderLabels(['', 'Identity'])
        self.identity_list.horizontalHeader().setStretchLastSection(True)
        self.identity_list.verticalHeader().setVisible(False)
        self.identity_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.identity_list.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.identity_list.itemSelectionChanged.connect(self.on_identity_selected)
        
        # Buttons for identity management
        btn_layout = QHBoxLayout()
        self.btn_new = QPushButton('New')
        self.btn_new.clicked.connect(self.create_identity)
        self.btn_import = QPushButton('Import')
        self.btn_import.clicked.connect(self.import_identity)
        self.btn_export = QPushButton('Export')
        self.btn_export.clicked.connect(self.export_identity)
        
        btn_layout.addWidget(self.btn_new)
        btn_layout.addWidget(self.btn_import)
        btn_layout.addWidget(self.btn_export)
        
        sidebar_layout.addWidget(QLabel('<b>My Identities</b>'))
        sidebar_layout.addWidget(self.identity_list)
        sidebar_layout.addLayout(btn_layout)
        
        # Main content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        
        # Identity details
        self.details_group = QGroupBox('Identity Details')
        details_layout = QFormLayout()
        
        self.lbl_did = QLabel()
        self.lbl_address = QLabel()
        self.lbl_blockchain = QLabel()
        self.lbl_status = QLabel()
        self.lbl_created = QLabel()
        
        details_layout.addRow('DID:', self.lbl_did)
        details_layout.addRow('Address:', self.lbl_address)
        details_layout.addRow('Blockchain:', self.lbl_blockchain)
        details_layout.addRow('Status:', self.lbl_status)
        details_layout.addRow('Created:', self.lbl_created)
        
        self.details_group.setLayout(details_layout)
        
        # Verifiable credentials
        self.credentials_group = QGroupBox('Verifiable Credentials')
        credentials_layout = QVBoxLayout()
        
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(4)
        self.credentials_table.setHorizontalHeaderLabels(['Type', 'Issuer', 'Status', 'Expires'])
        self.credentials_table.horizontalHeader().setStretchLastSection(True)
        self.credentials_table.verticalHeader().setVisible(False)
        self.credentials_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        btn_credentials = QHBoxLayout()
        self.btn_request = QPushButton('Request Verification')
        self.btn_request.clicked.connect(self.request_verification)
        self.btn_revoke = QPushButton('Revoke')
        self.btn_revoke.clicked.connect(self.revoke_credential)
        
        btn_credentials.addWidget(self.btn_request)
        btn_credentials.addWidget(self.btn_revoke)
        btn_credentials.addStretch()
        
        credentials_layout.addWidget(self.credentials_table)
        credentials_layout.addLayout(btn_credentials)
        self.credentials_group.setLayout(credentials_layout)
        
        # Verification requests
        self.requests_group = QGroupBox('Verification Requests')
        requests_layout = QVBoxLayout()
        
        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(4)
        self.requests_table.setHorizontalHeaderLabels(['From', 'Type', 'Status', 'Date'])
        self.requests_table.horizontalHeader().setStretchLastSection(True)
        self.requests_table.verticalHeader().setVisible(False)
        self.requests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.requests_table.itemDoubleClicked.connect(self.view_verification_request)
        
        requests_layout.addWidget(self.requests_table)
        self.requests_group.setLayout(requests_layout)
        
        # Add all to content layout
        content_layout.addWidget(self.details_group)
        content_layout.addWidget(self.credentials_group)
        content_layout.addWidget(self.requests_group)
        
        # Add sidebar and content to main layout
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content, 1)
        
        self.setLayout(main_layout)
        
        # Disable buttons until an identity is selected
        self.set_buttons_enabled(False)
    
    def load_identities(self):
        """Load identities from storage."""
        # TODO: Load from actual storage
        self.identities = []
        
        # Example identity (remove in production)
        example_identity = BlockchainIdentity(
            did="did:ethr:0x1234...",
            address="0x1234...",
            blockchain=BlockchainType.ETHEREUM,
            public_key="0x04abcd...",
            verification_methods=[],
            created=time.time(),
            updated=time.time(),
            metadata={"name": "Example Identity"}
        )
        self.identities.append(example_identity)
        
        self.update_identity_list()
    
    def update_identity_list(self):
        """Update the identity list widget."""
        self.identity_list.setRowCount(len(self.identities))
        
        for row, identity in enumerate(self.identities):
            # Name/identifier
            name = identity.metadata.get('name', 'Unnamed Identity')
            item = QTableWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, identity.did)
            
            # Status indicator
            status = QTableWidgetItem()
            status.setIcon(self.get_status_icon('verified'))
            
            self.identity_list.setItem(row, 0, status)
            self.identity_list.setItem(row, 1, item)
        
        self.identity_list.resizeColumnsToContents()
    
    def get_status_icon(self, status):
        """Get icon for verification status."""
        # TODO: Replace with actual icons
        if status == 'verified':
            return QIcon.fromTheme('security-high')
        elif status == 'pending':
            return QIcon.fromTheme('security-medium')
        else:
            return QIcon.fromTheme('security-low')
    
    def on_identity_selected(self):
        """Handle selection of an identity from the list."""
        selected = self.identity_list.selectedItems()
        if not selected:
            self.set_buttons_enabled(False)
            return
        
        did = selected[0].data(Qt.ItemDataRole.UserRole)
        self.current_identity = next(
            (i for i in self.identities if i.did == did), 
            None
        )
        
        if self.current_identity:
            self.update_identity_details()
            self.update_credentials_list()
            self.update_verification_requests()
            self.set_buttons_enabled(True)
    
    def update_identity_details(self):
        """Update the identity details panel."""
        if not self.current_identity:
            return
        
        identity = self.current_identity
        
        self.lbl_did.setText(identity.did)
        self.lbl_address.setText(identity.address)
        self.lbl_blockchain.setText(identity.blockchain.value)
        
        # Format dates
        created = datetime.fromtimestamp(identity.created).strftime('%Y-%m-%d %H:%M:%S')
        updated = datetime.fromtimestamp(identity.updated).strftime('%Y-%m-%d %H:%M:%S')
        
        self.lbl_created.setText(created)
        self.lbl_updated = QLabel(updated)
        
        # Status based on verification methods
        if identity.verification_methods:
            self.lbl_status.setText('Verified')
            self.lbl_status.setStyleSheet('color: green;')
        else:
            self.lbl_status.setText('Unverified')
            self.lbl_status.setStyleSheet('color: orange;')
    
    def update_credentials_list(self):
        """Update the list of verifiable credentials."""
        # TODO: Load actual credentials for the selected identity
        credentials = []
        
        self.credentials_table.setRowCount(len(credentials))
        
        for row, cred in enumerate(credentials):
            self.credentials_table.setItem(row, 0, QTableWidgetItem(cred.claim_type))
            self.credentials_table.setItem(row, 1, QTableWidgetItem(cred.issuer))
            self.credentials_table.setItem(row, 2, QTableWidgetItem(cred.status.name))
            
            expires = 'Never' if not cred.expiration_date else \
                datetime.fromtimestamp(cred.expiration_date).strftime('%Y-%m-%d')
            self.credentials_table.setItem(row, 3, QTableWidgetItem(expires))
        
        self.credentials_table.resizeColumnsToContents()
    
    def update_verification_requests(self):
        """Update the list of verification requests."""
        # TODO: Load actual verification requests
        requests = self.verification_requests
        
        self.requests_table.setRowCount(len(requests))
        
        for row, req in enumerate(requests):
            self.requests_table.setItem(row, 0, QTableWidgetItem(req.get('from', '')))
            self.requests_table.setItem(row, 1, QTableWidgetItem(req.get('type', '')))
            self.requests_table.setItem(row, 2, QTableWidgetItem(req.get('status', 'pending')))
            self.requests_table.setItem(row, 3, QTableWidgetItem(req.get('date', '')))
        
        self.requests_table.resizeColumnsToContents()
    
    def set_buttons_enabled(self, enabled):
        """Enable or disable action buttons."""
        self.btn_export.setEnabled(enabled)
        self.btn_request.setEnabled(enabled)
        self.btn_revoke.setEnabled(enabled)
    
    def create_identity(self):
        """Create a new blockchain identity."""
        from ..core.blockchain_identity import BlockchainIdentityManager
        
        # Show dialog to select blockchain
        blockchains = [t.value for t in BlockchainType]
        blockchain, ok = QInputDialog.getItem(
            self, 'Create Identity', 'Select Blockchain:', 
            blockchains, 0, False
        )
        
        if not ok or not blockchain:
            return
        
        # Get identity name
        name, ok = QInputDialog.getText(
            self, 'Create Identity', 'Enter a name for this identity:'
        )
        
        if not ok or not name:
            return
        
        try:
            # Initialize blockchain manager
            manager = BlockchainIdentityManager({
                'ethereum': {'enabled': blockchain == 'ethereum'},
                'strict_mode': False
            })
            
            # Generate keys and create identity
            key_pair = AdvancedCrypto().generate_key_pair(
                'ed25519' if blockchain == 'solana' else 'x25519'
            )
            
            # In a real implementation, this would register with the blockchain
            identity = BlockchainIdentity(
                did=f"did:{blockchain.lower()}:{key_pair['public_key'][:10]}...",
                address=key_pair['public_key'],
                blockchain=BlockchainType(blockchain),
                public_key=key_pair['public_key'],
                verification_methods=[],
                created=time.time(),
                updated=time.time(),
                metadata={'name': name}
            )
            
            self.identities.append(identity)
            self.update_identity_list()
            
            QMessageBox.information(
                self, 'Success', 
                f'Successfully created {blockchain} identity: {name}'
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, 'Error', 
                f'Failed to create identity: {str(e)}'
            )
    
    def import_identity(self):
        """Import an existing identity from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 'Import Identity', '',
            'Identity Files (*.json);;All Files (*)'
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
                # Validate the identity data
                required = ['did', 'address', 'blockchain', 'public_key', 'verification_methods']
                if not all(k in data for k in required):
                    raise ValueError('Invalid identity file format')
                
                # Create identity object
                identity = BlockchainIdentity(
                    did=data['did'],
                    address=data['address'],
                    blockchain=BlockchainType(data['blockchain']),
                    public_key=data['public_key'],
                    verification_methods=data['verification_methods'],
                    created=data.get('created', time.time()),
                    updated=data.get('updated', time.time()),
                    metadata=data.get('metadata', {})
                )
                
                self.identities.append(identity)
                self.update_identity_list()
                
                QMessageBox.information(
                    self, 'Success', 
                    f'Successfully imported identity: {identity.metadata.get("name", identity.did)}'
                )
                
        except Exception as e:
            QMessageBox.critical(
                self, 'Error', 
                f'Failed to import identity: {str(e)}'
            )
    
    def export_identity(self):
        """Export the selected identity to a file."""
        if not self.current_identity:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, 'Export Identity',
            f"{self.current_identity.metadata.get('name', 'identity')}.json",
            'JSON Files (*.json);;All Files (*)'
        )
        
        if not file_path:
            return
        
        try:
            identity = self.current_identity
            data = {
                'did': identity.did,
                'address': identity.address,
                'blockchain': identity.blockchain.value,
                'public_key': identity.public_key,
                'verification_methods': identity.verification_methods,
                'created': identity.created,
                'updated': identity.updated,
                'metadata': identity.metadata
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            QMessageBox.information(
                self, 'Success', 
                f'Successfully exported identity to {file_path}'
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, 'Error', 
                f'Failed to export identity: {str(e)}'
            )
    
    def request_verification(self):
        """Request verification for the selected identity."""
        if not self.current_identity:
            return
        
        # Show dialog to select verification type
        verifications = [
            'Email Verification',
            'Social Media',
            'Government ID',
            'Custom'
        ]
        
        vtype, ok = QInputDialog.getItem(
            self, 'Request Verification',
            'Select verification type:', verifications, 0, False
        )
        
        if not ok or not vtype:
            return
        
        # For demo purposes, just show a message
        QMessageBox.information(
            self, 'Verification Requested',
            f'Verification request for {vtype} has been submitted.\n\n' \
            'You will be notified when the verification is complete.'
        )
        
        # In a real implementation, this would create and sign a verification request
        # and send it to the verifier
    
    def revoke_credential(self):
        """Revoke the selected verifiable credential."""
        selected = self.credentials_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        cred_type = self.credentials_table.item(row, 0).text()
        
        if QMessageBox.question(
            self, 'Revoke Credential',
            f'Are you sure you want to revoke the "{cred_type}" credential?\n\n' \
            'This action cannot be undone.'
        ) == QMessageBox.StandardButton.Yes:
            # In a real implementation, this would revoke the credential on the blockchain
            QMessageBox.information(
                self, 'Credential Revoked',
                f'The "{cred_type}" credential has been revoked.'
            )
            
            # Refresh the credentials list
            self.update_credentials_list()
    
    def view_verification_request(self, item):
        """View details of a verification request."""
        row = item.row()
        from_addr = self.requests_table.item(row, 0).text()
        req_type = self.requests_table.item(row, 1).text()
        
        # In a real implementation, this would show more details and options
        QMessageBox.information(
            self, 'Verification Request',
            f'From: {from_addr}\nType: {req_type}\n\n' \
            'This is a placeholder for the verification request details.'
        )

# For testing the tab independently
if __name__ == '__main__':
    import sys
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the tab
    tab = IdentityTab()
    tab.setWindowTitle('Identity Management')
    tab.resize(1000, 700)
    tab.show()
    
    sys.exit(app.exec())
