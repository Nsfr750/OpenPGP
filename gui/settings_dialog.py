"""
Settings Dialog for OpenPGP.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QPushButton, 
    QMessageBox, QLabel, QGroupBox, QFormLayout, QCheckBox
)
from PySide6.QtCore import Qt
import logging

from .dialogs.tpm_settings_dialog import show_tpm_settings
from core.config import get_config

logger = logging.getLogger(__name__)

class SettingsDialog(QDialog):
    """Main settings dialog for the application."""
    
    def __init__(self, parent=None):
        """Initialize the settings dialog."""
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 400)
        
        self.config = get_config()
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # General tab
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        
        # Add general settings here
        general_group = QGroupBox("General Settings")
        general_form = QFormLayout()
        
        # Example setting
        self.auto_update_cb = QCheckBox("Check for updates automatically")
        general_form.addRow("Updates:", self.auto_update_cb)
        
        general_group.setLayout(general_form)
        general_layout.addWidget(general_group)
        general_layout.addStretch()
        
        # Security tab
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)
        
        # Security settings group
        security_group = QGroupBox("Security Settings")
        security_form = QFormLayout()
        
        # TPM settings button
        tpm_btn = QPushButton("Configure TPM...")
        tpm_btn.clicked.connect(self._show_tpm_settings)
        security_form.addRow("TPM Configuration:", tpm_btn)
        
        # Add more security settings here
        security_group.setLayout(security_form)
        security_layout.addWidget(security_group)
        security_layout.addStretch()
        
        # Add tabs
        self.tab_widget.addTab(general_tab, "General")
        self.tab_widget.addTab(security_tab, "Security")
        
        layout.addWidget(self.tab_widget)
        
        # Buttons
        btn_layout = QVBoxLayout()
        
        # Add TPM status label
        self.tpm_status_label = QLabel()
        self.tpm_status_label.setWordWrap(True)
        self.tpm_status_label.setStyleSheet("color: #666; font-style: italic;")
        btn_layout.addWidget(self.tpm_status_label)
        
        # Action buttons
        btn_row = QHBoxLayout()
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.accept)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_row.addStretch()
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(cancel_btn)
        
        btn_layout.addLayout(btn_row)
        layout.addLayout(btn_layout)
        
        # Load settings
        self._load_settings()
    
    def _load_settings(self):
        """Load current settings from config."""
        self.auto_update_cb.setChecked(self.config.get('auto_update', True))
        self._update_tpm_status()
    
    def _update_tpm_status(self):
        """Update the TPM status label."""
        from core.tpm_utils import get_tpm_status_message
        status = get_tpm_status_message()
        self.tpm_status_label.setText(f"TPM Status: {status}")
    
    def _show_tpm_settings(self):
        """Show the TPM settings dialog."""
        if show_tpm_settings(self):
            # Refresh status if settings were saved
            self._update_tpm_status()
    
    def accept(self):
        """Save settings and close the dialog."""
        try:
            self.config.set('auto_update', self.auto_update_cb.isChecked())
            super().accept()
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save settings: {str(e)}"
            )

def show_settings(parent=None) -> bool:
    """
    Show the settings dialog.
    
    Args:
        parent: Parent widget
        
    Returns:
        bool: True if settings were saved, False if canceled
    """
    dialog = SettingsDialog(parent)
    return dialog.exec() == QDialog.Accepted
