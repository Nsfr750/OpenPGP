""""
TPM Settings Dialog for OpenPGP.
"""
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QCheckBox,
    QPushButton,
    QMessageBox,
    QGroupBox,
    QFormLayout,
    QTextEdit,
    QHBoxLayout
)
from PySide6.QtCore import Qt
import logging
from typing import Optional, Dict, Any

from core.tpm_utils import get_tpm_status_message, check_tpm_requirements
from core.config import get_config

logger = logging.getLogger(__name__)


class TpmSettingsDialog(QDialog):
    """Dialog for configuring TPM settings."""
    
    def __init__(self, parent=None) -> None:
        """Initialize the TPM settings dialog."""
        super().__init__(parent)
        self.setWindowTitle("TPM Configuration")
        self.setMinimumWidth(500)
        
        self.config = get_config()
        self.tpm_status: Dict[str, Any] = {}
        
        self._setup_ui()
        self._load_settings()
    
    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Status group
        status_group = QGroupBox("TPM Status")
        status_layout = QVBoxLayout()
        
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(150)
        status_layout.addWidget(self.status_text)
        
        # Add refresh button
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self._refresh_status)
        status_layout.addWidget(refresh_btn, 0, Qt.AlignRight)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Settings group
        settings_group = QGroupBox("TPM Settings")
        settings_layout = QFormLayout()
        
        self.enable_tpm_cb = QCheckBox("Enable TPM support")
        self.enable_tpm_cb.setToolTip("Enable or disable TPM functionality")
        settings_layout.addRow("TPM Support:", self.enable_tpm_cb)
        
        self.tpm_required_cb = QCheckBox("Require TPM for operation")
        self.tpm_required_cb.setToolTip(
            "If enabled, the application will not start without TPM support"
        )
        settings_layout.addRow("TPM Required:", self.tpm_required_cb)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.accept)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_layout.addStretch()
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        
        # Update UI based on TPM availability
        self._update_ui_state()
    
    def _load_settings(self) -> None:
        """Load current settings from config."""
        self.enable_tpm_cb.setChecked(self.config.get('enable_tpm', True))
        self.tpm_required_cb.setChecked(self.config.get('tpm_required', False))
        self._refresh_status()
    
    def _refresh_status(self) -> None:
        """Refresh the TPM status display."""
        self.tpm_status = check_tpm_requirements()
        status_text = get_tpm_status_message()
        self.status_text.setPlainText(status_text)
        self._update_ui_state()
    
    def _update_ui_state(self) -> None:
        """Update UI elements based on current state."""
        tpm_available = self.tpm_status.get('tpm_available', False)
        dependencies_met = self.tpm_status.get('dependencies_met', False)
        
        # Enable/disable checkboxes based on TPM availability
        self.enable_tpm_cb.setEnabled(tpm_available)
        self.tpm_required_cb.setEnabled(tpm_available and dependencies_met)
        
        # Show warning if TPM is required but not available
        if self.tpm_required_cb.isChecked() and not (tpm_available and dependencies_met):
            QMessageBox.warning(
                self,
                "TPM Not Available",
                "TPM is required but not available. Some features may not work correctly."
            )
    
    def accept(self) -> None:
        """Save settings and close the dialog."""
        try:
            self.config.set('enable_tpm', self.enable_tpm_cb.isChecked())
            self.config.set('tpm_required', self.tpm_required_cb.isChecked())
            super().accept()
        except Exception as e:
            logger.error("Error saving TPM settings: %s", e)
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save TPM settings: {str(e)}"
            )


def show_tpm_settings(parent=None) -> bool:
    """
    Show the TPM settings dialog.
    
    Args:
        parent: Parent widget
        
    Returns:
        bool: True if settings were saved, False if canceled
    """
    dialog = TpmSettingsDialog(parent)
    return dialog.exec() == QDialog.DialogCode.Accepted
