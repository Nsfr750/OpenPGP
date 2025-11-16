"""
Identity Management Tab

This module provides a tab for managing digital identities.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFormLayout, QGroupBox, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt

class IdentityTab(QWidget):
    """Tab for managing digital identities."""
    
    def __init__(self, parent=None):
        """Initialize the identity tab."""
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Identity Information Group
        identity_group = QGroupBox("Identity Information")
        identity_layout = QFormLayout()
        
        # Name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Your Full Name")
        identity_layout.addRow("Name:", self.name_edit)
        
        # Email
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("your.email@example.com")
        identity_layout.addRow("Email:", self.email_edit)
        
        # Organization
        self.org_edit = QLineEdit()
        self.org_edit.setPlaceholderText("Your Organization (Optional)")
        identity_layout.addRow("Organization:", self.org_edit)
        
        # Comments
        self.comments_edit = QLineEdit()
        self.comments_edit.setPlaceholderText("Additional comments (Optional)")
        identity_layout.addRow("Comments:", self.comments_edit)
        
        identity_group.setLayout(identity_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save Identity")
        self.save_btn.clicked.connect(self.save_identity)
        
        self.load_btn = QPushButton("Load Identity")
        self.load_btn.clicked.connect(self.load_identity)
        
        self.clear_btn = QPushButton("Clear Form")
        self.clear_btn.clicked.connect(self.clear_form)
        
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.clear_btn)
        
        # Add widgets to main layout
        layout.addWidget(identity_group)
        layout.addLayout(btn_layout)
        layout.addStretch()
    
    def save_identity(self):
        """Save the current identity to a file."""
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        
        if not name or not email:
            QMessageBox.warning(self, "Incomplete Information", 
                              "Please fill in at least name and email fields.")
            return
        
        identity_data = {
            'name': name,
            'email': email,
            'organization': self.org_edit.text().strip(),
            'comments': self.comments_edit.text().strip()
        }
        
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Identity",
                "",
                "Identity Files (*.json);;All Files (*)"
            )
            
            if file_path:
                if not file_path.endswith('.json'):
                    file_path += '.json'
                
                with open(file_path, 'w') as f:
                    json.dump(identity_data, f, indent=4)
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"Identity saved successfully to:\n{file_path}"
                )
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save identity: {str(e)}"
            )
    
    def load_identity(self):
        """Load an identity from a file."""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Load Identity",
                "",
                "Identity Files (*.json);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'r') as f:
                    identity_data = json.load(f)
                
                self.name_edit.setText(identity_data.get('name', ''))
                self.email_edit.setText(identity_data.get('email', ''))
                self.org_edit.setText(identity_data.get('organization', ''))
                self.comments_edit.setText(identity_data.get('comments', ''))
                
                QMessageBox.information(
                    self,
                    "Success",
                    f"Identity loaded from:\n{file_path}"
                )
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to load identity: {str(e)}"
            )
    
    def clear_form(self):
        """Clear all form fields."""
        self.name_edit.clear()
        self.email_edit.clear()
        self.org_edit.clear()
        self.comments_edit.clear()


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = IdentityTab()
    window.setWindowTitle("Identity Management")
    window.resize(500, 300)
    window.show()
    sys.exit(app.exec())
