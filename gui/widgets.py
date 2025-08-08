"""
Custom Widgets Module (PySide6 Version)

This module provides reusable PySide6 widget components.

License: GPL v3.0 (see LICENSE)
"""

from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout,
    QSizePolicy, QFrame
)
from PySide6.QtCore import Qt, Signal

class LabeledInput(QWidget):
    """A labeled input field widget.
    
    Provides a reusable component that combines a label and an input field.
    """
    
    textChanged = Signal(str)
    
    def __init__(self, label_text: str, parent: QWidget = None):
        """Initialize the labeled input widget.
        
        Args:
            label_text: The text to display as the label
            parent: The parent widget
        """
        super().__init__(parent)
        self.setup_ui(label_text)
    
    def setup_ui(self, label_text: str):
        """Set up the user interface.
        
        Args:
            label_text: The text to display as the label
        """
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Create label
        self.label = QLabel(label_text)
        self.label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        self.label.setMinimumWidth(80)
        
        # Create line edit
        self.line_edit = QLineEdit()
        self.line_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.line_edit.textChanged.connect(self._on_text_changed)
        
        # Add widgets to layout
        layout.addWidget(self.label)
        layout.addWidget(self.line_edit, 1)
    
    def text(self) -> str:
        """Get the current text from the input field.
        
        Returns:
            The current text in the input field
        """
        return self.line_edit.text()
    
    def setText(self, text: str):
        """Set the text in the input field.
        
        Args:
            text: The text to set in the input field
        """
        self.line_edit.setText(text)
    
    def setReadOnly(self, read_only: bool):
        """Set whether the input field is read-only.
        
        Args:
            read_only: If True, the input field will be read-only
        """
        self.line_edit.setReadOnly(read_only)
    
    def setEchoMode(self, mode):
        """Set the echo mode for the input field.
        
        Args:
            mode: The echo mode (QLineEdit.EchoMode)
        """
        self.line_edit.setEchoMode(mode)
    
    def _on_text_changed(self, text: str):
        """Handle text changed signal from the line edit.
        
        Args:
            text: The new text
        """
        self.textChanged.emit(text)


def create_section_header(text: str, parent: QWidget = None) -> QFrame:
    """Create a styled section header.
    
    Args:
        text: The text to display in the header
        parent: The parent widget
        
    Returns:
        A QFrame containing the styled header
    """
    frame = QFrame(parent)
    frame.setFrameShape(QFrame.HLine)
    frame.setFrameShadow(QFrame.Sunken)
    frame.setLineWidth(1)
    
    layout = QHBoxLayout(frame)
    layout.setContentsMargins(0, 10, 0, 5)
    
    label = QLabel(text)
    font = label.font()
    font.setBold(True)
    font.setPointSize(font.pointSize() + 1)
    label.setFont(font)
    
    layout.addWidget(label)
    
    return frame


def create_horizontal_line(parent: QWidget = None) -> QFrame:
    """Create a horizontal line.
    
    Args:
        parent: The parent widget
        
    Returns:
        A QFrame styled as a horizontal line
    """
    line = QFrame(parent)
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    line.setLineWidth(1)
    return line
