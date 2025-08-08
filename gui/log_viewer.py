"""
Log Viewer Module (PySide6 Version)

This module provides a log viewer dialog for the OpenPGP application.
It allows viewing and filtering application logs with different log levels.

License: GPL v3.0 (see LICENSE)
"""

import os
import sys
import traceback
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTextEdit, QRadioButton, QButtonGroup, QApplication, QFrame
)
from PySide6.QtCore import Qt, QFile, QTextStream
from PySide6.QtGui import QFont, QTextCharFormat, QTextCursor, QColor, QTextOption

class LogViewerWindow(QDialog):
    """A dialog window for viewing and filtering application logs."""
    
    def __init__(self, parent=None):
        """Initialize the Log Viewer window."""
        super().__init__(parent)
        self.setWindowTitle("Application Log")
        self.resize(800, 600)
        self.setMinimumSize(600, 400)
        self.setWindowModality(Qt.ApplicationModal)
        
        # Define log file path
        self.LOG_FILE = 'traceback.log'
        
        self.setup_ui()
        self.load_logs()
    
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Filter options
        filter_frame = QFrame()
        filter_frame.setFrameShape(QFrame.StyledPanel)
        filter_frame.setStyleSheet("""
            QFrame {
                background-color: #2A2D32;
                border: 1px solid #3A3F44;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(5, 5, 5, 5)
        
        filter_label = QLabel("Show:")
        filter_label.setStyleSheet("color: #EFF0F1;")
        
        # Create radio buttons for log levels
        self.button_group = QButtonGroup(self)
        self.button_group.buttonClicked.connect(self.filter_logs)
        
        levels = ["ALL", "INFO", "WARNING", "ERROR"]
        for i, level in enumerate(levels):
            btn = QRadioButton(level)
            btn.setStyleSheet("""
                QRadioButton {
                    color: #EFF0F1;
                    spacing: 5px;
                }
                QRadioButton::indicator {
                    width: 14px;
                    height: 14px;
                }
                QRadioButton::indicator::unchecked {
                    border: 2px solid #7F8C8D;
                    border-radius: 7px;
                }
                QRadioButton::indicator::checked {
                    border: 2px solid #3DAEE9;
                    border-radius: 7px;
                    background-color: #3DAEE9;
                }
            """)
            self.button_group.addButton(btn, i)
            filter_layout.addWidget(btn)
            if i == 0:  # Select ALL by default
                btn.setChecked(True)
        
        filter_layout.addStretch()
        
        # Log text area
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #232629;
                color: #EFF0F1;
                border: 1px solid #3A3F44;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas', 'Monospace';
            }
        """)
        self.text_edit.setLineWrapMode(QTextEdit.NoWrap)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #7F8C8D;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #6C7A80;
            }
            QPushButton:pressed {
                background-color: #5D6D7E;
            }
        """)
        close_btn.clicked.connect(self.close)
        
        # Add widgets to main layout
        main_layout.addWidget(filter_frame)
        main_layout.addWidget(self.text_edit, 1)
        main_layout.addWidget(close_btn, 0, Qt.AlignRight)
        
        # Center the window
        self.center_window()
    
    def load_logs(self):
        """Load logs from the log file or last traceback."""
        log_content = ''
        
        # Try to read from log file
        if os.path.exists(self.LOG_FILE):
            try:
                with open(self.LOG_FILE, 'r', encoding='utf-8') as f:
                    log_content = f.read()
            except Exception as e:
                log_content = f"Error reading log file: {str(e)}\n"
        
        # If no log file or empty, try to get last traceback
        if not log_content:
            exc_type = getattr(sys, 'last_type', None)
            exc_value = getattr(sys, 'last_value', None)
            exc_tb = getattr(sys, 'last_traceback', None)
            
            if exc_type and exc_value and exc_tb:
                log_content = '--- Last Runtime Traceback ---\n' + \
                            ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
            else:
                log_content = 'Log file not found and no runtime traceback available.'
        
        self.original_logs = log_content
        self.filter_logs()
    
    def filter_logs(self):
        """Filter logs based on the selected log level."""
        if not hasattr(self, 'original_logs'):
            return
        
        level = self.button_group.checkedButton().text()
        
        if level == 'ALL':
            filtered_logs = self.original_logs
        else:
            lines = self.original_logs.split('\n')
            filtered_lines = []
            
            for line in lines:
                if f'[{level}]' in line or (level == 'ERROR' and 'Exception' in line):
                    filtered_lines.append(line)
            
            filtered_logs = '\n'.join(filtered_lines) if filtered_lines else f'No {level} logs found.'
        
        # Save cursor position and scroll position
        cursor = self.text_edit.textCursor()
        scrollbar = self.text_edit.verticalScrollBar()
        was_at_bottom = scrollbar.value() == scrollbar.maximum()
        
        # Update text
        self.text_edit.clear()
        self.text_edit.setPlainText(filtered_logs)
        
        # Restore scroll position
        if was_at_bottom:
            cursor.movePosition(QTextCursor.End)
            self.text_edit.setTextCursor(cursor)
    
    def center_window(self):
        """Center the window on the screen."""
        frame = self.frameGeometry()
        center_point = QApplication.primaryScreen().availableGeometry().center()
        frame.moveCenter(center_point)
        self.move(frame.topLeft())
