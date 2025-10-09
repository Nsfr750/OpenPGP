import webbrowser
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QWidget, QApplication
)
from PySide6.QtGui import QPixmap, QIcon, QFont
from PySide6.QtCore import Qt, QSize, QUrl

class SponsorWindow(QDialog):
    """A dialog window for showing sponsorship options."""
    
    def __init__(self, parent=None):
        """Initialize the Sponsor window."""
        super().__init__(parent)
        self.setWindowTitle("Support & Sponsor OpenPGP GUI")
        self.setMinimumSize(520, 220)
        self.resize(640, 320)
        self.setWindowModality(Qt.ApplicationModal)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(20, 15, 20, 15)
        
        # Title
        title = QLabel("❤️ Support the Project! ❤️")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #3DAEE9;")
        
        # Subtitle
        subtitle = QLabel("Your support helps us improve OpenPGP GUI!")
        subtitle_font = QFont()
        subtitle_font.setPointSize(11)
        subtitle.setFont(subtitle_font)
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #7F8C8D;")
        
        # Sponsor buttons
        btn_container = QWidget()
        btn_layout = QVBoxLayout(btn_container)
        btn_layout.setSpacing(10)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        
        # Define buttons with their respective URLs and styles
        buttons = [
            ("🐙 Sponsor on GitHub", "https://github.com/sponsors/Nsfr750", "#2ecc71"),
            ("💰 Donate on Paypal", "https://paypal.me/3dmega", "#f39c12")
        ]
        
        for text, url, color in buttons:
            btn = QPushButton(text)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    font-weight: bold;
                    min-width: 200px;
                }}
                QPushButton:hover {{
                    background-color: {'#27ae60' if color == '#2ecc71' else 
                                     '#2980b9' if color == '#3498db' else
                                     '#e67e22' if color == '#f39c12' else
                                     '#8e44ad'};
                }}
                QPushButton:pressed {{
                    background-color: {'#219653' if color == '#2ecc71' else 
                                     '#2471a3' if color == '#3498db' else
                                     '#d35400' if color == '#f39c12' else
                                     '#7d3c98'};
                }}
            """)
            btn.clicked.connect(lambda checked, u=url: self.open_url(u))
            btn_layout.addWidget(btn, 0, Qt.AlignCenter)
        
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
        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)
        main_layout.addStretch(1)
        main_layout.addWidget(btn_container, 1)
        main_layout.addStretch(1)
        main_layout.addWidget(close_btn, 0, Qt.AlignCenter)
        
        # Center the window
        self.center_window()
    
    def open_url(self, url):
        """Open the specified URL in the default web browser."""
        webbrowser.open(url)
    
    def center_window(self):
        """Center the window on the screen."""
        frame = self.frameGeometry()
        center_point = QApplication.primaryScreen().availableGeometry().center()
        frame.moveCenter(center_point)
        self.move(frame.topLeft())
