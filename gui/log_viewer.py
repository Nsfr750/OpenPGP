"""
Enhanced log viewer dialog with advanced features for browsing and analyzing application log files.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from PySide6.QtCore import Qt, QTimer, QThread, Signal, QObject
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QWidget,
    QLabel,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QSplitter,
    QGroupBox,
    QFormLayout,
    QSpinBox,
    QProgressBar,
    QApplication,
    QMenuBar,
    QStatusBar,
)
from PySide6.QtGui import (
    QTextCursor,
    QTextCharFormat,
    QColor,
    QFont,
    QIcon,
    QAction,
    QKeySequence,
    QPalette,
)

from utils.logger import get_log_files

class LogAnalyzer(QObject):
    """Background analyzer for log files."""

    analysis_complete = Signal(dict)  # Emits analysis results

    def __init__(self, file_path: Path):
        super().__init__()
        self.file_path = file_path

    def analyze(self):
        """Analyze log file in background."""
        try:
            content = self.file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.split('\n')

            # Analyze log levels
            level_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0, "DEBUG": 0, "OTHER": 0}
            timestamps = []

            for line in lines:
                # Extract log level
                if "ERROR" in line.upper():
                    level_counts["ERROR"] += 1
                elif "WARNING" in line.upper() or "WARN" in line.upper():
                    level_counts["WARNING"] += 1
                elif "INFO" in line.upper():
                    level_counts["INFO"] += 1
                elif "DEBUG" in line.upper():
                    level_counts["DEBUG"] += 1
                else:
                    level_counts["OTHER"] += 1

                # Extract timestamp (simple regex)
                timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line)
                if timestamp_match:
                    timestamps.append(timestamp_match.group())

            # Calculate statistics
            total_lines = len(lines)
            file_size = self.file_path.stat().st_size
            modified_time = datetime.fromtimestamp(self.file_path.stat().st_mtime)

            analysis = {
                "total_lines": total_lines,
                "file_size": file_size,
                "file_size_mb": round(file_size / (1024 * 1024), 2),
                "modified_time": modified_time,
                "level_counts": level_counts,
                "timestamps_count": len(timestamps),
                "oldest_timestamp": min(timestamps) if timestamps else None,
                "newest_timestamp": max(timestamps) if timestamps else None,
            }

            self.analysis_complete.emit(analysis)

        except Exception as e:
            self.analysis_complete.emit({"error": str(e)})

class LogViewerDialog(QDialog):
    """Enhanced log viewer with advanced features."""

    def __init__(self, log_file: str | Path | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Enhanced Log Viewer")
        self.resize(1200, 800)
        
        # Store the log file path if provided
        self.log_file_path = Path(log_file) if log_file else None

        # Current log file being viewed
        self.current_log_file: Optional[Path] = None
        self.log_content: str = ""
        self.search_results: List[int] = []
        self.current_search_index: int = -1

        # Auto-refresh timer
        self.auto_refresh_timer: Optional[QTimer] = None
        self.auto_refresh_enabled: bool = False

        # Log level filtering - now using dropdown selection
        self.current_filter = "all"  # Current filter mode

        self._setup_ui()
        self._populate_logs()

    def _setup_ui(self) -> None:
        """Set up the enhanced user interface."""
        main_layout = QVBoxLayout(self)

        # Toolbar
        toolbar_layout = QHBoxLayout()

        # File operations
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self._populate_logs)
        toolbar_layout.addWidget(self.refresh_btn)

        self.open_dir_btn = QPushButton("📁 Open Folder")
        self.open_dir_btn.clicked.connect(self._open_logs_folder)
        toolbar_layout.addWidget(self.open_dir_btn)

        self.export_btn = QPushButton("📤 Export")
        self.export_btn.clicked.connect(self._export_selected)
        toolbar_layout.addWidget(self.export_btn)

        toolbar_layout.addStretch()

        # Search functionality
        search_layout = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in log...")
        self.search_input.returnPressed.connect(self._search_logs)
        search_layout.addWidget(QLabel("🔍"))
        search_layout.addWidget(self.search_input, 2)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._search_logs)
        search_layout.addWidget(self.search_btn)

        self.next_result_btn = QPushButton("▼ Next")
        self.next_result_btn.clicked.connect(self._next_search_result)
        search_layout.addWidget(self.next_result_btn)

        self.prev_result_btn = QPushButton("▲ Prev")
        self.prev_result_btn.clicked.connect(self._prev_search_result)
        search_layout.addWidget(self.prev_result_btn)

        toolbar_layout.addLayout(search_layout)

        # Filter controls
        filter_layout = QHBoxLayout()

        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Logs", "all")
        self.filter_combo.addItem("Errors Only", "error")
        self.filter_combo.addItem("Warnings Only", "warning")
        self.filter_combo.addItem("Info Only", "info")
        self.filter_combo.addItem("Debug Only", "debug")
        self.filter_combo.addItem("Other Only", "other")
        self.filter_combo.setCurrentIndex(0)  # Default to "All Logs"
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_combo)

        filter_layout.addStretch()
        toolbar_layout.addLayout(filter_layout)

        main_layout.addLayout(toolbar_layout)

        # Main content area
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Log files list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        # Log files header
        files_header = QHBoxLayout()
        files_header.addWidget(QLabel("📋 Log Files"))
        self.file_count_label = QLabel("0 files")
        files_header.addWidget(self.file_count_label)
        left_layout.addLayout(files_header)

        # Log files list
        self.log_list = QListWidget()
        self.log_list.setMaximumWidth(300)
        self.log_list.currentRowChanged.connect(self._load_selected)
        left_layout.addWidget(self.log_list)

        # File info panel
        file_info_group = QGroupBox("File Information")
        file_info_layout = QFormLayout()

        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setWordWrap(True)
        file_info_layout.addRow("Path:", self.file_path_label)

        self.file_size_label = QLabel("0 bytes")
        file_info_layout.addRow("Size:", self.file_size_label)

        self.file_modified_label = QLabel("Never")
        file_info_layout.addRow("Modified:", self.file_modified_label)

        self.file_lines_label = QLabel("0 lines")
        file_info_layout.addRow("Lines:", self.file_lines_label)

        file_info_group.setLayout(file_info_layout)
        left_layout.addWidget(file_info_group)

        # Statistics panel
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()

        self.error_count_label = QLabel("ERROR: 0")
        self.error_count_label.setStyleSheet("color: red; font-weight: bold;")
        stats_layout.addWidget(self.error_count_label)

        self.warning_count_label = QLabel("WARNING: 0")
        self.warning_count_label.setStyleSheet("color: orange; font-weight: bold;")
        stats_layout.addWidget(self.warning_count_label)

        self.info_count_label = QLabel("INFO: 0")
        self.info_count_label.setStyleSheet("color: white; font-weight: bold;")
        stats_layout.addWidget(self.info_count_label)

        stats_group.setLayout(stats_layout)
        left_layout.addWidget(stats_group)

        left_layout.addStretch()
        splitter.addWidget(left_panel)

        # Right panel - Log content
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        # Log viewer header
        viewer_header = QHBoxLayout()
        viewer_header.addWidget(QLabel("📄 Log Content"))

        # Auto-refresh controls
        self.auto_refresh_cb = QCheckBox("Auto-refresh")
        self.auto_refresh_cb.stateChanged.connect(self._toggle_auto_refresh)
        viewer_header.addWidget(self.auto_refresh_cb)

        self.refresh_interval = QSpinBox()
        self.refresh_interval.setRange(1, 300)
        self.refresh_interval.setValue(5)
        self.refresh_interval.setSuffix("s")
        self.refresh_interval.setMaximumWidth(80)
        viewer_header.addWidget(QLabel("Interval:"))
        viewer_header.addWidget(self.refresh_interval)

        right_layout.addLayout(viewer_header)

        # Log content viewer
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Monospace", 9))
        right_layout.addWidget(self.log_view)

        # Search results info
        search_info_layout = QHBoxLayout()
        self.search_results_label = QLabel("No search active")
        search_info_layout.addWidget(self.search_results_label)

        self.clear_search_btn = QPushButton("Clear Search")
        self.clear_search_btn.clicked.connect(self._clear_search)
        self.clear_search_btn.setEnabled(False)
        search_info_layout.addWidget(self.clear_search_btn)

        right_layout.addLayout(search_info_layout)

        splitter.addWidget(right_panel)

        # Set splitter proportions (30% left, 70% right)
        splitter.setSizes([300, 700])

        main_layout.addWidget(splitter)

        # Bottom buttons
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        bottom_layout.addWidget(self.close_btn)

        main_layout.addLayout(bottom_layout)

        # Set focus on search input for better UX
        self.search_input.setFocus()

    def _clear_file_info(self) -> None:
        """Clear file information display."""
        if hasattr(self, 'file_info_label'):
            self.file_info_label.clear()
        if hasattr(self, 'log_view'):
            self.log_view.clear()
        self.current_log_file = None
        self.log_content = ""
        self.search_results = []
        self.current_search_index = -1
        
    def _populate_logs(self) -> None:
        """Populate the log files list."""
        self.log_list.clear()
        
        if self.log_file_path and self.log_file_path.exists():
            # If a specific log file was provided, use only that
            files = [self.log_file_path]
            
            # Add a single item for the specific log file
            try:
                stat = self.log_file_path.stat()
                size_mb = stat.st_size / (1024 * 1024)
                modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                
                item = QListWidgetItem(f"{self.log_file_path.name} ({size_mb:.1f} MB)")
                item.setToolTip(f"Path: {self.log_file_path}\nModified: {modified}\nSize: {size_mb:.2f} MB")
                self.log_list.addItem(item)
                self.log_list.setCurrentRow(0)
                self.file_count_label.setText("1 file")
                return
                
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load log file: {e}")
                files = []
        else:
            # Otherwise, get all log files
            files = get_log_files()
            
            # Sort files by modification time (newest first)
            files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        # Add files to the list
        for file_path in files:
            try:
                # Get file info
                stat = file_path.stat()
                size_mb = stat.st_size / (1024 * 1024)
                modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")

                # Create custom item with tooltip
                item = QListWidgetItem(f"{file_path.name} ({size_mb:.1f} MB)")
                item.setToolTip(f"Path: {file_path}\nModified: {modified}\nSize: {size_mb:.2f} MB")
                self.log_list.addItem(item)

            except Exception as e:
                # Add item even if we can't get full info
                item = QListWidgetItem(file_path.name)
                item.setToolTip(f"Error getting file info: {e}")
                self.log_list.addItem(item)

        # Update file count
        self.file_count_label.setText(f"{len(files)} files")

        if files:
            self.log_list.setCurrentRow(0)
        else:
            self.log_view.setPlainText("No log files found.")
            self._clear_file_info()

    def _load_selected(self, row: int) -> None:
        """Load and display the selected log file."""
        files = get_log_files()
        if 0 <= row < len(files):
            file_path = files[row]
            self.current_log_file = file_path

            # Update file information
            self._update_file_info(file_path)

            # Load and display content
            self._load_log_content(file_path)
        else:
            self.current_log_file = None
            self.log_view.clear()
            self._clear_file_info()

    def _load_log_content(self, file_path: Path) -> None:
        """Load and display log file content with filtering."""
        try:
            # Read file content
            content = file_path.read_text(encoding="utf-8", errors="replace")
            self.log_content = content

            # Update statistics
            self._update_statistics()

            # Apply filters and formatting
            self._apply_filters()

        except Exception as e:
            error_msg = f"Failed to read log file: {e}"
            self.log_view.setPlainText(error_msg)
            self.search_results_label.setText("Error loading file")
            self._update_statistics()  # Still update stats even on error

    def _apply_filters(self) -> None:
        """Apply log level filters to the current content."""
        if not self.log_content:
            return

        # Get current filter selection
        current_index = self.filter_combo.currentIndex()
        filter_data = self.filter_combo.itemData(current_index)
        self.current_filter = filter_data if filter_data else "all"

        lines = self.log_content.split('\n')
        filtered_lines = []

        for line in lines:
            show_line = False

            if self.current_filter == "all":
                # Show all lines
                show_line = True
            elif self.current_filter == "error":
                # Show only error lines
                if "ERROR" in line.upper():
                    show_line = True
            elif self.current_filter == "warning":
                # Show only warning lines
                if "WARNING" in line.upper() or "WARN" in line.upper():
                    show_line = True
            elif self.current_filter == "info":
                # Show only info lines
                if "INFO" in line.upper():
                    show_line = True
            elif self.current_filter == "debug":
                # Show only debug lines
                if "DEBUG" in line.upper():
                    show_line = True
            elif self.current_filter == "other":
                # Show lines that don't match any level filter
                if not any(level in line.upper() for level in ["ERROR", "WARNING", "WARN", "INFO", "DEBUG"]):
                    show_line = True

            if show_line:
                filtered_lines.append(line)

        # Apply formatting and display
        formatted_content = self._format_log_content('\n'.join(filtered_lines))
        self.log_view.setHtml(formatted_content)

        # Update search results if there's an active search
        if self.search_input.text().strip():
            self._apply_search()

    def _format_log_content(self, content: str) -> str:
        """Format log content with colors for different log levels."""
        if not content:
            return ""

        formatted_lines = []

        for line in content.split('\n'):
            if "ERROR" in line.upper():
                formatted_lines.append(f'<span style="color: red; font-weight: bold;">{line}</span>')
            elif "WARNING" in line.upper() or "WARN" in line.upper():
                formatted_lines.append(f'<span style="color: orange; font-weight: bold;">{line}</span>')
            elif "INFO" in line.upper():
                formatted_lines.append(f'<span style="color: white;">{line}</span>')
            elif "DEBUG" in line.upper():
                formatted_lines.append(f'<span style="color: yellow;">{line}</span>')
            else:
                formatted_lines.append(line)

        return '<br>'.join(formatted_lines)

    def _update_file_info(self, file_path: Path) -> None:
        """Update file information display."""
        try:
            stat = file_path.stat()
            size_mb = stat.st_size / (1024 * 1024)
            modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

            self.file_path_label.setText(str(file_path))
            self.file_size_label.setText(f"{size_mb:.2f} MB ({stat.st_size:,} bytes)")
            self.file_modified_label.setText(modified)
            self.file_lines_label.setText(f"{len(self.log_content.split(chr(10))):,}")

        except Exception as e:
            self.file_path_label.setText(f"Error: {e}")
            self.file_size_label.setText("Error")
            self.file_modified_label.setText("Error")
            self.file_lines_label.setText("Error")

    def _update_statistics(self) -> None:
        """Update statistics display with current log content."""
        if not self.log_content:
            self.error_count_label.setText("ERROR: 0")
            self.warning_count_label.setText("WARNING: 0")
            self.info_count_label.setText("INFO: 0")
            return

        lines = self.log_content.split('\n')
        error_count = 0
        warning_count = 0
        info_count = 0
        debug_count = 0
        other_count = 0

        for line in lines:
            line_upper = line.upper()
            if "ERROR" in line_upper:
                error_count += 1
            elif "WARNING" in line_upper or "WARN" in line_upper:
                warning_count += 1
            elif "INFO" in line_upper:
                info_count += 1
            elif "DEBUG" in line_upper:
                debug_count += 1
            else:
                other_count += 1

        self.error_count_label.setText(f"ERROR: {error_count}")
        self.warning_count_label.setText(f"WARNING: {warning_count}")
        self.info_count_label.setText(f"INFO: {info_count}")

    def _search_logs(self) -> None:
        """Search for text in the current log."""
        search_text = self.search_input.text().strip()
        if not search_text or not self.log_content:
            return

        # Clear previous search results
        self.search_results.clear()
        self.current_search_index = -1

        # Find all occurrences
        lines = self.log_content.split('\n')
        for i, line in enumerate(lines):
            if search_text.lower() in line.lower():
                self.search_results.append(i)

        if self.search_results:
            self.current_search_index = 0
            self.search_results_label.setText(f"Found {len(self.search_results)} results")
            self.clear_search_btn.setEnabled(True)
            self._highlight_search_result()
        else:
            self.search_results_label.setText("No results found")
            self.clear_search_btn.setEnabled(False)

    def _apply_search(self) -> None:
        """Apply current search to the displayed filtered content."""
        search_text = self.search_input.text().strip()
        if not search_text:
            return

        # Get the current displayed content (filtered)
        displayed_content = self.log_view.toPlainText()
        if not displayed_content:
            return

        # Clear previous search results
        self.search_results.clear()
        self.current_search_index = -1

        # Find all occurrences in the displayed content
        lines = displayed_content.split('\n')
        for i, line in enumerate(lines):
            if search_text.lower() in line.lower():
                self.search_results.append(i)

        if self.search_results:
            self.current_search_index = 0
            self.search_results_label.setText(f"Found {len(self.search_results)} results")
            self.clear_search_btn.setEnabled(True)
            self._highlight_search_result()
        else:
            self.search_results_label.setText("No results found")
            self.clear_search_btn.setEnabled(False)

    def _next_search_result(self) -> None:
        """Go to next search result."""
        if not self.search_results:
            return

        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self._highlight_search_result()
        self.search_results_label.setText(f"Result {self.current_search_index + 1} of {len(self.search_results)}")

    def _prev_search_result(self) -> None:
        """Go to previous search result."""
        if not self.search_results:
            return

        self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
        self._highlight_search_result()
        self.search_results_label.setText(f"Result {self.current_search_index + 1} of {len(self.search_results)}")

    def _clear_search(self) -> None:
        """Clear search results."""
        self.search_input.clear()
        self.search_results.clear()
        self.current_search_index = -1
        self.search_results_label.setText("No search active")
        self.clear_search_btn.setEnabled(False)
        self._apply_filters()  # Show all filtered content

    def _toggle_auto_refresh(self, state: int) -> None:
        """Toggle auto-refresh functionality."""
        self.auto_refresh_enabled = bool(state)

        if self.auto_refresh_enabled:
            # Start auto-refresh timer
            if not self.auto_refresh_timer:
                self.auto_refresh_timer = QTimer(self)
                self.auto_refresh_timer.timeout.connect(self._auto_refresh)

            interval_ms = self.refresh_interval.value() * 1000
            self.auto_refresh_timer.start(interval_ms)
        else:
            # Stop auto-refresh timer
            if self.auto_refresh_timer:
                self.auto_refresh_timer.stop()

    def _auto_refresh(self) -> None:
        """Auto-refresh current log file."""
        if self.current_log_file and self.current_log_file.exists():
            self._load_log_content(self.current_log_file)

    def _open_logs_folder(self) -> None:
        """Open the logs folder in the system file explorer."""
        files = get_log_files()
        target_dir = files[0].parent if files else Path.cwd()
        try:
            os.startfile(str(target_dir))  # Windows
        except Exception:
            # Cross-platform fallback: show info
            QMessageBox.information(self, "Logs", f"Logs folder: {target_dir}")

    def _export_selected(self) -> None:
        """Export the selected log file."""
        files = get_log_files()
        index = self.log_list.currentRow()
        if 0 <= index < len(files):
            src = files[index]
            target, _ = QFileDialog.getSaveFileName(
                self,
                "Export Log As",
                src.name,
                "Log Files (*.log);;Text Files (*.txt);;All Files (*.*)"
            )
            if target:
                try:
                    # Apply current filters before exporting
                    filtered_content = self._get_filtered_content()
                    Path(target).write_text(filtered_content, encoding="utf-8")
                    QMessageBox.information(self, "Export", f"Exported to {target}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Failed", str(e))
        else:
            QMessageBox.information(self, "Export", "No log selected.")

    def _get_filtered_content(self) -> str:
        """Get the currently filtered content for export."""
        if not self.log_content:
            return ""

        lines = self.log_content.split('\n')
        filtered_lines = []

        for line in lines:
            show_line = False

            if self.current_filter == "all":
                # Show all lines
                show_line = True
            elif self.current_filter == "error":
                # Show only error lines
                if "ERROR" in line.upper():
                    show_line = True
            elif self.current_filter == "warning":
                # Show only warning lines
                if "WARNING" in line.upper() or "WARN" in line.upper():
                    show_line = True
            elif self.current_filter == "info":
                # Show only info lines
                if "INFO" in line.upper():
                    show_line = True
            elif self.current_filter == "debug":
                # Show only debug lines
                if "DEBUG" in line.upper():
                    show_line = True
            elif self.current_filter == "other":
                # Show lines that don't match any level filter
                if not any(level in line.upper() for level in ["ERROR", "WARNING", "WARN", "INFO", "DEBUG"]):
                    show_line = True

            if show_line:
                filtered_lines.append(line)

        return '\n'.join(filtered_lines)

    def _highlight_search_result(self) -> None:
        """Highlight the current search result."""
        if not self.search_results or self.current_search_index < 0:
            return

        # Get the line number of current result
        line_num = self.search_results[self.current_search_index]

        # Scroll to that line (approximate)
        cursor = self.log_view.textCursor()
        cursor.setPosition(0)

        # Move to the approximate position (rough calculation)
        lines = self.log_content.split('\n')
        position = 0
        for i in range(min(line_num, len(lines))):
            position += len(lines[i]) + 1  # +1 for newline

        cursor.setPosition(position)
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def closeEvent(self, event) -> None:
        """Handle dialog close event."""
        # Stop auto-refresh timer
        if self.auto_refresh_timer:
            self.auto_refresh_timer.stop()

        event.accept()
