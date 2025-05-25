import tkinter as tk
from tkinter import ttk, scrolledtext
import os
import sys
import traceback

# Define the name of the log file to be viewed
LOG_FILE = 'traceback.log'

class LogViewer:
    """
    A dialog to view the application log file.
    Provides a scrollable window to examine the contents of Traceback.log.
    """
    @staticmethod
    def show_log(root):
        """
        Displays the log viewer dialog.
        
        :param root: The parent window of the log viewer dialog.
        """
        # Create a new top-level window for the log viewer
        log_window = tk.Toplevel(root)
        log_window.title('Application Log')
        log_window.geometry('700x500')
        log_window.minsize(500, 300)

        # Filter options
        filter_var = tk.StringVar(value='ALL')
        filter_frame = ttk.Frame(log_window)
        filter_frame.pack(pady=(8, 0))
        ttk.Label(filter_frame, text='Show:').pack(side=tk.LEFT, padx=(0, 6))
        for level in ['ALL', 'INFO', 'WARNING', 'ERROR']:
            ttk.Radiobutton(filter_frame, text=level, variable=filter_var, value=level, command=lambda: update_view()).pack(side=tk.LEFT, padx=2)

        # Log text area
        text_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=('Consolas', 10))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Load log file content or last traceback
        log_content = ''
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                log_content = f.read()
        if not log_content:
            # Try to show last runtime traceback if available
            exc_type, exc_value, exc_tb = getattr(sys, 'last_type', None), getattr(sys, 'last_value', None), getattr(sys, 'last_traceback', None)
            if exc_type and exc_value and exc_tb:
                log_content = '--- Last Runtime Traceback ---\n' + ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
            else:
                log_content = 'Log file not found and no runtime traceback available.'

        def update_view():
            text_area.config(state=tk.NORMAL)
            text_area.delete(1.0, tk.END)
            level = filter_var.get()
            if level == 'ALL':
                text_area.insert(tk.END, log_content)
            else:
                lines = log_content.splitlines()
                filtered = [l for l in lines if l.startswith(f'[{level}]') or (level == 'ERROR' and 'Exception' in l)]
                text_area.insert(tk.END, '\n'.join(filtered) if filtered else f'No {level} logs found.')
            text_area.config(state=tk.DISABLED)
        update_view()

        # Close button
        close_btn = ttk.Button(log_window, text='Close', command=log_window.destroy)
        close_btn.pack(pady=10)

        log_window.transient(root)
        log_window.grab_set()
        root.wait_window(log_window)
