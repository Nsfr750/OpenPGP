"""
Help Dialog Module

This module provides the Help dialog for the Project.
Displays usage instructions and feature highlights in a tabbed interface.

License: GPL v3.0 (see LICENSE)
"""

import tkinter as tk
from tkinter import ttk, messagebox

class Help:
    
    @staticmethod
    def show_help(parent):
        """
        Display the Help dialog.
        
        This method creates and shows a modal dialog with help information
        organized in tabs. The dialog includes sections for usage instructions,
        features, and tips.
        
        Args:
            parent (tk.Tk): The parent window for the dialog
        """
        # Create and configure the help window
        help_window = tk.Toplevel(parent)
        help_window.title("Help")
        help_window.geometry("700x500")
        help_window.minsize(600, 400)
        
        # Center the window on screen
        window_width = 700
        window_height = 500
        screen_width = help_window.winfo_screenwidth()
        screen_height = help_window.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        help_window.geometry(f'{window_width}x{window_height}+{x}+{y}')
        
        # Create a notebook (tabbed interface)
        notebook = ttk.Notebook(help_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ===== USAGE TAB =====
        usage_frame = ttk.Frame(notebook, padding=10)
        notebook.add(usage_frame, text="Usage")
        usage_text = (
            'To start the application, run main.py from the project root.\n'
            'Use the menu bar for Help, About, Log Viewer, and more.\n'
            'Log Viewer lets you see all info, warnings, errors, and tracebacks.\n'
            'If you see import errors, ensure you are running from the root directory.\n'
            'If you get an error, check the Application Log for details and traceback.\n'
        )
        usage_label = tk.Label(usage_frame, text=usage_text, justify=tk.LEFT, anchor='nw', wraplength=650)
        usage_label.pack(fill=tk.BOTH, expand=True)

        # ===== FEATURES TAB =====
        features_frame = ttk.Frame(notebook, padding=10)
        notebook.add(features_frame, text="Features")
        features_text = (
            '- Modern UI with ttkbootstrap themes (Superhero style)\n'
            '- Generate, load, and export OpenPGP key pairs\n'
            '- Set key name, email, passphrase, and view fingerprint\n'
            '- Encrypt and decrypt messages\n'
            '- Sign and verify messages (detached signatures)\n'
            '- Export public key\n'
            '- Generate SSL certificates\n'
            '- Clear/reset all fields with one click\n'
            '- Full log and error feedback\n'
        )
        features_label = tk.Label(features_frame, text=features_text, justify=tk.LEFT, anchor='nw', wraplength=650)
        features_label.pack(fill=tk.BOTH, expand=True)

        # ===== ADVANCED TAB =====
        advanced_frame = ttk.Frame(notebook, padding=10)
        notebook.add(advanced_frame, text="Advanced")
        advanced_text = (
            'Advanced Features:\n'
            '- Export public key in ASCII-armored format (.asc)\n'
            '- Visualize key fingerprint for security checks\n'
            '- Choose key algorithm (currently RSA, extensible)\n'
            '- Generate SSL certificates with custom CN\n'
            '- All cryptographic operations are performed locally (no cloud)\n'
            '- Modern error handling and user feedback\n'
            '- Centralized logging: info, warning, error, uncaught exceptions\n'
            '- Application Log Viewer with real-time filtering (ALL, INFO, WARNING, ERROR)\n'
            '- Automatic traceback capture and display for debugging\n'
        )
        advanced_label = tk.Label(advanced_frame, text=advanced_text, justify=tk.LEFT, anchor='nw', wraplength=650)
        advanced_label.pack(fill=tk.BOTH, expand=True)

        # ===== LOGGING TAB =====
        logging_frame = ttk.Frame(notebook, padding=10)
        notebook.add(logging_frame, text="Logging & Debug")
        logging_text = (
            'Logging and Debugging:\n'
            '- All info, warnings, errors, and uncaught exceptions are logged to traceback.log.\n'
            '- Use log_info(msg), log_warning(msg), log_error(msg) in your code to add custom entries.\n'
            '- The Application Log Viewer (menu: Log > View Log) allows you to filter and view logs by level.\n'
            '- If the log file is missing, the last runtime traceback is shown if available.\n'
            '- This makes debugging and support much easier!\n'
        )
        logging_label = tk.Label(logging_frame, text=logging_text, justify=tk.LEFT, anchor='nw', wraplength=650)
        logging_label.pack(fill=tk.BOTH, expand=True)
        features_label = tk.Label(features_frame, text=features_text, justify=tk.LEFT, anchor='nw', wraplength=650)
        features_label.pack(fill=tk.BOTH, expand=True)

        # Close button
        close_btn = tk.Button(help_window, text="Close", command=help_window.destroy)
        close_btn.pack(pady=10)
        
        # Make the window modal
        help_window.transient(parent)
        help_window.grab_set()
        parent.wait_window(help_window)
