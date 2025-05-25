import tkinter as tk
from tkinter import messagebox
from .about import About
from .help import Help
from .sponsor import Sponsor
from .log_viewer import LogViewer
from .version import show_version

def create_menu_bar(root, app):
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    # File menu
    file_menu = tk.Menu(menubar, tearoff=0)
    file_menu.add_command(label="Esporta chiave pubblica", command=lambda: app.export_pubkey())
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)

    # Log menu (advanced log viewer with filtering)
    log_menu = tk.Menu(menubar, tearoff=0)
    log_menu.add_command(label="View Log (with filters)", command=lambda: LogViewer.show_log(root))
    menubar.add_cascade(label="Log", menu=log_menu)

    # Help menu
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="Help", command=lambda: Help.show_help(root))
    help_menu.add_separator()
    help_menu.add_command(label="About", command=lambda: About.show_about(root))
    help_menu.add_command(label="Sponsor", command=lambda: Sponsor(root).show_sponsor())
    menubar.add_cascade(label="Help", menu=help_menu)

    return menubar
