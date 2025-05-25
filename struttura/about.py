import tkinter as tk
from tkinter import ttk
from .version import get_version

class About:
    @staticmethod
    def show_about(root):
        about_dialog = tk.Toplevel(root)
        about_dialog.title('About')
        about_dialog.geometry('400x300')
        about_dialog.transient(root)
        about_dialog.grab_set()

        # Add app icon or logo here if you have one
        title = ttk.Label(about_dialog, text='OpenPGP GUI App', font=('Helvetica', 16, 'bold'))
        title.pack(pady=20)

        # Get version dynamically from version.py
        version = ttk.Label(about_dialog, text=f'Version {get_version()}')
        version.pack()

        description = ttk.Label(
            about_dialog,
            text='A modern Python GUI for OpenPGP encryption, signature, key management and SSL certificate generation.\n\nAll operations are local and privacy-friendly.',
            justify=tk.CENTER, wraplength=350
        )
        description.pack(pady=20)

        author = ttk.Label(about_dialog, text='Author: Nsfr750')
        author.pack()
        copyright = ttk.Label(about_dialog, text='© 2025 Nsfr750, GPL v3.0')
        copyright.pack(pady=10)

        ttk.Button(about_dialog, text='Close', command=about_dialog.destroy).pack(pady=20)
