import tkinter as tk
import webbrowser
try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import SUCCESS, PRIMARY, WARNING, INFO, SECONDARY
except ImportError:
    ttkb = None
    SUCCESS = PRIMARY = WARNING = INFO = SECONDARY = None

# Sponsor Class
class Sponsor:
    def __init__(self, root):
        self.root = root

    def show_sponsor(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Support & Sponsor OpenPGP GUI")
        dialog.geometry('640x320')
        dialog.minsize(520, 220)
        dialog.resizable(False, False)
        if ttkb:
            style = ttkb.Style("superhero")
        # Title
        title = ttkb.Label(dialog, text="❤️ Support the Project! ❤️", font=("Arial", 16, "bold"), bootstyle=PRIMARY) if ttkb else tk.Label(dialog, text="❤️ Support the Project! ❤️", font=("Arial", 16, "bold"))
        title.pack(pady=(18, 8))
        # Subtitle
        subtitle = ttkb.Label(dialog, text="Your support helps us improve OpenPGP GUI!", font=("Arial", 11), bootstyle=INFO) if ttkb else tk.Label(dialog, text="Your support helps us improve OpenPGP GUI!", font=("Arial", 11))
        subtitle.pack(pady=(0, 10))
        # Sponsor buttons
        btn_frame = ttkb.Frame(dialog) if ttkb else tk.Frame(dialog)
        btn_frame.pack(pady=8)
        buttons = [
            ("🐙 Sponsor on GitHub", "https://github.com/sponsors/Nsfr750", SUCCESS),
            ("💬 Join Discord", "https://discord.gg/BvvkUEP9", INFO),
            ("☕ Buy Me a Coffee", "https://paypal.me/3dmega", WARNING),
            ("🎁 Join The Patreon", "https://www.patreon.com/Nsfr750", PRIMARY)
        ]
        for text, url, color in buttons:
            if ttkb:
                btn = ttkb.Button(btn_frame, text=text, width=19, bootstyle=color, command=lambda u=url: webbrowser.open(u))
            else:
                btn = tk.Button(btn_frame, text=text, width=19, command=lambda u=url: webbrowser.open(u))
            btn.pack(side=tk.LEFT, padx=8, pady=6)
        # Close button
        close_btn = ttkb.Button(dialog, text="Close", width=10, bootstyle=SECONDARY, command=dialog.destroy) if ttkb else tk.Button(dialog, text="Close", width=10, command=dialog.destroy)
        close_btn.pack(pady=16)

