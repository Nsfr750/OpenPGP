# Reusable widget helpers 

def create_labeled_entry(master, label, variable, **kwargs):
    import tkinter as tk
    frame = tk.Frame(master)
    tk.Label(frame, text=label).pack(side=tk.LEFT)
    entry = tk.Entry(frame, textvariable=variable, **kwargs)
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    return frame, entry
