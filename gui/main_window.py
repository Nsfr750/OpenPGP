import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import tkinter as tk
from struttura.menu import create_menu_bar
from openpgp import (
    generate_pgp_keypair, save_pgp_key, load_pgp_key,
    encrypt_message, decrypt_message,
    sign_message, verify_signature,
    generate_ssl_cert
)
from tkinter import filedialog, messagebox

class MainWindow(ttkb.Window):
    def __init__(self):
        super().__init__()
        # Menu bar
        create_menu_bar(self, self)
        # Variables
        self.file_path = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.output_filename = tk.StringVar()
        # Sezione OpenPGP
        row = 0
        # Titolo
        ttkb.Label(self, text="OpenPGP - Operazioni avanzate", font=("Arial", 14, "bold"), bootstyle=PRIMARY).grid(row=row, column=0, columnspan=4, pady=8)
        row += 1
        # Parametri chiave
        ttkb.Label(self, text="Nome:").grid(row=row, column=0, sticky="e", padx=2)
        self.name_var = tk.StringVar(value="Utente")
        ttkb.Entry(self, textvariable=self.name_var, width=16).grid(row=row, column=1, sticky="w", padx=2)
        ttkb.Label(self, text="Email:").grid(row=row, column=2, sticky="e", padx=2)
        self.email_var = tk.StringVar(value="utente@example.com")
        ttkb.Entry(self, textvariable=self.email_var, width=22).grid(row=row, column=3, sticky="w", padx=2)
        row += 1
        ttkb.Label(self, text="Passphrase:").grid(row=row, column=0, sticky="e", padx=2)
        self.passphrase = tk.StringVar()
        ttkb.Entry(self, textvariable=self.passphrase, show='*', width=16).grid(row=row, column=1, sticky="w", padx=2)
        ttkb.Label(self, text="Algoritmo:").grid(row=row, column=2, sticky="e", padx=2)
        self.algo_var = tk.StringVar(value="RSA")
        algo_opt = ttkb.Combobox(self, textvariable=self.algo_var, values=["RSA"], width=20, state="readonly")
        algo_opt.grid(row=row, column=3, sticky="w", padx=2)
        row += 1
        # Pulsanti chiavi
        ttkb.Button(self, text="Genera chiave", command=self.gen_key, bootstyle=SUCCESS).grid(row=row, column=0, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Carica chiave privata", command=self.load_key, bootstyle=INFO).grid(row=row, column=1, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Esporta chiave pubblica", command=self.export_pubkey, bootstyle=SECONDARY).grid(row=row, column=2, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Pulisci campi", command=self.clear_fields, bootstyle=WARNING).grid(row=row, column=3, padx=2, pady=2, sticky="we")
        row += 1
        # Fingerprint
        ttkb.Label(self, text="Fingerprint chiave:").grid(row=row, column=0, sticky="e", padx=2)
        self.fingerprint_var = tk.StringVar()
        ttkb.Entry(self, textvariable=self.fingerprint_var, width=48, state="readonly").grid(row=row, column=1, columnspan=3, sticky="we", padx=2)
        row += 1
        # Cifratura/decifratura
        ttkb.Button(self, text="Cifra messaggio", command=self.encrypt_msg, bootstyle=PRIMARY).grid(row=row, column=0, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Decifra messaggio", command=self.decrypt_msg, bootstyle=PRIMARY).grid(row=row, column=1, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Firma messaggio", command=self.sign_msg, bootstyle=PRIMARY).grid(row=row, column=2, padx=2, pady=2, sticky="we")
        ttkb.Button(self, text="Verifica firma", command=self.verify_msg, bootstyle=PRIMARY).grid(row=row, column=3, padx=2, pady=2, sticky="we")
        row += 1
        # Certificato SSL
        ttkb.Button(self, text="Genera certificato SSL", command=self.gen_ssl, bootstyle=SUCCESS).grid(row=row, column=0, padx=2, pady=2, sticky="we")
        row += 1
        # Input messaggio
        ttkb.Label(self, text="Messaggio/input:").grid(row=row, column=0, sticky="w", padx=2)
        self.input_text = ttkb.Text(self, height=3, width=60)
        self.input_text.grid(row=row, column=1, columnspan=3, sticky="we", padx=2, pady=2)
        row += 1
        # Output
        ttkb.Label(self, text="Output:").grid(row=row, column=0, sticky="w", padx=2)
        self.output_text = ttkb.Text(self, height=5, width=60, state='normal')
        self.output_text.grid(row=row, column=1, columnspan=3, sticky="we", padx=2, pady=2)
        row += 1
        # Log box
        self.log_box = ttkb.Text(self, height=7, state='disabled', wrap='word')
        self.log_box.grid(row=row, column=0, columnspan=4, sticky="we", padx=2, pady=5)
        # Stato chiavi
        self.privkey = None
        self.pubkey = None
        self.loaded_key_path = None

    def append_log(self, text):
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, text)
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

    # --- OpenPGP Actions ---
    def gen_key(self):
        try:
            name = self.name_var.get().strip() or "Utente"
            email = self.email_var.get().strip() or "utente@example.com"
            passphrase = self.passphrase.get() or None
            key = generate_pgp_keypair(name, email, passphrase)
            save_path = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=[("PGP Key", "*.asc")])
            if save_path:
                save_pgp_key(key, save_path)
                self.privkey = key
                self.pubkey = key.pubkey
                self.loaded_key_path = save_path
                self.fingerprint_var.set(str(key.fingerprint))
                self._show_success(f"Chiave generata e salvata in {save_path}")
        except Exception as e:
            self._show_error(f"Errore generazione chiave: {e}")

    def load_key(self):
        try:
            path = filedialog.askopenfilename(filetypes=[("PGP Key", "*.asc")])
            passphrase = self.passphrase.get() or None
            if path:
                key = load_pgp_key(path, passphrase)
                self.privkey = key
                self.pubkey = key.pubkey
                self.loaded_key_path = path
                self.fingerprint_var.set(str(key.fingerprint))
                self._show_success(f"Chiave caricata da {path}")
        except Exception as e:
            self._show_error(f"Errore caricamento chiave: {e}")

    def encrypt_msg(self):
        try:
            if not self.pubkey:
                self._show_error("Carica o genera prima una chiave pubblica/privata!")
                return
            msg = self.input_text.get("1.0", tk.END).strip()
            encrypted = encrypt_message(msg, self.pubkey)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted)
            self._show_success("Messaggio cifrato!")
        except Exception as e:
            self._show_error(f"Errore cifratura: {e}")

    def decrypt_msg(self):
        try:
            if not self.privkey:
                self._show_error("Carica prima una chiave privata!")
                return
            encrypted = self.input_text.get("1.0", tk.END).strip()
            passphrase = self.passphrase.get() or None
            decrypted = decrypt_message(encrypted, self.privkey, passphrase)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted)
            self._show_success("Messaggio decifrato!")
        except Exception as e:
            self._show_error(f"Errore decifratura: {e}")

    def sign_msg(self):
        try:
            if not self.privkey:
                self._show_error("Carica prima una chiave privata!")
                return
            msg = self.input_text.get("1.0", tk.END).strip()
            passphrase = self.passphrase.get() or None
            signature = sign_message(msg, self.privkey, passphrase)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, signature)
            self._show_success("Messaggio firmato!")
        except Exception as e:
            self._show_error(f"Errore firma: {e}")

    def verify_msg(self):
        try:
            if not self.pubkey:
                self._show_error("Carica o genera prima una chiave pubblica/privata!")
                return
            msg = self.input_text.get("1.0", tk.END).strip()
            signature = self.output_text.get("1.0", tk.END).strip()
            result = verify_signature(msg, signature, self.pubkey)
            self._show_success(f"Verifica firma: {result}")
        except Exception as e:
            self._show_error(f"Errore verifica firma: {e}")

    def gen_ssl(self):
        try:
            cn = self.name_var.get().strip() or "localhost"
            key_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Key", "*.pem")])
            cert_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Cert", "*.pem")])
            passphrase = self.passphrase.get() or None
            if key_file and cert_file:
                generate_ssl_cert(cn, key_file, cert_file, passphrase)
                self._show_success(f"Certificato SSL creato: {key_file}, {cert_file}")
        except Exception as e:
            self._show_error(f"Errore generazione SSL: {e}")

    def export_pubkey(self):
        try:
            if not self.pubkey:
                self._show_error("Nessuna chiave pubblica caricata o generata!")
                return
            save_path = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=[("PGP Public Key", "*.asc")])
            if save_path:
                with open(save_path, 'w') as f:
                    f.write(str(self.pubkey))
                self._show_success(f"Chiave pubblica esportata in {save_path}")
        except Exception as e:
            self._show_error(f"Errore esportazione chiave pubblica: {e}")

    def clear_fields(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.fingerprint_var.set("")
        self.name_var.set("Utente")
        self.email_var.set("utente@example.com")
        self.passphrase.set("")
        self.privkey = None
        self.pubkey = None
        self.loaded_key_path = None
        self._show_success("Campi puliti!")

    def _show_success(self, msg):
        self.append_log(f"SUCCESS: {msg}\n")

    def _show_error(self, msg):
        self.append_log(f"ERROR: {msg}\n")
