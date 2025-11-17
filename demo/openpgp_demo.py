import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.openpgp import (
    generate_pgp_keypair, save_pgp_key, load_pgp_key,
    encrypt_message, decrypt_message,
    sign_message, verify_signature,
    generate_ssl_cert
)

# --- DEMO: Generazione e utilizzo chiavi OpenPGP ---
# 1. Genera una coppia di chiavi
key = generate_pgp_keypair("Alice", "alice@example.com", passphrase="password123")
save_pgp_key(key, "demo/alice_private.asc")

# 2. Carica la chiave privata
privkey = load_pgp_key("demo/alice_private.asc", passphrase="password123")
pubkey = privkey.pubkey

# 3. Cifra e decifra un messaggio
messaggio = "Questo è un messaggio segreto."
cifrato = encrypt_message(messaggio, pubkey)
print("Messaggio cifrato:\n", cifrato)

decifrato = decrypt_message(cifrato, privkey, passphrase="password123")
print("Messaggio decifrato:\n", decifrato)

# 4. Firma e verifica (detached)
firma = sign_message(messaggio, privkey, passphrase="password123")
print("Firma digitale (detached):\n", firma)

verifica = verify_signature(messaggio, firma, pubkey)
print("Verifica firma detached:", verifica)

# 5. Genera certificato SSL
# Verranno creati i file 'ssl_key.pem' e 'ssl_cert.pem'
generate_ssl_cert("localhost", "demo/ssl_key.pem", "demo/ssl_cert.pem", passphrase="sslpass")
print("Certificato SSL generato: demo/ssl_key.pem, demo/ssl_cert.pem")
