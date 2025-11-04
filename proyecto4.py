#Jason Misael Gutierrez de Leon - 1624622
#Miguel Alfonzo Macario Velasquez - 1597421
#Abel Alexander de Leon Lima - 1572322

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import base64

# --------------------------- Función hash FNV-1a 64 bits ---------------------------
def fnv1a_64(data: bytes) -> str:
    """
    Calcula hash FNV-1a de 64 bits de los datos dados.
    Retorna una cadena hexadecimal de 16 dígitos.
    """
    fnv_prime = 0x100000001b3
    hash_ = 0xcbf29ce484222325
    for b in data:
        hash_ ^= b
        hash_ = (hash_ * fnv_prime) % (1 << 64)
    return f"{hash_:016x}"

# --------------------------- Librerías criptográficas (lazy import) ---------------------------
def import_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.backends import default_backend
        return {
            'rsa': rsa,
            'padding': padding,
            'serialization': serialization,
            'hashes': hashes,
            'default_backend': default_backend
        }
    except Exception as e:
        raise ImportError("Instala la librería 'cryptography' con: pip install cryptography") from e

# --------------------------- Clase para gestión de claves y cifrado ---------------------------
class KeyManager:
    def __init__(self):
        self._crypto = None

    def ensure_crypto(self):
        if self._crypto is None:
            self._crypto = import_crypto()

    def generate_rsa(self, key_size=2048):
        self.ensure_crypto()
        rsa = self._crypto['rsa']
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self._crypto['default_backend']()
        )
        return private_key, private_key.public_key()

    def private_to_pem(self, private_key):
        self.ensure_crypto()
        serialization = self._crypto['serialization']
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def public_to_pem(self, public_key):
        self.ensure_crypto()
        serialization = self._crypto['serialization']
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_private_pem(self, pem_data: bytes):
        self.ensure_crypto()
        serialization = self._crypto['serialization']
        return serialization.load_pem_private_key(
            pem_data, password=None, backend=self._crypto['default_backend']()
        )

    def load_public_pem(self, pem_data: bytes):
        self.ensure_crypto()
        serialization = self._crypto['serialization']
        return serialization.load_pem_public_key(
            pem_data, backend=self._crypto['default_backend']()
        )

    def encrypt_with_public(self, public_key, plaintext: bytes) -> bytes:
        self.ensure_crypto()
        padding = self._crypto['padding']
        hashes = self._crypto['hashes']
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_with_private(self, private_key, ciphertext: bytes) -> bytes:
        self.ensure_crypto()
        padding = self._crypto['padding']
        hashes = self._crypto['hashes']
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, private_key, data: bytes) -> bytes:
        self.ensure_crypto()
        padding = self._crypto['padding']
        hashes = self._crypto['hashes']
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, public_key, signature: bytes, data: bytes) -> bool:
        self.ensure_crypto()
        padding = self._crypto['padding']
        hashes = self._crypto['hashes']
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# --------------------------- Interfaz Tkinter ---------------------------
class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cifrado Asimétrico y Firma Digital (con Hash FNV-1a 64 bits)")
        self.geometry("950x600")
        self.km = KeyManager()
        self.private_key = None
        self.public_key = None

        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True, padx=8, pady=8)

        self.tab_gen = ttk.Frame(nb)
        self.tab_enc = ttk.Frame(nb)
        self.tab_sig = ttk.Frame(nb)

        nb.add(self.tab_gen, text="Generar Claves")
        nb.add(self.tab_enc, text="Cifrar / Descifrar")
        nb.add(self.tab_sig, text="Firmar / Verificar (FNV-1a)")

        self._build_gen_tab()
        self._build_enc_tab()
        self._build_sig_tab()

    # ---------------- Generar claves ----------------
    def _build_gen_tab(self):
        frm = self.tab_gen
        ttk.Label(frm, text="Tamaño de clave RSA:").pack(anchor='w', padx=10, pady=4)
        self.keysize = ttk.Spinbox(frm, values=(1024, 2048, 3072, 4096), width=10)
        self.keysize.set("2048")
        self.keysize.pack(anchor='w', padx=10, pady=4)

        ttk.Button(frm, text="Generar Par de Claves", command=self._generate_keys).pack(anchor='w', padx=10, pady=8)

        self.txt_priv = scrolledtext.ScrolledText(frm, height=10)
        self.txt_pub = scrolledtext.ScrolledText(frm, height=10)
        ttk.Label(frm, text="Clave privada:").pack(anchor='w', padx=10)
        self.txt_priv.pack(fill='both', expand=True, padx=10, pady=4)
        ttk.Label(frm, text="Clave pública:").pack(anchor='w', padx=10)
        self.txt_pub.pack(fill='both', expand=True, padx=10, pady=4)

    def _generate_keys(self):
        try:
            size = int(self.keysize.get())
            priv, pub = self.km.generate_rsa(size)
            self.private_key, self.public_key = priv, pub
            self.txt_priv.delete('1.0', tk.END)
            self.txt_priv.insert(tk.END, self.km.private_to_pem(priv).decode())
            self.txt_pub.delete('1.0', tk.END)
            self.txt_pub.insert(tk.END, self.km.public_to_pem(pub).decode())
            messagebox.showinfo("Éxito", f"Claves RSA ({size} bits) generadas correctamente.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- Cifrar / Descifrar ----------------
    def _build_enc_tab(self):
        frm = self.tab_enc
        ttk.Label(frm, text="Texto para cifrar / descifrar:").pack(anchor='w', padx=10, pady=4)
        self.txt_plain = scrolledtext.ScrolledText(frm, height=10)
        self.txt_plain.pack(fill='both', expand=True, padx=10, pady=4)

        ttk.Button(frm, text="Cifrar con clave pública", command=self._encrypt).pack(side='left', padx=10, pady=6)
        ttk.Button(frm, text="Descifrar con clave privada", command=self._decrypt).pack(side='left', padx=10, pady=6)

        ttk.Label(frm, text="Resultado (Base64):").pack(anchor='w', padx=10, pady=4)
        self.txt_result = scrolledtext.ScrolledText(frm, height=10)
        self.txt_result.pack(fill='both', expand=True, padx=10, pady=4)

    def _encrypt(self):
        try:
            if not self.public_key:
                messagebox.showwarning("Atención", "Cargue o genere una clave pública.")
                return
            data = self.txt_plain.get('1.0', tk.END).encode()
            ct = self.km.encrypt_with_public(self.public_key, data)
            self.txt_result.delete('1.0', tk.END)
            self.txt_result.insert(tk.END, base64.b64encode(ct).decode())
        except Exception as e:
            messagebox.showerror("Error al cifrar", str(e))

    def _decrypt(self):
        try:
            if not self.private_key:
                messagebox.showwarning("Atención", "Cargue o genere una clave privada.")
                return
            b64 = self.txt_result.get('1.0', tk.END).strip()
            data = base64.b64decode(b64)
            pt = self.km.decrypt_with_private(self.private_key, data)
            self.txt_plain.delete('1.0', tk.END)
            self.txt_plain.insert(tk.END, pt.decode())
        except Exception as e:
            messagebox.showerror("Error al descifrar", str(e))

    # ---------------- Firmar / Verificar ----------------
    def _build_sig_tab(self):
        frm = self.tab_sig
        ttk.Label(frm, text="Texto / Archivo para firmar:").pack(anchor='w', padx=10, pady=4)
        self.txt_sign = scrolledtext.ScrolledText(frm, height=10)
        self.txt_sign.pack(fill='both', expand=True, padx=10, pady=4)

        # Etiqueta y campo del hash
        ttk.Label(frm, text="Hash FNV-1a (64 bits):").pack(anchor='w', padx=10, pady=(8,0))
        self.hash_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.hash_var, state='readonly').pack(fill='x', padx=10, pady=(0,8))

        self.txt_sign.bind("<KeyRelease>", self._update_hash)

        ttk.Button(frm, text="Firmar con clave privada", command=self._sign_text).pack(side='left', padx=10, pady=6)
        ttk.Button(frm, text="Verificar firma", command=self._verify_signature).pack(side='left', padx=10, pady=6)

        ttk.Label(frm, text="Firma (Base64):").pack(anchor='w', padx=10, pady=4)
        self.txt_signature = scrolledtext.ScrolledText(frm, height=6)
        self.txt_signature.pack(fill='both', expand=True, padx=10, pady=4)

    def _update_hash(self, event=None):
        data = self.txt_sign.get('1.0', tk.END).encode('utf-8')
        h = fnv1a_64(data)
        self.hash_var.set(h)

    def _sign_text(self):
        try:
            if not self.private_key:
                messagebox.showwarning("Atención", "Cargue o genere una clave privada.")
                return
            data = self.txt_sign.get('1.0', tk.END).encode('utf-8')
            signature = self.km.sign(self.private_key, data)
            self.txt_signature.delete('1.0', tk.END)
            self.txt_signature.insert(tk.END, base64.b64encode(signature).decode())
            self._update_hash()
            messagebox.showinfo("Firmado", f"Datos firmados correctamente.\nHash FNV-1a: {self.hash_var.get()}")
        except Exception as e:
            messagebox.showerror("Error al firmar", str(e))

    def _verify_signature(self):
        try:
            if not self.public_key:
                messagebox.showwarning("Atención", "Cargue o genere una clave pública.")
                return
            sig_b64 = self.txt_signature.get('1.0', tk.END).strip()
            signature = base64.b64decode(sig_b64)
            data = self.txt_sign.get('1.0', tk.END).encode('utf-8')
            valid = self.km.verify(self.public_key, signature, data)
            self._update_hash()
            if valid:
                messagebox.showinfo("Verificación", f"Firma válida ✅\nHash FNV-1a: {self.hash_var.get()}")
            else:
                messagebox.showwarning("Verificación", f"Firma NO válida ❌\nHash FNV-1a: {self.hash_var.get()}")
        except Exception as e:
            messagebox.showerror("Error al verificar", str(e))

# ---------------- Ejecutar ----------------
if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
