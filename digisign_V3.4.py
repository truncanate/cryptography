from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os

class SecureMessageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Message Exchange (AES + RSA)")

        # State
        self.mode = tk.StringVar(value="encrypt")
        self.hash_alg = tk.StringVar(value="SHA256")
        self.private_key = None
        self.public_key = None
        self.partner_public_key = None

        self.setup_gui()

    def setup_gui(self):
        frm_top = tk.Frame(self.root)
        frm_top.pack(pady=5)

        tk.Label(frm_top, text="Mode:").pack(side=tk.LEFT)
        ttk.Combobox(frm_top, textvariable=self.mode, values=["encrypt", "decrypt"], width=10).pack(side=tk.LEFT)
        tk.Button(frm_top, text="Generate RSA", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(frm_top, text="Import Private Key", command=self.import_private_key).pack(side=tk.LEFT)
        tk.Button(frm_top, text="Import My Public Key", command=self.import_own_public_key).pack(side=tk.LEFT)

        self.partner_button = tk.Button(frm_top, text="Import Partner Public Key", command=self.import_partner_public_key)
        self.partner_button.pack(side=tk.LEFT)

        self.mode.trace_add("write", self.toggle_partner_button)

        self.txt_input = scrolledtext.ScrolledText(self.root, height=6)
        self.txt_input.pack(padx=10, pady=5, fill=tk.X)

        frm_hash = tk.Frame(self.root)
        frm_hash.pack(pady=5)
        tk.Label(frm_hash, text="Hash Algorithm:").pack(side=tk.LEFT)
        ttk.Combobox(frm_hash, textvariable=self.hash_alg, values=["MD5", "SHA1", "SHA256", "SHA512"], width=10).pack(side=tk.LEFT)

        tk.Button(self.root, text="Process", command=self.process).pack(pady=5)

        self.txt_output = scrolledtext.ScrolledText(self.root, height=10)
        self.txt_output.pack(padx=10, pady=5, fill=tk.X)

    def toggle_partner_button(self, *args):
        if self.mode.get() == "decrypt":
            self.partner_button.config(state=tk.DISABLED)
        else:
            self.partner_button.config(state=tk.NORMAL)

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()

        priv_path = filedialog.asksaveasfilename(title="Simpan Private Key", defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if priv_path:
            with open(priv_path, "wb") as f:
                f.write(self.private_key.export_key())

        pub_path = filedialog.asksaveasfilename(title="Simpan Public Key", defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if pub_path:
            with open(pub_path, "wb") as f:
                f.write(self.public_key.export_key())

        messagebox.showinfo("Sukses", "RSA key berhasil digenerate dan digunakan.")

    def import_private_key(self):
        file = filedialog.askopenfilename(title="Pilih Private Key Anda", filetypes=[("PEM files", "*.pem")])
        if file:
            with open(file, "rb") as f:
                self.private_key = RSA.import_key(f.read())
            messagebox.showinfo("Info", "Private key berhasil diimpor.")

    def import_own_public_key(self):
        file = filedialog.askopenfilename(title="Pilih Public Key Anda", filetypes=[("PEM files", "*.pem")])
        if file:
            with open(file, "rb") as f:
                self.public_key = RSA.import_key(f.read())
            messagebox.showinfo("Info", "Public key berhasil diimpor.")

    def import_partner_public_key(self):
        file = filedialog.askopenfilename(title="Pilih Public Key Partner", filetypes=[("PEM files", "*.pem")])
        if file:
            with open(file, "rb") as f:
                self.partner_public_key = RSA.import_key(f.read())
            messagebox.showinfo("Info", "Public key partner berhasil diimpor.")

    def hash_message(self, message: bytes):
        alg = self.hash_alg.get()
        if alg == "MD5":
            return MD5.new(message)
        elif alg == "SHA1":
            return SHA1.new(message)
        elif alg == "SHA256":
            return SHA256.new(message)
        elif alg == "SHA512":
            return SHA512.new(message)

    def process(self):
        try:
            if self.mode.get() == "encrypt":
                if not self.partner_public_key or not self.public_key or not self.private_key:
                    messagebox.showerror("Error", "Lengkapi kunci Anda dan kunci publik penerima.")
                    return

                msg = self.txt_input.get("1.0", tk.END).strip().encode()
                h = self.hash_message(msg)

                aes_key = get_random_bytes(16)

                # Enkripsi hash pesan (M2)
                cipher_aes1 = AES.new(aes_key, AES.MODE_EAX)
                enc_hash, tag1 = cipher_aes1.encrypt_and_digest(h.digest())
                payload1 = cipher_aes1.nonce + tag1 + enc_hash

                # Gabungkan pesan M dan M2
                combined = msg + b'||' + payload1

                # Enkripsi gabungan dengan AES
                cipher_aes2 = AES.new(aes_key, AES.MODE_EAX)
                enc_combined, tag2 = cipher_aes2.encrypt_and_digest(combined)
                payload2 = cipher_aes2.nonce + tag2 + enc_combined

                # Enkripsi AES key dengan public key penerima
                cipher_rsa = PKCS1_OAEP.new(self.partner_public_key)
                enc_aes_key = cipher_rsa.encrypt(aes_key)

                # Gabungkan AES key terenkripsi dengan payload
                full_payload = b64encode(enc_aes_key + payload2).decode()
                self.txt_output.delete("1.0", tk.END)
                self.txt_output.insert(tk.END, full_payload)

            elif self.mode.get() == "decrypt":
                if not self.private_key:
                    messagebox.showerror("Error", "Private key belum diimpor.")
                    return

                full_payload = b64decode(self.txt_input.get("1.0", tk.END).strip())
                enc_aes_key = full_payload[:256]
                payload2 = full_payload[256:]

                # Dekripsi AES key dengan private key penerima
                cipher_rsa = PKCS1_OAEP.new(self.private_key)
                aes_key = cipher_rsa.decrypt(enc_aes_key)

                nonce2 = payload2[:16]
                tag2 = payload2[16:32]
                ciphertext = payload2[32:]

                cipher_aes2 = AES.new(aes_key, AES.MODE_EAX, nonce=nonce2)
                combined = cipher_aes2.decrypt_and_verify(ciphertext, tag2)

                M, payload1 = combined.split(b'||')
                nonce1 = payload1[:16]
                tag1 = payload1[16:32]
                enc_hash = payload1[32:]

                cipher_aes1 = AES.new(aes_key, AES.MODE_EAX, nonce=nonce1)
                original_hash = cipher_aes1.decrypt_and_verify(enc_hash, tag1)

                recomputed_hash = self.hash_message(M).digest()
                valid = "✅ VALID" if recomputed_hash == original_hash else "❌ INVALID"

                self.txt_output.delete("1.0", tk.END)
                self.txt_output.insert(tk.END, f"Pesan: {M.decode()}\n\nValidasi: {valid}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessageApp(root)
    root.mainloop()


# created by Muhammad Mubdya Barry Sahya
# NIM 203022420021