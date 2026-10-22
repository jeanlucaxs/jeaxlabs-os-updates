#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JeaxLabs Update Packer: empacota atualizações em .jxu com AES-256-GCM e assinatura Ed25519."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError as exc:
    raise SystemExit("Falta a biblioteca cryptography. Instale com: py -m pip install cryptography") from exc


APP_NAME = "JeaxLabs Update Packer"
FORMAT_VERSION = 1
KDF_ROUNDS = 600_000
BG = "#100D20"
PANEL = "#1D1833"
PANEL_2 = "#292044"
PURPLE = "#8B5CF6"
WHITE = "#F7F3FF"
MUTED = "#B8AFCF"
GREEN = "#34D399"


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 8:
        raise ValueError("A senha de criptografia precisa ter pelo menos 8 caracteres.")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ROUNDS).derive(passphrase.encode("utf-8"))


def load_private_key(path: Path, password: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=password.encode("utf-8") if password else None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("O arquivo selecionado não contém uma chave privada Ed25519.")
    return key


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def create_certificate(folder: Path, password: str) -> tuple[Path, Path, str]:
    if len(password) < 8:
        raise ValueError("Use uma senha com pelo menos 8 caracteres para proteger a chave privada.")
    folder.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    pub = public_pem(private)
    der = private.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = sha256_bytes(der)
    private_path = folder / "JeaxLabs-Publisher-Private.pem"
    public_path = folder / "JeaxLabs-Publisher-Public.pem"
    private_path.write_bytes(private.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))))
    public_path.write_bytes(pub)
    cert = {
        "schema_version": 1, "publisher": "JeaxLabs", "algorithm": "Ed25519",
        "fingerprint_sha256": fingerprint, "public_key_pem": pub.decode("ascii"),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "note": "O receptor deve confiar neste fingerprint por um canal independente; não confie apenas na chave embutida no pacote."
    }
    (folder / "JeaxLabs-Publisher-Certificate.json").write_text(json.dumps(cert, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return private_path, public_path, fingerprint


def make_update(source: Path, output: Path, version: str, version_code: int,
                minimum_version: str, notes: str, password: str,
                key_path: Path, key_password: str) -> tuple[str, str]:
    if not source.is_file() or source.suffix.lower() != ".apk":
        raise ValueError("O .jxu de sistema deve conter o novo APK do JeaxLabs OS.")
    try:
        with zipfile.ZipFile(source, "r") as apk_archive:
            if apk_archive.getinfo("AndroidManifest.xml").file_size <= 0:
                raise ValueError("O APK não contém um AndroidManifest.xml válido.")
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ValueError("O arquivo selecionado não é um APK Android válido.") from exc
    if not version.strip() or not version_code or version_code < 1:
        raise ValueError("Informe a versão e um versionCode Android positivo.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version.strip()):
        raise ValueError("A versão deve usar o formato X.Y.Z, por exemplo 1.4.1.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", minimum_version.strip()):
        raise ValueError("A versão mínima deve usar o formato X.Y.Z, por exemplo 1.4.0.")
    if len(password) < 8:
        raise ValueError("Use pelo menos 8 caracteres na senha de criptografia.")
    private = load_private_key(key_path, key_password)
    pub = public_pem(private)
    der = private.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = sha256_bytes(der)
    salt, nonce = os.urandom(16), os.urandom(12)
    plain = source.read_bytes()
    aad = ("JeaxLabs-JXU-v1|" + version.strip() + "|" + minimum_version.strip()).encode("utf-8")
    encrypted = AESGCM(derive_key(password, salt)).encrypt(nonce, plain, aad)
    manifest = {
        "format": "JXU", "format_version": FORMAT_VERSION, "product": "JeaxLabs OS",
        "package_type": "system-update",
        "target_package": "br.com.jeaxlabs.os", "version": version.strip(),
        "version_code": int(version_code), "minimum_version": minimum_version.strip(),
        "release_notes": notes.strip(),
        "source_filename": source.name, "payload_filename": "payload.aesgcm",
        "encryption": "AES-256-GCM", "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": KDF_ROUNDS, "salt_hex": salt.hex(), "nonce_hex": nonce.hex(),
        "aad_utf8": aad.decode("utf-8"), "payload_sha256": sha256_bytes(encrypted),
        "payload_size": len(encrypted), "signature": "Ed25519",
        "publisher_fingerprint_sha256": fingerprint, "created_utc": datetime.now(timezone.utc).isoformat()
    }
    manifest_bytes = canonical_json(manifest)
    signature = private.sign(manifest_bytes)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_bytes)
        archive.writestr("payload.aesgcm", encrypted, compress_type=zipfile.ZIP_STORED)
        archive.writestr("signature.ed25519", signature)
        archive.writestr("publisher.pub.pem", pub)
    private.public_key().verify(signature, manifest_bytes)
    return fingerprint, sha256_bytes(output.read_bytes())


class UpdatePacker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JeaxLabs • Update Packer")
        self.geometry("920x780")
        self.minsize(830, 710)
        self.configure(bg=BG)
        self.source = tk.StringVar()
        self.output = tk.StringVar(value=str(Path.home() / "Desktop"))
        self.version = tk.StringVar(value="1.4.1")
        self.version_code = tk.StringVar(value="141")
        self.minimum_version = tk.StringVar(value="1.4.0")
        self.notes = tk.StringVar()
        self.password = tk.StringVar()
        self.key_path = tk.StringVar()
        self.key_password = tk.StringVar()
        self.status = tk.StringVar(value="Pronto para preparar atualização.")
        self._build()

    def _build(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TEntry", fieldbackground=PANEL_2, foreground=WHITE, insertcolor=WHITE)
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=26, pady=(22, 14))
        tk.Label(header, text="JX", font=("Segoe UI Black", 27), fg=WHITE, bg=PURPLE, width=3).pack(side="left", padx=(0, 14))
        title = tk.Frame(header, bg=BG)
        title.pack(side="left", fill="x", expand=True)
        tk.Label(title, text="JEAXLABS UPDATE PACKER", font=("Segoe UI", 20, "bold"), fg=WHITE, bg=BG).pack(anchor="w")
        tk.Label(title, text="Pacote do sistema .jxu • criptografia + certificado do publicador", font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w", pady=(3, 0))
        tk.Label(self, text="AES-256-GCM  •  PBKDF2-SHA256  •  ASSINATURA ED25519",
                 font=("Segoe UI", 9, "bold"), fg=GREEN, bg=BG).pack(anchor="w", padx=28, pady=(0, 10))
        panel = tk.Frame(self, bg=PANEL, highlightbackground="#3B3156", highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=26, pady=(0, 16))
        self._field(panel, "Arquivo de atualização", self.source, self._browse_source, 0)
        self._field(panel, "Versão nova (X.Y.Z)", self.version, None, 1)
        self._field(panel, "Código Android (versionCode)", self.version_code, None, 2)
        self._field(panel, "Versão mínima exigida", self.minimum_version, None, 3)
        self._field(panel, "Notas de versão", self.notes, None, 4)
        self._field(panel, "Pasta de saída", self.output, self._browse_output, 5)
        self._field(panel, "Chave privada Ed25519 (.pem)", self.key_path, self._browse_key, 6)
        self._field(panel, "Senha da chave privada", self.key_password, None, 7, secret=True)
        self._field(panel, "Senha de criptografia do .jxu", self.password, None, 8, secret=True)
        buttons = tk.Frame(panel, bg=PANEL)
        buttons.grid(row=9, column=0, columnspan=3, sticky="ew", padx=22, pady=(14, 8))
        tk.Button(buttons, text="＋  CRIAR CERTIFICADO", command=self._create_cert, bg=PANEL_2, fg=WHITE,
                  activebackground=PURPLE, relief="flat", font=("Segoe UI", 10, "bold"), padx=15, pady=13).pack(side="left", padx=(0, 10))
        tk.Button(buttons, text="GERAR .JXU ASSINADO", command=self._start_pack, bg=PURPLE, fg=WHITE,
                  activebackground="#7040D5", relief="flat", font=("Segoe UI", 11, "bold"), padx=25, pady=13).pack(side="left")
        tk.Label(panel, text="Selecione o APK novo do JeaxLabs OS. O .jxu valida versão, versionCode, pacote alvo, assinatura e criptografia.\nUse uma chave Ed25519 confiável e nunca publique a chave privada.",
                 font=("Segoe UI", 9), fg=MUTED, bg=PANEL, justify="left").grid(row=10, column=0, columnspan=3, sticky="w", padx=24, pady=(8, 16))
        footer = tk.Frame(self, bg=BG)
        footer.pack(fill="x", padx=28, pady=(0, 18))
        tk.Label(footer, textvariable=self.status, font=("Segoe UI", 10), fg=WHITE, bg=BG).pack(side="left")
        tk.Label(footer, text="JeaxLabs Security Tools", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(side="right")

    def _field(self, parent, label, variable, browse, row, secret=False):
        tk.Label(parent, text=label, font=("Segoe UI", 10, "bold"), fg=MUTED, bg=PANEL).grid(row=row, column=0, sticky="w", padx=(22, 14), pady=7)
        entry = ttk.Entry(parent, textvariable=variable, show="•" if secret else "")
        entry.grid(row=row, column=1, sticky="ew", padx=4, pady=7, ipady=6)
        if browse:
            tk.Button(parent, text="Procurar", command=browse, bg=PANEL_2, fg=WHITE, activebackground=PURPLE,
                      relief="flat", padx=12).grid(row=row, column=2, padx=(7, 22), pady=7)
        parent.grid_columnconfigure(1, weight=1)

    def _browse_source(self):
        path = filedialog.askopenfilename(title="Selecione o pacote de atualização",
            filetypes=[("APK do JeaxLabs OS", "*.apk")])
        if path:
            self.source.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Pasta de saída")
        if path:
            self.output.set(path)

    def _browse_key(self):
        path = filedialog.askopenfilename(title="Chave privada do publicador", filetypes=[("PEM", "*.pem"), ("Todos", "*.*")])
        if path:
            self.key_path.set(path)

    def _create_cert(self):
        folder = filedialog.askdirectory(title="Pasta segura do certificado")
        if not folder:
            return
        password = simpledialog.askstring("Proteger chave privada", "Crie uma senha para a chave privada (mín. 8 caracteres):", show="•", parent=self)
        if not password:
            return
        try:
            private, public, fingerprint = create_certificate(Path(folder), password)
            self.key_path.set(str(private))
            self.key_password.set(password)
            messagebox.showinfo("Certificado criado", f"Fingerprint SHA-256:\n{fingerprint}\n\nA chave privada é secreta e fica protegida por senha.", parent=self)
            self.status.set("Certificado Ed25519 criado.")
        except Exception as exc:
            messagebox.showerror("Falha ao criar certificado", str(exc), parent=self)

    def _start_pack(self):
        source = self.source.get().strip()
        version = self.version.get().strip()
        key_path = self.key_path.get().strip()
        password = self.password.get()
        out = self.output.get().strip()
        version_code = self.version_code.get().strip()
        if not all([source, version, version_code, key_path, password, out]):
            messagebox.showwarning("Campos incompletos", "Preencha arquivo, versão, pasta, certificado e senha.", parent=self)
            return
        if not version_code.isdigit() or int(version_code) < 1:
            messagebox.showwarning("Código inválido", "Informe um versionCode Android positivo, como 141.", parent=self)
            return
        if len(password) < 8:
            messagebox.showwarning("Senha curta", "Use pelo menos 8 caracteres na senha de criptografia.", parent=self)
            return
        target = Path(out) / f"JeaxLabsOS-{version}.jxu"
        self.status.set("Criptografando e assinando atualização…")
        args = (Path(source), target, version, int(version_code), self.minimum_version.get(), self.notes.get(),
                password, Path(key_path), self.key_password.get())
        threading.Thread(target=self._worker, args=args, daemon=True).start()

    def _worker(self, source, target, version, version_code, minimum_version, notes, password, key_path, key_password):
        try:
            fingerprint, digest = make_update(
                source, target, version, version_code, minimum_version, notes,
                password, key_path, key_password
            )
            self.after(0, lambda: self._done(target, fingerprint, digest))
        except Exception as exc:
            self.after(0, lambda error=str(exc): self._error(error))

    def _done(self, target, fingerprint, digest):
        self.status.set("Pacote .jxu criado e assinatura local verificada.")
        messagebox.showinfo("Atualização empacotada", f"Arquivo:\n{target}\n\nFingerprint SHA-256:\n{fingerprint}\nSHA-256 do pacote:\n{digest}\n\nNo JeaxLabs OS 1.4.1+, abra Atualizações, configure o fingerprint do publicador e escolha aplicar atualização. O novo APK substitui a instalação atual somente se tiver o mesmo certificado Android e um versionCode superior.", parent=self)

    def _error(self, error):
        self.status.set("Falha no empacotamento.")
        messagebox.showerror("Não foi possível criar o pacote", error, parent=self)


if __name__ == "__main__":
    UpdatePacker().mainloop()
