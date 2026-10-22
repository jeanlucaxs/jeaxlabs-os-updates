#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Headless CLI for creating a signed, encrypted JeaxLabs OS .jxu update."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ROUNDS = 600_000


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 8:
        raise ValueError("A senha do pacote .jxu precisa ter pelo menos 8 caracteres.")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ROUNDS).derive(
        password.encode("utf-8")
    )


def pack_update(
    apk_path: Path,
    output_path: Path,
    version: str,
    version_code: int,
    minimum_version: str,
    release_notes: str,
    package_password: str,
    key_path: Path,
    key_password: str,
) -> tuple[str, str]:
    semver = re.compile(r"^\d+\.\d+\.\d+$")
    if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
        raise ValueError("O arquivo de origem precisa ser o APK novo do JeaxLabs OS.")
    if not semver.fullmatch(version):
        raise ValueError("A versão precisa estar no formato X.Y.Z.")
    if not semver.fullmatch(minimum_version):
        raise ValueError("A versão mínima precisa estar no formato X.Y.Z.")
    if int(version_code) < 1:
        raise ValueError("O versionCode precisa ser um inteiro positivo.")
    if len(package_password) < 8:
        raise ValueError("Use no mínimo 8 caracteres na senha do .jxu.")

    with zipfile.ZipFile(apk_path, "r") as archive:
        if "AndroidManifest.xml" not in archive.namelist():
            raise ValueError("O arquivo selecionado não contém AndroidManifest.xml.")
        if archive.getinfo("AndroidManifest.xml").file_size <= 0:
            raise ValueError("AndroidManifest.xml está vazio.")

    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=key_password.encode("utf-8") if key_password else None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("A chave precisa ser uma chave privada Ed25519.")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = sha256_bytes(public_der)
    salt, nonce = os.urandom(16), os.urandom(12)
    aad = f"JeaxLabs-JXU-v1|{version}|{minimum_version}".encode("utf-8")
    encrypted = AESGCM(derive_key(package_password, salt)).encrypt(nonce, apk_path.read_bytes(), aad)
    manifest = {
        "format": "JXU",
        "format_version": 1,
        "product": "JeaxLabs OS",
        "package_type": "system-update",
        "target_package": "br.com.jeaxlabs.os",
        "version": version,
        "version_code": int(version_code),
        "minimum_version": minimum_version,
        "release_notes": release_notes.strip(),
        "source_filename": apk_path.name,
        "payload_filename": "payload.aesgcm",
        "encryption": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": KDF_ROUNDS,
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "aad_utf8": aad.decode("utf-8"),
        "payload_sha256": sha256_bytes(encrypted),
        "payload_size": len(encrypted),
        "signature": "Ed25519",
        "publisher_fingerprint_sha256": fingerprint,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    manifest_bytes = canonical_json(manifest)
    signature = private_key.sign(manifest_bytes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_bytes)
        archive.writestr("payload.aesgcm", encrypted, compress_type=zipfile.ZIP_STORED)
        archive.writestr("signature.ed25519", signature)
        archive.writestr("publisher.pub.pem", public_pem)
    private_key.public_key().verify(signature, manifest_bytes)
    return fingerprint, sha256_bytes(output_path.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--minimum-version", required=True)
    parser.add_argument("--notes-file", required=True, type=Path)
    parser.add_argument("--package-password", required=True)
    parser.add_argument("--key-path", required=True, type=Path)
    parser.add_argument("--key-password", default="")
    args = parser.parse_args()
    notes = args.notes_file.read_text(encoding="utf-8")
    fingerprint, package_hash = pack_update(
        args.apk, args.output, args.version, args.version_code,
        args.minimum_version, notes, args.package_password,
        args.key_path, args.key_password,
    )
    print(f"JXU={args.output}")
    print(f"JXU_SHA256={package_hash}")
    print(f"PUBLISHER_FINGERPRINT_SHA256={fingerprint}")
    print(f"JXU_SIZE_BYTES={args.output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
