"""storage.py — 库文件读写、备份轮换"""
from __future__ import annotations

import hmac
import json
import os
import shutil
import time

from crypto_layer import (
    KDF_PARAMS,
    VaultError,
    WrongKeyfile,
    WrongPassword,
    b64d,
    b64e,
    check_final,
    check_k1,
    decrypt_payload,
    derive_final_key,
    derive_k1,
    encrypt_payload,
    new_salt,
)

VAULT_MAGIC = b"VLTAULT1"
BACKUP_KEEP = 10


def _atomic_write(path: str, data: bytes) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _rotate_backup(path: str) -> None:
    if not os.path.exists(path):
        return
    bdir = os.path.join(os.path.dirname(os.path.abspath(path)), "backups")
    os.makedirs(bdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dst = os.path.join(bdir, f"{os.path.basename(path)}.{stamp}.bak")
    shutil.copy2(path, dst)
    files = sorted(
        (f for f in os.listdir(bdir) if f.startswith(os.path.basename(path))),
        key=lambda f: os.path.getmtime(os.path.join(bdir, f)),
    )
    for f in files[:-BACKUP_KEEP]:
        try:
            os.remove(os.path.join(bdir, f))
        except OSError:
            pass


class VaultFile:
    def __init__(self, path: str):
        self.path = path

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def read_header(self):
        with open(self.path, "rb") as f:
            magic = f.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                raise VaultError("不是有效的库文件")
            hlen = int.from_bytes(f.read(4), "big")
            header = json.loads(f.read(hlen).decode("utf-8"))
            ct = f.read()
        return header, ct

    def unlock(self, password: str, keyfile_bytes: bytes) -> dict:
        header, ct = self.read_header()
        salt = b64d(header["kdf"]["salt"])
        params = {k: header["kdf"][k] for k in ("n", "r", "p")}
        k1 = derive_k1(password, salt, params)
        if not hmac.compare_digest(check_k1(k1), b64d(header["check_k1"])):
            raise WrongPassword("主密码错误")
        final_key = derive_final_key(k1, keyfile_bytes)
        if not hmac.compare_digest(check_final(final_key), b64d(header["check_final"])):
            raise WrongKeyfile("U盘密钥不匹配（是否插错了U盘？）")
        pt = decrypt_payload(final_key, b64d(header["nonce"]), ct)
        data = json.loads(pt.decode("utf-8"))
        return {
            "k1": k1,
            "salt": salt,
            "params": params,
            "final_key": final_key,
            "header": header,
            "data": data,
        }

    def save(self, final_key: bytes, header: dict, data: dict) -> None:
        nonce, ct = encrypt_payload(
            final_key, json.dumps(data, ensure_ascii=False).encode("utf-8")
        )
        header = dict(header)
        header["nonce"] = b64e(nonce)
        h = json.dumps(header, ensure_ascii=False).encode("utf-8")
        blob = VAULT_MAGIC + len(h).to_bytes(4, "big") + h + ct
        _rotate_backup(self.path)
        _atomic_write(self.path, blob)

    def create(self, password: str, keyfile_bytes: bytes, data: dict) -> dict:
        salt = new_salt()
        k1 = derive_k1(password, salt, KDF_PARAMS)
        final_key = derive_final_key(k1, keyfile_bytes)
        header = {
            "version": 1,
            "kdf": {"algo": "scrypt", **KDF_PARAMS, "salt": b64e(salt)},
            "check_k1": b64e(check_k1(k1)),
            "check_final": b64e(check_final(final_key)),
        }
        self.save(final_key, header, data)
        return {
            "k1": k1,
            "salt": salt,
            "params": dict(KDF_PARAMS),
            "final_key": final_key,
            "header": header,
            "data": data,
        }

    def change_password(self, keyfile_bytes: bytes, new_password: str, data: dict) -> dict:
        salt = new_salt()
        k1 = derive_k1(new_password, salt, KDF_PARAMS)
        final_key = derive_final_key(k1, keyfile_bytes)
        header = {
            "version": 1,
            "kdf": {"algo": "scrypt", **KDF_PARAMS, "salt": b64e(salt)},
            "check_k1": b64e(check_k1(k1)),
            "check_final": b64e(check_final(final_key)),
        }
        self.save(final_key, header, data)
        return {
            "k1": k1,
            "salt": salt,
            "params": dict(KDF_PARAMS),
            "final_key": final_key,
            "header": header,
        }

    def change_keyfile(self, k1: bytes, new_keyfile_bytes: bytes, header: dict, data: dict) -> dict:
        final_key = derive_final_key(k1, new_keyfile_bytes)
        header = dict(header)
        header["check_final"] = b64e(check_final(final_key))
        self.save(final_key, header, data)
        return {"final_key": final_key, "header": header}