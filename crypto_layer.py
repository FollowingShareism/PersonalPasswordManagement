"""crypto_layer.py — 密钥派生与加解密

密钥链：
    主密码 --scrypt(salt)--> K1
    U盘 keyfile --HKDF(salt=K1)--> 最终密钥
    payload 用最终密钥 AES-GCM 加密

两个 HMAC 校验块用于区分「主密码错」和「U盘插错」。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYFILE_MAGIC = b"VLTKEY01"
KEYFILE_LEN = 32
KDF_PARAMS = {"n": 32768, "r": 8, "p": 1}
SCRYPT_MAXMEM = 64 * 1024 * 1024  # 64 MiB
BACKUP_MAGIC = b"VLTBK01"


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class WrongKeyfile(VaultError):
    pass


# ---------- 编码工具 ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def new_salt() -> bytes:
    return os.urandom(16)


# ---------- 密钥派生 ----------

def derive_k1(password: str, salt: bytes, params: dict) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=params["n"],
        r=params["r"],
        p=params["p"],
        #maxmem=SCRYPT_MAXMEM,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_final_key(k1: bytes, keyfile: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=k1,
        info=b"pwdvault-final-key-v1",
    )
    return hkdf.derive(keyfile)


def check_k1(k1: bytes) -> bytes:
    return hmac.new(k1, b"pwdvault-check-k1", hashlib.sha256).digest()


def check_final(final_key: bytes) -> bytes:
    return hmac.new(final_key, b"pwdvault-check-final", hashlib.sha256).digest()


# ---------- U盘 keyfile ----------

def make_keyfile_file() -> bytes:
    """生成完整的 keyfile 文件内容（magic + 32 字节随机）。"""
    return KEYFILE_MAGIC + os.urandom(KEYFILE_LEN)


def parse_keyfile_file(raw: bytes) -> bytes:
    """从 keyfile 文件内容中取出 32 字节密钥。"""
    if len(raw) != len(KEYFILE_MAGIC) + KEYFILE_LEN or not raw.startswith(KEYFILE_MAGIC):
        raise WrongKeyfile("keyfile 格式不正确或已损坏")
    return raw[len(KEYFILE_MAGIC):]


# ---------- payload 加解密 ----------

def encrypt_payload(final_key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    ct = AESGCM(final_key).encrypt(nonce, plaintext, b"pwdvault-payload")
    return nonce, ct


def decrypt_payload(final_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        return AESGCM(final_key).decrypt(nonce, ciphertext, b"pwdvault-payload")
    except Exception:
        raise VaultError("数据解密失败（库文件可能被篡改）")


# ---------- 密钥备份包 ----------

def make_key_backup(password: str, keyfile_bytes: bytes) -> bytes:
    """用主密码（独立 salt）加密 keyfile，生成可离线保存的备份包。"""
    salt = new_salt()
    k = derive_k1(password, salt, KDF_PARAMS)
    nonce = os.urandom(12)
    ct = AESGCM(k).encrypt(nonce, keyfile_bytes, b"pwdvault-keybackup")
    header = {
        "version": 1,
        "kdf": {**KDF_PARAMS, "salt": b64e(salt)},
        "nonce": b64e(nonce),
    }
    h = json.dumps(header).encode("utf-8")
    return BACKUP_MAGIC + len(h).to_bytes(4, "big") + h + ct


def open_key_backup(password: str, blob: bytes) -> bytes:
    if not blob.startswith(BACKUP_MAGIC):
        raise VaultError("备份包格式不正确")
    off = len(BACKUP_MAGIC)
    hlen = int.from_bytes(blob[off:off + 4], "big")
    off += 4
    header = json.loads(blob[off:off + hlen].decode("utf-8"))
    off += hlen
    ct = blob[off:]
    salt = b64d(header["kdf"]["salt"])
    params = {k: header["kdf"][k] for k in ("n", "r", "p")}
    k = derive_k1(password, salt, params)
    nonce = b64d(header["nonce"])
    try:
        return AESGCM(k).decrypt(nonce, ct, b"pwdvault-keybackup")
    except Exception:
        raise WrongPassword("主密码错误，无法解开密钥备份包")