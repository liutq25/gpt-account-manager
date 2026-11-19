"""
Credential encryption (Windows DPAPI + AES-256-GCM portable archive) and WebDAV E2EE sync.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import http.client
import json
import math
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DPAPI_PREFIX = "dpapi:v1:"
AESGCM_PREFIX = "aesgcm:v1:"
PORTABLE_BACKUP_MAGIC = "GPT_MANAGER_ENCRYPTED_BACKUP_V2"
PBKDF2_ITERATIONS = 600_000


class SecurityError(Exception):
    """Raised when encryption, decryption, or integrity verification fails."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _bytes_to_blob(data: bytes) -> Tuple[_DATA_BLOB, Any]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def dpapi_encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext string bound to current Windows user via CryptProtectData.
    Idempotent if already prefixed with DPAPI_PREFIX.
    """
    if not isinstance(plaintext, str):
        raise TypeError(f"plaintext 必须为字符串，实际类型: {type(plaintext).__name__}")
    if plaintext == "" or plaintext.startswith(DPAPI_PREFIX):
        return plaintext
    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        raise SecurityError("当前操作系统不支持 Windows DPAPI")

    raw = plaintext.encode("utf-8")
    in_blob, _in_buf = _bytes_to_blob(raw)
    out_blob = _DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "GPTAccountManagerSecret",
        None,
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    )
    if not ok:
        err_code = kernel32.GetLastError()
        raise SecurityError(f"Windows DPAPI 加密失败 (ErrorCode={err_code})")

    try:
        encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        b64 = base64.b64encode(encrypted_bytes).decode("ascii")
        return f"{DPAPI_PREFIX}{b64}"
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_decrypt(token: str) -> str:
    """
    Decrypt a `dpapi:v1:<base64>` token. Plaintext strings without prefix are returned as-is
    for backward compatibility with v1 plaintext JSON files.
    """
    if not isinstance(token, str):
        raise TypeError(f"token 必须为字符串，实际类型: {type(token).__name__}")
    if token == "" or not token.startswith(DPAPI_PREFIX):
        return token
    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        raise SecurityError("当前非 Windows 环境无法解密 DPAPI 绑定密文，请使用口令加密备份迁移")

    b64_payload = token[len(DPAPI_PREFIX) :]
    try:
        cipher_bytes = base64.b64decode(b64_payload.encode("ascii"), validate=True)
    except Exception as exc:
        raise SecurityError(f"DPAPI 密文 Base64 格式损坏: {exc}") from exc

    if not cipher_bytes:
        raise SecurityError("DPAPI 密文内容为空")

    in_blob, _in_buf = _bytes_to_blob(cipher_bytes)
    out_blob = _DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    )
    if not ok:
        err_code = kernel32.GetLastError()
        raise SecurityError(
            f"Windows DPAPI 解密失败 (ErrorCode={err_code})：该数据文件绑定了其他电脑或系统账户，请通过「跨设备加密备份」导入"
        )

    try:
        plain_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecurityError(f"DPAPI 明文 UTF-8 解码失败: {exc}") from exc
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _derive_aes_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    clean_pass = passphrase.strip() if isinstance(passphrase, str) else ""
    if len(clean_pass) < 4:
        raise ValueError("加密口令长度至少需要 4 个非空白字符")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(clean_pass.encode("utf-8"))


def passphrase_encrypt_bytes(raw_bytes: bytes, passphrase: str) -> Dict[str, Any]:
    """Encrypt arbitrary bytes with PBKDF2-HMAC-SHA256 + AES-256-GCM."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_aes_key(passphrase, salt, PBKDF2_ITERATIONS)
    aesgcm = AESGCM(key)
    aad = PORTABLE_BACKUP_MAGIC.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, aad)
    return {
        "magic": PORTABLE_BACKUP_MAGIC,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "cipher": "AES-256-GCM",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def passphrase_decrypt_bytes(envelope: Dict[str, Any], passphrase: str) -> bytes:
    """Verify AAD and decrypt portable AES-256-GCM envelope."""
    if not isinstance(envelope, dict) or envelope.get("magic") != PORTABLE_BACKUP_MAGIC:
        raise SecurityError("非法的加密备份文件头")
    if envelope.get("kdf") != "PBKDF2-HMAC-SHA256" or envelope.get("cipher") != "AES-256-GCM":
        raise SecurityError("不支持的加密算法或密钥派生参数")
    try:
        raw_iters = envelope.get("iterations", PBKDF2_ITERATIONS)
        if isinstance(raw_iters, bool):
            raise SecurityError("PBKDF2 迭代次数格式非法")
        iterations = int(raw_iters)
        if iterations < 10_000 or iterations > 10_000_000:
            raise SecurityError(f"PBKDF2 迭代次数超出安全边界: {iterations}")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) != 16:
            raise SecurityError(f"加密盐长度非法: {len(salt)}")
        if len(nonce) != 12:
            raise SecurityError(f"AES-GCM Nonce 长度非法: {len(nonce)}")
    except SecurityError:
        raise
    except Exception as exc:
        raise SecurityError(f"加密信封元数据损坏: {exc}") from exc

    try:
        key = _derive_aes_key(passphrase, salt, iterations)
    except ValueError as exc:
        raise SecurityError(str(exc)) from exc
    aesgcm = AESGCM(key)
    aad = PORTABLE_BACKUP_MAGIC.encode("utf-8")
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise SecurityError("解密失败：同步/备份口令错误，或密文已被篡改") from exc


def encrypt_portable_payload(payload: Dict[str, Any], passphrase: str) -> str:
    """Serialize dict payload and encrypt into portable JSON string."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    envelope = passphrase_encrypt_bytes(raw, passphrase)
    return json.dumps(envelope, ensure_ascii=False, indent=2)


def decrypt_portable_payload(serialized_envelope: str, passphrase: str) -> Dict[str, Any]:
    """Parse and decrypt portable JSON envelope back to dict."""
    try:
        envelope = json.loads(serialized_envelope)
    except json.JSONDecodeError as exc:
        raise SecurityError(f"备份文件不是合法的 JSON 格式: {exc}") from exc
    plain_bytes = passphrase_decrypt_bytes(envelope, passphrase)
    try:
        data = json.loads(plain_bytes.decode("utf-8"))
    except Exception as exc:
        raise SecurityError(f"解密后的数据结构损坏: {exc}") from exc
    if not isinstance(data, dict):
        raise SecurityError("解密后的顶层结构不是字典")
    return data


@dataclass
class MergeSummary:
    merged_accounts: List[Any]
    added_count: int
    updated_count: int
    kept_local_count: int


def _safe_updated_ts(val: Any) -> float:
    if val is None or isinstance(val, bool):
        return 0.0
    try:
        f = float(val)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(f) or math.isinf(f) or f < 0.0:
        return 0.0
    return f


def merge_account_dicts(
    local_dicts: List[Dict[str, Any]],
    remote_dicts: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int, int, int]:
    """
    Deterministic Last-Write-Wins (LWW) merge between local and remote account records.
    Matches primarily by `id`, secondarily by `(provider.lower(), email.lower())`.
    Returns (merged_list, added_count, updated_from_remote_count, kept_local_count).
    """
    result: List[Dict[str, Any]] = [dict(d) for d in local_dicts]
    by_id: Dict[str, int] = {}
    by_key: Dict[Tuple[str, str], int] = {}

    for idx, item in enumerate(result):
        aid = str(item.get("id", ""))
        prov = str(item.get("provider", "ChatGPT") or "ChatGPT").strip().lower()
        email = str(item.get("email", "")).strip().lower()
        if aid:
            by_id[aid] = idx
        if email:
            by_key[(prov, email)] = idx

    added = 0
    updated = 0
    kept_local = 0

    for rem in remote_dicts:
        rem_id = str(rem.get("id", ""))
        rem_prov = str(rem.get("provider", "ChatGPT") or "ChatGPT").strip().lower()
        rem_email = str(rem.get("email", "")).strip().lower()
        rem_ts = _safe_updated_ts(rem.get("updated_at", 0.0))

        match_idx: Optional[int] = None
        if rem_id and rem_id in by_id:
            match_idx = by_id[rem_id]
        elif rem_email and (rem_prov, rem_email) in by_key:
            match_idx = by_key[(rem_prov, rem_email)]

        if match_idx is None:
            new_copy = dict(rem)
            new_idx = len(result)
            result.append(new_copy)
            if rem_id:
                by_id[rem_id] = new_idx
            if rem_email:
                by_key[(rem_prov, rem_email)] = new_idx
            added += 1
        else:
            loc = result[match_idx]
            loc_ts = _safe_updated_ts(loc.get("updated_at", 0.0))
            if rem_ts > loc_ts:
                old_prov = str(loc.get("provider", "ChatGPT") or "ChatGPT").strip().lower()
                old_email = str(loc.get("email", "")).strip().lower()
                merged_item = dict(rem)
                # Keep local ID stable if matched via email
                merged_item["id"] = loc.get("id") or rem_id
                result[match_idx] = merged_item
                if merged_item["id"]:
                    by_id[str(merged_item["id"])] = match_idx
                if old_email and by_key.get((old_prov, old_email)) == match_idx:
                    del by_key[(old_prov, old_email)]
                if rem_email:
                    by_key[(rem_prov, rem_email)] = match_idx
                updated += 1
            else:
                kept_local += 1

    return result, added, updated, kept_local


class WebDavSyncClient:
    """Zero-dependency WebDAV client using stdlib urllib with Basic Auth over HTTPS/HTTP."""

    REMOTE_FILENAME = "gpt_manager_e2ee_sync.enc.json"

    def __init__(self, base_url: str, username: str, password: str, timeout: int = 12) -> None:
        clean_url = base_url.strip()
        if not clean_url:
            raise ValueError("WebDAV 服务器地址不能为空")
        parsed = urllib.parse.urlparse(clean_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("WebDAV 地址必须以 https:// 或 http:// 开头并包含有效域名")
        self.base_url = clean_url.rstrip("/")
        self.username = username.strip()
        self.password = password
        self.timeout = timeout

    @property
    def target_file_url(self) -> str:
        if self.base_url.endswith(".json"):
            return self.base_url
        return f"{self.base_url}/{self.REMOTE_FILENAME}"

    def _auth_header(self) -> str:
        token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def upload_encrypted(self, payload: Dict[str, Any], sync_passphrase: str) -> str:
        body = encrypt_portable_payload(payload, sync_passphrase).encode("utf-8")
        req = urllib.request.Request(
            self.target_file_url,
            data=body,
            method="PUT",
            headers={
                "Authorization": self._auth_header(),
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "GPTAccountManager/2.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status not in (200, 201, 204):
                    raise SecurityError(f"WebDAV 上传返回非预期状态码: HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            raise SecurityError(f"WebDAV 上传失败: HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise SecurityError(f"WebDAV 网络连接失败: {exc.reason}") from exc
        except (TimeoutError, http.client.HTTPException, ssl.SSLError, UnicodeDecodeError, OSError) as exc:
            raise SecurityError(f"WebDAV 传输异常: {exc}") from exc
        return self.target_file_url

    def download_decrypted(self, sync_passphrase: str) -> Dict[str, Any]:
        req = urllib.request.Request(
            self.target_file_url,
            method="GET",
            headers={
                "Authorization": self._auth_header(),
                "User-Agent": "GPTAccountManager/2.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise SecurityError("云端尚未找到同步文件（HTTP 404），请先执行一次「加密上传至云端」") from exc
            raise SecurityError(f"WebDAV 下载失败: HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise SecurityError(f"WebDAV 网络连接失败: {exc.reason}") from exc
        except (TimeoutError, http.client.HTTPException, ssl.SSLError, UnicodeDecodeError, OSError) as exc:
            raise SecurityError(f"WebDAV 传输或解码异常: {exc}") from exc

        return decrypt_portable_payload(raw_text, sync_passphrase)
