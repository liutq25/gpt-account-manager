from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.models import Account
from src.security import (
    PORTABLE_BACKUP_MAGIC,
    WebDavSyncClient,
    decrypt_portable_payload,
    dpapi_decrypt,
    dpapi_encrypt,
    encrypt_portable_payload,
    merge_account_dicts,
)

DATA_SCHEMA_VERSION = 2
SCHEDULED_TASK_NAME = "GPTManager_QuotaNotifier"


@dataclass
class AppSettings:
    theme: str = "light"
    notify_enabled: bool = True
    notify_quota_threshold: int = 20
    notify_hours_threshold: int = 24
    background_task_enabled: bool = False
    minimize_to_tray: bool = False
    warranty_notify_enabled: bool = True
    warranty_notify_hours: int = 24
    custom_browser_path: str = ""
    clipboard_burn_seconds: int = 12
    webdav_url: str = ""
    webdav_username: str = ""
    webdav_password: str = ""
    _preserved_encrypted_webdav_password: str = field(default="", repr=False, compare=False)

    def to_dict(self, encrypt_secrets: bool = True) -> Dict[str, Any]:
        wd_pwd = self.webdav_password
        if encrypt_secrets:
            if wd_pwd and sys.platform == "win32":
                wd_pwd = dpapi_encrypt(wd_pwd)
            elif not wd_pwd and self._preserved_encrypted_webdav_password:
                wd_pwd = self._preserved_encrypted_webdav_password
        return {
            "theme": self.theme,
            "notify_enabled": self.notify_enabled,
            "notify_quota_threshold": max(1, min(99, int(self.notify_quota_threshold))),
            "notify_hours_threshold": max(1, min(168, int(self.notify_hours_threshold))),
            "background_task_enabled": self.background_task_enabled,
            "minimize_to_tray": self.minimize_to_tray,
            "warranty_notify_enabled": self.warranty_notify_enabled,
            "warranty_notify_hours": max(1, min(168, int(self.warranty_notify_hours))),
            "custom_browser_path": self.custom_browser_path.strip(),
            "clipboard_burn_seconds": max(3, min(120, int(self.clipboard_burn_seconds))),
            "webdav_url": self.webdav_url.strip(),
            "webdav_username": self.webdav_username.strip(),
            "webdav_password": wd_pwd,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppSettings":
        raw_wd_pwd = str(data.get("webdav_password", "") or "")
        preserved_raw = ""
        try:
            wd_pwd = dpapi_decrypt(raw_wd_pwd) if raw_wd_pwd else ""
        except Exception:
            wd_pwd = ""
            preserved_raw = raw_wd_pwd
        return cls(
            theme=str(data.get("theme", "light")),
            notify_enabled=bool(data.get("notify_enabled", True)),
            notify_quota_threshold=max(1, min(99, int(data.get("notify_quota_threshold", 20)))),
            notify_hours_threshold=max(1, min(168, int(data.get("notify_hours_threshold", 24)))),
            background_task_enabled=bool(data.get("background_task_enabled", False)),
            minimize_to_tray=bool(data.get("minimize_to_tray", False)),
            warranty_notify_enabled=bool(data.get("warranty_notify_enabled", True)),
            warranty_notify_hours=max(1, min(168, int(data.get("warranty_notify_hours", 24)))),
            custom_browser_path=str(data.get("custom_browser_path", "")).strip(),
            clipboard_burn_seconds=max(3, min(120, int(data.get("clipboard_burn_seconds", 12)))),
            webdav_url=str(data.get("webdav_url", "")).strip(),
            webdav_username=str(data.get("webdav_username", "")).strip(),
            webdav_password=wd_pwd,
            _preserved_encrypted_webdav_password=preserved_raw,
        )


def resolve_check_notify_command(custom_exe: Optional[Path] = None) -> str:
    """Resolve full command line for Windows Task Scheduler checking."""
    if custom_exe and custom_exe.exists():
        return f'"{custom_exe.resolve()}" --check-notify'
    if getattr(sys, "frozen", False):
        exe_path = Path(sys.executable).resolve()
        return f'"{exe_path}" --check-notify'
    main_py = (Path(__file__).resolve().parent.parent / "main.py").resolve()
    py_exe = Path(sys.executable).resolve()
    return f'"{py_exe}" "{main_py}" --check-notify'


def is_windows_scheduled_task_installed() -> bool:
    """Check if GPTManager_QuotaNotifier task exists in Task Scheduler."""
    if sys.platform != "win32":
        return False
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/tn", SCHEDULED_TASK_NAME],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return proc.returncode == 0
    except Exception:
        return False


def configure_windows_scheduled_task(enable: bool, custom_exe: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Create or delete the Windows hourly scheduled task for background notifications.
    """
    if sys.platform != "win32":
        return False, "非 Windows 系统不支持计划任务"

    cmd_line = resolve_check_notify_command(custom_exe)
    startupinfo = None
    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

    if enable:
        proc = subprocess.run(
            [
                "schtasks",
                "/create",
                "/tn",
                SCHEDULED_TASK_NAME,
                "/tr",
                cmd_line,
                "/sc",
                "HOURLY",
                "/mo",
                "1",
                "/f",
            ],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        if proc.returncode == 0:
            return True, "后台计划任务已成功开启（系统每小时自动静默检测，无需打开软件）"
        err_msg = (proc.stderr or proc.stdout or "未知错误").strip()
        return False, f"创建计划任务失败: {err_msg}"
    else:
        proc = subprocess.run(
            ["schtasks", "/delete", "/tn", SCHEDULED_TASK_NAME, "/f"],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        combined = f"{proc.stderr or ''} {proc.stdout or ''}"
        if (
            proc.returncode == 0
            or "cannot find the file" in combined.lower()
            or "找不到指定的文件" in combined
        ):
            return True, "后台计划任务已关闭"
        err_msg = combined.strip() or "未知错误"
        return False, f"删除计划任务失败: {err_msg}"


def resolve_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


@dataclass
class LogEntry:
    timestamp: str
    trace_id: str
    level: str
    event: str
    account: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "level": self.level,
            "event": self.event,
            "account": self.account,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEntry":
        return cls(
            timestamp=str(data.get("timestamp", "")),
            trace_id=str(data.get("trace_id", "")),
            level=str(data.get("level", "INFO")),
            event=str(data.get("event", "")),
            account=str(data.get("account", "-")),
            detail=str(data.get("detail", "")),
        )


class StructuredLogger:
    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        level: str,
        event: str,
        detail: str,
        account: str = "-",
        trace_id: Optional[str] = None,
    ) -> LogEntry:
        entry = LogEntry(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            trace_id=trace_id or uuid.uuid4().hex[:8],
            level=level.upper(),
            event=event,
            account=account,
            detail=detail,
        )
        line = json.dumps(entry.to_dict(), ensure_ascii=False)
        with self.log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return entry

    def read_recent(self, limit: int = 500) -> List[LogEntry]:
        if not self.log_file.exists():
            return []
        entries: List[LogEntry] = []
        with self.log_file.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(LogEntry.from_dict(data))
                except json.JSONDecodeError:
                    entries.append(
                        LogEntry(
                            timestamp="-",
                            trace_id="-",
                            level="WARN",
                            event="LOG_PARSE_ERROR",
                            account="-",
                            detail=f"无法解析日志行: {line[:120]}",
                        )
                    )
        if limit > 0 and len(entries) > limit:
            return entries[-limit:]
        return entries

    def clear(self) -> None:
        if self.log_file.exists():
            self.log_file.write_text("", encoding="utf-8")


class AccountStorage:
    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir if base_dir is not None else resolve_app_dir()
        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.base_dir / "logs"
        self.profiles_dir = self.base_dir / "browser_profiles"
        self.codex_vault_dir = self.data_dir / "codex_vault"
        self.accounts_file = self.data_dir / "accounts.json"
        self.settings_file = self.data_dir / "settings.json"
        self.log_file = self.logs_dir / "events.jsonl"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.logger = StructuredLogger(self.log_file)

    def load_settings(self, strict: bool = False) -> AppSettings:
        if not self.settings_file.exists():
            return AppSettings()
        try:
            data = json.loads(self.settings_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("settings.json 顶层必须是 JSON 对象")
            settings = AppSettings.from_dict(data)
            if settings._preserved_encrypted_webdav_password:
                try:
                    self.logger.log(
                        "WARN",
                        "SETTINGS_WEBDAV_PWD_UNDECRYPTABLE",
                        "WebDAV 密码 DPAPI 解密失败（可能来自其他机器），已保留原密文未覆盖。",
                    )
                except Exception:
                    pass
            return settings
        except Exception as exc:
            try:
                self.logger.log("ERROR", "SETTINGS_LOAD_ERROR", f"加载设置文件失败: {exc}")
            except Exception:
                pass
            if strict:
                raise
            return AppSettings()

    def save_settings(self, settings: AppSettings) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(settings.to_dict(encrypt_secrets=True), ensure_ascii=False, indent=2)
        self._atomic_write_text(self.settings_file, serialized)

    def load_theme(self) -> str:
        return self.load_settings().theme

    def save_theme(self, theme: str) -> None:
        if theme not in ("light", "dark"):
            raise ValueError(f"Unsupported theme: {theme}")
        current = self.load_settings()
        current.theme = theme
        self.save_settings(current)

    def load_accounts(self) -> List[Account]:
        if not self.accounts_file.exists():
            return []
        raw_text = self.accounts_file.read_text(encoding="utf-8").strip()
        if not raw_text:
            return []
        payload = json.loads(raw_text)
        if not isinstance(payload, dict) or not isinstance(payload.get("accounts"), list):
            raise ValueError(f"数据文件格式非法: {self.accounts_file}")

        accounts: List[Account] = []
        had_legacy_plaintext = False
        for item in payload["accounts"]:
            if not isinstance(item, dict):
                raise ValueError(f"账号记录结构非法: {self.accounts_file}")
            item_copy = dict(item)
            raw_pwd = str(item_copy.get("password", ""))
            raw_tfa = str(item_copy.get("two_fa", ""))
            if (raw_pwd and not raw_pwd.startswith("dpapi:v1:")) or (
                raw_tfa and not raw_tfa.startswith("dpapi:v1:")
            ):
                had_legacy_plaintext = True
            item_copy["password"] = dpapi_decrypt(raw_pwd)
            item_copy["two_fa"] = dpapi_decrypt(raw_tfa)
            accounts.append(Account.from_dict(item_copy))

        # Transparently upgrade legacy v1 plaintext files to DPAPI-encrypted at rest
        if had_legacy_plaintext and accounts and sys.platform == "win32":
            try:
                self.save_accounts(accounts)
                self.logger.log("INFO", "STORAGE_DPAPI_UPGRADED", "已自动将旧版明文凭据透明升级为 Windows DPAPI 密文落盘。")
            except Exception as exc:
                try:
                    self.logger.log("ERROR", "STORAGE_DPAPI_UPGRADE_FAILED", f"旧版凭据升级落盘失败: {exc}")
                except Exception:
                    pass
        return accounts

    def save_accounts(self, accounts: List[Account], encrypt_at_rest: bool = True) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        serialized_accounts: List[Dict[str, Any]] = []
        for acc in accounts:
            d = acc.to_dict()
            if encrypt_at_rest and sys.platform == "win32":
                d["password"] = dpapi_encrypt(d["password"])
                d["two_fa"] = dpapi_encrypt(d["two_fa"])
            serialized_accounts.append(d)

        payload = {
            "schema_version": DATA_SCHEMA_VERSION,
            "encryption": "dpapi:v1" if (encrypt_at_rest and sys.platform == "win32") else "none",
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "accounts": serialized_accounts,
        }
        serialized = json.dumps(payload, ensure_ascii=False, indent=2)
        self._atomic_write_text(self.accounts_file, serialized)

    def export_portable_backup(
        self,
        accounts: List[Account],
        target_file: Path,
        passphrase: str,
    ) -> None:
        """Export cross-device AES-256-GCM encrypted backup file."""
        plain_payload = {
            "schema_version": DATA_SCHEMA_VERSION,
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "accounts": [acc.to_dict() for acc in accounts],
        }
        encrypted_json = encrypt_portable_payload(plain_payload, passphrase)
        target_file.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write_text(target_file, encrypted_json)

    def import_backup_merge(
        self,
        source_file: Path,
        existing_accounts: List[Account],
        passphrase: str = "",
    ) -> Tuple[List[Account], int, int, int]:
        """
        Import either an AES-256-GCM encrypted portable backup OR a legacy JSON backup,
        performing deterministic LWW merge with `existing_accounts`.
        Returns (merged_accounts, added_count, updated_count, kept_local_count).
        """
        raw_text = Path(source_file).read_text(encoding="utf-8").strip()
        if not raw_text:
            raise ValueError("备份文件为空")
        top = json.loads(raw_text)
        if not isinstance(top, dict):
            raise ValueError("备份文件顶层结构非法")

        if top.get("magic") == PORTABLE_BACKUP_MAGIC or ("kdf" in top and "ciphertext" in top):
            decrypted_payload = decrypt_portable_payload(raw_text, passphrase)
            remote_raw = decrypted_payload.get("accounts", [])
            if not isinstance(remote_raw, list) or any(not isinstance(r, dict) for r in remote_raw):
                raise ValueError("加密备份中的 accounts 结构非法")
        elif "accounts" in top:
            raw_list = top["accounts"]
            if not isinstance(raw_list, list) or any(not isinstance(r, dict) for r in raw_list):
                raise ValueError("备份文件中的 accounts 结构非法")
            # Legacy or local DPAPI backup
            remote_raw = []
            for item in raw_list:
                ic = dict(item)
                ic["password"] = dpapi_decrypt(str(ic.get("password", "")))
                ic["two_fa"] = dpapi_decrypt(str(ic.get("two_fa", "")))
                remote_raw.append(ic)
        else:
            raise ValueError("无法识别的备份文件结构")

        # Validate each remote record by round-tripping through Account.from_dict
        validated_remote = [Account.from_dict(r).to_dict() for r in remote_raw]
        local_dicts = [a.to_dict() for a in existing_accounts]

        merged_dicts, added, updated, kept = merge_account_dicts(local_dicts, validated_remote)
        merged_accounts = [Account.from_dict(m) for m in merged_dicts]
        self.save_accounts(merged_accounts)
        return merged_accounts, added, updated, kept

    def push_to_webdav(
        self,
        accounts: List[Account],
        settings: AppSettings,
        sync_passphrase: str,
    ) -> str:
        client = WebDavSyncClient(
            base_url=settings.webdav_url,
            username=settings.webdav_username,
            password=settings.webdav_password,
        )
        payload = {
            "schema_version": DATA_SCHEMA_VERSION,
            "synced_at": datetime.now().isoformat(timespec="seconds"),
            "accounts": [a.to_dict() for a in accounts],
        }
        return client.upload_encrypted(payload, sync_passphrase)

    def pull_from_webdav(
        self,
        existing_accounts: List[Account],
        settings: AppSettings,
        sync_passphrase: str,
    ) -> Tuple[List[Account], int, int, int]:
        client = WebDavSyncClient(
            base_url=settings.webdav_url,
            username=settings.webdav_username,
            password=settings.webdav_password,
        )
        remote_payload = client.download_decrypted(sync_passphrase)
        remote_raw = remote_payload.get("accounts", [])
        if not isinstance(remote_raw, list) or any(not isinstance(r, dict) for r in remote_raw):
            raise ValueError("云端同步数据中的 accounts 结构非法")
        validated_remote = [Account.from_dict(r).to_dict() for r in remote_raw]
        local_dicts = [a.to_dict() for a in existing_accounts]

        merged_dicts, added, updated, kept = merge_account_dicts(local_dicts, validated_remote)
        merged_accounts = [Account.from_dict(m) for m in merged_dicts]
        self.save_accounts(merged_accounts)
        return merged_accounts, added, updated, kept

    @staticmethod
    def _atomic_write_text(target_path: Path, content: str) -> None:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=f"{target_path.stem}_", suffix=".tmp", dir=str(target_path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                tmp_file.write(content)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, target_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
