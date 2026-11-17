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

DATA_SCHEMA_VERSION = 1
SCHEDULED_TASK_NAME = "GPTManager_QuotaNotifier"


@dataclass
class AppSettings:
    theme: str = "light"
    notify_enabled: bool = True
    notify_quota_threshold: int = 20  # 周额度剩余不少于此百分比（如20%）
    notify_hours_threshold: int = 24  # 离重置时间不足此小时数（如24小时=1天）
    background_task_enabled: bool = False  # 是否启用 Windows 计划任务后台提醒
    minimize_to_tray: bool = False  # 关闭窗口时最小化到系统托盘

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theme": self.theme,
            "notify_enabled": self.notify_enabled,
            "notify_quota_threshold": self.notify_quota_threshold,
            "notify_hours_threshold": self.notify_hours_threshold,
            "background_task_enabled": self.background_task_enabled,
            "minimize_to_tray": self.minimize_to_tray,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppSettings":
        return cls(
            theme=str(data.get("theme", "light")),
            notify_enabled=bool(data.get("notify_enabled", True)),
            notify_quota_threshold=int(data.get("notify_quota_threshold", 20)),
            notify_hours_threshold=int(data.get("notify_hours_threshold", 24)),
            background_task_enabled=bool(data.get("background_task_enabled", False)),
            minimize_to_tray=bool(data.get("minimize_to_tray", False)),
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
        # Create or update hourly task
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
        # Delete task
        proc = subprocess.run(
            ["schtasks", "/delete", "/tn", SCHEDULED_TASK_NAME, "/f"],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        if proc.returncode == 0 or "ERROR: The system cannot find the file specified" in (proc.stderr or ""):
            return True, "后台计划任务已关闭"
        err_msg = (proc.stderr or proc.stdout or "未知错误").strip()
        return False, f"删除计划任务失败: {err_msg}"



def resolve_app_dir() -> Path:
    """
    Resolve the directory where persistent `data/` and `logs/` live.
    When frozen by PyInstaller (`--onefile`), `sys.executable` points to the `.exe` location.
    When running from source, use the project root directory.
    """
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
        self.accounts_file = self.data_dir / "accounts.json"
        self.settings_file = self.data_dir / "settings.json"
        self.log_file = self.logs_dir / "events.jsonl"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.logger = StructuredLogger(self.log_file)

    def load_settings(self) -> AppSettings:
        if not self.settings_file.exists():
            return AppSettings()
        try:
            data = json.loads(self.settings_file.read_text(encoding="utf-8"))
            return AppSettings.from_dict(data)
        except Exception:
            return AppSettings()

    def save_settings(self, settings: AppSettings) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings_file.write_text(
            json.dumps(settings.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

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
        if not isinstance(payload, dict) or "accounts" not in payload:
            raise ValueError(f"数据文件格式非法: {self.accounts_file}")
        accounts: List[Account] = []
        for item in payload["accounts"]:
            accounts.append(Account.from_dict(item))
        return accounts

    def save_accounts(self, accounts: List[Account]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": DATA_SCHEMA_VERSION,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "accounts": [acc.to_dict() for acc in accounts],
        }
        serialized = json.dumps(payload, ensure_ascii=False, indent=2)
        fd, tmp_path = tempfile.mkstemp(
            prefix="accounts_", suffix=".tmp", dir=str(self.data_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                tmp_file.write(serialized)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, self.accounts_file)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
