"""
Codex CLI session detector, JWT claims parser, real-time file watcher, and zero-manual login controller.
Supports Windows Win32 environments with zero external network requests.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtCore import QFileSystemWatcher, QObject, QTimer, pyqtSignal


@dataclass
class CodexProfile:
    email: str
    name: str
    plan_type: str
    subscription_active_until: Optional[str] = None
    subscription_expire_timestamp: Optional[float] = None
    account_id: str = ""
    user_id: str = ""
    last_refresh: str = ""
    raw_auth_data: Dict[str, Any] = None  # type: ignore

    @property
    def display_plan(self) -> str:
        pt = (self.plan_type or "").strip().lower()
        if pt == "plus":
            return "Plus会员"
        elif pt == "team":
            return "Team企业"
        elif pt == "pro":
            return "Pro专业版"
        elif pt == "free":
            return "Free免费版"
        return self.plan_type.upper() if self.plan_type else "未知订阅"


def parse_jwt_payload(token: str) -> Dict[str, Any]:
    """Parse payload from unverified JWT token without external crypto dependencies."""
    if not isinstance(token, str) or "." not in token:
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # Add padding if needed
    remainder = len(payload_b64) % 4
    if remainder:
        payload_b64 += "=" * (4 - remainder)
    try:
        raw_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii", "ignore"))
        data = json.loads(raw_bytes.decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def parse_iso_timestamp(iso_str: Optional[str]) -> Optional[float]:
    """Parse ISO 8601 string like '2026-11-29T05:55:14+00:00' to Unix epoch seconds."""
    if not iso_str or not isinstance(iso_str, str):
        return None
    clean = iso_str.strip()
    try:
        # Handles Z or +00:00
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean)
        return dt.timestamp()
    except Exception:
        return None


def extract_codex_profile(auth_path: Optional[Path] = None) -> Optional[CodexProfile]:
    """
    Read and parse `~/.codex/auth.json` (or custom path).
    Extracts identity, email, name, plan, and subscription expiration.
    Returns None if file is missing, empty, invalid, or unauthenticated.
    """
    target = auth_path if auth_path is not None else (Path.home() / ".codex" / "auth.json")
    if not target.exists() or not target.is_file():
        return None
    try:
        content = target.read_text(encoding="utf-8-sig").strip()
        if not content:
            return None
        data = json.loads(content)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None

    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        return None

    id_token = str(tokens.get("id_token") or "").strip()
    access_token = str(tokens.get("access_token") or "").strip()
    if not id_token and not access_token:
        return None

    id_payload = parse_jwt_payload(id_token) if id_token else {}
    acc_payload = parse_jwt_payload(access_token) if access_token else {}

    auth_claim = (
        id_payload.get("https://api.openai.com/auth")
        or acc_payload.get("https://api.openai.com/auth")
        or {}
    )
    if not isinstance(auth_claim, dict):
        auth_claim = {}

    prof_claim = (
        id_payload.get("https://api.openai.com/profile")
        or acc_payload.get("https://api.openai.com/profile")
        or {}
    )
    if not isinstance(prof_claim, dict):
        prof_claim = {}

    email = (
        id_payload.get("email")
        or prof_claim.get("email")
        or acc_payload.get("email")
        or ""
    )
    email = str(email).strip()

    name = (
        id_payload.get("name")
        or prof_claim.get("name")
        or acc_payload.get("name")
        or (email.split("@")[0] if email else "CodexUser")
    )
    name = str(name).strip()

    plan_type = str(auth_claim.get("chatgpt_plan_type") or "plus").strip()
    sub_until = auth_claim.get("chatgpt_subscription_active_until")
    sub_expire_ts = parse_iso_timestamp(sub_until) if sub_until else None

    user_id = str(auth_claim.get("user_id") or id_payload.get("sub") or "").strip()
    account_id = str(auth_claim.get("chatgpt_account_id") or tokens.get("account_id") or "").strip()
    last_refresh = str(data.get("last_refresh") or "").strip()

    if not email:
        return None

    return CodexProfile(
        email=email,
        name=name,
        plan_type=plan_type,
        subscription_active_until=sub_until,
        subscription_expire_timestamp=sub_expire_ts,
        account_id=account_id,
        user_id=user_id,
        last_refresh=last_refresh,
        raw_auth_data=data,
    )


def find_codex_executable() -> Optional[str]:
    """Locate npm or system codex executable."""
    # 1. System PATH
    found = shutil.which("codex")
    if found:
        return found

    # 2. Windows Roaming npm
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        npm_cmd = Path(appdata) / "npm" / "codex.cmd"
        if npm_cmd.exists():
            return str(npm_cmd)
        npm_ps1 = Path(appdata) / "npm" / "codex.ps1"
        if npm_ps1.exists():
            return str(npm_ps1)

    # 3. Local npm prefix
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        cand = Path(userprofile) / "AppData" / "Roaming" / "npm" / "codex.cmd"
        if cand.exists():
            return str(cand)

    return None


class CodexMonitor(QObject):
    """
    Watches `~/.codex/auth.json` in real time using QFileSystemWatcher and polling fallback.
    Emits `profile_updated(Optional[CodexProfile])` whenever auth state changes.
    """

    profile_updated = pyqtSignal(object)  # Optional[CodexProfile]

    def __init__(
        self,
        codex_home: Optional[Path] = None,
        parent: Optional[QObject] = None,
        poll_interval_ms: int = 3000,
    ) -> None:
        super().__init__(parent)
        self.codex_dir = codex_home if codex_home is not None else (Path.home() / ".codex")
        self.auth_file = self.codex_dir / "auth.json"
        self._last_profile: Optional[CodexProfile] = None
        self._last_mtime: float = -1.0

        # File system watcher
        self._watcher = QFileSystemWatcher(self)
        self._ensure_watched()
        self._watcher.fileChanged.connect(self._on_file_changed)
        self._watcher.directoryChanged.connect(self._on_dir_changed)

        # Polling fallback timer
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self.check_now)
        self._poll_timer.start(max(1000, int(poll_interval_ms)))

    def _ensure_watched(self) -> None:
        if self.codex_dir.exists():
            dir_str = str(self.codex_dir)
            if dir_str not in self._watcher.directories():
                self._watcher.addPath(dir_str)
        if self.auth_file.exists():
            file_str = str(self.auth_file)
            if file_str not in self._watcher.files():
                self._watcher.addPath(file_str)

    def _on_file_changed(self, path: str) -> None:
        self._ensure_watched()
        self.check_now()

    def _on_dir_changed(self, path: str) -> None:
        self._ensure_watched()
        self.check_now()

    def check_now(self) -> Optional[CodexProfile]:
        """Check auth.json mtime and extract profile if changed."""
        self._ensure_watched()
        if not self.auth_file.exists():
            if self._last_profile is not None or self._last_mtime != -1.0:
                self._last_mtime = -1.0
                self._last_profile = None
                self.profile_updated.emit(None)
            return None

        try:
            mtime = self.auth_file.stat().st_mtime
        except OSError:
            return self._last_profile

        if mtime == self._last_mtime:
            return self._last_profile

        self._last_mtime = mtime
        new_prof = extract_codex_profile(self.auth_file)
        self._last_profile = new_prof
        self.profile_updated.emit(new_prof)
        return new_prof

    @property
    def current_profile(self) -> Optional[CodexProfile]:
        if self._last_profile is None and self.auth_file.exists():
            return self.check_now()
        return self._last_profile


class CodexLoginController(QObject):
    """
    Manages non-blocking `codex login` process and awaits browser OAuth callback.
    """

    status_message = pyqtSignal(str)
    login_succeeded = pyqtSignal(object)  # CodexProfile
    login_failed = pyqtSignal(str)

    def __init__(
        self,
        monitor: CodexMonitor,
        parent: Optional[QObject] = None,
        timeout_seconds: int = 180,
    ) -> None:
        super().__init__(parent)
        self.monitor = monitor
        self.timeout_seconds = max(30, int(timeout_seconds))
        self._proc: Optional[subprocess.Popen] = None
        self._start_time: float = 0.0
        self._initial_email: Optional[str] = None

        self._check_timer = QTimer(self)
        self._check_timer.timeout.connect(self._on_check_tick)

    def start_login(self) -> bool:
        """Start the official codex login process in background."""
        if self._proc is not None and self._proc.poll() is None:
            self.status_message.emit("已有正在进行的登录流程，请在浏览器中完成...")
            return False

        codex_bin = find_codex_executable()
        if not codex_bin:
            self.login_failed.emit(
                "未在系统中检测到 Codex CLI 命令。请先通过终端执行 `npm install -g @openai/codex` 安装。"
            )
            return False

        curr = self.monitor.current_profile
        self._initial_email = curr.email.lower() if curr else None
        self._start_time = time.time()

        try:
            # Run codex login which will open default browser to ChatGPT login
            if codex_bin.lower().endswith(".ps1"):
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", codex_bin, "login"]
            else:
                cmd = [codex_bin, "login"]

            creationflags = 0
            if hasattr(subprocess, "CREATE_NO_WINDOW") and sys.platform == "win32":
                creationflags = subprocess.CREATE_NO_WINDOW

            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
        except Exception as err:
            self.login_failed.emit(f"调起 Codex 登录进程失败: {err}")
            return False

        self.status_message.emit("已调起浏览器官方登录页面，正在监听授权回调...")
        self._check_timer.start(1500)
        return True

    def cancel_login(self) -> None:
        """Abort login monitoring and terminate child process."""
        self._check_timer.stop()
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None
        self.status_message.emit("登录流程已取消")

    def _on_check_tick(self) -> None:
        elapsed = time.time() - self._start_time
        if elapsed > self.timeout_seconds:
            self.cancel_login()
            self.login_failed.emit(f"登录监听超时 ({self.timeout_seconds}秒)，未收到授权回调")
            return

        # Check monitor profile
        prof = self.monitor.check_now()
        if prof is not None:
            # If initial was None and now exists, OR email/refresh changed
            if self._initial_email is None or prof.email.lower() != self._initial_email:
                self._check_timer.stop()
                if self._proc is not None:
                    try:
                        self._proc.terminate()
                    except Exception:
                        pass
                    self._proc = None
                self.login_succeeded.emit(prof)
                return

        # Check process status
        if self._proc is not None and self._proc.poll() is not None:
            # Process finished; check if profile updated
            prof = self.monitor.check_now()
            if prof is not None and (self._initial_email is None or prof.email.lower() != self._initial_email):
                self._check_timer.stop()
                self._proc = None
                self.login_succeeded.emit(prof)
                return
            err_out = ""
            if self._proc.stderr:
                try:
                    err_out = self._proc.stderr.read()
                except Exception:
                    pass
            self.cancel_login()
            self.login_failed.emit(f"Codex 登录进程已退出，未检测到有效授权变化: {err_out.strip() or '用户取消'}")
