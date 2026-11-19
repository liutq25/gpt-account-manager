"""
Isolated Chromium profile launcher (--user-data-dir + --proxy-server) and
3-step sequential credential paste queue with TOTP expiry guard & clipboard auto-burn.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable, List, Optional

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication

from src.models import Account, compute_totp_with_safety, validate_proxy_url


def _candidate_browser_paths() -> List[Path]:
    local_app = os.environ.get("LOCALAPPDATA", "").strip()
    prog_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").strip()
    prog_64 = os.environ.get("ProgramFiles", r"C:\Program Files").strip()

    raw_paths: List[Path] = []
    if prog_x86:
        raw_paths.append(Path(prog_x86) / "Microsoft/Edge/Application/msedge.exe")
    if prog_64:
        raw_paths.append(Path(prog_64) / "Microsoft/Edge/Application/msedge.exe")
    if local_app:
        raw_paths.append(Path(local_app) / "Microsoft/Edge/Application/msedge.exe")
    if prog_64:
        raw_paths.append(Path(prog_64) / "Google/Chrome/Application/chrome.exe")
    if prog_x86:
        raw_paths.append(Path(prog_x86) / "Google/Chrome/Application/chrome.exe")
    if local_app:
        raw_paths.append(Path(local_app) / "Google/Chrome/Application/chrome.exe")
    if prog_64:
        raw_paths.append(Path(prog_64) / "BraveSoftware/Brave-Browser/Application/brave.exe")
    if local_app:
        raw_paths.append(Path(local_app) / "BraveSoftware/Brave-Browser/Application/brave.exe")
    return raw_paths


def detect_chromium_browser(custom_path: str = "") -> Path:
    """Locate an installed Chromium-based browser (Edge / Chrome / Brave) or validate custom path."""
    clean_custom = (custom_path or "").strip()
    if clean_custom:
        p = Path(clean_custom)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"自定义浏览器路径不存在: {clean_custom}")
        if p.suffix.lower() != ".exe":
            raise ValueError("自定义浏览器路径必须指向 .exe 可执行文件")
        return p.resolve()

    for cand in _candidate_browser_paths():
        if cand.exists() and cand.is_file():
            return cand.resolve()

    raise FileNotFoundError(
        "未在系统默认位置检测到 Edge / Chrome / Brave 浏览器，请在「设置」中指定浏览器 .exe 路径"
    )


_WINDOWS_RESERVED_DEVICE_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def build_isolated_browser_args(
    account: Account,
    profiles_root: Path,
    custom_browser_path: str = "",
) -> tuple[List[str], Path]:
    """
    Construct safe subprocess argument list (shell=False) for isolated browser launch.
    Returns (argv_list, profile_dir).
    """
    browser_exe = detect_chromium_browser(custom_browser_path)
    safe_id = re.sub(r"[^A-Za-z0-9_\-]", "", account.id)
    if not safe_id or safe_id.upper() in _WINDOWS_RESERVED_DEVICE_NAMES:
        raise ValueError("账号 ID 非法，无法创建隔离目录")

    profile_dir = (profiles_root / safe_id).resolve()
    profile_dir.mkdir(parents=True, exist_ok=True)

    proxy = validate_proxy_url(account.proxy_url)
    args: List[str] = [
        str(browser_exe),
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--new-window",
    ]
    if proxy:
        args.append(f"--proxy-server={proxy}")
    args.append(account.target_url)
    return args, profile_dir


def launch_isolated_browser(
    account: Account,
    profiles_root: Path,
    custom_browser_path: str = "",
) -> Path:
    """Spawn isolated Chromium browser process without shell privilege escalation."""
    args, profile_dir = build_isolated_browser_args(account, profiles_root, custom_browser_path)
    creation_flags = 0
    if hasattr(subprocess, "DETACHED_PROCESS") and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creation_flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(
        args,
        shell=False,
        close_fds=True,
        creationflags=creation_flags,
    )
    return profile_dir


class SequentialPasteController(QObject):
    """
    State machine for frictionless 3-step login credential pasting:
      STEP 1: Copy Email
      STEP 2: Copy Password (with 60s idle auto-burn)
      STEP 3: Copy 2FA / TOTP (if remaining <= 3s, auto-wait for fresh 30s window!)
      BURN  : Auto-clear clipboard after `burn_seconds` ONLY if clipboard still holds our secret.
    """

    state_changed = pyqtSignal(str, str)  # (state_code, human_message)

    def __init__(self, parent: Optional[QObject] = None, burn_seconds: int = 12) -> None:
        super().__init__(parent)
        self.burn_seconds = max(3, int(burn_seconds))
        self._account: Optional[Account] = None
        self._state: str = "IDLE"
        self._last_sensitive_value: Optional[str] = None

        self._wait_timer = QTimer(self)
        self._wait_timer.setSingleShot(True)
        self._wait_timer.timeout.connect(self._on_totp_wait_finished)

        self._burn_timer = QTimer(self)
        self._burn_timer.setSingleShot(True)
        self._burn_timer.timeout.connect(self._on_burn_timeout)

    @property
    def state(self) -> str:
        return self._state

    @property
    def active_account(self) -> Optional[Account]:
        return self._account

    def start(self, account: Account) -> None:
        self._stop_timers()
        self._account = account
        self._last_sensitive_value = None
        self._set_clipboard(account.email)
        self._state = "STEP_1_EMAIL"
        self.state_changed.emit(
            self._state,
            f"【上号队列 1/3】「{account.name}」邮箱已复制！粘贴后点击「下一步: 密码」（或按 Ctrl+2）",
        )

    def copy_step_email(self) -> None:
        if self._account is None:
            return
        self.start(self._account)

    def copy_step_password(self) -> None:
        if self._account is None:
            return
        self._stop_timers()
        self._set_clipboard(self._account.password)
        self._last_sensitive_value = self._account.password
        self._state = "STEP_2_PASSWORD"
        # Safety idle burn after 60s if user abandons flow at password step
        self._burn_timer.start(60 * 1000)
        self.state_changed.emit(
            self._state,
            f"【上号队列 2/3】「{self._account.name}」密码已复制！粘贴后点击「下一步: 2FA验证码」（或按 Ctrl+3）",
        )

    def copy_step_totp(self, now_ts: Optional[float] = None) -> None:
        if self._account is None:
            return
        self._stop_timers()
        cur_code, rem_sec, _next_code, expiring_soon = compute_totp_with_safety(
            self._account.two_fa, min_remaining_sec=3, for_time=now_ts
        )
        if cur_code is None:
            # Static recovery/initial code
            self._deliver_final_totp(self._account.two_fa, is_totp=False, rem_sec=0)
            return

        if expiring_soon and now_ts is None:
            self._state = "STEP_3_TOTP_WAIT"
            wait_ms = max(200, int(rem_sec * 1000) + 200)
            self._wait_timer.start(wait_ms)
            self.state_changed.emit(
                self._state,
                f"【防过期等待】当前 2FA 仅剩 {rem_sec}s 即将刷新，正自动顺延等待下一周期新码...",
            )
        elif expiring_soon and now_ts is not None:
            # Deterministic synchronous branch for unit tests with injected timestamp
            self._deliver_final_totp(_next_code or cur_code, is_totp=True, rem_sec=30)
        else:
            self._deliver_final_totp(cur_code, is_totp=True, rem_sec=rem_sec)

    def advance(self, now_ts: Optional[float] = None) -> None:
        """Advance to the next logical step in sequence."""
        if self._account is None or self._state == "IDLE":
            return
        if self._state == "STEP_1_EMAIL":
            self.copy_step_password()
        elif self._state == "STEP_2_PASSWORD":
            self.copy_step_totp(now_ts=now_ts)
        elif self._state in ("STEP_3_TOTP_WAIT", "STEP_3_TOTP_READY", "BURNING"):
            self.cancel(burn_now=True)

    def cancel(self, burn_now: bool = True) -> None:
        self._stop_timers()
        if burn_now:
            self._burn_clipboard_if_matching()
        self._account = None
        self._state = "IDLE"
        self.state_changed.emit("IDLE", "")

    def _on_totp_wait_finished(self) -> None:
        if self._account is None:
            return
        cur_code, rem_sec, _, _ = compute_totp_with_safety(
            self._account.two_fa, min_remaining_sec=3, for_time=time.time()
        )
        final_val = cur_code if cur_code is not None else self._account.two_fa
        self._deliver_final_totp(final_val, is_totp=(cur_code is not None), rem_sec=rem_sec)

    def _deliver_final_totp(self, code_val: str, is_totp: bool, rem_sec: int) -> None:
        if self._account is None:
            return
        self._set_clipboard(code_val)
        self._last_sensitive_value = code_val
        self._state = "BURNING"
        self._burn_timer.start(self.burn_seconds * 1000)
        kind = f"6位动态码 {code_val} (有效 {rem_sec}s)" if is_totp else "静态2FA码"
        self.state_changed.emit(
            self._state,
            f"【上号队列 3/3】「{self._account.name}」{kind} 已复制！将在 {self.burn_seconds}s 后自动阅后即焚清空剪贴板。",
        )

    def _on_burn_timeout(self) -> None:
        burned = self._burn_clipboard_if_matching()
        acc_name = self._account.name if self._account else ""
        self._account = None
        self._state = "IDLE"
        msg = f"已自动清空「{acc_name}」在剪贴板中的敏感凭据。" if burned else ""
        self.state_changed.emit("IDLE", msg)

    def _burn_clipboard_if_matching(self) -> bool:
        if not self._last_sensitive_value:
            return False
        cb = QApplication.clipboard()
        if cb is not None and cb.text() == self._last_sensitive_value:
            cb.clear()
            self._last_sensitive_value = None
            return True
        self._last_sensitive_value = None
        return False

    def _stop_timers(self) -> None:
        if self._wait_timer.isActive():
            self._wait_timer.stop()
        if self._burn_timer.isActive():
            self._burn_timer.stop()

    @staticmethod
    def _set_clipboard(text: str) -> None:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)


_PENDING_TWO_FA_TIMER: Optional[QTimer] = None


def _cancel_pending_two_fa_timer() -> None:
    global _PENDING_TWO_FA_TIMER
    timer = _PENDING_TWO_FA_TIMER
    _PENDING_TWO_FA_TIMER = None
    if timer is not None:
        try:
            if timer.isActive():
                timer.stop()
            timer.deleteLater()
        except RuntimeError:
            pass


def copy_two_fa_with_expiry_guard(
    account: Account,
    on_done: Callable[[str, bool, bool], None],
    min_remaining_sec: int = 3,
    parent: Optional[QObject] = None,
) -> None:
    """
    Copy 2FA for a single click on table row.
    If TOTP remaining <= min_remaining_sec, waits asynchronously for fresh 30s window before copying.
    Callback `on_done(copied_value, is_totp, waited_for_next_window)`.
    """
    global _PENDING_TWO_FA_TIMER
    _cancel_pending_two_fa_timer()

    cur_code, rem_sec, _, expiring_soon = compute_totp_with_safety(
        account.two_fa, min_remaining_sec=min_remaining_sec
    )
    cb = QApplication.clipboard()
    if cur_code is None:
        if cb is not None:
            cb.setText(account.two_fa)
        on_done(account.two_fa, False, False)
        return

    if not expiring_soon:
        if cb is not None:
            cb.setText(cur_code)
        on_done(cur_code, True, False)
        return

    wait_ms = max(200, int(rem_sec * 1000) + 200)
    timer = QTimer(parent)
    timer.setSingleShot(True)
    _PENDING_TWO_FA_TIMER = timer

    def _delayed() -> None:
        global _PENDING_TWO_FA_TIMER
        if _PENDING_TWO_FA_TIMER is timer:
            _PENDING_TWO_FA_TIMER = None
        fresh_code, _, _, _ = compute_totp_with_safety(account.two_fa, min_remaining_sec=1)
        val = fresh_code or cur_code
        if cb is not None:
            cb.setText(val)
        on_done(val, True, True)
        try:
            timer.deleteLater()
        except RuntimeError:
            pass

    timer.timeout.connect(_delayed)
    timer.start(wait_ms)
