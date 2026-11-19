from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMessageBox

from src.main_window import MainWindow
from src.storage import AccountStorage
from src.ui_styles import build_stylesheet


def _resolve_resource(rel_path: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / rel_path


def run_background_notification_check(storage: Optional[AccountStorage] = None) -> int:
    """
    Called by Windows Task Scheduler in the background (no GUI window).
    Silently loads DPAPI-protected data, checks expiring weekly quotas and expiring warranties,
    sends native Windows Toast notifications if needed.
    """
    import time
    from src.models import (
        check_warranty_expiring_accounts,
        check_weekly_expiring_accounts,
        format_duration,
    )
    from src.notifier import send_windows_toast

    if storage is None:
        storage = AccountStorage()
    try:
        settings = storage.load_settings(strict=True)
    except Exception as exc:
        try:
            storage.logger.log("ERROR", "BG_NOTIFY_SETTINGS_ERROR", f"后台提醒加载设置失败: {exc}")
        except Exception:
            pass
        if sys.stderr is not None:
            try:
                print(f"[check-notify] failed to load settings: {exc}", file=sys.stderr)
            except Exception:
                pass
        return 1

    if not settings.notify_enabled and not settings.warranty_notify_enabled:
        return 0

    try:
        accounts = storage.load_accounts()
    except Exception as exc:
        try:
            storage.logger.log("ERROR", "BG_NOTIFY_LOAD_ERROR", f"后台提醒加载账号数据失败: {exc}")
        except Exception:
            pass
        if sys.stderr is not None:
            try:
                print(f"[check-notify] failed to load accounts: {exc}", file=sys.stderr)
            except Exception:
                pass
        return 1

    now = time.time()
    dirty = False

    if settings.notify_enabled:
        expiring = check_weekly_expiring_accounts(
            accounts,
            quota_threshold=settings.notify_quota_threshold,
            hours_threshold=settings.notify_hours_threshold,
            now_ts=now,
        )
        for acc in expiring:
            rem_str = format_duration(acc.weekly_remaining_seconds(now) or 0)
            title = f"{acc.provider} 账号周额度即将刷新提醒"
            msg = f"账号「{acc.name}」周额度还剩 {acc.weekly_quota}%，将在 {rem_str} 后重置，请及时使用！"
            if send_windows_toast(title, msg):
                acc.weekly_notified_reset_at = acc.weekly_reset_at
                storage.logger.log("WARN", "BG_WEEKLY_EXPIRING_NOTIFICATION", msg, f"{acc.name} ({acc.email})")
                dirty = True
            else:
                storage.logger.log("ERROR", "BG_TOAST_SEND_FAILED", f"周额度提醒弹窗发送失败: {title}", f"{acc.name} ({acc.email})")

    if settings.warranty_notify_enabled:
        w_expiring = check_warranty_expiring_accounts(
            accounts,
            hours_threshold=settings.warranty_notify_hours,
            now_ts=now,
        )
        for acc in w_expiring:
            rem_str = format_duration(acc.warranty_remaining_seconds(now) or 0)
            title = "外购账号质保即将到期验号提醒"
            msg = f"账号「{acc.name}」({acc.vendor_tag or '外购'}) 质保仅剩 {rem_str}，请尽快验号排查封禁！"
            if send_windows_toast(title, msg):
                acc.warranty_notified_at = acc.warranty_expire_at
                storage.logger.log("WARN", "BG_WARRANTY_EXPIRING_NOTIFICATION", msg, f"{acc.name} ({acc.email})")
                dirty = True
            else:
                storage.logger.log("ERROR", "BG_TOAST_SEND_FAILED", f"质保提醒弹窗发送失败: {title}", f"{acc.name} ({acc.email})")

    if dirty:
        storage.save_accounts(accounts)
    return 0


def main() -> int:
    if "--check-notify" in sys.argv:
        return run_background_notification_check()

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("GPT账号额度管理助手")

    storage = AccountStorage()
    initial_theme = storage.load_theme()
    app.setStyleSheet(build_stylesheet(initial_theme))

    icon_path = _resolve_resource("assets/app.ico")
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    def excepthook(exc_type, exc_value, exc_tb) -> None:
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            storage.logger.log("ERROR", "UNCAUGHT_EXCEPTION", details)
        except Exception:
            pass
        QMessageBox.critical(None, "未捕获异常", f"程序遇到异常：\n{exc_value}\n\n详情已写入日志。")

    sys.excepthook = excepthook

    window = MainWindow(storage, initial_theme=initial_theme)
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
