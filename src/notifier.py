from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


def send_windows_toast(title: str, message: str, app_id: str = "GPT账号额度管理助手") -> bool:
    """
    Send native Windows 10/11 Toast Notification via WinRT API without third-party dependencies.
    Works even when the GUI window is completely closed or running in background task mode.
    """
    if sys.platform != "win32":
        return False

    clean_title = title.replace('"', '""').replace("`", "``")
    clean_msg = message.replace('"', '""').replace("`", "``")
    clean_app_id = app_id.replace('"', '""')

    ps_script = f"""
    try {{
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode("{clean_title}")) | Out-Null
        $textNodes.Item(1).AppendChild($template.CreateTextNode("{clean_msg}")) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("{clean_app_id}").Show($toast)
    }} catch {{
        exit 1
    }}
    """
    try:
        startupinfo = None
        if hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=8,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return proc.returncode == 0
    except Exception:
        return False
