from __future__ import annotations

import base64
import subprocess
import sys


def _encode_ps_utf8_b64(text: str) -> str:
    return base64.b64encode((text or "").encode("utf-8")).decode("ascii")


def send_windows_toast(title: str, message: str, app_id: str = "GPT账号额度管理助手") -> bool:
    """
    Send native Windows 10/11 Toast Notification via WinRT API without third-party dependencies.
    Works even when the GUI window is completely closed or running in background task mode.
    """
    if sys.platform != "win32":
        return False

    title_b64 = _encode_ps_utf8_b64(title)
    msg_b64 = _encode_ps_utf8_b64(message)
    app_id_b64 = _encode_ps_utf8_b64(app_id)

    ps_script = f"""
    try {{
        $titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{title_b64}'))
        $msgText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{msg_b64}'))
        $appIdText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{app_id_b64}'))
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode($titleText)) | Out-Null
        $textNodes.Item(1).AppendChild($template.CreateTextNode($msgText)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appIdText).Show($toast)
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
