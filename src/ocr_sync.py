"""
Offline Windows WinRT OCR quota parser and local ~/.codex/auth.json credential switcher.
Zero external network requests; zero third-party OCR heavy dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.security import DPAPI_PREFIX, SecurityError, dpapi_decrypt, dpapi_encrypt


@dataclass
class OcrQuotaResult:
    raw_text: str
    five_hour_quota: Optional[int] = None
    weekly_quota: Optional[int] = None
    weekly_reset_seconds: Optional[int] = None
    five_hour_was_used_mode: bool = False
    weekly_was_used_mode: bool = False

    @property
    def has_any_value(self) -> bool:
        return (
            self.five_hour_quota is not None
            or self.weekly_quota is not None
            or self.weekly_reset_seconds is not None
        )


def run_windows_ocr(image_path: Path, lang_tag: str = "") -> str:
    """
    Execute native Windows 10/11 WinRT `Windows.Media.Ocr.OcrEngine` on a local image file.
    Returns UTF-8 recognized text lines.
    """
    if sys.platform != "win32":
        raise RuntimeError("离线原生 OCR 仅支持 Windows 10/11 系统")
    img_file = Path(image_path).resolve()
    if not img_file.exists() or img_file.stat().st_size == 0:
        raise FileNotFoundError(f"待识别截图文件不存在或为空: {img_file}")

    escaped_path = str(img_file).replace("'", "''")
    escaped_lang = (lang_tag or "").strip().replace("'", "")

    ps_script = f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Runtime.WindowsRuntime

$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
}})[0]

function Await-WinRT($WinRtTask, $ResultType) {{
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}}

[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Globalization.Language, Windows.Globalization, ContentType = WindowsRuntime] | Out-Null

$file = Await-WinRT ([Windows.Storage.StorageFile]::GetFileFromPathAsync('{escaped_path}')) ([Windows.Storage.StorageFile])
$stream = Await-WinRT ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
try {{
    $decoder = Await-WinRT ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await-WinRT ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

    $engine = $null
    if ('{escaped_lang}' -ne '') {{
        try {{
            $langObj = New-Object Windows.Globalization.Language('{escaped_lang}')
            if ([Windows.Media.Ocr.OcrEngine]::IsLanguageSupported($langObj)) {{
                $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($langObj)
            }}
        }} catch {{
            $engine = $null
        }}
    }}
    if ($null -eq $engine) {{
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    }}
    if ($null -eq $engine) {{
        $avail = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages
        if ($avail.Count -gt 0) {{
            $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($avail[0])
        }}
    }}
    if ($null -eq $engine) {{
        throw '系统未安装可用的 Windows OCR 语言包'
    }}

    $result = Await-WinRT ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
    foreach ($line in $result.Lines) {{
        Write-Output $line.Text
    }}
}} finally {{
    if ($null -ne $stream) {{ $stream.Dispose() }}
}}
"""
    startupinfo = None
    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        startupinfo=startupinfo,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    if proc.returncode != 0:
        err_detail = (proc.stderr or proc.stdout or "未知 WinRT OCR 错误").strip()
        raise RuntimeError(f"Windows 原生 OCR 识别失败: {err_detail}")

    return proc.stdout.strip()


_USED_KEYWORDS = re.compile(
    r"(?:u\s*s\s*e\s*d|c\s*o\s*n\s*s\s*u\s*m\s*e\s*d|已\s*使\s*用|已\s*用|消\s*耗)",
    re.IGNORECASE,
)
_LEFT_KEYWORDS = re.compile(
    r"(?:l\s*e\s*f\s*t|r\s*e\s*m\s*a\s*i\s*n\s*i\s*n\s*g|a\s*v\s*a\s*i\s*l\s*a\s*b\s*l\s*e|剩\s*余|可\s*用|还\s*剩)",
    re.IGNORECASE,
)
_FIVE_H_ANCHOR = re.compile(
    r"(?:(?<!\d)(?<!\dd)(?<!\dd\s)(?<!day\s)(?<!days\s)(?<!天)(?<!天\s)(?<!in\s)"
    r"(?:5\s*[-–]?\s*(?:h|hr|hrs|h\s*o\s*u\s*r\s*s?)(?![a-zA-Z])|5\s*小\s*时)|"
    r"五\s*小\s*时|c\s*u\s*r\s*r\s*e\s*n\s*t\s*s\s*e\s*s\s*s\s*i\s*o\s*n|当前会话|短期额度)",
    re.IGNORECASE,
)
_WEEKLY_ANCHOR = re.compile(
    r"(?:w\s*e\s*e\s*k(?:\s*l\s*y)?|(?<!\d)7\s*[-–]?\s*d\s*a\s*y\s*s?|(?<!\d)7\s*[-–]?\s*d(?![a-zA-Z])|"
    r"周\s*额\s*度|每\s*周|周\s*限\s*额|周\s*剩\s*余|a\s*l\s*l\s*m\s*o\s*d\s*e\s*l\s*s)",
    re.IGNORECASE,
)
_PCT_PATTERN = re.compile(r"(?<![\d.\-])(100|[1-9]?\d)(?:\.\d+)?\s*%")


def _normalize_ocr_spacing(text: str) -> str:
    """Normalize full-width characters (e.g., ％ -> %) and fix CJK OCR spacing artifacts."""
    cleaned = unicodedata.normalize("NFKC", text)
    cleaned = re.sub(r"(?<=[\u4e00-\u9fff])[ \t]+(?=[\u4e00-\u9fff])", "", cleaned)
    cleaned = re.sub(r"(\d)\s+%", r"\1%", cleaned)
    return cleaned


_RESET_5H_SANITIZE_RE = re.compile(
    r"(?:"
    r"(?:resets?|refresh(?:es)?)\s*(?:in\b)?\s*(?:\d{1,2}\s*(?:days?|d|hours?|hrs?|hr|h|minutes?|mins?|m)\s*,?\s*)+|"
    r"(?<!\d)\d{1,2}\s*(?:days?|d|天)\s*,?\s*\d{1,3}\s*(?:hours?|hrs?|hr|h|小时)|"
    r"(?:\d{1,2}\s*(?:天|小时|时|分钟|分)\s*)+后\s*(?:重置|刷新|恢复)|"
    r"(?:重置|刷新)\s*(?:倒计时)?\s*(?:\d{1,2}\s*(?:天|小时|时|分钟|分)\s*)+"
    r")",
    re.IGNORECASE,
)


def _strip_reset_clauses_for_anchor(line: str, anchor_re: re.Pattern[str]) -> str:
    if anchor_re is _FIVE_H_ANCHOR:
        return _RESET_5H_SANITIZE_RE.sub(" ", line)
    return line


def _extract_pct_near_anchor(
    lines: list[str],
    anchor_re: re.Pattern[str],
    other_anchor_re: re.Pattern[str],
) -> tuple[Optional[int], bool, int]:
    """
    Locate percentage on the anchor line first; only inspect subsequent lines until
    another section anchor appears, preventing cross-line keyword contamination.
    """
    for idx, line in enumerate(lines):
        if anchor_re.search(_strip_reset_clauses_for_anchor(line, anchor_re)):
            scoped_lines = [line]
            if not _PCT_PATTERN.search(line):
                for next_i in range(idx + 1, min(len(lines), idx + 3)):
                    if other_anchor_re.search(_strip_reset_clauses_for_anchor(lines[next_i], other_anchor_re)):
                        break
                    scoped_lines.append(lines[next_i])
                    if _PCT_PATTERN.search(lines[next_i]):
                        break
            window_text = " ".join(scoped_lines)
            pct_match = _PCT_PATTERN.search(window_text)
            if pct_match:
                raw_val = int(pct_match.group(1))
                is_used = bool(_USED_KEYWORDS.search(window_text)) and not bool(
                    _LEFT_KEYWORDS.search(window_text)
                )
                rem_val = max(0, min(100, 100 - raw_val)) if is_used else max(0, min(100, raw_val))
                return rem_val, is_used, idx
    return None, False, -1


def _parse_duration_seconds(text: str) -> Optional[int]:
    """
    Parse reset duration strings like:
    - `2d 5h 30m`, `3 days 12 hours`, `14h 25m`
    - `2天 05:12:00`, `2天5小时30分`, `18小时20分钟`
    """
    # Strip wall-clock times (e.g., "at 14:30", "@ 14:30", "Resets 14:30", "重置 14:30") so they are not misread as countdowns
    no_wallclock = re.sub(
        r"(?:\b(?:at|on)\b|@|于)\s*(?:[A-Za-z]+\s+\d{1,2}\s*(?:at\s+)?)?\d{1,2}:\d{2}(?::\d{2})?(?:\s*(?:AM|PM))?",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    no_wallclock = re.sub(
        r"(?:\b(?:resets?|refresh(?:es)?)\b|重置|刷新)\s*(?:[A-Za-z]+\s+\d{1,2}\s*)?\d{1,2}:\d{2}(?:\s*(?:AM|PM))?(?!:\d{2})",
        " ",
        no_wallclock,
        flags=re.IGNORECASE,
    )

    # Pattern 1: X天 HH:MM(:SS)
    m_clock = re.search(
        r"(?:(\d{1,2})\s*(?:天|d|days?)\s*)?(\d{1,2}):(\d{2})(?::(\d{2}))?",
        no_wallclock,
        re.IGNORECASE,
    )
    if m_clock:
        d = int(m_clock.group(1) or 0)
        h = int(m_clock.group(2) or 0)
        m = int(m_clock.group(3) or 0)
        s = int(m_clock.group(4) or 0)
        total = d * 86400 + h * 3600 + m * 60 + s
        if 0 < total <= 31 * 86400:
            return total

    # Pattern 2: English / Chinese explicit units (days / hours / minutes)
    # Guard against matching "5-hour limit", "7d quota", or bare "5h 80% left" headers as reset durations,
    # without erasing legitimate durations like "2d 5h 30m"!
    cleaned_for_units = re.sub(
        r"(?<!\d)(?:"
        r"5\s*[-–]\s*(?:h|hr|hrs|hour|hours)|"
        r"7\s*[-–]\s*(?:d|day|days)|"
        r"(?:5\s*(?:h|hr|hrs|hour|hours|小时)|7\s*(?:d|day|days|天))\s*(?:limit|quota|window|left|remaining|used|available|额度|窗口|限制|剩余|已用|:|：)|"
        r"(?<!\dd)(?<!\dd\s)(?:5[ \t]*h|7[ \t]*d)(?=[ \t]*\d+(?:\.\d+)?[ \t]*%)"
        r")",
        " ",
        no_wallclock,
        flags=re.IGNORECASE,
    )
    days_m = re.search(r"(\d{1,2})\s*(?:days?|d\b|天)", cleaned_for_units, re.IGNORECASE)
    hours_m = re.search(r"(\d{1,3})\s*(?:hours?|hrs?|h\b|小时|时)", cleaned_for_units, re.IGNORECASE)
    mins_m = re.search(r"(\d{1,2})\s*(?:minutes?|mins?|m\b|分钟|分)", cleaned_for_units, re.IGNORECASE)

    if days_m or hours_m or mins_m:
        d = int(days_m.group(1)) if days_m else 0
        h = int(hours_m.group(1)) if hours_m else 0
        m = int(mins_m.group(1)) if mins_m else 0
        total = d * 86400 + h * 3600 + m * 60
        if 0 < total <= 31 * 86400:
            return total

    return None


def parse_quota_from_ocr_text(raw_text: str) -> OcrQuotaResult:
    """
    Deterministically extract 5h remaining %, weekly remaining %, and weekly reset countdown
    from raw OCR text across ChatGPT / Codex / Claude usage screens.
    """
    if not isinstance(raw_text, str) or not raw_text.strip():
        return OcrQuotaResult(raw_text="")

    normalized = _normalize_ocr_spacing(raw_text)
    lines = [ln.strip() for ln in normalized.splitlines() if ln.strip()]

    five_q, five_used, _five_idx = _extract_pct_near_anchor(lines, _FIVE_H_ANCHOR, _WEEKLY_ANCHOR)
    week_q, week_used, week_idx = _extract_pct_near_anchor(lines, _WEEKLY_ANCHOR, _FIVE_H_ANCHOR)

    # Fallback: if two standalone percentages appear in standard top-down order (5h first, weekly second)
    if five_q is None and week_q is None:
        all_pcts = list(_PCT_PATTERN.finditer(normalized))
        is_global_used = bool(_USED_KEYWORDS.search(normalized)) and not bool(
            _LEFT_KEYWORDS.search(normalized)
        )
        if len(all_pcts) >= 2:
            v1 = int(all_pcts[0].group(1))
            v2 = int(all_pcts[1].group(1))
            five_q = (100 - v1) if is_global_used else v1
            week_q = (100 - v2) if is_global_used else v2
            five_used = is_global_used
            week_used = is_global_used
        elif len(all_pcts) == 1:
            v1 = int(all_pcts[0].group(1))
            five_q = (100 - v1) if is_global_used else v1
            five_used = is_global_used

    # Extract weekly reset duration: prefer searching from weekly anchor onwards (stopping before any later 5h section)
    weekly_sec: Optional[int] = None
    if week_idx >= 0:
        tail_lines = []
        for ln in lines[week_idx : min(len(lines), week_idx + 4)]:
            if tail_lines and _FIVE_H_ANCHOR.search(_strip_reset_clauses_for_anchor(ln, _FIVE_H_ANCHOR)):
                break
            tail_lines.append(ln)
        tail_text = "\n".join(tail_lines)
        weekly_sec = _parse_duration_seconds(tail_text)

    if weekly_sec is None:
        # Search lines containing reset keywords or multi-day durations without stealing 5h countdowns
        scan_lines = []
        if week_idx >= 0:
            for ln in lines[week_idx:]:
                if scan_lines and _FIVE_H_ANCHOR.search(_strip_reset_clauses_for_anchor(ln, _FIVE_H_ANCHOR)):
                    break
                scan_lines.append(ln)
        else:
            scan_lines = lines
        for ln in scan_lines:
            if re.search(r"(?:reset|refresh|重置|刷新|后恢复|天\s*\d|\d+\s*(?:days?|d\b))", ln, re.IGNORECASE):
                cand = _parse_duration_seconds(ln)
                has_day_unit = bool(re.search(r"\d+\s*(?:days?|d\b|天)", ln, re.IGNORECASE))
                if cand is not None and (cand > FIVE_HOURS_FALLBACK_THRESHOLD or week_idx >= 0 or has_day_unit):
                    weekly_sec = cand
                    break

    return OcrQuotaResult(
        raw_text=normalized,
        five_hour_quota=five_q,
        weekly_quota=week_q,
        weekly_reset_seconds=weekly_sec,
        five_hour_was_used_mode=five_used,
        weekly_was_used_mode=week_used,
    )


FIVE_HOURS_FALLBACK_THRESHOLD = 5 * 3600


class CodexAuthManager:
    """
    Manage DPAPI-encrypted snapshots of `~/.codex/auth.json` per account and switch atomically.
    """

    def __init__(self, vault_dir: Path, codex_home: Optional[Path] = None) -> None:
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.codex_dir = codex_home if codex_home is not None else (Path.home() / ".codex")
        self.auth_file = self.codex_dir / "auth.json"

    def snapshot_path(self, account_id: str) -> Path:
        if not isinstance(account_id, str) or not account_id.strip():
            raise ValueError("非法的 account_id")
        safe_id = re.sub(r"[^A-Za-z0-9_\-]", "", account_id)
        if safe_id == account_id and safe_id:
            return self.vault_dir / f"{safe_id}.codex.enc"
        digest = hashlib.sha256(account_id.encode("utf-8")).hexdigest()[:8]
        prefix = safe_id if safe_id else "id"
        return self.vault_dir / f"{prefix}_{digest}.codex.enc"

    def has_snapshot(self, account_id: str) -> bool:
        return self.snapshot_path(account_id).exists()

    def capture_current_auth(self, account_id: str, source_path: Optional[Path] = None) -> Path:
        """Read current `~/.codex/auth.json` (or custom file), validate JSON, and store DPAPI-encrypted."""
        src = source_path if source_path is not None else self.auth_file
        if not src.exists():
            raise FileNotFoundError(f"未找到本地 Codex 授权文件: {src}")
        content = src.read_text(encoding="utf-8-sig").strip()
        if not content:
            raise ValueError("Codex 授权文件内容为空")
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("Codex 授权文件顶层必须是 JSON 对象")

        enc_token = dpapi_encrypt(content)
        dest = self.snapshot_path(account_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="codex_snap_", suffix=".tmp", dir=str(dest.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(enc_token)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, dest)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        return dest

    def activate_snapshot(self, account_id: str) -> Path:
        """Decrypt account's Codex snapshot and atomically write into `~/.codex/auth.json`."""
        snap = self.snapshot_path(account_id)
        if not snap.exists():
            raise FileNotFoundError("该账号尚未绑定本地 Codex CLI 授权快照")

        raw = snap.read_text(encoding="utf-8").strip()
        if not raw.startswith(DPAPI_PREFIX):
            raise SecurityError("Codex 授权快照未加密或格式非法")
        plain_json = dpapi_decrypt(raw)
        # Verify valid JSON object before writing
        parsed = json.loads(plain_json)
        if not isinstance(parsed, dict):
            raise ValueError("Codex 授权快照顶层必须是 JSON 对象")

        self.codex_dir.mkdir(parents=True, exist_ok=True)
        if self.auth_file.exists():
            bak_file = self.codex_dir / "auth.json.bak"
            shutil.copy2(self.auth_file, bak_file)

        fd, tmp_path = tempfile.mkstemp(prefix="codex_auth_", suffix=".tmp", dir=str(self.codex_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(plain_json)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.auth_file)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        return self.auth_file
