from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import struct
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

FIVE_HOURS_SECONDS = 5 * 3600
DEFAULT_WEEKLY_HOURS = 168.0
MAX_QUOTA = 100
MIN_QUOTA = 0

VALID_PROVIDERS: Tuple[str, ...] = ("ChatGPT", "Claude", "Codex", "Custom")
PROVIDER_DEFAULT_URLS: Dict[str, str] = {
    "ChatGPT": "https://chatgpt.com/",
    "Claude": "https://claude.ai/",
    "Codex": "https://chatgpt.com/codex",
    "Custom": "https://chatgpt.com/",
}

VALID_HEALTH_STATUSES: Tuple[str, ...] = (
    "ACTIVE",
    "DEGRADED_POW",
    "PHONE_VERIFY",
    "BANNED",
)
HEALTH_STATUS_LABELS: Dict[str, str] = {
    "ACTIVE": "正常可用",
    "DEGRADED_POW": "疑似降智",
    "PHONE_VERIFY": "待接码",
    "BANNED": "已封禁",
}

_FOUR_DASH_PATTERN = re.compile(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"\s*(?:-{2,}|—{1,})\s*"
    r"([^\r\n]+?)"
    r"\s*(?:-{2,}|—{1,})\s*"
    r"([A-Za-z0-9=]+)"
)

_ALT_DELIM_PATTERN = re.compile(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"\s*(?:\||\t|:)\s*"
    r"([^\r\n|\t:]+?)"
    r"\s*(?:\||\t|:)\s*"
    r"([A-Za-z0-9=]+)"
)


@dataclass
class ParsedAccount:
    suggested_name: str
    email: str
    password: str
    two_fa: str


def parse_accounts_from_text(raw_text: str) -> List[ParsedAccount]:
    """
    Extract account tuples (email, password, 2FA) from free-form text blocks.
    Supports `email----password----2fa` (primary), `|` / tab / `:` delimiters,
    and single-record labeled fallback (`邮箱:`, `密码:`, `2FA:`).
    Preserves original character order in text and deduplicates identical (email, 2fa).
    """
    if not isinstance(raw_text, str):
        return []
    text = raw_text.strip()
    if not text:
        return []

    seen_keys: set[Tuple[str, str]] = set()
    raw_matches: List[Tuple[int, ParsedAccount]] = []

    for pattern in (_FOUR_DASH_PATTERN, _ALT_DELIM_PATTERN):
        for match in pattern.finditer(text):
            email = match.group(1).strip()
            password = match.group(2).strip()
            two_fa = match.group(3).strip()
            if not email or not password or not two_fa:
                continue
            dedup_key = (email.lower(), two_fa)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            suggested = email.split("@", 1)[0]
            raw_matches.append(
                (
                    match.start(),
                    ParsedAccount(
                        suggested_name=suggested,
                        email=email,
                        password=password,
                        two_fa=two_fa,
                    ),
                )
            )

    if raw_matches:
        raw_matches.sort(key=lambda item: item[0])
        return [item[1] for item in raw_matches]

    # Fallback: labeled lines for a single account
    email_m = re.search(
        r"(?:邮箱|账号|email|account)\s*[:：]\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
        text,
        re.IGNORECASE,
    )
    pwd_m = re.search(
        r"(?:密码|pass(?:word)?)\s*[:：]\s*([^\s\r\n]+)",
        text,
        re.IGNORECASE,
    )
    tfa_m = re.search(
        r"(?:2fa(?:\s*初始验证码|\s*验证码|\s*密钥)?|totp|secret)\s*[:：]\s*([A-Za-z0-9=]+)",
        text,
        re.IGNORECASE,
    )
    if email_m and pwd_m and tfa_m:
        email = email_m.group(1).strip()
        return [
            ParsedAccount(
                suggested_name=email.split("@", 1)[0],
                email=email,
                password=pwd_m.group(1).strip(),
                two_fa=tfa_m.group(1).strip(),
            )
        ]

    return []


def validate_quota(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} 必须是整数，实际为: {type(value).__name__}")
    if value < MIN_QUOTA or value > MAX_QUOTA:
        raise ValueError(f"{field_name} 必须在 {MIN_QUOTA} 到 {MAX_QUOTA} 之间，实际为: {value}")
    return value


def validate_provider(provider: Optional[str]) -> str:
    clean = (provider or "").strip() or "ChatGPT"
    for p in VALID_PROVIDERS:
        if p.lower() == clean.lower():
            return p
    raise ValueError(f"不支持的平台类型: {provider!r}，可选值: {', '.join(VALID_PROVIDERS)}")


def validate_health_status(status: str) -> str:
    clean = (status or "ACTIVE").strip().upper()
    if clean not in VALID_HEALTH_STATUSES:
        raise ValueError(f"不支持的健康状态: {status!r}，可选值: {', '.join(VALID_HEALTH_STATUSES)}")
    return clean


def validate_proxy_url(proxy_url: str) -> str:
    """
    Validate browser proxy URL and strictly block command-line flag injection or whitespace.
    Allowed schemes: http, https, socks5, socks5h, socks4.
    """
    clean = (proxy_url or "").strip()
    if not clean:
        return ""
    if any(ch.isspace() or ch in ('"', "'", ";", "|", "&", "`", ",", "\x00") for ch in clean):
        raise ValueError("代理地址包含非法空白或特殊控制字符")
    if clean.startswith("-"):
        raise ValueError("代理地址格式非法：禁止以连字符开头")
    parsed = urllib.parse.urlparse(clean)
    if parsed.scheme.lower() not in ("http", "https", "socks5", "socks5h", "socks4"):
        raise ValueError("代理地址必须以 http://, https:// 或 socks5:// 开头")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("代理地址主机名或端口号无效") from exc
    if not hostname:
        raise ValueError("代理地址缺少有效的主机名或 IP")
    if port is not None and (port < 1 or port > 65535):
        raise ValueError("代理端口号必须在 1~65535 之间")
    return clean


def validate_price(price: float) -> float:
    if isinstance(price, bool) or not isinstance(price, (int, float)):
        raise ValueError("购入单价必须为数值")
    val = float(price)
    if math.isnan(val) or math.isinf(val) or val < 0.0:
        raise ValueError("购入单价必须为大于等于 0 的有限实数")
    if val > 1_000_000.0:
        raise ValueError("购入单价超出合理上限 (1,000,000)")
    return round(val, 2)


def _decode_totp_key(secret_or_code: str) -> Optional[bytes]:
    if not isinstance(secret_or_code, str):
        return None
    cleaned = "".join(secret_or_code.strip().split()).upper()
    if len(cleaned) < 16:
        return None
    base32_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    if not set(cleaned).issubset(base32_chars):
        return None
    try:
        padded = cleaned + ("=" * ((8 - len(cleaned) % 8) % 8))
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None
    if len(key) < 10:
        return None
    return key


def _hotp_at_counter(key: bytes, counter: int) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def compute_totp(secret_or_code: str, for_time: Optional[float] = None) -> Tuple[Optional[str], int]:
    """
    If `secret_or_code` is a valid Base32 TOTP secret (>= 16 base32 chars),
    returns (6-digit TOTP code, remaining seconds in 30s window).
    Otherwise returns (None, 0) indicating a static initial/recovery code.
    """
    if for_time is not None and (
        isinstance(for_time, bool)
        or not isinstance(for_time, (int, float))
        or math.isnan(for_time)
        or math.isinf(for_time)
    ):
        raise ValueError("for_time 必须为有限实数")
    key = _decode_totp_key(secret_or_code)
    if key is None:
        return None, 0
    now = time.time() if for_time is None else float(for_time)
    timestep = 30
    counter = int(now // timestep)
    remaining = timestep - int(now % timestep)
    return _hotp_at_counter(key, counter), remaining


def compute_totp_with_safety(
    secret_or_code: str,
    min_remaining_sec: int = 3,
    for_time: Optional[float] = None,
) -> Tuple[Optional[str], int, Optional[str], bool]:
    """
    Compute current TOTP and also next-window TOTP when remaining time <= min_remaining_sec.
    Returns (current_code, remaining_sec, next_window_code, is_expiring_soon).
    """
    if for_time is not None and (
        isinstance(for_time, bool)
        or not isinstance(for_time, (int, float))
        or math.isnan(for_time)
        or math.isinf(for_time)
    ):
        raise ValueError("for_time 必须为有限实数")
    key = _decode_totp_key(secret_or_code)
    if key is None:
        return None, 0, None, False
    now = time.time() if for_time is None else float(for_time)
    timestep = 30
    counter = int(now // timestep)
    remaining = timestep - int(now % timestep)
    cur_code = _hotp_at_counter(key, counter)
    next_code = _hotp_at_counter(key, counter + 1)
    is_expiring_soon = remaining <= max(1, int(min_remaining_sec))
    return cur_code, remaining, next_code, is_expiring_soon


def format_duration(seconds: float) -> str:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or math.isnan(seconds) or math.isinf(seconds):
        return "--:--:--"
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}天 {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


@dataclass
class Account:
    id: str
    name: str
    email: str
    password: str
    two_fa: str
    five_hour_quota: int = MAX_QUOTA
    five_hour_reset_at: Optional[float] = None
    weekly_quota: int = MAX_QUOTA
    weekly_reset_at: Optional[float] = None
    weekly_notified_reset_at: Optional[float] = None
    provider: str = "ChatGPT"
    proxy_url: str = ""
    purchase_price: float = 0.0
    warranty_expire_at: Optional[float] = None
    warranty_notified_at: Optional[float] = None
    vendor_tag: str = ""
    health_status: str = "ACTIVE"
    usage_5h_count: int = 0
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        self.email = self.email.strip()
        if not self.name:
            raise ValueError("账号名称不能为空")
        if not self.email:
            raise ValueError("账号邮箱不能为空")
        if not self.password:
            raise ValueError("账号密码不能为空")
        self.two_fa = self.two_fa.strip()
        if not self.two_fa:
            raise ValueError("2FA初始验证码/密钥不能为空")
        self.five_hour_quota = validate_quota(self.five_hour_quota, "5h额度")
        self.weekly_quota = validate_quota(self.weekly_quota, "周额度")
        self.provider = validate_provider(self.provider)
        self.proxy_url = validate_proxy_url(self.proxy_url)
        self.purchase_price = validate_price(self.purchase_price)
        self.health_status = validate_health_status(self.health_status)
        self.vendor_tag = (self.vendor_tag or "").strip()
        self.notes = (self.notes or "").strip()
        if isinstance(self.usage_5h_count, bool) or not isinstance(self.usage_5h_count, int) or self.usage_5h_count < 0:
            raise ValueError("累计 5h 使用次数必须为非负整数")
        if self.warranty_expire_at is not None:
            if (
                isinstance(self.warranty_expire_at, bool)
                or not isinstance(self.warranty_expire_at, (int, float))
                or not math.isfinite(float(self.warranty_expire_at))
            ):
                raise ValueError("质保到期时间戳必须为有限实数")
            self.warranty_expire_at = float(self.warranty_expire_at)

    @classmethod
    def create(
        cls,
        name: str,
        email: str,
        password: str,
        two_fa: str,
        five_hour_quota: int = MAX_QUOTA,
        weekly_quota: int = MAX_QUOTA,
        weekly_reset_duration_seconds: Optional[int] = None,
        provider: str = "ChatGPT",
        proxy_url: str = "",
        purchase_price: float = 0.0,
        warranty_days: Optional[float] = None,
        vendor_tag: str = "",
        health_status: str = "ACTIVE",
        notes: str = "",
        now_ts: Optional[float] = None,
    ) -> "Account":
        now = time.time() if now_ts is None else now_ts
        five_q = validate_quota(five_hour_quota, "5h额度")
        week_q = validate_quota(weekly_quota, "周额度")

        five_reset = (now + FIVE_HOURS_SECONDS) if five_q == 0 else None
        weekly_reset: Optional[float] = None
        if weekly_reset_duration_seconds is not None and weekly_reset_duration_seconds > 0:
            weekly_reset = now + weekly_reset_duration_seconds

        warranty_exp: Optional[float] = None
        if warranty_days is not None:
            if isinstance(warranty_days, bool) or not isinstance(warranty_days, (int, float)):
                raise ValueError("质保天数必须为数值")
            w_days = float(warranty_days)
            if not math.isfinite(w_days) or w_days < 0.0:
                raise ValueError("质保天数必须为非负有限实数")
            if w_days > 0.0:
                warranty_exp = now + w_days * 86400.0

        return cls(
            id=uuid.uuid4().hex,
            name=name,
            email=email,
            password=password,
            two_fa=two_fa,
            five_hour_quota=five_q,
            five_hour_reset_at=five_reset,
            weekly_quota=week_q,
            weekly_reset_at=weekly_reset,
            provider=provider,
            proxy_url=proxy_url,
            purchase_price=purchase_price,
            warranty_expire_at=warranty_exp,
            vendor_tag=vendor_tag,
            health_status=health_status,
            usage_5h_count=1 if five_q == 0 else 0,
            notes=notes,
            created_at=now,
            updated_at=now,
        )

    @property
    def target_url(self) -> str:
        return PROVIDER_DEFAULT_URLS.get(self.provider, "https://chatgpt.com/")

    @property
    def can_start_five_hour_usage(self) -> Tuple[bool, str]:
        """
        Check if 5h countdown can be newly started by user.
        Preconditions:
        1. health_status is not BANNED or PHONE_VERIFY
        2. five_hour_reset_at is None
        3. weekly_quota > 0
        4. five_hour_quota > 0
        """
        if self.health_status == "BANNED":
            return False, "账号状态为「已封禁」，无法开始使用"
        if self.health_status == "PHONE_VERIFY":
            return False, "账号状态为「待接码」，完成验证前无法开始使用"
        if self.five_hour_reset_at is not None:
            return False, "5h 倒计时正在运行中"
        if self.weekly_quota <= 0:
            return False, "周额度已耗尽 (0%)，无法开始使用"
        if self.five_hour_quota <= 0:
            return False, "5h 额度已为 0，正在等待重置"
        return True, "可以开始使用"

    def update_five_hour_quota(
        self,
        new_quota: int,
        clear_timer: bool = False,
        now_ts: Optional[float] = None,
    ) -> List[str]:
        now = time.time() if now_ts is None else now_ts
        new_quota = validate_quota(new_quota, "5h额度")
        events: List[str] = []

        self.five_hour_quota = new_quota
        if clear_timer:
            if self.five_hour_reset_at is not None:
                self.five_hour_reset_at = None
                events.append("CLEAR_5H_COUNTDOWN")
        else:
            if self.five_hour_reset_at is None and new_quota == 0:
                self.five_hour_reset_at = now + FIVE_HOURS_SECONDS
                self.usage_5h_count += 1
                events.append("START_5H_COUNTDOWN")

        self.updated_at = now
        return events

    def start_five_hour_usage(self, now_ts: Optional[float] = None) -> List[str]:
        can_start, reason = self.can_start_five_hour_usage
        if not can_start:
            raise ValueError(reason)

        now = time.time() if now_ts is None else now_ts
        self.five_hour_reset_at = now + FIVE_HOURS_SECONDS
        self.usage_5h_count += 1
        self.updated_at = now
        return ["START_5H_COUNTDOWN"]

    def set_weekly_quota_and_timer(
        self,
        new_quota: int,
        reset_duration_seconds: Optional[int] = None,
        clear_timer: bool = False,
        now_ts: Optional[float] = None,
    ) -> List[str]:
        now = time.time() if now_ts is None else now_ts
        new_quota = validate_quota(new_quota, "周额度")
        events: List[str] = []

        self.weekly_quota = new_quota
        if clear_timer:
            if self.weekly_reset_at is not None:
                self.weekly_reset_at = None
                self.weekly_notified_reset_at = None
                events.append("CLEAR_WEEKLY_COUNTDOWN")
        elif reset_duration_seconds is not None:
            if reset_duration_seconds < 0:
                raise ValueError("周额度剩余重置时间不能为负数")
            if reset_duration_seconds > 0:
                self.weekly_reset_at = now + reset_duration_seconds
                self.weekly_notified_reset_at = None
                events.append("START_WEEKLY_COUNTDOWN")
            else:
                if self.weekly_reset_at is not None:
                    self.weekly_reset_at = None
                    self.weekly_notified_reset_at = None
                    events.append("CLEAR_WEEKLY_COUNTDOWN")

        self.updated_at = now
        return events

    def tick(self, now_ts: Optional[float] = None) -> List[str]:
        now = time.time() if now_ts is None else now_ts
        triggered: List[str] = []

        if self.five_hour_reset_at is not None and now >= self.five_hour_reset_at:
            self.five_hour_quota = MAX_QUOTA
            self.five_hour_reset_at = None
            self.updated_at = now
            triggered.append("AUTO_RESET_5H")

        if self.weekly_reset_at is not None and now >= self.weekly_reset_at:
            self.weekly_quota = MAX_QUOTA
            self.weekly_reset_at = None
            self.weekly_notified_reset_at = None
            self.updated_at = now
            triggered.append("AUTO_RESET_WEEKLY")

        return triggered

    def five_hour_remaining_seconds(self, now_ts: Optional[float] = None) -> Optional[float]:
        if self.five_hour_reset_at is None:
            return None
        now = time.time() if now_ts is None else now_ts
        return max(0.0, self.five_hour_reset_at - now)

    def weekly_remaining_seconds(self, now_ts: Optional[float] = None) -> Optional[float]:
        if self.weekly_reset_at is None:
            return None
        now = time.time() if now_ts is None else now_ts
        return max(0.0, self.weekly_reset_at - now)

    def warranty_remaining_seconds(self, now_ts: Optional[float] = None) -> Optional[float]:
        if self.warranty_expire_at is None:
            return None
        now = time.time() if now_ts is None else now_ts
        return max(0.0, self.warranty_expire_at - now)

    def burn_urgency_score(self, now_ts: Optional[float] = None) -> float:
        """
        Compute Earliest-Expiring Quota First (EEQF) urgency score:
        U_i = (weekly_quota / max(weekly_hours_left, 1.0)) * health_weight
        Returns 0.0 if account cannot be used right now.
        """
        if self.health_status in ("BANNED", "PHONE_VERIFY"):
            return 0.0
        now = time.time() if now_ts is None else now_ts
        eff_5h = MAX_QUOTA if (self.five_hour_reset_at is not None and now >= self.five_hour_reset_at) else self.five_hour_quota
        wk_expired = self.weekly_reset_at is not None and now >= self.weekly_reset_at
        eff_wk = MAX_QUOTA if wk_expired else self.weekly_quota
        if eff_wk <= 0 or eff_5h <= 0:
            return 0.0
        w_rem = None if wk_expired else self.weekly_remaining_seconds(now)
        hours_left = (w_rem / 3600.0) if (w_rem is not None and w_rem > 0) else DEFAULT_WEEKLY_HOURS
        denom = max(hours_left, 1.0)
        health_weight = 1.0 if self.health_status == "ACTIVE" else 0.5
        return (float(eff_wk) / denom) * health_weight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "password": self.password,
            "two_fa": self.two_fa,
            "five_hour_quota": self.five_hour_quota,
            "five_hour_reset_at": self.five_hour_reset_at,
            "weekly_quota": self.weekly_quota,
            "weekly_reset_at": self.weekly_reset_at,
            "weekly_notified_reset_at": self.weekly_notified_reset_at,
            "provider": self.provider,
            "proxy_url": self.proxy_url,
            "purchase_price": self.purchase_price,
            "warranty_expire_at": self.warranty_expire_at,
            "warranty_notified_at": self.warranty_notified_at,
            "vendor_tag": self.vendor_tag,
            "health_status": self.health_status,
            "usage_5h_count": self.usage_5h_count,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def _parse_strict_int(val: Any, field_name: str, default: Optional[int] = None) -> int:
        if val is None:
            if default is not None:
                return default
            raise ValueError(f"{field_name} 不能为空")
        if isinstance(val, bool) or isinstance(val, float):
            raise ValueError(f"{field_name} 必须是整数，实际为: {type(val).__name__}")
        return int(val)

    @staticmethod
    def _parse_finite_float(
        val: Any,
        field_name: str,
        default: Optional[float] = None,
        allow_none: bool = False,
    ) -> Optional[float]:
        if val is None:
            if allow_none:
                return default
            if default is not None:
                return default
            raise ValueError(f"{field_name} 不能为空")
        if isinstance(val, bool):
            raise ValueError(f"{field_name} 不能为布尔值")
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            raise ValueError(f"{field_name} 必须为有限实数")
        return f

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Account":
        now_default = time.time()
        raw_provider = data.get("provider", "ChatGPT")
        raw_health = data.get("health_status", "ACTIVE")
        raw_price = data.get("purchase_price", 0.0)
        if raw_price is None:
            raw_price = 0.0
        if isinstance(raw_price, bool):
            raise ValueError("购入单价不能为布尔值")
        raw_usage = data.get("usage_5h_count", 0)
        usage_val = cls._parse_strict_int(raw_usage, "usage_5h_count", default=0)

        created_val = cls._parse_finite_float(data.get("created_at"), "created_at", default=now_default)
        updated_val = cls._parse_finite_float(data.get("updated_at"), "updated_at", default=now_default)

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            email=str(data["email"]),
            password=str(data["password"]),
            two_fa=str(data["two_fa"]),
            five_hour_quota=cls._parse_strict_int(data["five_hour_quota"], "five_hour_quota"),
            five_hour_reset_at=cls._parse_finite_float(
                data.get("five_hour_reset_at"), "five_hour_reset_at", allow_none=True
            ),
            weekly_quota=cls._parse_strict_int(data["weekly_quota"], "weekly_quota"),
            weekly_reset_at=cls._parse_finite_float(
                data.get("weekly_reset_at"), "weekly_reset_at", allow_none=True
            ),
            weekly_notified_reset_at=cls._parse_finite_float(
                data.get("weekly_notified_reset_at"), "weekly_notified_reset_at", allow_none=True
            ),
            provider="ChatGPT" if raw_provider is None else str(raw_provider),
            proxy_url=str(data.get("proxy_url") or ""),
            purchase_price=float(cls._parse_finite_float(raw_price, "purchase_price", default=0.0) or 0.0),
            warranty_expire_at=cls._parse_finite_float(
                data.get("warranty_expire_at"), "warranty_expire_at", allow_none=True
            ),
            warranty_notified_at=cls._parse_finite_float(
                data.get("warranty_notified_at"), "warranty_notified_at", allow_none=True
            ),
            vendor_tag=str(data.get("vendor_tag") or ""),
            health_status="ACTIVE" if raw_health is None else str(raw_health),
            usage_5h_count=max(0, usage_val),
            notes=str(data.get("notes") or ""),
            created_at=float(now_default if created_val is None else created_val),
            updated_at=float(now_default if updated_val is None else updated_val),
        )


@dataclass
class DispatchRecommendation:
    status: str  # "READY_NEW_5H" | "ACTIVE_WINDOW_REUSE" | "COOLING_DOWN" | "NONE_AVAILABLE"
    account: Optional[Account]
    urgency_score: float
    wait_seconds: Optional[float]
    reason: str


def select_optimal_account(
    accounts: List[Account],
    provider: Optional[str] = None,
    now_ts: Optional[float] = None,
) -> DispatchRecommendation:
    """
    Earliest-Expiring Quota First (EEQF) dual-window scheduler.
    1. Prefer accounts with `five_hour_reset_at is None` and valid balance, ranked by `burn_urgency_score` DESC,
       then `five_hour_quota` DESC, then `created_at` ASC.
    2. Fallback to accounts already inside an active 5h window (`five_hour_reset_at is not None`) that still have
       `five_hour_quota > 0` and `weekly_quota > 0`, ranked by `burn_urgency_score` DESC.
    3. Otherwise compute the earliest recovery wait time across cooling-down healthy accounts.
    """
    now = time.time() if now_ts is None else now_ts
    target_provider: Optional[str] = None
    if provider is not None and provider != "全部平台":
        clean_prov = provider.strip()
        if clean_prov:
            target_provider = validate_provider(clean_prov)

    candidates = [
        a
        for a in accounts
        if (target_provider is None or a.provider.lower() == target_provider.lower())
        and a.health_status in ("ACTIVE", "DEGRADED_POW")
    ]
    if not candidates:
        return DispatchRecommendation(
            status="NONE_AVAILABLE",
            account=None,
            urgency_score=0.0,
            wait_seconds=None,
            reason="当前没有健康可用的账号（列表为空，或全部处于封禁/待接码状态）",
        )

    def _eff(acc: Account) -> Tuple[int, Optional[float], int, Optional[float]]:
        five_exp = acc.five_hour_reset_at is not None and now >= acc.five_hour_reset_at
        eff_5h_q = MAX_QUOTA if five_exp else acc.five_hour_quota
        eff_5h_reset = None if five_exp else acc.five_hour_reset_at
        wk_exp = acc.weekly_reset_at is not None and now >= acc.weekly_reset_at
        eff_wk_q = MAX_QUOTA if wk_exp else acc.weekly_quota
        eff_wk_reset = None if wk_exp else acc.weekly_reset_at
        return eff_5h_q, eff_5h_reset, eff_wk_q, eff_wk_reset

    # Tier 1: Ready to start a fresh 5h window
    fresh_pool = []
    for a in candidates:
        eff_5h_q, eff_5h_reset, eff_wk_q, _eff_wk_reset = _eff(a)
        if eff_5h_reset is None and eff_5h_q > 0 and eff_wk_q > 0:
            fresh_pool.append(a)

    if fresh_pool:
        fresh_pool.sort(
            key=lambda a: (
                -a.burn_urgency_score(now),
                -_eff(a)[0],
                a.created_at,
            )
        )
        best = fresh_pool[0]
        score = best.burn_urgency_score(now)
        eff_wk_q = _eff(best)[2]
        eff_wk_reset = _eff(best)[3]
        w_rem = None if eff_wk_reset is None else best.weekly_remaining_seconds(now)
        w_desc = f"距周刷新剩余 {format_duration(w_rem)}" if w_rem is not None else "未设周倒计时"
        return DispatchRecommendation(
            status="READY_NEW_5H",
            account=best,
            urgency_score=score,
            wait_seconds=0.0,
            reason=f"EEQF 最优派发：周余量 {eff_wk_q}%（{w_desc}），防过期紧急度 {score:.2f}%/h",
        )

    # Tier 2: Already counting down 5h, but still has remaining 5h & weekly quota
    reuse_pool = []
    for a in candidates:
        eff_5h_q, eff_5h_reset, eff_wk_q, _eff_wk_reset = _eff(a)
        if eff_5h_reset is not None and eff_5h_q > 0 and eff_wk_q > 0:
            reuse_pool.append(a)

    if reuse_pool:
        reuse_pool.sort(
            key=lambda a: (
                -a.burn_urgency_score(now),
                -_eff(a)[0],
                _eff(a)[1] or 0.0,
            )
        )
        best = reuse_pool[0]
        score = best.burn_urgency_score(now)
        eff_5h_q = _eff(best)[0]
        rem_5h = best.five_hour_remaining_seconds(now) or 0.0
        return DispatchRecommendation(
            status="ACTIVE_WINDOW_REUSE",
            account=best,
            urgency_score=score,
            wait_seconds=0.0,
            reason=f"复用活跃 5h 会话：当前窗口还剩 {eff_5h_q}% 额度（{format_duration(rem_5h)} 后重置满额）",
        )

    # Tier 3: All exhausted, find earliest recovery timestamp
    earliest_acc: Optional[Account] = None
    earliest_wait: Optional[float] = None

    for a in candidates:
        eff_5h_q, eff_5h_reset, eff_wk_q, eff_wk_reset = _eff(a)
        # Case A: Weekly quota > 0, waiting for 5h reset
        if eff_wk_q > 0 and eff_5h_reset is not None:
            wait = max(0.0, eff_5h_reset - now)
            if earliest_wait is None or wait < earliest_wait:
                earliest_wait = wait
                earliest_acc = a
        # Case B: Weekly quota == 0, waiting for weekly reset
        elif eff_wk_q <= 0 and eff_wk_reset is not None:
            wait = max(0.0, eff_wk_reset - now)
            # Also ensure 5h will be ready or take max of both
            if eff_5h_reset is not None and eff_5h_q <= 0:
                wait = max(wait, max(0.0, eff_5h_reset - now))
            if earliest_wait is None or wait < earliest_wait:
                earliest_wait = wait
                earliest_acc = a

    if earliest_acc is not None and earliest_wait is not None:
        return DispatchRecommendation(
            status="COOLING_DOWN",
            account=earliest_acc,
            urgency_score=0.0,
            wait_seconds=earliest_wait,
            reason=f"全部账号冷却中：最早恢复为「{earliest_acc.name}」，需等待 {format_duration(earliest_wait)}",
        )

    return DispatchRecommendation(
        status="NONE_AVAILABLE",
        account=None,
        urgency_score=0.0,
        wait_seconds=None,
        reason="所有账号周额度或 5h 额度均已耗尽，且未设置重置倒计时",
    )


def check_weekly_expiring_accounts(
    accounts: List[Account],
    quota_threshold: int = 20,
    hours_threshold: int = 24,
    now_ts: Optional[float] = None,
) -> List[Account]:
    now = time.time() if now_ts is None else now_ts
    window_sec = hours_threshold * 3600
    expiring: List[Account] = []
    for acc in accounts:
        if acc.health_status == "BANNED":
            continue
        if acc.weekly_reset_at is None:
            continue
        rem = acc.weekly_remaining_seconds(now)
        if rem is None or rem <= 0:
            continue
        if rem <= window_sec and acc.weekly_quota >= quota_threshold:
            if acc.weekly_notified_reset_at != acc.weekly_reset_at:
                expiring.append(acc)
    return expiring


def check_warranty_expiring_accounts(
    accounts: List[Account],
    hours_threshold: int = 24,
    now_ts: Optional[float] = None,
) -> List[Account]:
    """
    Find non-banned accounts whose warranty period expires within `hours_threshold` hours
    and have not yet been notified for the current `warranty_expire_at`.
    """
    now = time.time() if now_ts is None else now_ts
    window_sec = hours_threshold * 3600
    expiring: List[Account] = []
    for acc in accounts:
        if acc.health_status == "BANNED":
            continue
        if acc.warranty_expire_at is None:
            continue
        rem = acc.warranty_remaining_seconds(now)
        if rem is None or rem <= 0:
            continue
        if rem <= window_sec and acc.warranty_notified_at != acc.warranty_expire_at:
            expiring.append(acc)
    return expiring


def _safe_fmt_date(ts: float) -> str:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or math.isnan(ts) or math.isinf(ts) or ts < 0:
        return "未知日期"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    except (OSError, OverflowError, ValueError):
        return "未知日期"


def format_after_sales_slip(accounts: List[Account], now_ts: Optional[float] = None) -> str:
    """
    Generate formatted after-sales claim text for BANNED, PHONE_VERIFY, or DEGRADED_POW accounts.
    """
    if now_ts is None:
        now = time.time()
        now_valid = True
    elif isinstance(now_ts, bool) or not isinstance(now_ts, (int, float)) or not math.isfinite(float(now_ts)):
        now = float("nan")
        now_valid = False
    else:
        now = float(now_ts)
        now_valid = True
    abnormal = [a for a in accounts if a.health_status in ("BANNED", "PHONE_VERIFY", "DEGRADED_POW")]
    if not abnormal:
        return ""
    try:
        gen_time = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S") if now_valid else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: List[str] = [
        f"=== 售后异常账号核验清单（生成时间: {gen_time}） ==="
    ]
    for idx, acc in enumerate(abnormal, start=1):
        vendor = acc.vendor_tag or "未标注渠道"
        status_cn = HEALTH_STATUS_LABELS.get(acc.health_status, acc.health_status)
        created_str = _safe_fmt_date(acc.created_at)
        if acc.warranty_expire_at is not None:
            if math.isnan(acc.warranty_expire_at) or math.isinf(acc.warranty_expire_at):
                w_str = "质保永久/异常" if acc.warranty_expire_at == float("inf") else "未设质保"
            elif not now_valid:
                w_str = "质保状态未知"
            else:
                w_rem = acc.warranty_expire_at - now
                if w_rem > 0:
                    w_str = f"质保内（剩余 {format_duration(w_rem)}）"
                else:
                    w_str = "已过质保期"
        else:
            w_str = "未设质保"
        note_part = f" | 备注: {acc.notes}" if acc.notes else ""
        lines.append(
            f"{idx}. [{vendor}][{acc.provider}] {acc.email}----{acc.password}----{acc.two_fa} "
            f"| 状态: {status_cn} | 入库: {created_str} | {w_str}{note_part}"
        )
    return "\n".join(lines)


@dataclass
class VendorRoiRow:
    vendor: str
    total_count: int
    active_count: int
    banned_count: int
    ban_rate_pct: float
    total_cost: float
    total_5h_sessions: int
    cost_per_session: Optional[float]


def compute_vendor_roi_stats(accounts: List[Account]) -> List[VendorRoiRow]:
    """Aggregate survival rate, ban rate, total spend, and amortized session cost per vendor."""
    buckets: Dict[str, List[Account]] = {}
    for acc in accounts:
        key = acc.vendor_tag.strip() if acc.vendor_tag.strip() else "默认/未分类"
        buckets.setdefault(key, []).append(acc)

    rows: List[VendorRoiRow] = []
    for vendor, grp in sorted(buckets.items(), key=lambda x: (-len(x[1]), x[0])):
        total = len(grp)
        banned = sum(1 for a in grp if a.health_status == "BANNED")
        active = sum(1 for a in grp if a.health_status == "ACTIVE")
        ban_rate = (banned / total * 100.0) if total > 0 else 0.0
        cost = round(sum(a.purchase_price for a in grp), 2)
        sessions = sum(a.usage_5h_count for a in grp)
        cps = round(cost / sessions, 2) if sessions > 0 and cost > 0 else None
        rows.append(
            VendorRoiRow(
                vendor=vendor,
                total_count=total,
                active_count=active,
                banned_count=banned,
                ban_rate_pct=round(ban_rate, 1),
                total_cost=cost,
                total_5h_sessions=sessions,
                cost_per_session=cps,
            )
        )
    return rows
