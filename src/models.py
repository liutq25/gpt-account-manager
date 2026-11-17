from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

FIVE_HOURS_SECONDS = 5 * 3600
MAX_QUOTA = 100
MIN_QUOTA = 0

_FOUR_DASH_PATTERN = re.compile(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"\s*(?:-{2,}|—{2,})\s*"
    r"([^\r\n]+?)"
    r"\s*(?:-{2,}|—{2,})\s*"
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
    Supports `email----password----2fa` (primary), `|` or tab delimiters,
    and single-record labeled fallback (`邮箱:`, `密码:`, `2FA:`).
    Ignores surrounding disclaimers, URLs, emojis, and boilerplate like `邮箱----密码----2FA`.
    """
    text = raw_text.strip()
    if not text:
        return []

    results: List[ParsedAccount] = []
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
        results.append(
            ParsedAccount(
                suggested_name=email.split("@", 1)[0],
                email=email,
                password=pwd_m.group(1).strip(),
                two_fa=tfa_m.group(1).strip(),
            )
        )

    return results


def validate_quota(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} 必须是整数，实际为: {type(value).__name__}")
    if value < MIN_QUOTA or value > MAX_QUOTA:
        raise ValueError(f"{field_name} 必须在 {MIN_QUOTA} 到 {MAX_QUOTA} 之间，实际为: {value}")
    return value


def compute_totp(secret_or_code: str, for_time: Optional[float] = None) -> Tuple[Optional[str], int]:
    """
    If `secret_or_code` is a valid Base32 TOTP secret (>= 16 base32 chars),
    returns (6-digit TOTP code, remaining seconds in 30s window).
    Otherwise returns (None, 0) indicating a static initial/recovery code.
    """
    cleaned = "".join(secret_or_code.strip().split()).upper()
    if len(cleaned) < 16:
        return None, 0
    # Base32 alphabet check (allow missing '=' padding)
    base32_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    if not set(cleaned).issubset(base32_chars):
        return None, 0
    try:
        padded = cleaned + ("=" * ((8 - len(cleaned) % 8) % 8))
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return None, 0
    if len(key) < 10:
        return None, 0

    now = time.time() if for_time is None else for_time
    timestep = 30
    counter = int(now // timestep)
    remaining = timestep - int(now % timestep)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}", remaining


def format_duration(seconds: float) -> str:
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

    @classmethod
    def create(
        cls,
        name: str,
        email: str,
        password: str,
        two_fa: str,
        five_hour_quota: int = MAX_QUOTA,
        weekly_quota: int = MAX_QUOTA,
        weekly_reset_duration_seconds: int = 0,
        now_ts: Optional[float] = None,
    ) -> "Account":
        now = time.time() if now_ts is None else now_ts
        validate_quota(five_hour_quota, "5h额度")
        validate_quota(weekly_quota, "周额度")
        if weekly_reset_duration_seconds < 0:
            raise ValueError("周额度剩余重置时间不能为负数")

        five_reset_at = now + FIVE_HOURS_SECONDS if five_hour_quota == 0 else None
        weekly_reset_at = (
            now + weekly_reset_duration_seconds if weekly_reset_duration_seconds > 0 else None
        )
        return cls(
            id=uuid.uuid4().hex[:12],
            name=name,
            email=email,
            password=password,
            two_fa=two_fa,
            five_hour_quota=five_hour_quota,
            five_hour_reset_at=five_reset_at,
            weekly_quota=weekly_quota,
            weekly_reset_at=weekly_reset_at,
            created_at=now,
            updated_at=now,
        )

    @property
    def can_start_five_hour_usage(self) -> tuple[bool, str]:
        """
        Check if 5h countdown can be started by user.
        Returns (can_start: bool, reason: str).
        """
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
        """
        Update 5h quota and enforce state consistency:
        - If clear_timer is True, explicitly cancel existing 5h countdown.
        - If already counting down and clear_timer is False, preserve existing reset timestamp.
        - If not counting down and new_quota becomes 0, automatically start 5h countdown.
        Returns list of event tags triggered.
        """
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
                events.append("START_5H_COUNTDOWN")

        self.updated_at = now
        return events

    def start_five_hour_usage(self, now_ts: Optional[float] = None) -> List[str]:
        """
        Start 5h countdown immediately upon user action.
        Precondition: Weekly quota must have remaining balance (> 0) and 5h quota > 0,
        and not already counting down.
        Returns triggered event list.
        """
        can_start, reason = self.can_start_five_hour_usage
        if not can_start:
            raise ValueError(reason)

        now = time.time() if now_ts is None else now_ts
        self.five_hour_reset_at = now + FIVE_HOURS_SECONDS
        self.updated_at = now
        return ["START_5H_COUNTDOWN"]

    def set_weekly_quota_and_timer(
        self,
        new_quota: int,
        reset_duration_seconds: Optional[int] = None,
        clear_timer: bool = False,
        now_ts: Optional[float] = None,
    ) -> List[str]:
        """
        Update weekly quota and optionally set or clear the weekly countdown.
        If `reset_duration_seconds` is provided and > 0, start countdown immediately.
        If `reset_duration_seconds == 0` and `clear_timer=True`, clear countdown.
        If `reset_duration_seconds is None` and not `clear_timer`, keep existing countdown.
        """
        now = time.time() if now_ts is None else now_ts
        new_quota = validate_quota(new_quota, "周额度")
        events: List[str] = []

        self.weekly_quota = new_quota
        if clear_timer:
            if self.weekly_reset_at is not None:
                self.weekly_reset_at = None
                events.append("CLEAR_WEEKLY_COUNTDOWN")
        elif reset_duration_seconds is not None:
            if reset_duration_seconds < 0:
                raise ValueError("周额度剩余重置时间不能为负数")
            if reset_duration_seconds > 0:
                self.weekly_reset_at = now + reset_duration_seconds
                events.append("START_WEEKLY_COUNTDOWN")
            else:
                if self.weekly_reset_at is not None:
                    self.weekly_reset_at = None
                    events.append("CLEAR_WEEKLY_COUNTDOWN")

        self.updated_at = now
        return events

    def tick(self, now_ts: Optional[float] = None) -> List[str]:
        """
        Check timers against `now_ts`.
        Returns list of auto-reset event codes triggered:
        - "AUTO_RESET_5H"
        - "AUTO_RESET_WEEKLY"
        """
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
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Account":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            email=str(data["email"]),
            password=str(data["password"]),
            two_fa=str(data["two_fa"]),
            five_hour_quota=int(data["five_hour_quota"]),
            five_hour_reset_at=(
                float(data["five_hour_reset_at"])
                if data.get("five_hour_reset_at") is not None
                else None
            ),
            weekly_quota=int(data["weekly_quota"]),
            weekly_reset_at=(
                float(data["weekly_reset_at"])
                if data.get("weekly_reset_at") is not None
                else None
            ),
            weekly_notified_reset_at=(
                float(data["weekly_notified_reset_at"])
                if data.get("weekly_notified_reset_at") is not None
                else None
            ),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )


def check_weekly_expiring_accounts(
    accounts: List[Account],
    quota_threshold: int = 20,
    hours_threshold: int = 24,
    now_ts: Optional[float] = None,
) -> List[Account]:
    """
    Find accounts whose weekly quota has significant remaining amount (>= quota_threshold)
    and reset time is within hours_threshold (and > 0),
    and has NOT been notified for the current reset cycle.
    """
    now = time.time() if now_ts is None else now_ts
    window_sec = hours_threshold * 3600
    expiring: List[Account] = []
    for acc in accounts:
        if acc.weekly_reset_at is None:
            continue
        rem = acc.weekly_remaining_seconds(now)
        if rem is None or rem <= 0:
            continue
        if rem <= window_sec and acc.weekly_quota >= quota_threshold:
            if acc.weekly_notified_reset_at != acc.weekly_reset_at:
                expiring.append(acc)
    return expiring

