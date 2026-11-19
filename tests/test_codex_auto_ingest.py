import base64
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PyQt5.QtWidgets import QApplication

from src.codex_detector import (
    CodexLoginController,
    CodexMonitor,
    CodexProfile,
    CodexRateLimits,
    extract_codex_profile,
    extract_codex_rate_limits,
    find_codex_executable,
    parse_iso_timestamp,
    parse_jwt_payload,
)
from src.dialogs import AccountDialog, CodexLoginDialog
from src.main_window import MainWindow
from src.models import Account
from src.storage import AccountStorage


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_dummy_jwt(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.dummy_signature"


def test_jwt_and_iso_parser():
    # Test valid payload
    jwt = _make_dummy_jwt({"email": "test@example.com", "name": "Tester"})
    res = parse_jwt_payload(jwt)
    assert res.get("email") == "test@example.com"
    assert res.get("name") == "Tester"

    # Test malformed / invalid
    assert parse_jwt_payload("") == {}
    assert parse_jwt_payload("not.a.valid.jwt.at.all") == {}
    assert parse_jwt_payload("invalid") == {}

    # Test ISO timestamp
    ts = parse_iso_timestamp("2026-11-29T05:55:14+00:00")
    assert ts is not None and ts > 1700000000
    assert parse_iso_timestamp("invalid-date") is None
    assert parse_iso_timestamp(None) is None


def test_extract_codex_profile_from_file(tmp_path: Path):
    auth_file = tmp_path / "auth.json"

    # 1. Non-existent file
    assert extract_codex_profile(auth_file) is None

    # 2. Corrupt file
    auth_file.write_text("not json", encoding="utf-8")
    assert extract_codex_profile(auth_file) is None

    # 3. Valid auth file
    id_jwt = _make_dummy_jwt({
        "email": "codex_user@openai.com",
        "name": "OpenAI Explorer",
        "sub": "auth0|12345",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "plus",
            "chatgpt_subscription_active_until": "2026-12-31T23:59:59Z",
            "chatgpt_account_id": "acc-999",
            "user_id": "usr-888",
        },
    })
    acc_jwt = _make_dummy_jwt({
        "https://api.openai.com/profile": {
            "email": "codex_user@openai.com",
            "name": "OpenAI Explorer",
        }
    })

    data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "id_token": id_jwt,
            "access_token": acc_jwt,
            "account_id": "acc-999",
        },
        "last_refresh": "2026-11-19T00:00:00Z",
    }
    auth_file.write_text(json.dumps(data), encoding="utf-8")

    prof = extract_codex_profile(auth_file)
    assert prof is not None
    assert prof.email == "codex_user@openai.com"
    assert prof.name == "OpenAI Explorer"
    assert prof.plan_type == "plus"
    assert prof.display_plan == "Plus会员"
    assert prof.subscription_expire_timestamp is not None
    assert prof.account_id == "acc-999"


def test_codex_monitor_updates(qapp, tmp_path: Path):
    codex_home = tmp_path / ".codex"
    codex_home.mkdir(parents=True)
    auth_file = codex_home / "auth.json"

    monitor = CodexMonitor(codex_home=codex_home, poll_interval_ms=500)
    assert monitor.current_profile is None

    # Write auth
    id_jwt = _make_dummy_jwt({
        "email": "live@codex.ai",
        "name": "Live Agent",
        "https://api.openai.com/auth": {"chatgpt_plan_type": "pro"},
    })
    auth_file.write_text(
        json.dumps({"tokens": {"id_token": id_jwt}}),
        encoding="utf-8",
    )

    prof = monitor.check_now()
    assert prof is not None
    assert prof.email == "live@codex.ai"
    assert prof.display_plan == "Pro专业版"


def test_account_dialog_pull_from_codex(qapp, tmp_path: Path):
    # Mock extract_codex_profile
    fake_prof = CodexProfile(
        email="auto_pull@gpt.com",
        name="Auto Puller",
        plan_type="team",
        subscription_active_until="2027-01-01T00:00:00+00:00",
        subscription_expire_timestamp=time.time() + 30 * 86400,
        account_id="acc-team",
    )

    with patch("src.dialogs.extract_codex_profile", return_value=fake_prof):
        dlg = AccountDialog()
        dlg._on_pull_from_codex()
        assert dlg.email_edit.text() == "auto_pull@gpt.com"
        assert "Auto Puller" in dlg.name_edit.text()
        assert dlg.provider_combo.currentText() == "Codex"
        assert dlg.warranty_days_spin.value() > 28.0
        dlg.close()


def test_extract_codex_rate_limits_and_isolation(tmp_path: Path):
    codex_home = tmp_path / ".codex"
    sess_dir = codex_home / "sessions" / "2026" / "11" / "19"
    sess_dir.mkdir(parents=True)

    now = time.time()
    future_5h = now + 4 * 3600
    future_wk = now + 5 * 86400

    # Session belonging to Account A
    sess_a = sess_dir / "rollout-a.jsonl"
    sess_a.write_text(
        "\n".join([
            json.dumps({
                "timestamp": "2026-11-19T03:00:00Z",
                "type": "session_meta",
                "payload": {"creator_account_id": "acc-A", "creator_user_id": "usr-A"},
            }),
            json.dumps({
                "timestamp": "2026-11-19T03:05:00Z",
                "type": "event_msg",
                "payload": {
                    "type": "token_count",
                    "rate_limits": {
                        "limit_id": "codex",
                        "primary": {"used_percent": 39.0, "window_minutes": 300, "resets_at": future_5h},
                        "secondary": {"used_percent": 12.0, "window_minutes": 10080, "resets_at": future_wk},
                    },
                },
            }),
        ]),
        encoding="utf-8",
    )

    # Matching Account A returns exact remaining quotas (100 - used)
    rl_a = extract_codex_rate_limits(codex_home=codex_home, account_id="acc-A", user_id="usr-A", now_ts=now)
    assert rl_a is not None
    assert rl_a.five_hour_quota == 61
    assert rl_a.weekly_quota == 88
    assert abs(rl_a.five_hour_reset_at - future_5h) < 1.0
    assert abs(rl_a.weekly_reset_at - future_wk) < 1.0

    # Querying Account B must NOT inherit Account A's quota
    rl_b = extract_codex_rate_limits(codex_home=codex_home, account_id="acc-B", user_id="usr-B", now_ts=now)
    assert rl_b is None

    # Expired reset timestamps should automatically reset remaining quota to 100% and clear reset_at
    rl_expired = extract_codex_rate_limits(
        codex_home=codex_home, account_id="acc-A", user_id="usr-A", now_ts=future_wk + 100
    )
    assert rl_expired is not None
    assert rl_expired.five_hour_quota == 100
    assert rl_expired.five_hour_reset_at is None
    assert rl_expired.weekly_quota == 100
    assert rl_expired.weekly_reset_at is None


def test_main_window_auto_surveillance_and_ingestion(qapp, tmp_path: Path):
    storage = AccountStorage(base_dir=tmp_path)
    codex_home = tmp_path / ".codex"
    codex_home.mkdir(parents=True)
    auth_file = codex_home / "auth.json"

    win = MainWindow(storage=storage, codex_home=codex_home)
    win.show()

    # Account 1 logs into Codex -> automatically retained without clicking banner
    id_jwt_1 = _make_dummy_jwt({
        "email": "account_one@codex.com",
        "name": "Account One",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "plus",
            "chatgpt_account_id": "acc-1",
            "user_id": "usr-1",
        },
    })
    auth_file.write_text(json.dumps({"tokens": {"id_token": id_jwt_1}}), encoding="utf-8")

    with patch("src.main_window.send_windows_toast"):
        prof1 = win.codex_monitor.check_now()
    assert prof1 is not None
    assert "account_one@codex.com" in win.codex_status_badge.text()

    acc1_list = [a for a in win.accounts if a.email == "account_one@codex.com"]
    assert len(acc1_list) == 1
    acc1 = acc1_list[0]
    assert acc1.provider == "Codex"
    assert win.codex_mgr.has_snapshot(acc1.id)

    # Account 2 logs into Codex -> BOTH Account 1 and Account 2 are retained with separate snapshots!
    id_jwt_2 = _make_dummy_jwt({
        "email": "account_two@codex.com",
        "name": "Account Two",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "pro",
            "chatgpt_account_id": "acc-2",
            "user_id": "usr-2",
        },
    })
    # Ensure different mtime
    time.sleep(0.02)
    auth_file.write_text(json.dumps({"tokens": {"id_token": id_jwt_2}}), encoding="utf-8")

    with patch("src.main_window.send_windows_toast"):
        prof2 = win.codex_monitor.check_now()
    assert prof2 is not None
    assert len([a for a in win.accounts if a.email == "account_one@codex.com"]) == 1
    acc2_list = [a for a in win.accounts if a.email == "account_two@codex.com"]
    assert len(acc2_list) == 1
    acc2 = acc2_list[0]
    assert win.codex_mgr.has_snapshot(acc1.id)
    assert win.codex_mgr.has_snapshot(acc2.id)

    # Real-time 5h & weekly rate-limit sync for active Account 2
    now = time.time()
    rl = CodexRateLimits(
        five_hour_quota=42,
        five_hour_reset_at=now + 7200,
        weekly_quota=77,
        weekly_reset_at=now + 3 * 86400,
        event_timestamp="2026-11-19T05:00:00Z",
        account_id="acc-2",
        user_id="usr-2",
    )
    win._on_codex_rate_limits_changed(rl)
    assert acc2.five_hour_quota == 42
    assert acc2.weekly_quota == 77
    assert acc2.five_hour_reset_at is not None
    assert acc2.weekly_reset_at is not None
    # Account 1 must remain untouched
    assert acc1.five_hour_quota == 100

    # Duplicate prevention
    with patch("PyQt5.QtWidgets.QMessageBox.information"):
        win._auto_ingest_codex_profile(prof2, silent=False)
    assert len([a for a in win.accounts if a.email == "account_two@codex.com"]) == 1

    win.close()
