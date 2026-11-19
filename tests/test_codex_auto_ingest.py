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
    extract_codex_profile,
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


def test_main_window_auto_surveillance_and_ingestion(qapp, tmp_path: Path):
    storage = AccountStorage(base_dir=tmp_path)
    win = MainWindow(storage=storage)
    win.show()

    fake_prof = CodexProfile(
        email="new_detected@codex.com",
        name="Detected Hero",
        plan_type="plus",
        subscription_active_until="2026-12-01T00:00:00+00:00",
        subscription_expire_timestamp=time.time() + 10 * 86400,
        account_id="acc-hero",
    )

    # 1. Profile updated signal with unmanaged account
    win._on_codex_profile_changed(fake_prof)
    assert win.codex_banner.isVisible()
    assert "new_detected@codex.com" in win.codex_banner_lbl.text()
    assert "new_detected@codex.com" in win.codex_status_badge.text()

    # 2. Ingest account
    with patch("src.main_window.send_windows_toast") as mock_toast:
        with patch("PyQt5.QtWidgets.QMessageBox.information") as mock_info:
            win._on_ingest_current_codex()

    # Banner should hide and account added
    assert not win.codex_banner.isVisible()
    matching = [a for a in win.accounts if a.email == "new_detected@codex.com"]
    assert len(matching) == 1
    acc = matching[0]
    assert acc.provider == "Codex"
    assert "Detected Hero" in acc.name
    assert acc.warranty_expire_at is not None

    # Verify DPAPI snapshot created in vault
    assert win.codex_mgr.has_snapshot(acc.id)

    # 3. Check duplicate prevention
    with patch("PyQt5.QtWidgets.QMessageBox.information") as mock_info:
        win._auto_ingest_codex_profile(fake_prof)
    # Should not add another copy
    assert len([a for a in win.accounts if a.email == "new_detected@codex.com"]) == 1

    win.close()
