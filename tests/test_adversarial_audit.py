from __future__ import annotations

import base64
import http.client
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image, ImageDraw, ImageFont
from PyQt5.QtWidgets import QApplication, QMessageBox

import main as app_main
from src.dialogs import SettingsDialog
from src.launcher import (
    SequentialPasteController,
    _candidate_browser_paths,
    build_isolated_browser_args,
    copy_two_fa_with_expiry_guard,
    launch_isolated_browser,
)
from src.main_window import MainWindow
from src.mini_hud import MiniHudWindow
from src.models import (
    FIVE_HOURS_SECONDS,
    Account,
    check_warranty_expiring_accounts,
    compute_totp_with_safety,
    compute_vendor_roi_stats,
    format_after_sales_slip,
    select_optimal_account,
    validate_price,
    validate_provider,
    validate_proxy_url,
    validate_quota,
)
from src.notifier import send_windows_toast
from src.ocr_sync import CodexAuthManager, parse_quota_from_ocr_text, run_windows_ocr
from src.security import (
    DPAPI_PREFIX,
    PORTABLE_BACKUP_MAGIC,
    SecurityError,
    WebDavSyncClient,
    decrypt_portable_payload,
    dpapi_decrypt,
    dpapi_encrypt,
    encrypt_portable_payload,
    merge_account_dicts,
    passphrase_decrypt_bytes,
)
from src.storage import AccountStorage, AppSettings


class TestM1AdversarialSecurityAndStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_dpapi_malformed_and_non_utf8_raise_security_error(self) -> None:
        with self.assertRaises(SecurityError):
            dpapi_decrypt(f"{DPAPI_PREFIX}!!!not_base64!!!")
        with self.assertRaises(SecurityError):
            dpapi_decrypt(DPAPI_PREFIX)
        with self.assertRaises(SecurityError):
            dpapi_decrypt(f"{DPAPI_PREFIX}{base64.b64encode(b'corrupt_dpapi_blob').decode('ascii')}")

        # Simulate CryptUnprotectData returning raw non-UTF8 bytes -> must raise SecurityError
        valid_token = dpapi_encrypt("hello")
        with mock.patch("ctypes.string_at", return_value=b"\xff\xfe\x80\x81"):
            with self.assertRaises(SecurityError):
                dpapi_decrypt(valid_token)

    def test_appsettings_foreign_dpapi_password_preserved_across_theme_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            foreign_blob = f"{DPAPI_PREFIX}{base64.b64encode(b'foreign_machine_cipher').decode('ascii')}"
            storage.settings_file.write_text(
                json.dumps({"theme": "light", "webdav_password": foreign_blob}),
                encoding="utf-8",
            )
            loaded = storage.load_settings()
            self.assertEqual(loaded.webdav_password, "")

            # Saving theme must preserve the undecryptable blob rather than wiping it
            storage.save_theme("dark")
            raw_after = json.loads(storage.settings_file.read_text(encoding="utf-8"))
            self.assertEqual(raw_after["theme"], "dark")
            self.assertEqual(raw_after["webdav_password"], foreign_blob)

            # Saving via SettingsDialog with empty password field must also preserve foreign DPAPI blob
            loaded_again = storage.load_settings()
            dlg = SettingsDialog(loaded_again)
            try:
                dlg.burn_spin.setValue(30)
                with mock.patch("src.dialogs.is_windows_scheduled_task_installed", return_value=False):
                    dlg._on_save()
                self.assertIsNotNone(dlg.saved_settings)
                storage.save_settings(dlg.saved_settings)
                raw_dlg = json.loads(storage.settings_file.read_text(encoding="utf-8"))
                self.assertEqual(raw_dlg["clipboard_burn_seconds"], 30)
                self.assertEqual(raw_dlg["webdav_password"], foreign_blob)

                # Typing a new password replaces the preserved foreign blob
                dlg.wd_pwd_edit.setText("NewLocalSecret")
                dlg._on_save()
                storage.save_settings(dlg.saved_settings)
                self.assertEqual(storage.load_settings().webdav_password, "NewLocalSecret")
            finally:
                dlg.close()

    def test_aes_gcm_envelope_malformations_raise_security_error(self) -> None:
        enc = json.loads(encrypt_portable_payload({"accounts": []}, "StrongPass#2026"))

        # 4-byte nonce -> SecurityError (not raw ValueError)
        bad_nonce = dict(enc)
        bad_nonce["nonce"] = base64.b64encode(b"1234").decode("ascii")
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(bad_nonce, "StrongPass#2026")

        # 8-byte salt -> SecurityError
        bad_salt = dict(enc)
        bad_salt["salt"] = base64.b64encode(b"12345678").decode("ascii")
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(bad_salt, "StrongPass#2026")

        # Bad kdf / cipher -> SecurityError
        bad_kdf = dict(enc)
        bad_kdf["kdf"] = "MD5"
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(bad_kdf, "StrongPass#2026")

        bad_cipher = dict(enc)
        bad_cipher["cipher"] = "RC4"
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(bad_cipher, "StrongPass#2026")

        # Short / empty passphrase on decrypt -> SecurityError
        for short_pw in ("", "ab", "   "):
            with self.assertRaises(SecurityError):
                decrypt_portable_payload(json.dumps(enc), short_pw)

        # Iteration bounds
        for bad_iter in (9999, 10_000_001, "abc", True):
            bad_env = dict(enc)
            bad_env["iterations"] = bad_iter
            with self.assertRaises(SecurityError):
                passphrase_decrypt_bytes(bad_env, "StrongPass#2026")

        # Truncated ciphertext & wrong magic
        trunc = dict(enc)
        trunc["ciphertext"] = base64.b64encode(b"short").decode("ascii")
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(trunc, "StrongPass#2026")

        wrong_magic = dict(enc)
        wrong_magic["magic"] = "OTHER"
        with self.assertRaises(SecurityError):
            passphrase_decrypt_bytes(wrong_magic, "StrongPass#2026")

        # Non-dict inner JSON -> SecurityError
        from src.security import passphrase_encrypt_bytes
        non_dict_env = passphrase_encrypt_bytes(b"[1, 2, 3]", "StrongPass#2026")
        with self.assertRaises(SecurityError):
            decrypt_portable_payload(json.dumps(non_dict_env), "StrongPass#2026")

    def test_mainwindow_import_backup_detects_encrypted_magic_past_200_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            storage = AccountStorage(tmp_path / "app")
            acc = Account.create("远端号", "pad@t.com", "secret", "123456")
            raw_enc = encrypt_portable_payload(
                {"schema_version": 2, "accounts": [acc.to_dict()]},
                "BackupKey#99",
            )
            env = json.loads(raw_enc)
            # Put >220 chars of padding before magic
            reordered = {"padding_metadata": "X" * 260, **env}
            backup_file = tmp_path / "padded.enc.json"
            backup_file.write_text(json.dumps(reordered, indent=2), encoding="utf-8")

            win = MainWindow(storage)
            try:
                with mock.patch("src.main_window.QFileDialog.getOpenFileName", return_value=(str(backup_file), "")), \
                     mock.patch("src.main_window.PassphraseDialog") as mock_pw_dlg, \
                     mock.patch("src.main_window.QMessageBox.information"):
                    mock_pw_dlg.Accepted = 1
                    inst = mock_pw_dlg.return_value
                    inst.exec_.return_value = 1
                    inst.passphrase = "BackupKey#99"
                    win._on_import_backup_merge()
                    self.assertTrue(mock_pw_dlg.called)
                self.assertEqual(len(win.accounts), 1)
                self.assertEqual(win.accounts[0].email, "pad@t.com")
            finally:
                win.close()

    def test_storage_load_accounts_rejects_malformed_containers_and_logs_upgrade_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))

            storage.accounts_file.write_text("{corrupt", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                storage.load_accounts()

            storage.accounts_file.write_text(json.dumps({"accounts": "not_a_list"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                storage.load_accounts()

            storage.accounts_file.write_text(json.dumps({"accounts": [123]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                storage.load_accounts()

            # v1 upgrade failure logs structured error instead of silent swallow
            legacy = {
                "schema_version": 1,
                "accounts": [
                    {
                        "id": "v1id",
                        "name": "老号",
                        "email": "v1@t.com",
                        "password": "plain",
                        "two_fa": "123456",
                        "five_hour_quota": 100,
                        "weekly_quota": 100,
                    }
                ],
            }
            storage.accounts_file.write_text(json.dumps(legacy), encoding="utf-8")
            with mock.patch.object(storage, "save_accounts", side_effect=PermissionError("read-only")):
                loaded = storage.load_accounts()
            self.assertEqual(len(loaded), 1)
            events = [e.event for e in storage.logger.read_recent()]
            self.assertIn("STORAGE_DPAPI_UPGRADE_FAILED", events)

    def test_webdav_chaos_errors_normalize_to_security_error(self) -> None:
        for bad_url in ("", "ftp://example.com", "http://"):
            with self.assertRaises(ValueError):
                WebDavSyncClient(bad_url, "u", "p")

        # Raw socket server simulating RemoteDisconnected, non-UTF8, and slow timeout
        class _ChaosTcpServer:
            def __init__(self, mode: str) -> None:
                self.mode = mode
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.bind(("127.0.0.1", 0))
                self.sock.listen(4)
                self.port = self.sock.getsockname()[1]
                self._stop = False
                self.thread = threading.Thread(target=self._serve, daemon=True)
                self.thread.start()

            def _serve(self) -> None:
                while not self._stop:
                    try:
                        self.sock.settimeout(0.2)
                        conn, _ = self.sock.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        break
                    try:
                        _ = conn.recv(4096)
                        if self.mode == "drop":
                            conn.close()
                        elif self.mode == "nonutf8":
                            conn.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\xff\xfe\x80\x81"
                            )
                            conn.close()
                        elif self.mode == "slow":
                            time.sleep(1.5)
                            conn.close()
                    except OSError:
                        pass

            def close(self) -> None:
                self._stop = True
                try:
                    self.sock.close()
                except OSError:
                    pass

        # HTTP 404, 500, 302, and connection refused -> SecurityError
        class _StatusHandler(BaseHTTPRequestHandler):
            code = 500
            def log_message(self, format: str, *args) -> None:
                pass
            def do_GET(self) -> None:
                self.send_response(self.__class__.code)
                if self.__class__.code == 302:
                    self.send_header("Location", "http://127.0.0.1:1/redirect")
                self.end_headers()

        srv_http = HTTPServer(("127.0.0.1", 0), _StatusHandler)
        t_http = threading.Thread(target=srv_http.serve_forever, daemon=True)
        t_http.start()
        try:
            c_http = WebDavSyncClient(f"http://127.0.0.1:{srv_http.server_port}/dav", "u", "p", timeout=3)
            for sc in (404, 500, 302):
                _StatusHandler.code = sc
                with self.assertRaises(SecurityError, msg=f"HTTP {sc} should raise SecurityError"):
                    c_http.download_decrypted("SyncKey#2026")
        finally:
            srv_http.shutdown()
            srv_http.server_close()

        # Connection refused
        dead_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dead_sock.bind(("127.0.0.1", 0))
        dead_port = dead_sock.getsockname()[1]
        dead_sock.close()
        with self.assertRaises(SecurityError):
            WebDavSyncClient(f"http://127.0.0.1:{dead_port}/dav", "u", "p", timeout=2).download_decrypted("SyncKey#2026")

        for mode in ("drop", "nonutf8", "slow"):
            srv = _ChaosTcpServer(mode)
            try:
                client = WebDavSyncClient(
                    f"http://127.0.0.1:{srv.port}/dav",
                    "u",
                    "p",
                    timeout=1 if mode == "slow" else 5,
                )
                with self.assertRaises(SecurityError, msg=f"mode={mode} did not raise SecurityError"):
                    client.download_decrypted("SyncKey#2026")
            finally:
                srv.close()

    def test_lww_merge_handles_non_numeric_timestamps_and_email_rename_by_key(self) -> None:
        local = [
            {
                "id": "id1",
                "provider": "ChatGPT",
                "email": "old@x.com",
                "updated_at": 100.0,
            }
        ]
        # Remote updates id1 email old@x.com -> new@x.com, and also brings id2 with new@x.com
        remote = [
            {
                "id": "id1",
                "provider": "ChatGPT",
                "email": "new@x.com",
                "updated_at": 200.0,
            },
            {
                "id": "id2",
                "provider": "ChatGPT",
                "email": "new@x.com",
                "updated_at": 300.0,
            },
            {
                "id": "id3",
                "provider": "ChatGPT",
                "email": "badts@x.com",
                "updated_at": "not_a_number",
            },
        ]
        merged, added, updated, kept = merge_account_dicts(local, remote)
        self.assertEqual(len(merged), 2)
        self.assertEqual(added, 1)  # only id3 added; id2 matched updated by_key (ChatGPT, new@x.com)
        self.assertEqual(updated, 2)
        self.assertEqual(kept, 0)
        by_id = {m["id"]: m for m in merged}
        self.assertEqual(by_id["id1"]["email"], "new@x.com")
        self.assertEqual(by_id["id1"]["updated_at"], 300.0)

        # Empty local id matched by (provider, email) must adopt rem_id
        merged_id, added_id, upd_id, kept_id = merge_account_dicts(
            [{"id": "", "provider": "ChatGPT", "email": "e@x.com", "updated_at": 10.0}],
            [{"id": "rem_real_id", "provider": "ChatGPT", "email": "e@x.com", "updated_at": 20.0}],
        )
        self.assertEqual((added_id, upd_id, kept_id), (0, 1, 0))
        self.assertEqual(merged_id[0]["id"], "rem_real_id")

    def test_load_settings_strict_vs_gui_resilience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            storage.settings_file.write_text("{corrupt_settings", encoding="utf-8")

            # Default non-strict mode logs SETTINGS_LOAD_ERROR and falls back to defaults
            s = storage.load_settings()
            self.assertEqual(s.theme, "light")
            events = [e.event for e in storage.logger.read_recent()]
            self.assertIn("SETTINGS_LOAD_ERROR", events)

            # Strict mode raises so --check-notify can fail visibly
            with self.assertRaises(json.JSONDecodeError):
                storage.load_settings(strict=True)

            storage.settings_file.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                storage.load_settings(strict=True)


class TestM2AdversarialModelsAndEEQF(unittest.TestCase):
    def test_eeqf_expired_timers_without_prior_tick_and_case_insensitive_provider(self) -> None:
        t_now = 1000.0
        acc = Account.create("过期测试", "exp@t.com", "pw", "123456", five_hour_quota=0, weekly_quota=50, now_ts=100.0)
        acc.five_hour_reset_at = 900.0  # already expired at t_now=1000.0, tick() NOT yet called

        rec = select_optimal_account([acc], provider="chatgpt", now_ts=t_now)
        self.assertEqual(rec.status, "READY_NEW_5H")
        self.assertIsNotNone(rec.account)
        self.assertEqual(rec.account.id, acc.id)

        # Weekly expired without tick -> burn_urgency_score uses MAX_QUOTA / DEFAULT_WEEKLY_HOURS
        acc_wk = Account.create("周过期", "wk@t.com", "pw", "123456", five_hour_quota=100, weekly_quota=0, now_ts=100.0)
        acc_wk.weekly_reset_at = 900.0
        self.assertGreater(acc_wk.burn_urgency_score(t_now), 0.0)
        rec_wk = select_optimal_account([acc_wk], now_ts=t_now)
        self.assertEqual(rec_wk.status, "READY_NEW_5H")

    def test_eeqf_boundary_states_and_clamping(self) -> None:
        t0 = 1_700_000_000.0
        self.assertEqual(select_optimal_account([], now_ts=t0).status, "NONE_AVAILABLE")

        # Clamp w_rem < 1h to 1.0h
        a_1m = Account.create("1m", "a1@t.com", "p", "123456", weekly_quota=50, weekly_reset_duration_seconds=60, now_ts=t0)
        a_1h = Account.create("1h", "a2@t.com", "p", "123456", weekly_quota=50, weekly_reset_duration_seconds=3600, now_ts=t0)
        self.assertAlmostEqual(a_1m.burn_urgency_score(t0), a_1h.burn_urgency_score(t0))

        # Tier 3 Case B: weekly_quota=0 with weekly_reset_at
        a_cool = Account.create("wk0", "c@t.com", "p", "123456", five_hour_quota=0, weekly_quota=0, weekly_reset_duration_seconds=1000, now_ts=t0)
        a_cool.five_hour_reset_at = None
        rec = select_optimal_account([a_cool], now_ts=t0)
        self.assertEqual(rec.status, "COOLING_DOWN")
        self.assertAlmostEqual(rec.wait_seconds or 0.0, 1000.0, places=1)

    def test_account_from_dict_rejects_bool_nan_inf_and_handles_nulls(self) -> None:
        base = Account.create("有效", "v@t.com", "pw", "123456").to_dict()

        for bool_field in ("five_hour_quota", "weekly_quota", "purchase_price", "usage_5h_count"):
            bad = dict(base)
            bad[bool_field] = True
            with self.assertRaises(ValueError, msg=f"{bool_field}=True should fail"):
                Account.from_dict(bad)

        for nan_field in ("five_hour_reset_at", "weekly_reset_at", "warranty_expire_at", "created_at", "updated_at", "purchase_price"):
            bad = dict(base)
            bad[nan_field] = float("nan")
            with self.assertRaises(ValueError, msg=f"{nan_field}=NaN should fail"):
                Account.from_dict(bad)

        # None provider, created_at, updated_at handled safely
        nullable = dict(base)
        nullable["provider"] = None
        nullable["created_at"] = None
        nullable["updated_at"] = None
        acc = Account.from_dict(nullable)
        self.assertEqual(acc.provider, "ChatGPT")
        self.assertGreater(acc.created_at, 0.0)

        for invalid_q in (-1, 101, 50.5, True, "50"):
            with self.assertRaises(ValueError):
                validate_quota(invalid_q, "q")  # type: ignore[arg-type]

    def test_epoch_zero_timestamps_and_invalid_warranty_days(self) -> None:
        # Epoch 0.0 timestamps must be preserved (not overwritten by time.time())
        base = Account.create("基线", "e0@t.com", "pw", "123456").to_dict()
        base["created_at"] = 0.0
        base["updated_at"] = 0.0
        acc0 = Account.from_dict(base)
        self.assertEqual(acc0.created_at, 0.0)
        self.assertEqual(acc0.updated_at, 0.0)

        # End-to-end LWW merge: epoch-0 remote must NOT override newer local record
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            local_acc = Account.create("本地较新", "lww@t.com", "pw_local", "123456", now_ts=1_700_000_000.0)
            remote_dict = local_acc.to_dict()
            remote_dict["name"] = "远端零纪元"
            remote_dict["created_at"] = 0.0
            remote_dict["updated_at"] = 0.0
            backup_path = Path(tmp) / "epoch0.json"
            backup_path.write_text(json.dumps({"schema_version": 2, "accounts": [remote_dict]}), encoding="utf-8")
            merged, added, updated, kept = storage.import_backup_merge(backup_path, [local_acc])
            self.assertEqual((added, updated, kept), (0, 0, 1))
            self.assertEqual(merged[0].name, "本地较新")
            self.assertEqual(merged[0].updated_at, 1_700_000_000.0)

        # Non-finite or negative warranty_days and non-finite warranty_expire_at must fail fast
        for bad_days in (-1.0, float("inf"), -float("inf"), float("nan"), True):
            with self.assertRaises(ValueError, msg=f"warranty_days={bad_days!r} should fail"):
                Account.create("质保异常", "w@t.com", "pw", "123456", warranty_days=bad_days)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Account(
                id="badw",
                name="质保无限",
                email="wi@t.com",
                password="pw",
                two_fa="123456",
                warranty_expire_at=float("inf"),
            )


class TestM3AdversarialLauncherAndPaste(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_totp_exact_3s_boundaries_and_nan_rejection(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        expected = {
            26.0: (4, False),
            26.9: (4, False),
            27.0: (3, True),
            27.1: (3, True),
            29.9: (1, True),
            30.0: (30, False),
        }
        for ts, (exp_rem, exp_soon) in expected.items():
            code, rem, nxt, soon = compute_totp_with_safety(secret, min_remaining_sec=3, for_time=ts)
            self.assertIsNotNone(code)
            self.assertEqual(rem, exp_rem)
            self.assertEqual(soon, exp_soon)
            self.assertIsNotNone(nxt)

        for bad_t in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                compute_totp_with_safety(secret, for_time=bad_t)

    def test_proxy_url_and_reserved_names_and_empty_localappdata(self) -> None:
        for bad in (
            "http://127.0.0.1:7890,direct://",
            "http://127.0.0.1:7890\x00",
            "http://[::1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
        ):
            with self.assertRaises(ValueError, msg=f"Failed to reject {bad!r}"):
                validate_proxy_url(bad)
        self.assertEqual(validate_proxy_url("http://[::1]:7890"), "http://[::1]:7890")

        with mock.patch.dict(os.environ, {"LOCALAPPDATA": ""}, clear=False):
            paths = _candidate_browser_paths()
            self.assertTrue(all(p.is_absolute() for p in paths))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_exe = tmp_path / "msedge.exe"
            fake_exe.write_bytes(b"MZ")
            for bad_id in ("CON", "con", "PRN", "AUX", "NUL", "COM1", "LPT9", "中文"):
                acc = Account.create("测试", "t@t.com", "pw", "123456")
                acc.id = bad_id
                with self.assertRaises(ValueError, msg=f"Failed to reject id={bad_id!r}"):
                    build_isolated_browser_args(acc, tmp_path / "profiles", str(fake_exe))

    def test_paste_advance_totp_wait_launch_order_and_2fa_debounce(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        acc = Account.create("测试号", "q@t.com", "pw123", secret)
        ctrl = SequentialPasteController(burn_seconds=5)
        cb = QApplication.clipboard()
        cb.setText("USER_CLIPBOARD")

        # IDLE advance is safe no-op
        ctrl.advance()
        self.assertEqual(ctrl.state, "IDLE")
        self.assertEqual(cb.text(), "USER_CLIPBOARD")

        # Simulate STEP_3_TOTP_WAIT -> advance() cancels cleanly to IDLE
        ctrl.start(acc)
        ctrl.advance()
        self.assertEqual(ctrl.state, "STEP_2_PASSWORD")
        with mock.patch("src.launcher.compute_totp_with_safety", return_value=("123456", 2, "654321", True)):
            ctrl.copy_step_totp(now_ts=None)
        self.assertEqual(ctrl.state, "STEP_3_TOTP_WAIT")
        ctrl.advance()
        self.assertEqual(ctrl.state, "IDLE")
        self.assertFalse(ctrl._wait_timer.isActive())

        # Rapid double-trigger of copy_two_fa_with_expiry_guard cancels prior timer
        calls = []
        with mock.patch("src.launcher.compute_totp_with_safety", return_value=("111111", 1, "222222", True)):
            copy_two_fa_with_expiry_guard(acc, on_done=lambda v, t, w: calls.append(v), min_remaining_sec=3)
            copy_two_fa_with_expiry_guard(acc, on_done=lambda v, t, w: calls.append(v), min_remaining_sec=3)
        # Wait long enough for 1.2s timer via Qt event loop
        deadline = time.time() + 1.5
        while time.time() < deadline and not calls:
            QApplication.processEvents()
            time.sleep(0.02)
        self.assertEqual(len(calls), 1)

        # MainWindow._on_launch_isolated_and_paste must NOT start paste_ctrl if browser launch fails
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            storage.save_accounts([acc])
            win = MainWindow(storage)
            try:
                cb.setText("CLEAN_BEFORE")
                with mock.patch("src.main_window.launch_isolated_browser", side_effect=FileNotFoundError("no browser")), \
                     mock.patch("src.main_window.QMessageBox.warning"):
                    win._on_launch_isolated_and_paste(acc.id)
                self.assertEqual(win.paste_ctrl.state, "IDLE")
                self.assertEqual(cb.text(), "CLEAN_BEFORE")
            finally:
                win.close()


class TestM4AdversarialOcrAndCodexVault(unittest.TestCase):
    def test_ocr_text_anomalies_fixed(self) -> None:
        # 2d 5h in weekly section must NOT steal weekly quota
        r1 = parse_quota_from_ocr_text("Weekly limit\nResets in 2d 5h\n60% left")
        self.assertIsNone(r1.five_hour_quota)
        self.assertEqual(r1.weekly_quota, 60)
        self.assertEqual(r1.weekly_reset_seconds, 2 * 86400 + 5 * 3600)

        # 7d standalone
        r2 = parse_quota_from_ocr_text("7d limit: 80% left")
        self.assertIsNone(r2.five_hour_quota)
        self.assertEqual(r2.weekly_quota, 80)
        self.assertIsNone(r2.weekly_reset_seconds)

        # Decimal 42.5% -> 42 (not 5)
        r3 = parse_quota_from_ocr_text("5h: 42.5% left")
        self.assertEqual(r3.five_hour_quota, 42)

        # Negative -10% rejected
        r4 = parse_quota_from_ocr_text("5h: -10% left")
        self.assertIsNone(r4.five_hour_quota)

        # Wall-clock time at 14:30 ignored
        r5 = parse_quota_from_ocr_text("Weekly limit: 50% left\nResets at 14:30")
        self.assertEqual(r5.weekly_quota, 50)
        self.assertIsNone(r5.weekly_reset_seconds)

        # 15h does not collide with 5h anchor
        r6 = parse_quota_from_ocr_text("15h limit: 50% left\n5h limit: 90% left")
        self.assertEqual(r6.five_hour_quota, 90)

        # Bare "5h 80% left" not treated as 5h reset countdown
        r7 = parse_quota_from_ocr_text("5h 80% left")
        self.assertEqual(r7.five_hour_quota, 80)
        self.assertIsNone(r7.weekly_reset_seconds)

        # Gibberish
        r8 = parse_quota_from_ocr_text("random gibberish without percentages")
        self.assertFalse(r8.has_any_value)

        # Chinese multi-line WinRT OCR spacing must preserve newlines and separate 5h / weekly lines
        r9 = parse_quota_from_ocr_text("5 小 时 限 制 75% 剩 余\n每 周 限 制 40 ％ 剩 余\n3 天 5 小 时 后 重 置")
        self.assertEqual(r9.five_hour_quota, 75)
        self.assertEqual(r9.weekly_quota, 40)
        self.assertEqual(r9.weekly_reset_seconds, 3 * 86400 + 5 * 3600)

        # Chinese multi-line with 5h countdown before weekly section must not contaminate weekly reset
        r10 = parse_quota_from_ocr_text("5小时限制\n75% 剩余\n2小时10分钟后重置\n每周限制\n40% 剩余\n3天5小时后重置")
        self.assertEqual(r10.five_hour_quota, 75)
        self.assertEqual(r10.weekly_quota, 40)
        self.assertEqual(r10.weekly_reset_seconds, 3 * 86400 + 5 * 3600)

        # Multi-day reset formats ("2 days, 5 hours", "2d  5h") must not match _FIVE_H_ANCHOR
        r11 = parse_quota_from_ocr_text("Weekly limit\nResets in 2 days, 5 hours\n60% left")
        self.assertIsNone(r11.five_hour_quota)
        self.assertEqual(r11.weekly_quota, 60)
        self.assertEqual(r11.weekly_reset_seconds, 2 * 86400 + 5 * 3600)

        r12 = parse_quota_from_ocr_text("Weekly limit\nResets in 2d  5h\n60% left")
        self.assertIsNone(r12.five_hour_quota)
        self.assertEqual(r12.weekly_quota, 60)
        self.assertEqual(r12.weekly_reset_seconds, 2 * 86400 + 5 * 3600)

        # 5h countdown before weekly section when weekly has no reset must not be stolen
        r13 = parse_quota_from_ocr_text("5h limit: 75% left\nResets in 2h 10m\nWeekly limit: 40% left")
        self.assertEqual(r13.five_hour_quota, 75)
        self.assertEqual(r13.weekly_quota, 40)
        self.assertIsNone(r13.weekly_reset_seconds)

        # Bare wall-clock times without "at"/"on" ("Resets 14:30", "重置 14:30") ignored
        r14 = parse_quota_from_ocr_text("Weekly limit: 50% left\nResets 14:30")
        self.assertEqual(r14.weekly_quota, 50)
        self.assertIsNone(r14.weekly_reset_seconds)
        r15 = parse_quota_from_ocr_text("每周限制: 50% 剩余\n重置 14:30")
        self.assertEqual(r15.weekly_quota, 50)
        self.assertIsNone(r15.weekly_reset_seconds)

        # Zero network imports in src/ocr_sync.py
        import ast
        ocr_src = (Path(__file__).resolve().parent.parent / "src" / "ocr_sync.py").read_text(encoding="utf-8")
        tree = ast.parse(ocr_src)
        imported_mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_mods.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_mods.add(node.module.split(".")[0])
        self.assertEqual(imported_mods & {"urllib", "requests", "http", "socket", "httpx", "aiohttp"}, set())

    def test_winrt_ocr_invalid_lang_fallback_and_corrupt_png(self) -> None:
        font = ImageFont.truetype("C:/Windows/Fonts/msyh.ttc", 22)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "light_en.png"
            img = Image.new("RGB", (520, 140), "#FFFFFF")
            d = ImageDraw.Draw(img)
            d.text((20, 20), "5-hour limit: 75% left", fill="#111827", font=font)
            d.text((20, 70), "Weekly limit: 40% left", fill="#111827", font=font)
            img.save(p)

            # Invalid lang_tag should fall back cleanly to installed OCR language
            txt = run_windows_ocr(p, lang_tag="invalid-lang-tag-999")
            res = parse_quota_from_ocr_text(txt)
            self.assertEqual(res.five_hour_quota, 75)
            self.assertEqual(res.weekly_quota, 40)

            bad_png = Path(tmp) / "corrupt.png"
            bad_png.write_bytes(b"NOT_A_PNG_FILE_123456")
            with self.assertRaises(RuntimeError):
                run_windows_ocr(bad_png)

            # Real WinRT Chinese multi-line screenshot (light mode)
            p_zh = Path(tmp) / "light_zh.png"
            img_zh = Image.new("RGB", (560, 190), "#FFFFFF")
            dz = ImageDraw.Draw(img_zh)
            dz.text((20, 20), "5小时限制 75% 剩余", fill="#111827", font=font)
            dz.text((20, 70), "每周限制 40% 剩余", fill="#111827", font=font)
            dz.text((20, 120), "3天5小时后重置", fill="#111827", font=font)
            img_zh.save(p_zh)
            txt_zh = run_windows_ocr(p_zh, lang_tag="zh-Hans-CN")
            res_zh = parse_quota_from_ocr_text(txt_zh)
            self.assertEqual(res_zh.five_hour_quota, 75)
            self.assertEqual(res_zh.weekly_quota, 40)
            self.assertEqual(res_zh.weekly_reset_seconds, 3 * 86400 + 5 * 3600)

    def test_codex_vault_bom_plaintext_collision_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            codex_dir = base / ".codex"
            codex_dir.mkdir()
            mgr = CodexAuthManager(vault_dir=base / "vault", codex_home=codex_dir)

            # Clean ID preserves exact filename
            self.assertEqual(mgr.snapshot_path("acc_one").name, "acc_one.codex.enc")
            # Sanitized IDs never collide
            p1 = mgr.snapshot_path("a:1")
            p2 = mgr.snapshot_path("a/1")
            self.assertNotEqual(p1, p2)

            # UTF-8 BOM auth.json capture + activate roundtrip
            bom_json = json.dumps({"access_token": "tok_bom"}).encode("utf-8-sig")
            # Explicitly prepend UTF-8 BOM
            (codex_dir / "auth.json").write_bytes(b"\xef\xbb\xbf" + json.dumps({"access_token": "tok_bom"}).encode("utf-8"))
            mgr.capture_current_auth("bom_acc")
            mgr.activate_snapshot("bom_acc")
            self.assertEqual(json.loads((codex_dir / "auth.json").read_text(encoding="utf-8"))["access_token"], "tok_bom")

            # Empty or unencrypted plaintext .codex.enc must raise SecurityError
            snap_plain = mgr.snapshot_path("plain_acc")
            snap_plain.write_text('{"access_token": "steal"}', encoding="utf-8")
            with self.assertRaises(SecurityError):
                mgr.activate_snapshot("plain_acc")

            snap_empty = mgr.snapshot_path("empty_acc")
            snap_empty.write_text("", encoding="utf-8")
            with self.assertRaises(SecurityError):
                mgr.activate_snapshot("empty_acc")

            # Failed os.replace leaves auth.json intact and cleans temp file
            with mock.patch("os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    mgr.activate_snapshot("bom_acc")
            self.assertEqual(json.loads((codex_dir / "auth.json").read_text(encoding="utf-8"))["access_token"], "tok_bom")
            self.assertEqual(list(codex_dir.glob("*.tmp")), [])


class TestM5M6AdversarialHudWarrantyNotifierCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_providers_warranty_banned_roi_and_claim_slip_edges(self) -> None:
        for p in ("ChatGPT", "Claude", "Codex", "Custom", "", "   ", None):
            self.assertIn(validate_provider(p), ("ChatGPT", "Claude", "Codex", "Custom"))
        self.assertEqual(validate_provider("   "), "ChatGPT")
        self.assertEqual(validate_provider(None), "ChatGPT")
        with self.assertRaises(ValueError):
            validate_provider("UnknownPlat")

        t0 = 1_700_000_000.0
        banned_w = Account.create("封禁质保", "bw@t.com", "pw", "123456", warranty_days=0.5, health_status="BANNED", now_ts=t0)
        active_w = Account.create("正常质保", "aw@t.com", "pw", "123456", warranty_days=0.5, health_status="ACTIVE", now_ts=t0)
        expiring = check_warranty_expiring_accounts([banned_w, active_w], hours_threshold=24, now_ts=t0 + 60)
        self.assertEqual([a.id for a in expiring], [active_w.id])

        # DEGRADED_POW included in after-sales slip; NaN/Inf now_ts must not mislabel active warranty as expired
        degraded_w = Account.create("降智质保", "dw@t.com", "pw", "123456", warranty_days=1.0, health_status="DEGRADED_POW", now_ts=t0)
        slip_nan = format_after_sales_slip([degraded_w], now_ts=float("nan"))
        self.assertIn("dw@t.com", slip_nan)
        self.assertNotIn("已过质保期", slip_nan)
        self.assertIn("质保状态未知", slip_nan)
        slip_inf = format_after_sales_slip([degraded_w], now_ts=float("inf"))
        self.assertNotIn("已过质保期", slip_inf)

        # Negative created_at and infinite warranty_expire_at must not crash slip formatting
        weird = Account.create("奇葩售后", "w@t.com", "pw", "123456", health_status="BANNED", vendor_tag="=CMD()", now_ts=t0)
        weird.created_at = -100.0
        weird.warranty_expire_at = float("inf")
        slip = format_after_sales_slip([weird], now_ts=t0 + 10)
        self.assertIn("未知日期", slip)
        self.assertIn("w@t.com----pw----123456", slip)

        # ROI edge cases
        self.assertEqual(compute_vendor_roi_stats([]), [])
        zero_acc = Account.create("零价", "z@t.com", "pw", "123456", purchase_price=0.0)
        roi = compute_vendor_roi_stats([weird, zero_acc])
        self.assertEqual(len(roi), 2)

    def test_minihud_skips_phone_verify_honors_provider_filter_and_truncates(self) -> None:
        t0 = 1_700_000_000.0
        hud = MiniHudWindow(lambda: None, lambda: None, lambda: None, lambda: None)
        try:
            hud.refresh_snapshot([], now_ts=t0)
            self.assertEqual(hud.title_lbl.text(), "无可用账号")

            pv = Account.create("VerifyMe", "pv@t.com", "pw", "123456", health_status="PHONE_VERIFY", now_ts=t0)
            pv.five_hour_reset_at = t0 + 500
            banned = Account.create("BannedAcc", "ban@t.com", "pw", "123456", health_status="BANNED", now_ts=t0)
            disabled = Account.create("DisabledAcc", "dis@t.com", "pw", "123456", health_status="ACTIVE", now_ts=t0)
            disabled.health_status = "DISABLED"
            claude_urg = Account.create("CLUrgent", "cl@t.com", "pw", "123456", provider="Claude", weekly_quota=90, weekly_reset_duration_seconds=3600, now_ts=t0)
            gpt_ok = Account.create("G" * 50, "gp@t.com", "pw", "123456", provider="ChatGPT", weekly_quota=50, weekly_reset_duration_seconds=7200, now_ts=t0)

            # Should NOT pick PHONE_VERIFY cooling; with provider_filter="ChatGPT", must pick gpt_ok and truncate badge
            hud.refresh_snapshot([pv, claude_urg, gpt_ok], now_ts=t0, provider_filter="ChatGPT")
            self.assertTrue(hud.title_lbl.text().startswith("[ChatGPT]"))
            self.assertLessEqual(len(hud.title_lbl.text()), 18)

            # Focused BANNED / DISABLED / PHONE_VERIFY account must be skipped in favor of healthy fallback
            for unhealthy in (banned, disabled, pv):
                hud.refresh_snapshot([unhealthy, gpt_ok], focused_account_id=unhealthy.id, now_ts=t0)
                self.assertTrue(hud.title_lbl.text().startswith("[ChatGPT] GGG"))

            # Unknown provider_filter must not raise uncaught ValueError
            hud.refresh_snapshot([gpt_ok], now_ts=t0, provider_filter="UnknownProvider")
            self.assertEqual(hud.title_lbl.text(), "无可用账号")
        finally:
            hud.close()

    def test_notifier_escapes_powershell_dollar_injection(self) -> None:
        captured_cmds = []

        def _fake_run(cmd, **_kwargs):
            captured_cmds.append(cmd)
            return mock.MagicMock(returncode=0)

        title_payload = 'Title \u201c$env:USER\u201d \u201e`calc`\u201d'
        msg_payload = 'bad\u201d); Write-Output "INJECTED"; #\n$(whoami)\r\nline2'
        app_payload = 'App\u201cName\u201d'

        with mock.patch("src.notifier.subprocess.run", side_effect=_fake_run), \
             mock.patch("src.notifier.sys.platform", "win32"):
            ok = send_windows_toast(title_payload, msg_payload, app_payload)
        self.assertTrue(ok)
        self.assertEqual(len(captured_cmds), 1)
        ps_script = captured_cmds[0][-1]
        # Raw payloads must NOT be interpolated into PowerShell script; UTF-8 Base64 decoding is used instead
        self.assertNotIn("$(whoami)", ps_script)
        self.assertNotIn("$env:USER", ps_script)
        self.assertNotIn("\u201d", ps_script)
        self.assertIn("FromBase64String(", ps_script)

        # Verify in real Windows PowerShell 5.1 that decoded strings round-trip identically with zero injection
        b64_literals = re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", ps_script)
        self.assertEqual(len(b64_literals), 3)
        probe_ps = (
            f"$t = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_literals[0]}')); "
            f"$m = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_literals[1]}')); "
            f"$a = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_literals[2]}')); "
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($t))); "
            "Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($m))); "
            "Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($a)))"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", probe_ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out_lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(out_lines), 3)
        self.assertEqual(base64.b64decode(out_lines[0]).decode("utf-8"), title_payload)
        self.assertEqual(base64.b64decode(out_lines[1]).decode("utf-8"), msg_payload)
        self.assertEqual(base64.b64decode(out_lines[2]).decode("utf-8"), app_payload)

    def test_cli_check_notify_corrupt_json_and_toast_failure_non_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            storage.accounts_file.write_text("{corrupt_json_not_valid", encoding="utf-8")
            code = app_main.run_background_notification_check(storage)
            self.assertEqual(code, 1)
            events = [e.event for e in storage.logger.read_recent()]
            self.assertIn("BG_NOTIFY_LOAD_ERROR", events)

            # Failed toast must NOT mark weekly_notified_reset_at / warranty_notified_at
            t0 = 1_700_000_000.0
            acc = Account.create(
                "未送达", "fail@t.com", "pw", "123456",
                weekly_quota=50, weekly_reset_duration_seconds=3600,
                warranty_days=0.5, now_ts=t0,
            )
            storage.save_accounts([acc])
            with mock.patch("src.notifier.send_windows_toast", return_value=False), \
                 mock.patch("time.time", return_value=t0 + 60):
                code2 = app_main.run_background_notification_check(storage)
            self.assertEqual(code2, 0)
            reloaded = storage.load_accounts()
            self.assertIsNone(reloaded[0].weekly_notified_reset_at)
            self.assertIsNone(reloaded[0].warranty_notified_at)

        # Corrupt settings.json under --check-notify must log BG_NOTIFY_SETTINGS_ERROR and exit 1
        with tempfile.TemporaryDirectory() as tmp_set:
            storage_set = AccountStorage(Path(tmp_set))
            storage_set.settings_file.write_text("{corrupt_settings_json", encoding="utf-8")
            code_set = app_main.run_background_notification_check(storage_set)
            self.assertEqual(code_set, 1)
            events_set = [e.event for e in storage_set.logger.read_recent()]
            self.assertIn("BG_NOTIFY_SETTINGS_ERROR", events_set)


if __name__ == "__main__":
    unittest.main(verbosity=2)
