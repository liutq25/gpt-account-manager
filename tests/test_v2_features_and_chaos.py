"""
Comprehensive functional & adversarial ("weird user" chaos) test suite for v2.0 modules:
- M1: Windows DPAPI at-rest encryption, legacy v1 plaintext auto-upgrade, AES-256-GCM portable backup,
      tamper detection, LWW multi-device merge, and live local HTTP WebDAV server roundtrip.
- M2: EEQF dual-window anti-waste scheduler, health-status filtering/weighting, provider scoping,
      and 14-day discrete-event Monte Carlo simulation proving waste reduction.
- M3: Chromium isolated profile & proxy builder, command-injection blocking, 3-step sequential paste
      state machine, TOTP <=3s expiry guard, and user-clipboard-safe auto-burn.
- M4: Real Windows 11 WinRT `Windows.Media.Ocr` execution on light/dark English/Chinese images,
      blank/corrupt image resilience, and `~/.codex/auth.json` encrypted vault hot-switching.
- M5/M6: Multi-platform (`ChatGPT`/`Claude`/`Codex`), banned account blocking, warranty notifications,
      zero-division-safe vendor ROI table, after-sales slip export, and Mini HUD lifecycle.
"""

from __future__ import annotations

import base64
import json
import math
import os
import random
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image, ImageDraw, ImageFont
from PyQt5.QtWidgets import QApplication

import main as app_main
from src.dialogs import AccountDialog, OcrConfirmDialog, PassphraseDialog, SettingsDialog
from src.launcher import (
    SequentialPasteController,
    build_isolated_browser_args,
    detect_chromium_browser,
)
from src.main_window import MainWindow
from src.models import (
    FIVE_HOURS_SECONDS,
    Account,
    check_warranty_expiring_accounts,
    check_weekly_expiring_accounts,
    compute_totp_with_safety,
    compute_vendor_roi_stats,
    format_after_sales_slip,
    select_optimal_account,
    validate_price,
    validate_proxy_url,
)
from src.ocr_sync import CodexAuthManager, parse_quota_from_ocr_text, run_windows_ocr
from src.security import (
    DPAPI_PREFIX,
    SecurityError,
    decrypt_portable_payload,
    dpapi_decrypt,
    dpapi_encrypt,
    encrypt_portable_payload,
)
from src.storage import AccountStorage, AppSettings


class _InMemoryWebDavHandler(BaseHTTPRequestHandler):
    store: Dict[str, bytes] = {}
    expected_auth: str = ""

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass  # Silence HTTP test logs

    def _check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth != self.expected_auth:
            self.send_response(401)
            self.end_headers()
            return False
        return True

    def do_PUT(self) -> None:
        if not self._check_auth():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.__class__.store[self.path] = body
        self.send_response(201)
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_auth():
            return
        if self.path not in self.__class__.store:
            self.send_response(404)
            self.end_headers()
            return
        data = self.__class__.store[self.path]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestM1SecurityEncryptionAndWebDav(unittest.TestCase):
    def test_dpapi_at_rest_no_plaintext_leak_and_idempotency(self) -> None:
        secret = "MySuper$ecretPwd!2026"
        enc1 = dpapi_encrypt(secret)
        self.assertTrue(enc1.startswith(DPAPI_PREFIX))
        self.assertNotIn(secret, enc1)
        # Idempotent when called repeatedly
        enc2 = dpapi_encrypt(enc1)
        self.assertEqual(enc1, enc2)
        self.assertEqual(dpapi_decrypt(enc1), secret)

        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            acc = Account.create(
                name="加密测试号",
                email="sec@test.com",
                password="RawPassword#999",
                two_fa="JBSWY3DPEHPK3PXP",
            )
            settings = AppSettings(webdav_password="WebDavSecretAppPwd")
            storage.save_accounts([acc])
            storage.save_settings(settings)

            # In-memory object must remain usable plaintext
            self.assertEqual(acc.password, "RawPassword#999")

            # Raw disk files MUST NOT contain plaintext secrets
            disk_acc_raw = storage.accounts_file.read_text(encoding="utf-8")
            self.assertNotIn("RawPassword#999", disk_acc_raw)
            self.assertNotIn("JBSWY3DPEHPK3PXP", disk_acc_raw)
            self.assertIn(DPAPI_PREFIX, disk_acc_raw)

            disk_set_raw = storage.settings_file.read_text(encoding="utf-8")
            self.assertNotIn("WebDavSecretAppPwd", disk_set_raw)

            reloaded = storage.load_accounts()
            self.assertEqual(reloaded[0].password, "RawPassword#999")
            self.assertEqual(reloaded[0].two_fa, "JBSWY3DPEHPK3PXP")
            self.assertEqual(storage.load_settings().webdav_password, "WebDavSecretAppPwd")

    def test_legacy_v1_plaintext_file_auto_upgrades_to_dpapi(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            legacy_v1 = {
                "schema_version": 1,
                "accounts": [
                    {
                        "id": "legacy001",
                        "name": "老版本明文号",
                        "email": "old@v1.com",
                        "password": "LegacyPlainPassword",
                        "two_fa": "112233",
                        "five_hour_quota": 80,
                        "five_hour_reset_at": None,
                        "weekly_quota": 90,
                        "weekly_reset_at": None,
                    }
                ],
            }
            storage.accounts_file.write_text(json.dumps(legacy_v1), encoding="utf-8")

            loaded = storage.load_accounts()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].password, "LegacyPlainPassword")
            self.assertEqual(loaded[0].provider, "ChatGPT")
            self.assertEqual(loaded[0].health_status, "ACTIVE")

            # Verify transparent upgrade on disk
            upgraded_raw = storage.accounts_file.read_text(encoding="utf-8")
            self.assertNotIn("LegacyPlainPassword", upgraded_raw)
            self.assertIn(DPAPI_PREFIX, upgraded_raw)

    def test_portable_aes_gcm_backup_tamper_and_wrong_passphrase(self) -> None:
        payload = {"accounts": [{"email": "a@b.com"}]}
        with self.assertRaises(ValueError):
            encrypt_portable_payload(payload, "12")  # Too short
        with self.assertRaises(ValueError):
            encrypt_portable_payload(payload, "     ")  # Whitespace only

        enc_str = encrypt_portable_payload(payload, "CorrectHorseBattery")
        self.assertNotIn("a@b.com", enc_str)

        # Wrong passphrase
        with self.assertRaises(SecurityError):
            decrypt_portable_payload(enc_str, "WrongPassphrase")

        # Tamper 1 byte of ciphertext
        env = json.loads(enc_str)
        raw_ct = bytearray(base64.b64decode(env["ciphertext"]))
        raw_ct[0] ^= 0xFF
        env["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")
        with self.assertRaises(SecurityError):
            decrypt_portable_payload(json.dumps(env), "CorrectHorseBattery")

    def test_webdav_live_http_server_e2ee_push_pull_and_lww_merge(self) -> None:
        _InMemoryWebDavHandler.store.clear()
        token = base64.b64encode(b"dav_user:dav_pass").decode("ascii")
        _InMemoryWebDavHandler.expected_auth = f"Basic {token}"

        server = HTTPServer(("127.0.0.1", 0), _InMemoryWebDavHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as dir_a, tempfile.TemporaryDirectory() as dir_b:
                store_a = AccountStorage(Path(dir_a))
                store_b = AccountStorage(Path(dir_b))
                settings = AppSettings(
                    webdav_url=f"http://127.0.0.1:{port}/dav",
                    webdav_username="dav_user",
                    webdav_password="dav_pass",
                )

                acc1_old = Account.create("一号", "u1@test.com", "pw1", "2fa1", five_hour_quota=90, now_ts=1000.0)
                acc2_new = Account.create("二号", "u2@test.com", "pw2", "2fa2", five_hour_quota=25, now_ts=3000.0)
                store_a.push_to_webdav([acc1_old, acc2_new], settings, "SyncKey#2026")

                # Verify server only received encrypted ciphertext
                stored_bytes = next(iter(_InMemoryWebDavHandler.store.values())).decode("utf-8")
                self.assertNotIn("pw1", stored_bytes)
                self.assertNotIn("u1@test.com", stored_bytes)

                # Device B has a NEWER version of acc1 (ts=2000), an OLDER version of acc2 (ts=1500), and local acc3
                b_acc1 = Account.create("一号改", "u1@test.com", "pw1_b", "2fa1", five_hour_quota=40, now_ts=2000.0)
                b_acc1.id = acc1_old.id
                b_acc2 = Account.create("二号旧", "u2@test.com", "pw2", "2fa2", five_hour_quota=80, now_ts=1500.0)
                b_acc2.id = acc2_new.id
                b_acc3 = Account.create("三号本地", "u3@test.com", "pw3", "2fa3", five_hour_quota=100, now_ts=1800.0)

                # Wrong sync passphrase must fail
                with self.assertRaises(SecurityError):
                    store_b.pull_from_webdav([b_acc1, b_acc2, b_acc3], settings, "WrongKey999")

                merged, added, updated, kept = store_b.pull_from_webdav(
                    [b_acc1, b_acc2, b_acc3], settings, "SyncKey#2026"
                )
                self.assertEqual(len(merged), 3)
                self.assertEqual(added, 0)
                self.assertEqual(updated, 1)  # acc2 updated from remote (ts 3000 > 1500)
                self.assertEqual(kept, 1)     # acc1 kept local (ts 2000 > 1000)
                by_email = {a.email: a for a in merged}
                self.assertEqual(by_email["u1@test.com"].five_hour_quota, 40)
                self.assertEqual(by_email["u2@test.com"].five_hour_quota, 25)

                # Bad HTTP auth must raise SecurityError
                bad_settings = AppSettings(
                    webdav_url=f"http://127.0.0.1:{port}/dav",
                    webdav_username="dav_user",
                    webdav_password="wrong_http_password",
                )
                with self.assertRaises(SecurityError):
                    store_b.pull_from_webdav(merged, bad_settings, "SyncKey#2026")
        finally:
            server.shutdown()
            server.server_close()


class TestM2EEQFSchedulerAndSimulation(unittest.TestCase):
    def test_eeqf_ranking_skips_banned_and_prioritizes_expiring_weekly(self) -> None:
        t0 = 1_700_000_000.0
        # High weekly quota & 2h left, BUT BANNED -> must be skipped!
        acc_banned = Account.create(
            "封禁号", "ban@t.com", "p", "2f", weekly_quota=95,
            weekly_reset_duration_seconds=2 * 3600, health_status="BANNED", now_ts=t0,
        )
        # Needs phone verify -> must be skipped!
        acc_phone = Account.create(
            "待接码号", "ph@t.com", "p", "2f", weekly_quota=95,
            weekly_reset_duration_seconds=2 * 3600, health_status="PHONE_VERIFY", now_ts=t0,
        )
        # 80% weekly left, 6 days until reset -> urgency = 80 / 144 = 0.55%/h
        acc_relaxed = Account.create(
            "宽裕号", "rel@t.com", "p", "2f", weekly_quota=80,
            weekly_reset_duration_seconds=6 * 86400, now_ts=t0,
        )
        # 50% weekly left, 4 hours until reset -> urgency = 50 / 4 = 12.5%/h (MOST URGENT!)
        acc_urgent = Account.create(
            "临期紧急号", "urg@t.com", "p", "2f", weekly_quota=50,
            weekly_reset_duration_seconds=4 * 3600, now_ts=t0,
        )
        # Same 50% & 4h, but DEGRADED_POW -> weighted 0.5x = 6.25%/h
        acc_degraded = Account.create(
            "降智号", "deg@t.com", "p", "2f", weekly_quota=50,
            weekly_reset_duration_seconds=4 * 3600, health_status="DEGRADED_POW", now_ts=t0,
        )

        rec = select_optimal_account(
            [acc_banned, acc_phone, acc_relaxed, acc_degraded, acc_urgent], now_ts=t0
        )
        self.assertEqual(rec.status, "READY_NEW_5H")
        self.assertEqual(rec.account.id, acc_urgent.id)

        # Provider filter test
        acc_claude = Account.create(
            "Claude主力", "cl@t.com", "p", "2f", provider="Claude", weekly_quota=40,
            weekly_reset_duration_seconds=10 * 3600, now_ts=t0,
        )
        rec_claude = select_optimal_account(
            [acc_urgent, acc_claude], provider="Claude", now_ts=t0
        )
        self.assertEqual(rec_claude.account.id, acc_claude.id)

    def test_eeqf_fallback_to_active_window_and_cooling_wait_estimate(self) -> None:
        t0 = 1_700_000_000.0
        acc = Account.create("单号", "s@t.com", "p", "2f", five_hour_quota=70, weekly_quota=80, now_ts=t0)
        acc.start_five_hour_usage(now_ts=t0)

        # Active 5h window still has 70% quota -> ACTIVE_WINDOW_REUSE
        rec_reuse = select_optimal_account([acc], now_ts=t0 + 60)
        self.assertEqual(rec_reuse.status, "ACTIVE_WINDOW_REUSE")
        self.assertEqual(rec_reuse.account.id, acc.id)

        # Exhaust 5h quota -> COOLING_DOWN with exact remaining seconds
        acc.update_five_hour_quota(0, now_ts=t0 + 100)
        rec_cool = select_optimal_account([acc], now_ts=t0 + 1000)
        self.assertEqual(rec_cool.status, "COOLING_DOWN")
        self.assertAlmostEqual(rec_cool.wait_seconds, FIVE_HOURS_SECONDS - 1000, places=1)

    def test_monte_carlo_simulation_eeqf_reduces_expired_weekly_waste(self) -> None:
        """Empirical verification of EEQF scheduler vs Random selection over 14 simulated days."""
        def _simulate(strategy: str) -> int:
            rng = random.Random(42)
            now = 1_700_000_000.0
            pool = [
                Account.create(
                    name=f"A{i}",
                    email=f"a{i}@sim.com",
                    password="p",
                    two_fa="123456",
                    five_hour_quota=100,
                    weekly_quota=rng.randint(40, 100),
                    weekly_reset_duration_seconds=rng.randint(6, 160) * 3600,
                    now_ts=now,
                )
                for i in range(8)
            ]
            wasted_weekly = 0
            # Step every 2 hours for 14 days (168 steps)
            for _step in range(168):
                now += 2 * 3600
                for a in pool:
                    if a.weekly_reset_at is not None and now >= a.weekly_reset_at:
                        wasted_weekly += a.weekly_quota
                    ev = a.tick(now)
                    if "AUTO_RESET_WEEKLY" in ev:
                        a.set_weekly_quota_and_timer(100, reset_duration_seconds=7 * 86400, now_ts=now)

                # Consume 2 sessions per 2-hour step
                for _req in range(2):
                    if strategy == "EEQF":
                        rec = select_optimal_account(pool, now_ts=now)
                        chosen = rec.account if rec.status in ("READY_NEW_5H", "ACTIVE_WINDOW_REUSE") else None
                    else:
                        avail = [a for a in pool if a.five_hour_quota > 0 and a.weekly_quota > 0]
                        chosen = rng.choice(avail) if avail else None

                    if chosen is not None:
                        if chosen.five_hour_reset_at is None:
                            chosen.start_five_hour_usage(now_ts=now)
                        chosen.update_five_hour_quota(max(0, chosen.five_hour_quota - 50), now_ts=now)
                        chosen.weekly_quota = max(0, chosen.weekly_quota - 10)
            return wasted_weekly

        waste_random = _simulate("RANDOM")
        waste_eeqf = _simulate("EEQF")
        self.assertLess(waste_eeqf, waste_random)


class TestM3LauncherProxySecurityAndPasteQueue(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_proxy_url_blocks_flag_injection_and_malformed_inputs(self) -> None:
        self.assertEqual(validate_proxy_url(""), "")
        self.assertEqual(validate_proxy_url("socks5://127.0.0.1:10808"), "socks5://127.0.0.1:10808")
        self.assertEqual(validate_proxy_url("http://proxy.local:7890"), "http://proxy.local:7890")

        malicious_inputs = [
            "http://127.0.0.1:7890 --remote-debugging-port=9222",
            "--no-sandbox",
            'http://127.0.0.1:7890" --headless',
            "ftp://127.0.0.1:21",
            "socks5://127.0.0.1:99999",
            "http://",
        ]
        for bad in malicious_inputs:
            with self.assertRaises(ValueError, msg=f"Failed to block: {bad}"):
                validate_proxy_url(bad)

    def test_custom_browser_path_validation_and_isolated_args(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Non-existent path
            with self.assertRaises(FileNotFoundError):
                detect_chromium_browser(str(tmp_path / "missing.exe"))

            # Non-.exe file (e.g., .bat script) must be rejected
            bad_script = tmp_path / "evil.bat"
            bad_script.write_text("echo hi", encoding="utf-8")
            with self.assertRaises(ValueError):
                detect_chromium_browser(str(bad_script))

            fake_browser = tmp_path / "msedge.exe"
            fake_browser.write_bytes(b"MZ")
            acc = Account.create(
                "隔离号", "iso@t.com", "pw", "123456",
                provider="Claude", proxy_url="socks5://127.0.0.1:1080",
            )
            args, prof_dir = build_isolated_browser_args(acc, tmp_path / "profiles", str(fake_browser))
            self.assertEqual(args[0], str(fake_browser.resolve()))
            self.assertIn(f"--user-data-dir={prof_dir}", args)
            self.assertIn("--proxy-server=socks5://127.0.0.1:1080", args)
            self.assertEqual(args[-1], "https://claude.ai/")

    def test_sequential_paste_totp_expiry_guard_and_safe_clipboard_burn(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        # At t=58s, only 2s left in [30..60) window -> expiring_soon must be True and next_code != cur_code
        cur_c, rem, next_c, expiring = compute_totp_with_safety(secret, min_remaining_sec=3, for_time=58.0)
        self.assertEqual(rem, 2)
        self.assertTrue(expiring)
        self.assertNotEqual(cur_c, next_c)

        acc = Account.create("队列号", "queue@test.com", "SecretPass!1", secret)
        ctrl = SequentialPasteController(burn_seconds=5)
        cb = QApplication.clipboard()

        # Step 1: Email
        ctrl.start(acc)
        self.assertEqual(ctrl.state, "STEP_1_EMAIL")
        self.assertEqual(cb.text(), "queue@test.com")

        # Step 2: Password
        ctrl.advance()
        self.assertEqual(ctrl.state, "STEP_2_PASSWORD")
        self.assertEqual(cb.text(), "SecretPass!1")

        # Step 3 at t=58.0 (expiring in 2s!) -> delivers NEXT window code synchronously when now_ts given
        ctrl.advance(now_ts=58.0)
        self.assertEqual(ctrl.state, "BURNING")
        self.assertEqual(cb.text(), next_c)

        # Weird User Case A: User copies their own text BEFORE burn timer fires -> MUST NOT wipe user's text!
        cb.setText("UserOwnImportantCode()")
        ctrl._on_burn_timeout()
        self.assertEqual(ctrl.state, "IDLE")
        self.assertEqual(cb.text(), "UserOwnImportantCode()")

        # Case B: Clipboard still holds sensitive password/2FA -> MUST wipe clipboard!
        ctrl.start(acc)
        ctrl.advance()  # Now clipboard has "SecretPass!1"
        self.assertEqual(cb.text(), "SecretPass!1")
        ctrl._on_burn_timeout()
        self.assertEqual(cb.text(), "")


class TestM4WinRtOcrAndCodexVault(unittest.TestCase):
    def test_winrt_ocr_light_and_dark_cjk_english_screenshots(self) -> None:
        font = ImageFont.truetype("C:/Windows/Fonts/msyh.ttc", 22)
        with tempfile.TemporaryDirectory() as tmp:
            # Dark mode Chinese screenshot
            dark_img = Image.new("RGB", (560, 190), "#0F172A")
            draw = ImageDraw.Draw(dark_img)
            draw.text((24, 20), "5小时额度：剩余 42%", fill="#F8FAFC", font=font)
            draw.text((24, 70), "周额度：已使用 15%", fill="#F8FAFC", font=font)
            draw.text((24, 120), "3天 6小时 20分钟后重置", fill="#93C5FD", font=font)
            p_dark = Path(tmp) / "dark_cn.png"
            dark_img.save(p_dark)

            raw_cn = run_windows_ocr(p_dark)
            res_cn = parse_quota_from_ocr_text(raw_cn)
            self.assertEqual(res_cn.five_hour_quota, 42)
            self.assertEqual(res_cn.weekly_quota, 85)  # 100 - 15% used!
            self.assertEqual(res_cn.weekly_reset_seconds, 3 * 86400 + 6 * 3600 + 20 * 60)

            # Blank image resilience (weird user snips empty wallpaper)
            blank_img = Image.new("RGB", (200, 100), "white")
            p_blank = Path(tmp) / "blank.png"
            blank_img.save(p_blank)
            raw_blank = run_windows_ocr(p_blank)
            res_blank = parse_quota_from_ocr_text(raw_blank)
            self.assertFalse(res_blank.has_any_value)

            # Empty 0-byte file must raise FileNotFoundError cleanly
            p_zero = Path(tmp) / "zero.png"
            p_zero.write_bytes(b"")
            with self.assertRaises(FileNotFoundError):
                run_windows_ocr(p_zero)

    def test_codex_cli_auth_vault_capture_and_atomic_switch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fake_codex = base / ".codex"
            fake_codex.mkdir()
            auth_file = fake_codex / "auth.json"

            mgr = CodexAuthManager(vault_dir=base / "vault", codex_home=fake_codex)

            # Unbound account switch must raise FileNotFoundError
            with self.assertRaises(FileNotFoundError):
                mgr.activate_snapshot("acc_one")

            # Capture Account 1
            auth_file.write_text(json.dumps({"access_token": "tok_AAA", "account": "1"}), encoding="utf-8")
            snap1 = mgr.capture_current_auth("acc_one")
            self.assertTrue(mgr.has_snapshot("acc_one"))
            self.assertNotIn("tok_AAA", snap1.read_text(encoding="utf-8"))  # DPAPI encrypted!

            # Capture Account 2
            auth_file.write_text(json.dumps({"access_token": "tok_BBB", "account": "2"}), encoding="utf-8")
            mgr.capture_current_auth("acc_two")

            # Switch back to Account 1 and verify backup + atomic content
            mgr.activate_snapshot("acc_one")
            active_data = json.loads(auth_file.read_text(encoding="utf-8"))
            bak_data = json.loads((fake_codex / "auth.json.bak").read_text(encoding="utf-8"))
            self.assertEqual(active_data["access_token"], "tok_AAA")
            self.assertEqual(bak_data["access_token"], "tok_BBB")


class TestM5M6WarrantyRoiMiniHudAndWeirdInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_weird_price_and_banned_account_invariants(self) -> None:
        for bad_price in (-0.01, float("nan"), float("inf"), -float("inf"), True):
            with self.assertRaises(ValueError):
                validate_price(bad_price)  # type: ignore[arg-type]

        t0 = 1_700_000_000.0
        banned_acc = Account.create(
            "封禁测试", "b@t.com", "pw", "123456",
            five_hour_quota=100, weekly_quota=90,
            weekly_reset_duration_seconds=5 * 3600,
            purchase_price=55.0, warranty_days=7.0,
            vendor_tag="渠道X", health_status="BANNED", now_ts=t0,
        )
        can_start, reason = banned_acc.can_start_five_hour_usage
        self.assertFalse(can_start)
        self.assertIn("已封禁", reason)
        with self.assertRaises(ValueError):
            banned_acc.start_five_hour_usage(now_ts=t0)

        # Banned account must NOT trigger weekly expiring usage notification!
        self.assertEqual(check_weekly_expiring_accounts([banned_acc], now_ts=t0 + 10), [])

        # Zero-session ROI calculation must not divide by zero
        roi_rows = compute_vendor_roi_stats([banned_acc])
        self.assertEqual(len(roi_rows), 1)
        self.assertEqual(roi_rows[0].ban_rate_pct, 100.0)
        self.assertIsNone(roi_rows[0].cost_per_session)

        # After-sales slip generation
        slip = format_after_sales_slip([banned_acc], now_ts=t0 + 3600)
        self.assertIn("渠道X", slip)
        self.assertIn("b@t.com----pw----123456", slip)
        self.assertIn("质保内", slip)

    def test_warranty_expiry_notification_and_mainwindow_hud_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t0 = 1_700_000_000.0
            storage = AccountStorage(Path(tmp))
            acc_w = Account.create(
                "质保临期号", "war@t.com", "pw", "123456",
                provider="Claude", purchase_price=48.0,
                warranty_days=0.5,  # 12h left (< 24h threshold)
                vendor_tag="发卡网B", now_ts=t0,
            )
            storage.save_accounts([acc_w])

            with mock.patch("src.storage.resolve_app_dir", return_value=Path(tmp)), \
                 mock.patch("src.notifier.send_windows_toast") as mock_toast, \
                 mock.patch("time.time", return_value=t0 + 60):
                code = app_main.run_background_notification_check(storage)
                self.assertEqual(code, 0)
                self.assertEqual(mock_toast.call_count, 1)

                # Second check in same cycle must NOT spam
                app_main.run_background_notification_check(storage)
                self.assertEqual(mock_toast.call_count, 1)

            # GUI integration: MainWindow + Mini HUD + Smart Dispatch + Theme toggle
            win = MainWindow(storage)
            win.show()
            win._on_toggle_mini_hud()
            self.assertTrue(win.mini_hud.isVisible())
            win._on_toggle_theme()
            self.assertEqual(win.current_theme, "dark")

            win._on_smart_dispatch()
            self.assertIsNotNone(win.accounts[0].five_hour_reset_at)
            self.assertEqual(win.accounts[0].usage_5h_count, 1)
            self.assertTrue(win.paste_banner.isVisible())
            self.assertTrue(win.mini_hud.paste_btn.isEnabled())

            # Dialog height invariant check (must remain <= 520px with scroll area)
            dlg = AccountDialog(win, account=win.accounts[0], palette=win._palette)
            self.assertLessEqual(dlg.height(), 520)
            dlg.close()

            ocr_dlg = OcrConfirmDialog(
                win.accounts,
                parse_quota_from_ocr_text("5-hour limit: 20% used\nWeekly: 60% left\nResets in 1d 2h"),
                parent=win,
            )
            self.assertEqual(ocr_dlg.five_spin.value(), 80)
            self.assertEqual(ocr_dlg.week_spin.value(), 60)
            ocr_dlg.close()

            pw_dlg = PassphraseDialog("测试", "输入口令", require_confirm=True, parent=win)
            pw_dlg.close()

            set_dlg = SettingsDialog(win.settings, parent=win, palette=win._palette)
            self.assertLessEqual(set_dlg.height(), 560)
            set_dlg.close()

            # Weird user closes window while password is in clipboard -> must auto-burn clipboard!
            win.paste_ctrl.advance()
            self.assertEqual(QApplication.clipboard().text(), "pw")
            win.close()
            self.assertFalse(win.mini_hud.isVisible())
            self.assertEqual(QApplication.clipboard().text(), "")

    def test_cross_provider_same_email_isolation_and_corrupted_files_resilience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            # Corrupt settings.json and inject garbage into events.jsonl
            storage.settings_file.write_text("{corrupted_json!!!", encoding="utf-8")
            storage.log_file.write_text("NOT_JSON_LINE_123\n", encoding="utf-8")

            # Must recover gracefully without crashing
            win = MainWindow(storage)
            self.assertEqual(win.current_theme, "light")

            # Same email under ChatGPT and Claude must coexist as 2 distinct accounts
            acc_gpt = Account.create("同邮GPT", "shared@me.com", "pw_gpt", "111111", provider="ChatGPT")
            acc_claude = Account.create("同邮Claude", "shared@me.com", "pw_claude", "222222", provider="Claude")
            win.accounts = [acc_gpt, acc_claude]
            win._save_accounts_safe()

            reloaded = storage.load_accounts()
            self.assertEqual(len(reloaded), 2)
            providers = {a.provider: a.password for a in reloaded}
            self.assertEqual(providers["ChatGPT"], "pw_gpt")
            self.assertEqual(providers["Claude"], "pw_claude")
            win.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
