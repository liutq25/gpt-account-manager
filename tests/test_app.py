from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from unittest import mock

from PyQt5.QtWidgets import QApplication

from src.dialogs import AccountDialog, BatchImportDialog, QuickQuotaDialog, SettingsDialog
from src.main_window import MainWindow
from src.models import (
    Account,
    FIVE_HOURS_SECONDS,
    check_weekly_expiring_accounts,
    compute_totp,
    format_duration,
    parse_accounts_from_text,
)
from src.storage import AccountStorage, AppSettings
from src.ui_styles import get_palette


class TestQuotaLogic(unittest.TestCase):
    def test_five_hour_zero_triggers_countdown_and_restores_100(self) -> None:
        t0 = 1_700_000_000.0
        acc = Account.create(
            name="主力号",
            email="main@example.com",
            password="secret",
            two_fa="123456",
            five_hour_quota=80,
            weekly_quota=90,
            now_ts=t0,
        )
        self.assertIsNone(acc.five_hour_reset_at)

        events = acc.update_five_hour_quota(0, now_ts=t0 + 10)
        self.assertEqual(events, ["START_5H_COUNTDOWN"])
        self.assertEqual(acc.five_hour_quota, 0)
        self.assertEqual(acc.five_hour_reset_at, t0 + 10 + FIVE_HOURS_SECONDS)

        events2 = acc.update_five_hour_quota(0, now_ts=t0 + 100)
        self.assertEqual(events2, [])
        self.assertEqual(acc.five_hour_reset_at, t0 + 10 + FIVE_HOURS_SECONDS)

        self.assertEqual(acc.tick(t0 + 10 + FIVE_HOURS_SECONDS - 1), [])
        self.assertEqual(acc.five_hour_quota, 0)

        triggered = acc.tick(t0 + 10 + FIVE_HOURS_SECONDS)
        self.assertEqual(triggered, ["AUTO_RESET_5H"])
        self.assertEqual(acc.five_hour_quota, 100)
        self.assertIsNone(acc.five_hour_reset_at)

    def test_five_hour_manual_restore_clears_timer(self) -> None:
        t0 = 1_700_000_000.0
        acc = Account.create(
            name="号B",
            email="b@example.com",
            password="pw",
            two_fa="654321",
            five_hour_quota=0,
            now_ts=t0,
        )
        self.assertIsNotNone(acc.five_hour_reset_at)
        events = acc.update_five_hour_quota(50, now_ts=t0 + 60)
        self.assertEqual(events, ["CLEAR_5H_COUNTDOWN"])
        self.assertIsNone(acc.five_hour_reset_at)

    def test_weekly_countdown_and_auto_restore_100(self) -> None:
        t0 = 1_700_000_000.0
        duration = 2 * 86400 + 3 * 3600 + 15 * 60
        acc = Account.create(
            name="周号",
            email="w@example.com",
            password="pw",
            two_fa="112233",
            five_hour_quota=100,
            weekly_quota=25,
            weekly_reset_duration_seconds=duration,
            now_ts=t0,
        )
        self.assertEqual(acc.weekly_reset_at, t0 + duration)
        self.assertEqual(acc.weekly_remaining_seconds(t0 + 15), duration - 15)

        self.assertEqual(acc.tick(t0 + duration - 1), [])
        self.assertEqual(acc.weekly_quota, 25)

        triggered = acc.tick(t0 + duration)
        self.assertEqual(triggered, ["AUTO_RESET_WEEKLY"])
        self.assertEqual(acc.weekly_quota, 100)
        self.assertIsNone(acc.weekly_reset_at)

    def test_totp_and_static_2fa(self) -> None:
        code, rem = compute_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", for_time=59)
        self.assertEqual(code, "287082")
        self.assertEqual(rem, 1)

        static_code, static_rem = compute_totp("123456", for_time=59)
        self.assertIsNone(static_code)
        self.assertEqual(static_rem, 0)

    def test_format_duration(self) -> None:
        self.assertEqual(format_duration(5 * 3600), "05:00:00")
        self.assertEqual(format_duration(86400 + 3661), "1天 01:01:01")


class TestAccountTextParser(unittest.TestCase):
    def test_parse_sample_one_with_disclaimer_and_boilerplate(self) -> None:
        sample_1 = (
            "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "郑重声明上号不要去关掉2FA，你可以选择直接更换邮箱(如果你关了2FA登录不上不要来售后，"
            "我是可以通过AT查询到你的记录的)• 登录：邮箱账密+2FA登录• 发货形式：邮箱----密码----2FA "
            "或者 邮箱----取件链接2FA取码网址： https://2fa.fun/ • 接马状态：🚨 未接马！！"
            "未接马网页号，使用codex需要自己接马（手机接马部分不在售后范围）"
            "如果是2FA验证方式的，不会修改的不要乱改，删除2FA后接不到邮箱验证的不售后"
        )
        parsed = parse_accounts_from_text(sample_1)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].email, "graph.57chap@icloud.com")
        self.assertEqual(parsed[0].password, "V198jmeE&N6a@4x!")
        self.assertEqual(parsed[0].two_fa, "L7CM2UJJV65TCH5CXL3PURLX7GJC554D")
        self.assertEqual(parsed[0].suggested_name, "graph.57chap")

    def test_parse_sample_two_with_quotes_and_special_chars(self) -> None:
        sample_2 = "“emeries.gloss-1i+shlf@icloud.com----#uWOE^riLIPD9dLN----HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF”"
        parsed = parse_accounts_from_text(sample_2)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].email, "emeries.gloss-1i+shlf@icloud.com")
        self.assertEqual(parsed[0].password, "#uWOE^riLIPD9dLN")
        self.assertEqual(parsed[0].two_fa, "HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF")

    def test_parse_multiple_mixed_accounts(self) -> None:
        combined = (
            "1. graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "发货形式：邮箱----密码----2FA\n"
            "2. “emeries.gloss-1i+shlf@icloud.com----#uWOE^riLIPD9dLN----HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF”\n"
        )
        parsed = parse_accounts_from_text(combined)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].email, "graph.57chap@icloud.com")
        self.assertEqual(parsed[1].email, "emeries.gloss-1i+shlf@icloud.com")


class TestPersistenceThemeAndUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_storage_roundtrip_catchup_and_theme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            self.assertEqual(storage.load_theme(), "light")
            storage.save_theme("dark")
            self.assertEqual(storage.load_theme(), "dark")

            t0 = 1_700_000_000.0
            acc = Account.create(
                name="测试号",
                email="test@example.com",
                password="p@ss",
                two_fa="JBSWY3DPEHPK3PXP",
                five_hour_quota=0,
                weekly_quota=10,
                weekly_reset_duration_seconds=3600,
                now_ts=t0,
            )
            storage.save_accounts([acc])
            storage.logger.log("INFO", "TEST_EVENT", "写入测试日志", "测试号")

            loaded = storage.load_accounts()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].email, "test@example.com")

            events = loaded[0].tick(t0 + 6 * 3600)
            self.assertEqual(events, ["AUTO_RESET_5H", "AUTO_RESET_WEEKLY"])
            self.assertEqual(loaded[0].five_hour_quota, 100)
            self.assertEqual(loaded[0].weekly_quota, 100)

    def test_theme_contrast_and_gui_dialogs(self) -> None:
        light = get_palette("light")
        dark = get_palette("dark")
        self.assertNotEqual(dark.surface_bg, dark.text_primary)
        self.assertNotEqual(dark.window_bg, dark.text_primary)
        self.assertNotEqual(light.surface_bg, dark.surface_bg)

        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            acc = Account.create(
                name="GUI测试",
                email="gui@example.com",
                password="secret",
                two_fa="123456",
                five_hour_quota=0,
                weekly_quota=40,
                weekly_reset_duration_seconds=7200,
            )
            storage.save_accounts([acc])

            win = MainWindow(storage)
            self.assertEqual(win.current_theme, "light")
            win._on_toggle_theme()
            self.assertEqual(win.current_theme, "dark")
            self.assertEqual(storage.load_theme(), "dark")
            win._on_tick()

            # Smart parse inside AccountDialog
            add_dlg = AccountDialog(win, palette=win._palette)
            self.assertIsNotNone(add_dlg.scroll_area)
            self.assertTrue(add_dlg.scroll_area.widgetResizable())
            self.assertLessEqual(add_dlg.height(), 520)
            add_dlg.raw_text_edit.setPlainText(
                "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n郑重声明..."
            )
            add_dlg._on_smart_parse()
            self.assertEqual(add_dlg.email_edit.text(), "graph.57chap@icloud.com")
            self.assertEqual(add_dlg.password_edit.text(), "V198jmeE&N6a@4x!")
            self.assertEqual(add_dlg.two_fa_edit.text(), "L7CM2UJJV65TCH5CXL3PURLX7GJC554D")
            self.assertEqual(add_dlg.name_edit.text(), "graph.57chap")
            add_dlg.close()

            # Test edit AccountDialog
            edit_dlg = AccountDialog(win, account=acc, palette=win._palette)
            self.assertIsNotNone(edit_dlg.scroll_area)
            self.assertLessEqual(edit_dlg.height(), 520)
            self.assertEqual(edit_dlg.name_edit.text(), "GUI测试")
            edit_dlg.close()

            # BatchImportDialog
            batch_dlg = BatchImportDialog(win, palette=win._palette)
            batch_dlg.input_text.setPlainText(
                "emeries.gloss-1i+shlf@icloud.com----#uWOE^riLIPD9dLN----HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF"
            )
            batch_dlg._on_parse()
            self.assertEqual(batch_dlg.preview_table.rowCount(), 1)
            batch_dlg._on_confirm_import()
            self.assertEqual(len(batch_dlg.imported_items), 1)
            self.assertEqual(batch_dlg.imported_items[0].email, "emeries.gloss-1i+shlf@icloud.com")
            batch_dlg.close()

            qdlg = QuickQuotaDialog(acc, win, palette=win._palette)
            self.assertEqual(qdlg.five_spin.value(), 0)
            qdlg.close()

            sdlg = SettingsDialog(AppSettings(), win, palette=win._palette)
            self.assertTrue(sdlg.notify_chk.isChecked())
            self.assertEqual(sdlg.quota_spin.value(), 20)
            self.assertEqual(sdlg.hours_spin.value(), 24)
            sdlg.close()
            win.close()

    def test_start_five_hour_usage_and_weekly_expiring_notifications(self) -> None:
        t0 = 1_700_000_000.0
        acc_ready = Account.create(
            name="满额号",
            email="ready@example.com",
            password="pw",
            two_fa="123456",
            five_hour_quota=100,
            weekly_quota=60,
            weekly_reset_duration_seconds=12 * 3600,  # 12h left (< 24h)
            now_ts=t0,
        )
        # Manual start usage without waiting for 0
        self.assertIsNone(acc_ready.five_hour_reset_at)
        events = acc_ready.start_five_hour_usage(now_ts=t0 + 5)
        self.assertEqual(events, ["START_5H_COUNTDOWN"])
        self.assertEqual(acc_ready.five_hour_reset_at, t0 + 5 + FIVE_HOURS_SECONDS)
        # Calling again preserves existing timer
        self.assertEqual(acc_ready.start_five_hour_usage(now_ts=t0 + 50), [])
        self.assertEqual(acc_ready.five_hour_reset_at, t0 + 5 + FIVE_HOURS_SECONDS)
        # Expiry restores 100
        self.assertEqual(acc_ready.tick(t0 + 5 + FIVE_HOURS_SECONDS), ["AUTO_RESET_5H"])
        self.assertEqual(acc_ready.five_hour_quota, 100)
        self.assertIsNone(acc_ready.five_hour_reset_at)

        # Low weekly quota (< 20%) should not trigger
        acc_low = Account.create(
            name="低余量号",
            email="low@example.com",
            password="pw",
            two_fa="123456",
            weekly_quota=10,
            weekly_reset_duration_seconds=10 * 3600,
            now_ts=t0,
        )
        # High weekly quota (> 20%) but > 24h left should not trigger
        acc_far = Account.create(
            name="远期号",
            email="far@example.com",
            password="pw",
            two_fa="123456",
            weekly_quota=80,
            weekly_reset_duration_seconds=48 * 3600,
            now_ts=t0,
        )
        expiring = check_weekly_expiring_accounts(
            [acc_ready, acc_low, acc_far],
            quota_threshold=20,
            hours_threshold=24,
            now_ts=t0 + 60,
        )
        self.assertEqual(len(expiring), 1)
        self.assertEqual(expiring[0].id, acc_ready.id)

        # Mark notified -> should not trigger again in same cycle
        acc_ready.weekly_notified_reset_at = acc_ready.weekly_reset_at
        expiring_2 = check_weekly_expiring_accounts(
            [acc_ready, acc_low, acc_far],
            quota_threshold=20,
            hours_threshold=24,
            now_ts=t0 + 120,
        )
        self.assertEqual(len(expiring_2), 0)

    @mock.patch("src.main_window.send_windows_toast", return_value=True)
    def test_mainwindow_start_5h_button_and_notify_tick(self, mock_toast) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = AccountStorage(Path(tmp))
            settings = AppSettings(
                notify_enabled=True,
                notify_quota_threshold=20,
                notify_hours_threshold=24,
            )
            storage.save_settings(settings)

            acc = Account.create(
                name="预警号",
                email="warn@example.com",
                password="secret",
                two_fa="123456",
                five_hour_quota=100,
                weekly_quota=75,
                weekly_reset_duration_seconds=3600 * 10,  # 10h left
            )
            storage.save_accounts([acc])

            win = MainWindow(storage)
            rw = win._row_widgets[acc.id]
            self.assertTrue(rw.start_5h_btn.isEnabled())
            self.assertEqual(rw.start_5h_btn.text(), "开始使用")

            # Click start usage
            win._on_start_5h_usage(acc.id)
            rw = win._row_widgets[acc.id]
            self.assertFalse(rw.start_5h_btn.isEnabled())
            self.assertEqual(rw.start_5h_btn.text(), "计时中")
            self.assertIsNotNone(win.accounts[0].five_hour_reset_at)

            # Tick triggers weekly expiring notification once
            win._on_tick()
            self.assertTrue(mock_toast.called)
            self.assertEqual(mock_toast.call_count, 1)
            win._on_tick()
            self.assertEqual(mock_toast.call_count, 1)
            win.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
