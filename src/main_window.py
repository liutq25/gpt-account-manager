from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src.dialogs import AccountDialog, BatchImportDialog, QuickQuotaDialog, SettingsDialog
from src.models import (
    Account,
    MAX_QUOTA,
    check_weekly_expiring_accounts,
    compute_totp,
    format_duration,
)
from src.notifier import send_windows_toast
from src.storage import AccountStorage, AppSettings, LogEntry
from src.ui_styles import ThemePalette, build_stylesheet, get_palette


@dataclass
class RowWidgets:
    five_bar: QProgressBar
    five_label: QLabel
    start_5h_btn: QPushButton
    zero_btn: QPushButton
    five_timer_label: QLabel
    weekly_bar: QProgressBar
    weekly_label: QLabel
    weekly_timer_label: QLabel
    pwd_label: QLabel
    pwd_toggle_btn: QPushButton
    two_fa_label: QLabel


class MainWindow(QMainWindow):
    def __init__(self, storage: AccountStorage, initial_theme: Optional[str] = None) -> None:
        super().__init__()
        self.storage = storage
        self.settings: AppSettings = self.storage.load_settings()
        self.current_theme = initial_theme or self.settings.theme
        self._palette: ThemePalette = get_palette(self.current_theme)
        self.accounts: List[Account] = []
        self._row_widgets: Dict[str, RowWidgets] = {}
        self._revealed_pwds: Set[str] = set()
        self._is_force_quitting: bool = False

        self.setWindowTitle("GPT 账号额度管理助手")
        self.resize(1380, 820)
        self.setMinimumSize(1120, 680)

        self._build_ui()
        self._init_system_tray()
        self._apply_theme(self.current_theme, persist=False, log_event=False)
        self._load_initial_data()

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._on_tick)
        self._tick_timer.start()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header Bar
        header = QWidget()
        header.setObjectName("HeaderBar")
        header.setFixedHeight(64)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel("GPT 账号额度管理控制台")
        title_lbl.setObjectName("AppTitle")
        sub_lbl = QLabel("本地持久化存储 · 5h 额度自动恢复 · 周额度重置倒计时 · 智能文本识别 · 结构化审计日志")
        sub_lbl.setObjectName("AppSubtitle")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)

        header_layout.addLayout(title_col)
        header_layout.addStretch()

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("ThemeToggleBtn")
        self.theme_btn.setToolTip("在日间（白色背景）与夜间（黑色背景）之间切换")
        self.theme_btn.clicked.connect(self._on_toggle_theme)
        header_layout.addWidget(self.theme_btn)

        self.settings_btn = QPushButton("⚙ 设置")
        self.settings_btn.setObjectName("SettingsBtn")
        self.settings_btn.setToolTip("配置周额度刷新预警、系统后台计划任务与托盘行为")
        self.settings_btn.clicked.connect(self._on_open_settings)
        header_layout.addWidget(self.settings_btn)

        self.clock_label = QLabel("")
        self.clock_label.setStyleSheet(
            "color: #CBD5E1; font-family: 'Consolas', monospace; font-size: 13px;"
        )
        header_layout.addWidget(self.clock_label)
        root.addWidget(header)

        # Body container
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 14, 16, 12)
        body_layout.setSpacing(12)

        # KPI Cards Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        self.kpi_total = self._create_kpi_card("总账号数", "0")
        self.kpi_5h_ready = self._create_kpi_card("5h 额度可用", "0")
        self.kpi_5h_cooling = self._create_kpi_card("5h 恢复倒计时中", "0")
        self.kpi_weekly_cooling = self._create_kpi_card("周额度倒计时中", "0")
        kpi_row.addWidget(self.kpi_total[0])
        kpi_row.addWidget(self.kpi_5h_ready[0])
        kpi_row.addWidget(self.kpi_5h_cooling[0])
        kpi_row.addWidget(self.kpi_weekly_cooling[0])
        body_layout.addLayout(kpi_row)

        # Main Tabs
        self.tabs = QTabWidget()
        self.accounts_tab = self._build_accounts_tab()
        self.logs_tab = self._build_logs_tab()
        self.tabs.addTab(self.accounts_tab, "账号与额度管理")
        self.tabs.addTab(self.logs_tab, "运行日志")
        body_layout.addWidget(self.tabs)

        root.addWidget(body)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"本地数据路径: {self.storage.accounts_file}")

    def _create_kpi_card(self, title: str, initial_value: str) -> tuple[QFrame, QLabel, QLabel]:
        card = QFrame()
        card.setObjectName("KpiCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        t_lbl = QLabel(title)
        v_lbl = QLabel(initial_value)
        layout.addWidget(t_lbl)
        layout.addWidget(v_lbl)
        return card, t_lbl, v_lbl

    def _style_kpi_cards(self) -> None:
        p = self._palette
        specs = [
            (self.kpi_total, p.kpi_total_accent),
            (self.kpi_5h_ready, p.kpi_5h_ready_accent),
            (self.kpi_5h_cooling, p.kpi_5h_cool_accent),
            (self.kpi_weekly_cooling, p.kpi_weekly_cool_accent),
        ]
        for (card, t_lbl, v_lbl), accent in specs:
            card.setStyleSheet(
                f"QFrame#KpiCard {{ background-color: {p.surface_bg}; border: 1px solid {p.border}; "
                f"border-left: 4px solid {accent}; border-radius: 8px; }}"
            )
            t_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 12px; font-weight: 600;")
            v_lbl.setStyleSheet(f"color: {accent}; font-size: 22px; font-weight: 700;")

    def _apply_theme(self, theme_name: str, persist: bool = True, log_event: bool = True) -> None:
        self.current_theme = "dark" if theme_name == "dark" else "light"
        self._palette = get_palette(self.current_theme)

        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(build_stylesheet(self.current_theme))

        if self.current_theme == "dark":
            self.theme_btn.setText("日间模式 (白)")
        else:
            self.theme_btn.setText("夜间模式 (黑)")

        self._style_kpi_cards()

        if persist:
            try:
                self.storage.save_theme(self.current_theme)
            except Exception as exc:
                self._record_log("ERROR", "THEME_SAVE_FAILED", f"保存主题设置失败: {exc}")

        if hasattr(self, "account_table") and self.accounts is not None:
            self._rebuild_account_table()
        if hasattr(self, "log_table"):
            self._refresh_log_table()

        if log_event:
            mode_label = "夜间模式（黑色背景）" if self.current_theme == "dark" else "日间模式（白色背景）"
            self._record_log("INFO", "THEME_CHANGED", f"界面主题已切换为：{mode_label}。")

    def _on_toggle_theme(self) -> None:
        next_theme = "dark" if self.current_theme == "light" else "light"
        self._apply_theme(next_theme, persist=True, log_event=True)

    def _build_accounts_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QFrame()
        toolbar.setObjectName("ToolbarFrame")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(12, 10, 12, 10)
        tb_layout.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索账号名称或邮箱...")
        self.search_input.setMaximumWidth(260)
        self.search_input.textChanged.connect(self._rebuild_account_table)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(
            ["全部账号", "5h 额度 > 0", "5h 额度已耗尽 (倒计时中)", "周额度倒计时中"]
        )
        self.filter_combo.currentIndexChanged.connect(self._rebuild_account_table)

        tb_layout.addWidget(QLabel("筛选:"))
        tb_layout.addWidget(self.search_input)
        tb_layout.addWidget(self.filter_combo)
        tb_layout.addStretch()

        export_btn = QPushButton("备份导出")
        export_btn.clicked.connect(self._on_export_backup)
        tb_layout.addWidget(export_btn)

        batch_btn = QPushButton("批量文本识别导入")
        batch_btn.setToolTip("粘贴一段或多段账号文本，自动识别邮箱、密码与 2FA 初始验证码")
        batch_btn.clicked.connect(self._on_batch_import)
        tb_layout.addWidget(batch_btn)

        add_btn = QPushButton("+ 添加 GPT 账号")
        add_btn.setObjectName("PrimaryButton")
        add_btn.clicked.connect(self._on_add_account)
        tb_layout.addWidget(add_btn)

        layout.addWidget(toolbar)

        # Account Table
        self.account_table = QTableWidget()
        self.account_table.setColumnCount(9)
        self.account_table.setHorizontalHeaderLabels(
            [
                "账号名称",
                "账号邮箱",
                "登录密码",
                "2FA 验证码",
                "5h 剩余额度",
                "5h 重置倒计时",
                "周剩余额度",
                "周重置倒计时",
                "操作",
            ]
        )
        self.account_table.setAlternatingRowColors(True)
        self.account_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.account_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.account_table.verticalHeader().setVisible(False)
        self.account_table.setFocusPolicy(Qt.NoFocus)

        header = self.account_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        header.setSectionResizeMode(6, QHeaderView.Fixed)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        header.setSectionResizeMode(8, QHeaderView.Fixed)

        self.account_table.setColumnWidth(0, 130)
        self.account_table.setColumnWidth(2, 165)
        self.account_table.setColumnWidth(3, 175)
        self.account_table.setColumnWidth(4, 215)
        self.account_table.setColumnWidth(5, 135)
        self.account_table.setColumnWidth(6, 125)
        self.account_table.setColumnWidth(7, 145)
        self.account_table.setColumnWidth(8, 175)

        layout.addWidget(self.account_table)
        return tab

    def _build_logs_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        bar = QHBoxLayout()
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["全部级别", "INFO", "WARN", "ERROR"])
        self.log_level_combo.currentIndexChanged.connect(self._refresh_log_table)

        self.log_search_input = QLineEdit()
        self.log_search_input.setPlaceholderText("搜索日志内容或账号...")
        self.log_search_input.setMaximumWidth(280)
        self.log_search_input.textChanged.connect(self._refresh_log_table)

        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_log_table)
        export_log_btn = QPushButton("导出日志")
        export_log_btn.clicked.connect(self._on_export_logs)
        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.setObjectName("DangerButton")
        clear_log_btn.clicked.connect(self._on_clear_logs)

        bar.addWidget(QLabel("级别:"))
        bar.addWidget(self.log_level_combo)
        bar.addWidget(self.log_search_input)
        bar.addStretch()
        bar.addWidget(refresh_btn)
        bar.addWidget(export_log_btn)
        bar.addWidget(clear_log_btn)
        layout.addLayout(bar)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels(["时间", "Trace ID", "级别", "事件类型", "关联账号", "详细信息"])
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.log_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_table.verticalHeader().setVisible(False)
        lh = self.log_table.horizontalHeader()
        lh.setSectionResizeMode(0, QHeaderView.Fixed)
        lh.setSectionResizeMode(1, QHeaderView.Fixed)
        lh.setSectionResizeMode(2, QHeaderView.Fixed)
        lh.setSectionResizeMode(3, QHeaderView.Fixed)
        lh.setSectionResizeMode(4, QHeaderView.Fixed)
        lh.setSectionResizeMode(5, QHeaderView.Stretch)
        self.log_table.setColumnWidth(0, 155)
        self.log_table.setColumnWidth(1, 85)
        self.log_table.setColumnWidth(2, 70)
        self.log_table.setColumnWidth(3, 175)
        self.log_table.setColumnWidth(4, 170)

        layout.addWidget(self.log_table)
        return tab

    def _load_initial_data(self) -> None:
        try:
            self.accounts = self.storage.load_accounts()
        except Exception as exc:
            self.storage.logger.log("ERROR", "LOAD_FAILED", f"读取本地账号数据失败: {exc}")
            QMessageBox.critical(
                self,
                "数据加载错误",
                f"无法解析本地数据文件：{self.storage.accounts_file}\n错误详情：{exc}",
            )
            self.accounts = []

        self._record_log("INFO", "APP_START", f"程序启动，已加载 {len(self.accounts)} 个账号。")

        now = time.time()
        changed = False
        for acc in self.accounts:
            triggered = acc.tick(now)
            if triggered:
                changed = True
                for ev in triggered:
                    self._log_auto_reset(acc, ev, catch_up=True)

        if changed:
            self._save_accounts_safe()

        self._rebuild_account_table()
        self._refresh_kpis(now)
        self._refresh_log_table()

    def _record_log(self, level: str, event: str, detail: str, account: str = "-") -> None:
        self.storage.logger.log(level=level, event=event, detail=detail, account=account)
        if hasattr(self, "log_table"):
            self._refresh_log_table()
        if hasattr(self, "status_bar"):
            self.status_bar.showMessage(f"[{event}] {detail}  |  数据文件: {self.storage.accounts_file}", 6000)

    def _log_auto_reset(self, acc: Account, event_code: str, catch_up: bool = False) -> None:
        prefix = "离线到期补齐：" if catch_up else ""
        acc_ref = f"{acc.name} ({acc.email})"
        if event_code == "AUTO_RESET_5H":
            self._record_log("INFO", "AUTO_RESET_5H", f"{prefix}5h 倒计时结束，5h 额度已自动恢复为 100。", acc_ref)
        elif event_code == "AUTO_RESET_WEEKLY":
            self._record_log("INFO", "AUTO_RESET_WEEKLY", f"{prefix}周额度倒计时结束，周额度已自动恢复为 100。", acc_ref)

    def _save_accounts_safe(self) -> None:
        try:
            self.storage.save_accounts(self.accounts)
        except Exception as exc:
            self._record_log("ERROR", "SAVE_FAILED", f"保存本地数据失败: {exc}")
            QMessageBox.critical(self, "保存失败", f"写入本地数据失败：{exc}")

    def _filtered_accounts(self) -> List[Account]:
        kw = self.search_input.text().strip().lower()
        mode = self.filter_combo.currentIndex()
        now = time.time()
        result: List[Account] = []
        for acc in self.accounts:
            if kw and kw not in acc.name.lower() and kw not in acc.email.lower():
                continue
            if mode == 1 and acc.five_hour_quota <= 0:
                continue
            if mode == 2 and acc.five_hour_reset_at is None:
                continue
            if mode == 3 and (acc.weekly_reset_at is None or acc.weekly_remaining_seconds(now) == 0):
                continue
            result.append(acc)
        return result

    def _rebuild_account_table(self) -> None:
        p = self._palette
        visible = self._filtered_accounts()
        self._row_widgets.clear()
        self.account_table.setRowCount(len(visible))
        now = time.time()

        for row_idx, acc in enumerate(visible):
            self.account_table.setRowHeight(row_idx, 52)

            # Col 0: Name
            name_item = QTableWidgetItem(acc.name)
            bold_font = QFont()
            bold_font.setBold(True)
            name_item.setFont(bold_font)
            name_item.setForeground(QColor(p.text_primary))
            self.account_table.setItem(row_idx, 0, name_item)

            # Col 1: Email + copy
            email_cell = self._make_copy_cell(
                acc.email,
                lambda _=False, text=acc.email, a=acc: self._copy_text(text, "邮箱", a),
            )
            self.account_table.setCellWidget(row_idx, 1, email_cell)

            # Col 2: Password (masked/revealed + toggle + copy)
            is_rev = acc.id in self._revealed_pwds
            pwd_cell = QWidget()
            pwd_lay = QHBoxLayout(pwd_cell)
            pwd_lay.setContentsMargins(6, 4, 6, 4)
            pwd_lay.setSpacing(4)
            pwd_lbl = QLabel(acc.password if is_rev else "••••••••")
            pwd_lbl.setStyleSheet(f"font-family: 'Consolas', monospace; color: {p.text_secondary};")
            pwd_toggle = QPushButton("隐藏" if is_rev else "显示")
            pwd_toggle.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            pwd_toggle.clicked.connect(lambda _=False, aid=acc.id: self._toggle_password_visibility(aid))
            pwd_copy = QPushButton("复制")
            pwd_copy.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            pwd_copy.clicked.connect(lambda _=False, a=acc: self._copy_text(a.password, "密码", a, sensitive=True))
            pwd_lay.addWidget(pwd_lbl, 1)
            pwd_lay.addWidget(pwd_toggle)
            pwd_lay.addWidget(pwd_copy)
            self.account_table.setCellWidget(row_idx, 2, pwd_cell)

            # Col 3: 2FA + copy
            two_fa_cell = QWidget()
            tfa_lay = QHBoxLayout(two_fa_cell)
            tfa_lay.setContentsMargins(6, 4, 6, 4)
            tfa_lay.setSpacing(4)
            tfa_lbl = QLabel()
            tfa_lbl.setStyleSheet(
                f"font-family: 'Consolas', monospace; font-weight: 600; color: {p.text_primary};"
            )
            tfa_copy = QPushButton("复制")
            tfa_copy.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            tfa_copy.clicked.connect(lambda _=False, a=acc: self._copy_two_fa(a))
            tfa_lay.addWidget(tfa_lbl, 1)
            tfa_lay.addWidget(tfa_copy)
            self.account_table.setCellWidget(row_idx, 3, two_fa_cell)

            # Col 4: 5h Quota + Start Usage btn + quick zero btn
            five_cell = QWidget()
            five_lay = QHBoxLayout(five_cell)
            five_lay.setContentsMargins(4, 4, 4, 4)
            five_lay.setSpacing(4)
            five_bar = QProgressBar()
            five_bar.setRange(0, MAX_QUOTA)
            five_bar.setTextVisible(False)
            five_bar.setFixedHeight(10)
            five_lbl = QLabel()
            five_lbl.setFixedWidth(34)
            five_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            five_lbl.setStyleSheet(
                f"font-family: 'Consolas', monospace; font-weight: 700; color: {p.text_primary};"
            )
            start_5h_btn = QPushButton("开始使用")
            start_5h_btn.setToolTip("开始使用并立即启动 5 小时倒计时（5 小时后自动恢复为 100 额度）")
            start_5h_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_start_5h_usage(aid))

            zero_btn = QPushButton("归0")
            zero_btn.setToolTip("一键将 5h 额度设为 0 并启动 5 小时重置倒计时")
            zero_btn.setStyleSheet(
                f"padding: 2px 5px; font-size: 11px; background-color: {p.warn_bg}; "
                f"border: 1px solid {p.warn_border}; color: {p.warn_text};"
            )
            zero_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_quick_zero_5h(aid))
            five_lay.addWidget(five_bar, 1)
            five_lay.addWidget(five_lbl)
            five_lay.addWidget(start_5h_btn)
            five_lay.addWidget(zero_btn)
            self.account_table.setCellWidget(row_idx, 4, five_cell)

            # Col 5: 5h Countdown
            five_timer_lbl = QLabel()
            five_timer_lbl.setAlignment(Qt.AlignCenter)
            self.account_table.setCellWidget(row_idx, 5, five_timer_lbl)

            # Col 6: Weekly Quota
            w_cell = QWidget()
            w_lay = QHBoxLayout(w_cell)
            w_lay.setContentsMargins(6, 4, 6, 4)
            w_lay.setSpacing(6)
            w_bar = QProgressBar()
            w_bar.setRange(0, MAX_QUOTA)
            w_bar.setTextVisible(False)
            w_bar.setFixedHeight(10)
            w_lbl = QLabel()
            w_lbl.setFixedWidth(36)
            w_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            w_lbl.setStyleSheet(
                f"font-family: 'Consolas', monospace; font-weight: 700; color: {p.text_primary};"
            )
            w_lay.addWidget(w_bar, 1)
            w_lay.addWidget(w_lbl)
            self.account_table.setCellWidget(row_idx, 6, w_cell)

            # Col 7: Weekly Countdown
            w_timer_lbl = QLabel()
            w_timer_lbl.setAlignment(Qt.AlignCenter)
            self.account_table.setCellWidget(row_idx, 7, w_timer_lbl)

            # Col 8: Actions
            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(6, 4, 6, 4)
            act_lay.setSpacing(4)
            quota_btn = QPushButton("改额度")
            quota_btn.setStyleSheet(
                f"padding: 3px 7px; font-size: 11px; background-color: {p.info_bg}; "
                f"border: 1px solid {p.info_border}; color: {p.info_text};"
            )
            quota_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_quick_quota(aid))
            edit_btn = QPushButton("编辑")
            edit_btn.setStyleSheet("padding: 3px 7px; font-size: 11px;")
            edit_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_edit_account(aid))
            del_btn = QPushButton("删除")
            del_btn.setStyleSheet(
                f"padding: 3px 7px; font-size: 11px; background-color: {p.danger_bg}; "
                f"border: 1px solid {p.danger_border}; color: {p.danger_text};"
            )
            del_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_delete_account(aid))
            act_lay.addWidget(quota_btn)
            act_lay.addWidget(edit_btn)
            act_lay.addWidget(del_btn)
            self.account_table.setCellWidget(row_idx, 8, act_cell)

            rw = RowWidgets(
                five_bar=five_bar,
                five_label=five_lbl,
                start_5h_btn=start_5h_btn,
                zero_btn=zero_btn,
                five_timer_label=five_timer_lbl,
                weekly_bar=w_bar,
                weekly_label=w_lbl,
                weekly_timer_label=w_timer_lbl,
                pwd_label=pwd_lbl,
                pwd_toggle_btn=pwd_toggle,
                two_fa_label=tfa_lbl,
            )
            self._row_widgets[acc.id] = rw
            self._update_row_live_state(acc, rw, now)

    def _make_copy_cell(self, text: str, handler) -> QWidget:
        p = self._palette
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(6, 4, 6, 4)
        lay.setSpacing(4)
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {p.text_primary};")
        lbl.setToolTip(text)
        btn = QPushButton("复制")
        btn.setStyleSheet("padding: 2px 6px; font-size: 11px;")
        btn.clicked.connect(handler)
        lay.addWidget(lbl, 1)
        lay.addWidget(btn)
        return w

    def _set_bar_color(self, bar: QProgressBar, value: int) -> None:
        p = self._palette
        if value <= 0:
            chunk = "#DC2626"
        elif value <= 30:
            chunk = "#D97706"
        else:
            chunk = "#16A34A"
        bar.setStyleSheet(
            f"QProgressBar {{ background-color: {p.progress_track}; border: none; border-radius: 4px; }}"
            f"QProgressBar::chunk {{ background-color: {chunk}; border-radius: 4px; }}"
        )

    def _update_row_live_state(self, acc: Account, rw: RowWidgets, now: float) -> None:
        p = self._palette
        # 5h quota
        rw.five_bar.setValue(acc.five_hour_quota)
        self._set_bar_color(rw.five_bar, acc.five_hour_quota)
        rw.five_label.setText(f"{acc.five_hour_quota}%")
        rw.zero_btn.setEnabled(acc.five_hour_quota > 0)

        five_rem = acc.five_hour_remaining_seconds(now)
        if five_rem is not None:
            rw.start_5h_btn.setText("计时中")
            rw.start_5h_btn.setEnabled(False)
            rw.start_5h_btn.setStyleSheet(
                f"padding: 2px 6px; font-size: 11px; background-color: {p.input_disabled_bg}; "
                f"color: {p.text_muted}; border: 1px solid {p.border}; border-radius: 4px;"
            )
            rw.five_timer_label.setText(format_duration(five_rem))
            rw.five_timer_label.setStyleSheet(
                f"font-family: 'Consolas', monospace; font-weight: 700; "
                f"color: {p.warn_text}; background-color: {p.warn_bg}; border-radius: 4px; padding: 3px 6px;"
            )
        else:
            rw.start_5h_btn.setText("开始使用")
            rw.start_5h_btn.setEnabled(True)
            rw.start_5h_btn.setStyleSheet(
                f"padding: 2px 6px; font-size: 11px; background-color: {p.primary_bg}; "
                f"color: #FFFFFF; border: none; border-radius: 4px; font-weight: 600;"
            )
            rw.five_timer_label.setText("未触发")
            rw.five_timer_label.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")

        # Weekly quota
        rw.weekly_bar.setValue(acc.weekly_quota)
        self._set_bar_color(rw.weekly_bar, acc.weekly_quota)
        rw.weekly_label.setText(f"{acc.weekly_quota}%")

        w_rem = acc.weekly_remaining_seconds(now)
        if w_rem is not None:
            rw.weekly_timer_label.setText(format_duration(w_rem))
            rw.weekly_timer_label.setStyleSheet(
                f"font-family: 'Consolas', monospace; font-weight: 700; "
                f"color: {p.info_text}; background-color: {p.info_bg}; border-radius: 4px; padding: 3px 6px;"
            )
        else:
            rw.weekly_timer_label.setText("未设置")
            rw.weekly_timer_label.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")

        # 2FA live TOTP or static initial code
        totp_code, totp_rem = compute_totp(acc.two_fa, now)
        if totp_code is not None:
            rw.two_fa_label.setText(f"{totp_code} ({totp_rem:02d}s)")
            rw.two_fa_label.setToolTip("根据 Base32 密钥实时计算的 6 位 TOTP 验证码")
        else:
            rw.two_fa_label.setText(acc.two_fa)
            rw.two_fa_label.setToolTip("初始/静态 2FA 验证码")

    def _refresh_kpis(self, now: Optional[float] = None) -> None:
        ts = time.time() if now is None else now
        total = len(self.accounts)
        ready_5h = sum(1 for a in self.accounts if a.five_hour_quota > 0)
        cooling_5h = sum(1 for a in self.accounts if a.five_hour_reset_at is not None)
        cooling_weekly = sum(
            1
            for a in self.accounts
            if a.weekly_reset_at is not None and (a.weekly_remaining_seconds(ts) or 0) > 0
        )
        self.kpi_total[2].setText(str(total))
        self.kpi_5h_ready[2].setText(str(ready_5h))
        self.kpi_5h_cooling[2].setText(str(cooling_5h))
        self.kpi_weekly_cooling[2].setText(str(cooling_weekly))

    def _on_start_5h_usage(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        now = time.time()
        events = acc.start_five_hour_usage(now)
        if events:
            self._save_accounts_safe()
            acc_ref = f"{acc.name} ({acc.email})"
            self._record_log(
                "INFO",
                "USAGE_5H_STARTED",
                "点击「开始使用」，已启动 5 小时重置倒计时（5 小时后自动恢复为 100 额度）。",
                acc_ref,
            )
            self._rebuild_account_table()
            self._refresh_kpis(now)

    def _on_tick(self) -> None:
        now = time.time()
        self.clock_label.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        any_reset = False
        for acc in self.accounts:
            triggered = acc.tick(now)
            if triggered:
                any_reset = True
                for ev in triggered:
                    self._log_auto_reset(acc, ev, catch_up=False)

        # Weekly quota expiry notification check
        if getattr(self, "settings", None) and self.settings.notify_enabled:
            expiring = check_weekly_expiring_accounts(
                self.accounts,
                quota_threshold=self.settings.notify_quota_threshold,
                hours_threshold=self.settings.notify_hours_threshold,
                now_ts=now,
            )
            if expiring:
                for acc in expiring:
                    acc.weekly_notified_reset_at = acc.weekly_reset_at
                    rem_str = format_duration(acc.weekly_remaining_seconds(now) or 0)
                    title = "GPT 账号周额度即将刷新提醒"
                    msg = f"账号「{acc.name}」周额度还剩 {acc.weekly_quota}%，将在 {rem_str} 后重置，请及时使用！"
                    self._notify_user(title, msg)
                    self._record_log("WARN", "WEEKLY_EXPIRING_NOTIFICATION", msg, f"{acc.name} ({acc.email})")
                any_reset = True

        if any_reset:
            self._save_accounts_safe()
            if self.filter_combo.currentIndex() != 0:
                self._rebuild_account_table()

        for acc in self.accounts:
            rw = self._row_widgets.get(acc.id)
            if rw is not None:
                self._update_row_live_state(acc, rw, now)

        self._refresh_kpis(now)

    def _find_account(self, account_id: str) -> Optional[Account]:
        for acc in self.accounts:
            if acc.id == account_id:
                return acc
        return None

    def _toggle_password_visibility(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        rw = self._row_widgets.get(account_id)
        if acc is None or rw is None:
            return
        if account_id in self._revealed_pwds:
            self._revealed_pwds.remove(account_id)
            rw.pwd_label.setText("••••••••")
            rw.pwd_toggle_btn.setText("显示")
        else:
            self._revealed_pwds.add(account_id)
            rw.pwd_label.setText(acc.password)
            rw.pwd_toggle_btn.setText("隐藏")

    def _copy_text(self, text: str, label: str, acc: Account, sensitive: bool = False) -> None:
        QApplication.clipboard().setText(text)
        acc_ref = f"{acc.name} ({acc.email})"
        detail = f"已复制{label}到剪贴板。" if sensitive else f"已复制{label} ({text}) 到剪贴板。"
        self._record_log("INFO", "CLIPBOARD_COPY", detail, acc_ref)

    def _copy_two_fa(self, acc: Account) -> None:
        totp_code, _ = compute_totp(acc.two_fa, time.time())
        value_to_copy = totp_code if totp_code is not None else acc.two_fa
        QApplication.clipboard().setText(value_to_copy)
        acc_ref = f"{acc.name} ({acc.email})"
        kind = "实时 6 位 TOTP 验证码" if totp_code is not None else "2FA 初始验证码"
        self._record_log("INFO", "CLIPBOARD_COPY", f"已复制{kind}到剪贴板。", acc_ref)

    def _on_add_account(self) -> None:
        dlg = AccountDialog(self, palette=self._palette)
        if dlg.exec_() != AccountDialog.Accepted or dlg.result_data is None:
            return
        form = dlg.result_data
        now = time.time()
        acc = Account.create(
            name=form.name,
            email=form.email,
            password=form.password,
            two_fa=form.two_fa,
            five_hour_quota=form.five_hour_quota,
            weekly_quota=form.weekly_quota,
            weekly_reset_duration_seconds=form.weekly_reset_seconds if form.apply_weekly_timer else 0,
            now_ts=now,
        )
        self.accounts.append(acc)
        self._save_accounts_safe()

        acc_ref = f"{acc.name} ({acc.email})"
        timer_notes: List[str] = []
        if acc.five_hour_reset_at is not None:
            timer_notes.append("5h额度为0，已启动5小时倒计时")
        if acc.weekly_reset_at is not None:
            timer_notes.append(f"已启动周额度倒计时 ({format_duration(form.weekly_reset_seconds)})")
        suffix = f"；{', '.join(timer_notes)}" if timer_notes else ""
        self._record_log(
            "INFO",
            "ACCOUNT_ADDED",
            f"新增账号：5h额度={acc.five_hour_quota}，周额度={acc.weekly_quota}{suffix}。",
            acc_ref,
        )

        self._rebuild_account_table()
        self._refresh_kpis(now)

    def _on_batch_import(self) -> None:
        dlg = BatchImportDialog(self, palette=self._palette)
        if dlg.exec_() != BatchImportDialog.Accepted or not dlg.imported_items:
            return
        now = time.time()
        added_count = 0
        for item in dlg.imported_items:
            acc = Account.create(
                name=item.name,
                email=item.email,
                password=item.password,
                two_fa=item.two_fa,
                five_hour_quota=item.five_hour_quota,
                weekly_quota=item.weekly_quota,
                weekly_reset_duration_seconds=0,
                now_ts=now,
            )
            self.accounts.append(acc)
            added_count += 1
            self._record_log(
                "INFO",
                "ACCOUNT_BATCH_IMPORTED",
                f"智能文本导入账号：5h={acc.five_hour_quota}，周={acc.weekly_quota}。",
                f"{acc.name} ({acc.email})",
            )

        self._save_accounts_safe()
        self._rebuild_account_table()
        self._refresh_kpis(now)
        QMessageBox.information(self, "导入完成", f"成功识别并导入 {added_count} 个账号。")

    def _on_edit_account(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        dlg = AccountDialog(self, account=acc, palette=self._palette)
        if dlg.exec_() != AccountDialog.Accepted or dlg.result_data is None:
            return
        form = dlg.result_data
        now = time.time()

        acc.name = form.name
        acc.email = form.email
        acc.password = form.password
        acc.two_fa = form.two_fa

        events_5h = acc.update_five_hour_quota(form.five_hour_quota, now_ts=now)
        events_weekly = acc.set_weekly_quota_and_timer(
            new_quota=form.weekly_quota,
            reset_duration_seconds=form.weekly_reset_seconds if form.apply_weekly_timer else None,
            clear_timer=form.clear_weekly_timer,
            now_ts=now,
        )

        self._save_accounts_safe()
        acc_ref = f"{acc.name} ({acc.email})"
        all_events = events_5h + events_weekly
        event_note = f"；触发状态: {', '.join(all_events)}" if all_events else ""
        self._record_log(
            "INFO",
            "ACCOUNT_UPDATED",
            f"编辑账号：5h额度={acc.five_hour_quota}，周额度={acc.weekly_quota}{event_note}。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_kpis(now)

    def _on_quick_quota(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        dlg = QuickQuotaDialog(acc, self, palette=self._palette)
        if dlg.exec_() != QuickQuotaDialog.Accepted or dlg.result_data is None:
            return
        res = dlg.result_data
        now = time.time()

        events_5h = acc.update_five_hour_quota(res.five_hour_quota, now_ts=now)
        events_weekly = acc.set_weekly_quota_and_timer(
            new_quota=res.weekly_quota,
            reset_duration_seconds=res.weekly_reset_seconds if res.apply_weekly_timer else None,
            clear_timer=res.clear_weekly_timer,
            now_ts=now,
        )
        self._save_accounts_safe()

        acc_ref = f"{acc.name} ({acc.email})"
        notes: List[str] = []
        if "START_5H_COUNTDOWN" in events_5h:
            notes.append("启动5h重置倒计时")
        if "START_WEEKLY_COUNTDOWN" in events_weekly:
            notes.append(f"启动周重置倒计时({format_duration(res.weekly_reset_seconds)})")
        if "CLEAR_WEEKLY_COUNTDOWN" in events_weekly:
            notes.append("清除周重置倒计时")
        extra = f"；{', '.join(notes)}" if notes else ""
        self._record_log(
            "INFO",
            "QUOTA_UPDATED",
            f"手动更新额度：5h={acc.five_hour_quota}，周={acc.weekly_quota}{extra}。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_kpis(now)

    def _on_quick_zero_5h(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        now = time.time()
        acc.update_five_hour_quota(0, now_ts=now)
        self._save_accounts_safe()

        acc_ref = f"{acc.name} ({acc.email})"
        self._record_log(
            "INFO",
            "QUOTA_5H_ZERO",
            "手动将 5h 额度归 0，已开始 5 小时重置倒计时（5 小时后自动恢复为 100）。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_kpis(now)

    def _on_delete_account(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        reply = QMessageBox.question(
            self,
            "确认删除",
            f"确定要删除账号“{acc.name}” ({acc.email}) 吗？\n删除后将从本地数据文件中移除。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self.accounts = [a for a in self.accounts if a.id != account_id]
        self._revealed_pwds.discard(account_id)
        self._save_accounts_safe()
        self._record_log("WARN", "ACCOUNT_DELETED", "已删除该账号记录。", f"{acc.name} ({acc.email})")
        self._rebuild_account_table()
        self._refresh_kpis(time.time())

    def _refresh_log_table(self) -> None:
        p = self._palette
        entries = list(reversed(self.storage.logger.read_recent(limit=500)))
        level_filter = self.log_level_combo.currentText()
        kw = self.log_search_input.text().strip().lower()

        filtered: List[LogEntry] = []
        for entry in entries:
            if level_filter != "全部级别" and entry.level != level_filter:
                continue
            if kw and kw not in entry.detail.lower() and kw not in entry.account.lower() and kw not in entry.event.lower():
                continue
            filtered.append(entry)

        self.log_table.setRowCount(len(filtered))
        for idx, entry in enumerate(filtered):
            self.log_table.setRowHeight(idx, 30)
            for col_i, text in enumerate(
                [entry.timestamp, entry.trace_id, entry.level, entry.event, entry.account, entry.detail]
            ):
                cell_item = QTableWidgetItem(text)
                if col_i == 2:
                    cell_item.setTextAlignment(Qt.AlignCenter)
                    if entry.level == "ERROR":
                        cell_item.setForeground(QColor(p.log_error_color))
                    elif entry.level == "WARN":
                        cell_item.setForeground(QColor(p.log_warn_color))
                    else:
                        cell_item.setForeground(QColor(p.log_info_color))
                else:
                    cell_item.setForeground(QColor(p.text_primary))
                self.log_table.setItem(idx, col_i, cell_item)

    def _on_export_backup(self) -> None:
        default_name = f"gpt_accounts_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        target, _ = QFileDialog.getSaveFileName(
            self, "导出账号数据备份", default_name, "JSON Files (*.json)"
        )
        if not target:
            return
        self._save_accounts_safe()
        shutil.copy2(self.storage.accounts_file, target)
        self._record_log("INFO", "BACKUP_EXPORTED", f"已导出数据备份至: {target}")
        QMessageBox.information(self, "导出成功", f"数据已成功备份至：\n{target}")

    def _on_export_logs(self) -> None:
        default_name = f"gpt_manager_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        target, _ = QFileDialog.getSaveFileName(
            self, "导出结构化日志", default_name, "JSONL Files (*.jsonl);;Text Files (*.txt)"
        )
        if not target:
            return
        if self.storage.log_file.exists():
            shutil.copy2(self.storage.log_file, target)
        else:
            with open(target, "w", encoding="utf-8") as f:
                f.write("")
        self._record_log("INFO", "LOGS_EXPORTED", f"已导出日志文件至: {target}")
        QMessageBox.information(self, "导出成功", f"日志已导出至：\n{target}")

    def _on_clear_logs(self) -> None:
        reply = QMessageBox.question(
            self,
            "确认清空日志",
            "确定要清空全部历史运行日志吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.storage.logger.clear()
        self._record_log("INFO", "LOGS_CLEARED", "历史运行日志已清空。")

    def _init_system_tray(self) -> None:
        self.tray_icon = QSystemTrayIcon(self)
        app_icon = QApplication.windowIcon()
        if not app_icon.isNull():
            self.tray_icon.setIcon(app_icon)
        self.tray_icon.setToolTip("GPT 账号额度管理助手")

        tray_menu = QMenu(self)
        show_action = QAction("显示主窗口", self)
        show_action.triggered.connect(self._restore_from_tray)
        settings_action = QAction("系统与提醒设置", self)
        settings_action.triggered.connect(self._on_open_settings)
        quit_action = QAction("退出程序", self)
        quit_action.triggered.connect(self._on_force_quit)

        tray_menu.addAction(show_action)
        tray_menu.addAction(settings_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.activateWindow()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.isVisible():
                if self.isMinimized():
                    self.showNormal()
                else:
                    self.activateWindow()
            else:
                self.showNormal()
                self.activateWindow()

    def _on_force_quit(self) -> None:
        self._is_force_quitting = True
        if hasattr(self, "tray_icon"):
            self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event) -> None:
        if getattr(self, "_is_force_quitting", False):
            event.accept()
            return
        if getattr(self, "settings", None) and self.settings.minimize_to_tray and self.tray_icon.isVisible():
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "GPT 账号额度管理助手",
                "已最小化到系统托盘，后台持续运行倒计时与即将刷新提醒。",
                QSystemTrayIcon.Information,
                3000,
            )
        else:
            event.accept()

    def _notify_user(self, title: str, message: str) -> None:
        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Warning, 7000)
        send_windows_toast(title, message)

    def _on_open_settings(self) -> None:
        dlg = SettingsDialog(self.settings, self, palette=self._palette)
        if dlg.exec_() == SettingsDialog.Accepted and dlg.saved_settings is not None:
            self.settings = dlg.saved_settings
            self.storage.save_settings(self.settings)

            task_status = "已开启" if self.settings.background_task_enabled else "已关闭"
            tray_status = "已启用" if self.settings.minimize_to_tray else "未启用"
            self._record_log(
                "INFO",
                "SETTINGS_UPDATED",
                f"设置已保存：提醒开关={self.settings.notify_enabled}，阈值=额度≥{self.settings.notify_quota_threshold}%/"
                f"剩余<{self.settings.notify_hours_threshold}h，后台计划任务={task_status}，托盘后台={tray_status}。",
            )

