from __future__ import annotations

import json
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QKeySequence, QPixmap
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QShortcut,
    QStatusBar,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src.dialogs import (
    AccountDialog,
    BatchImportDialog,
    CodexLoginDialog,
    OcrConfirmDialog,
    PassphraseDialog,
    QuickQuotaDialog,
    SettingsDialog,
)
from src.codex_detector import (
    CodexMonitor,
    CodexProfile,
    CodexRateLimits,
    extract_codex_profile,
    extract_codex_rate_limits,
)
from src.launcher import (
    SequentialPasteController,
    copy_two_fa_with_expiry_guard,
    launch_isolated_browser,
)
from src.mini_hud import MiniHudWindow, ScreenSnipOverlay
from src.models import (
    HEALTH_STATUS_LABELS,
    MAX_QUOTA,
    VALID_PROVIDERS,
    Account,
    check_warranty_expiring_accounts,
    check_weekly_expiring_accounts,
    compute_totp,
    compute_vendor_roi_stats,
    format_after_sales_slip,
    format_duration,
    select_optimal_account,
)
from src.notifier import send_windows_toast
from src.network_widget import NetworkLabTab
from src.ocr_sync import CodexAuthManager, parse_quota_from_ocr_text, run_windows_ocr
from src.security import SecurityError
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
    def __init__(
        self,
        storage: AccountStorage,
        initial_theme: Optional[str] = None,
        codex_home: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.storage = storage
        self.settings: AppSettings = self.storage.load_settings()
        self.current_theme = initial_theme or self.settings.theme
        self._palette: ThemePalette = get_palette(self.current_theme)
        self.accounts: List[Account] = []
        self._row_widgets: Dict[str, RowWidgets] = {}
        self._revealed_pwds: Set[str] = set()
        self._is_force_quitting: bool = False
        self._focused_account_id: Optional[str] = None
        self._snip_overlay: Optional[ScreenSnipOverlay] = None

        self.codex_mgr = CodexAuthManager(self.storage.codex_vault_dir, codex_home=codex_home)
        self.codex_monitor = CodexMonitor(codex_home=self.codex_mgr.codex_dir, parent=self)
        self.codex_monitor.profile_updated.connect(self._on_codex_profile_changed)
        self.codex_monitor.rate_limits_updated.connect(self._on_codex_rate_limits_changed)
        self._dismissed_codex_emails: Set[str] = set()
        self._deleted_codex_emails_this_session: Set[str] = set()
        self._pending_codex_profile: Optional[CodexProfile] = None

        self.paste_ctrl = SequentialPasteController(
            self, burn_seconds=self.settings.clipboard_burn_seconds
        )
        self.paste_ctrl.state_changed.connect(self._on_paste_queue_state_changed)

        self.mini_hud = MiniHudWindow(
            on_dispatch=self._on_smart_dispatch,
            on_advance_paste=self.paste_ctrl.advance,
            on_snip_ocr=self._on_start_screen_snip_ocr,
            on_expand_main=self._restore_from_tray,
            palette=self._palette,
        )

        self.setWindowTitle("AI 多平台账号额度与防关联调度控制台 (v2.0)")
        self.resize(1440, 840)
        self.setMinimumSize(1160, 680)

        self._build_ui()
        self._bind_shortcuts()
        self._init_system_tray()
        self._apply_theme(self.current_theme, persist=False, log_event=False)
        self._load_initial_data()
        self._startup_codex_timer = QTimer(self)
        self._startup_codex_timer.setSingleShot(True)
        self._startup_codex_timer.timeout.connect(self.codex_monitor.check_now)
        self._startup_codex_timer.start(0)

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._on_tick)
        self._tick_timer.start()

    def _bind_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+Shift+D"), self, activated=self._on_smart_dispatch)
        QShortcut(QKeySequence("Ctrl+1"), self, activated=self.paste_ctrl.copy_step_email)
        QShortcut(QKeySequence("Ctrl+2"), self, activated=self.paste_ctrl.copy_step_password)
        QShortcut(QKeySequence("Ctrl+3"), self, activated=self.paste_ctrl.copy_step_totp)

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
        header_layout.setSpacing(10)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel("AI 账号双窗额度与防关联调度控制台")
        title_lbl.setObjectName("AppTitle")
        sub_lbl = QLabel(
            "DPAPI 密文仓 · EEQF 智能派号 · 独立代理隔离 · 节点 IP 风控 · 离线 OCR"
        )
        sub_lbl.setObjectName("AppSubtitle")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)

        header_layout.addLayout(title_col)
        header_layout.addStretch()

        self.hud_btn = QPushButton("🗔 置顶胶囊窗")
        self.hud_btn.setObjectName("SettingsBtn")
        self.hud_btn.setToolTip("打开/隐藏置顶微型悬浮胶囊，支持一键派号、三段吐码与框选 OCR")
        self.hud_btn.clicked.connect(self._on_toggle_mini_hud)
        header_layout.addWidget(self.hud_btn)

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("ThemeToggleBtn")
        self.theme_btn.setToolTip("切换日间（白色）与夜间（深色）模式")
        self.theme_btn.clicked.connect(self._on_toggle_theme)
        header_layout.addWidget(self.theme_btn)

        self.settings_btn = QPushButton("⚙ 设置与云同步")
        self.settings_btn.setObjectName("SettingsBtn")
        self.settings_btn.setToolTip("配置额度/质保提醒、后台计划任务、浏览器隔离与 WebDAV 加密同步")
        self.settings_btn.clicked.connect(self._on_open_settings)
        header_layout.addWidget(self.settings_btn)

        self.codex_status_badge = QLabel("Codex: 检测中...")
        self.codex_status_badge.setStyleSheet(
            "color: #94A3B8; font-size: 11px; padding: 4px 10px; border-radius: 10px; border: 1px solid #334155;"
        )
        header_layout.addWidget(self.codex_status_badge)

        self.clock_label = QLabel("")
        self.clock_label.setMinimumWidth(148)
        self.clock_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
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
        self.kpi_total = self._create_kpi_card("总纳管账号", "0")
        self.kpi_5h_ready = self._create_kpi_card("当前可派发 (5h&周>0)", "0")
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
        self.roi_tab = self._build_roi_tab()
        self.logs_tab = self._build_logs_tab()
        self.network_tab = NetworkLabTab(
            config_path=self.storage.data_dir / "network_config.json",
            get_accounts_fn=lambda: self.accounts,
            palette=self._palette,
            parent=self,
        )
        self.tabs.addTab(self.accounts_tab, "📊 账号调度与额度管理")
        self.tabs.addTab(self.roi_tab, "💰 资产质保与渠道 ROI")
        self.tabs.addTab(self.logs_tab, "📜 结构化审计日志")
        self.tabs.addTab(self.network_tab, "🌐 节点测速与 IP 风控")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        body_layout.addWidget(self.tabs)

        root.addWidget(body)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"本地加密数据仓: {self.storage.accounts_file}")

    def _create_kpi_card(self, title: str, initial_value: str) -> tuple[QFrame, QLabel, QLabel]:
        card = QFrame()
        card.setObjectName("KpiCard")
        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(16)
        shadow.setOffset(0, 3)
        shadow.setColor(QColor(15, 23, 42, 22))
        card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        t_lbl = QLabel(title)
        v_lbl = QLabel(initial_value)
        layout.addWidget(t_lbl)
        layout.addWidget(v_lbl)
        return card, t_lbl, v_lbl

    def _style_kpi_cards(self) -> None:
        p = self._palette
        is_dark = p.name == "dark"
        specs = [
            (self.kpi_total, p.kpi_total_accent),
            (self.kpi_5h_ready, p.kpi_5h_ready_accent),
            (self.kpi_5h_cooling, p.kpi_5h_cool_accent),
            (self.kpi_weekly_cooling, p.kpi_weekly_cool_accent),
        ]
        for (card, t_lbl, v_lbl), accent in specs:
            card.setStyleSheet(
                f"QFrame#KpiCard {{ background-color: {p.surface_bg}; border: 1px solid {p.border}; "
                f"border-left: 4px solid {accent}; border-radius: 12px; }}"
                f"QFrame#KpiCard:hover {{ border-color: {accent}; }}"
            )
            eff = card.graphicsEffect()
            if isinstance(eff, QGraphicsDropShadowEffect):
                eff.setColor(QColor(0, 0, 0, 85) if is_dark else QColor(15, 23, 42, 22))
            t_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 12px; font-weight: 600;")
            v_lbl.setStyleSheet(
                f"color: {accent}; font-size: 25px; font-weight: 800; font-family: 'Segoe UI', 'Microsoft YaHei UI';"
            )

    def _apply_theme(self, theme_name: str, persist: bool = True, log_event: bool = True) -> None:
        self.current_theme = "dark" if theme_name == "dark" else "light"
        self._palette = get_palette(self.current_theme)

        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(build_stylesheet(self.current_theme))

        self.theme_btn.setText("日间模式 (白)" if self.current_theme == "dark" else "夜间模式 (黑)")
        self._style_kpi_cards()
        self._style_paste_banner()
        self.mini_hud.apply_palette(self._palette)
        if hasattr(self, "network_tab"):
            self.network_tab.apply_palette(self._palette)

        if persist:
            try:
                self.storage.save_theme(self.current_theme)
            except Exception as exc:
                self._record_log("ERROR", "THEME_SAVE_FAILED", f"保存主题设置失败: {exc}")

        if hasattr(self, "account_table") and self.accounts is not None:
            self._rebuild_account_table()
        if hasattr(self, "roi_table") and self.accounts is not None:
            self._refresh_roi_tab()
        if hasattr(self, "log_table"):
            self._refresh_log_table()

        if log_event:
            mode_label = "夜间模式（深色背景）" if self.current_theme == "dark" else "日间模式（浅色背景）"
            self._record_log("INFO", "THEME_CHANGED", f"界面主题已切换为：{mode_label}。")

    def _on_toggle_theme(self) -> None:
        next_theme = "dark" if self.current_theme == "light" else "light"
        self._apply_theme(next_theme, persist=True, log_event=True)

    def _on_toggle_mini_hud(self) -> None:
        if self.mini_hud.isVisible():
            self.mini_hud.hide()
        else:
            prov_filter = (
                self.provider_filter_combo.currentText()
                if hasattr(self, "provider_filter_combo")
                else "全部平台"
            )
            self.mini_hud.refresh_snapshot(
                self.accounts,
                self._focused_account_id,
                provider_filter=prov_filter,
            )
            self.mini_hud.show()
            self.mini_hud.raise_()

    def _build_accounts_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar (2-tier layout to prevent horizontal clipping on any DPI/resolution)
        toolbar = QFrame()
        toolbar.setObjectName("ToolbarFrame")
        tb_outer = QVBoxLayout(toolbar)
        tb_outer.setContentsMargins(12, 10, 12, 10)
        tb_outer.setSpacing(8)

        tb_row1 = QHBoxLayout()
        tb_row1.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 搜索名称、邮箱或渠道...")
        self.search_input.setMinimumWidth(220)
        self.search_input.setMaximumWidth(300)
        self.search_input.textChanged.connect(self._rebuild_account_table)

        self.provider_filter_combo = QComboBox()
        self.provider_filter_combo.addItems(["全部平台", *VALID_PROVIDERS])
        self.provider_filter_combo.setMinimumWidth(110)
        self.provider_filter_combo.currentIndexChanged.connect(self._rebuild_account_table)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(
            [
                "全部状态",
                "5h 额度 > 0 (可用)",
                "5h 额度倒计时中",
                "周额度倒计时中",
                "异常/封禁/质保临期",
            ]
        )
        self.filter_combo.setMinimumWidth(155)
        self.filter_combo.currentIndexChanged.connect(self._rebuild_account_table)

        tb_row1.addWidget(self.search_input)
        tb_row1.addWidget(self.provider_filter_combo)
        tb_row1.addWidget(self.filter_combo)
        tb_row1.addStretch()

        # Primary Action Buttons
        dispatch_btn = QPushButton("⚡ 智能派号 (EEQF)")
        dispatch_btn.setObjectName("PrimaryButton")
        dispatch_btn.setToolTip(
            "按「最早过期周额度优先」算法一键选出最紧急可用账号，自动启动 5h 倒计时并装载上号队列 (Ctrl+Shift+D)"
        )
        dispatch_btn.clicked.connect(self._on_smart_dispatch)
        tb_row1.addWidget(dispatch_btn)

        codex_login_btn = QPushButton("🌐 官方登录新号")
        codex_login_btn.setObjectName("PrimaryButton")
        codex_login_btn.setToolTip("通过官方 OAuth 登录网页，完成后免密全自动提取账号凭据与会员状态")
        codex_login_btn.clicked.connect(self._on_codex_login_ingest)
        tb_row1.addWidget(codex_login_btn)

        add_btn = QPushButton("+ 添加账号")
        add_btn.setObjectName("PrimaryButton")
        add_btn.clicked.connect(self._on_add_account)
        tb_row1.addWidget(add_btn)

        tb_outer.addLayout(tb_row1)

        tb_row2 = QHBoxLayout()
        tb_row2.setSpacing(8)

        batch_btn = QPushButton("📋 批量识别导入")
        batch_btn.clicked.connect(self._on_batch_import)
        tb_row2.addWidget(batch_btn)

        # Offline OCR Menu Button
        ocr_btn = QPushButton("📷 离线OCR校准")
        ocr_menu = QMenu(ocr_btn)
        ocr_menu.addAction("框选屏幕网页区域识别", self._on_start_screen_snip_ocr)
        ocr_menu.addAction("从系统剪贴板截图识别 (Win+Shift+S)", self._on_clipboard_ocr)
        ocr_menu.addAction("选择本地截图文件识别...", self._on_file_ocr)
        ocr_btn.setMenu(ocr_menu)
        tb_row2.addWidget(ocr_btn)

        # Backup & Sync Menu Button
        backup_btn = QPushButton("🔐 加密备份/恢复")
        backup_menu = QMenu(backup_btn)
        backup_menu.addAction("导出跨设备 AES-256 加密备份...", self._on_export_encrypted_backup)
        backup_menu.addAction("导入加密/历史备份并智能合并...", self._on_import_backup_merge)
        backup_menu.addSeparator()
        backup_menu.addAction("导出本地原文件备份...", self._on_export_backup)
        backup_btn.setMenu(backup_menu)
        tb_row2.addWidget(backup_btn)
        tb_row2.addStretch()

        tb_outer.addLayout(tb_row2)
        layout.addWidget(toolbar)

        # Codex Auto-Detection Banner (shows when unmanaged Codex account detected)
        self.codex_banner = QFrame()
        self.codex_banner.setVisible(False)
        self.codex_banner.setObjectName("CodexAlertBanner")
        cb_lay = QHBoxLayout(self.codex_banner)
        cb_lay.setContentsMargins(12, 8, 12, 8)
        cb_lay.setSpacing(10)

        self.codex_banner_lbl = QLabel("")
        self.codex_banner_lbl.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.codex_ingest_btn = QPushButton("⚡ 一键自动纳管")
        self.codex_ingest_btn.setObjectName("PrimaryButton")
        self.codex_ingest_btn.clicked.connect(self._on_ingest_current_codex)
        self.codex_dismiss_btn = QPushButton("忽略")
        self.codex_dismiss_btn.clicked.connect(self._on_dismiss_codex_banner)

        cb_lay.addWidget(self.codex_banner_lbl, 1)
        cb_lay.addWidget(self.codex_ingest_btn)
        cb_lay.addWidget(self.codex_dismiss_btn)
        layout.addWidget(self.codex_banner)

        # Sequential Paste Queue Interactive Banner (hidden when IDLE)
        self.paste_banner = QFrame()
        self.paste_banner.setVisible(False)
        pb_lay = QHBoxLayout(self.paste_banner)
        pb_lay.setContentsMargins(12, 8, 12, 8)
        pb_lay.setSpacing(8)

        self.paste_msg_lbl = QLabel("")
        self.paste_msg_lbl.setStyleSheet("font-weight: 700; font-size: 12px;")

        btn_s1 = QPushButton("1.邮箱 (Ctrl+1)")
        btn_s1.clicked.connect(self.paste_ctrl.copy_step_email)
        btn_s2 = QPushButton("2.密码 (Ctrl+2)")
        btn_s2.clicked.connect(self.paste_ctrl.copy_step_password)
        btn_s3 = QPushButton("3.防过期2FA (Ctrl+3)")
        btn_s3.clicked.connect(self.paste_ctrl.copy_step_totp)
        btn_next = QPushButton("▶ 下一步")
        btn_next.setObjectName("PrimaryButton")
        btn_next.clicked.connect(self.paste_ctrl.advance)
        btn_cancel = QPushButton("🔥 清空退出")
        btn_cancel.clicked.connect(lambda: self.paste_ctrl.cancel(burn_now=True))

        pb_lay.addWidget(self.paste_msg_lbl, 1)
        pb_lay.addWidget(btn_s1)
        pb_lay.addWidget(btn_s2)
        pb_lay.addWidget(btn_s3)
        pb_lay.addWidget(btn_next)
        pb_lay.addWidget(btn_cancel)
        layout.addWidget(self.paste_banner)

        # Account Table
        self.account_table = QTableWidget()
        self.account_table.setColumnCount(9)
        self.account_table.setHorizontalHeaderLabels(
            [
                "平台 / 账号名称",
                "账号邮箱",
                "登录密码",
                "2FA 动态/初始码",
                "5h 剩余额度",
                "5h 重置倒计时",
                "周剩余额度",
                "周重置倒计时",
                "防关联与管理操作",
            ]
        )
        self.account_table.setAlternatingRowColors(True)
        self.account_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.account_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.account_table.verticalHeader().setVisible(False)
        self.account_table.setFocusPolicy(Qt.NoFocus)
        self.account_table.cellDoubleClicked.connect(self._on_table_cell_double_clicked)

        header = self.account_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.Interactive)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        header.setSectionResizeMode(6, QHeaderView.Interactive)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        header.setSectionResizeMode(8, QHeaderView.Fixed)

        self.account_table.setColumnWidth(0, 155)
        self.account_table.setColumnWidth(1, 185)
        self.account_table.setColumnWidth(2, 140)
        self.account_table.setColumnWidth(3, 140)
        self.account_table.setColumnWidth(4, 200)
        self.account_table.setColumnWidth(5, 102)
        self.account_table.setColumnWidth(6, 115)
        self.account_table.setColumnWidth(7, 122)
        self.account_table.setColumnWidth(8, 310)

        layout.addWidget(self.account_table, 1)
        return tab

    def _style_paste_banner(self) -> None:
        p = self._palette
        if hasattr(self, "paste_banner"):
            self.paste_banner.setStyleSheet(
                f"QFrame {{ background-color: {p.info_bg}; border: 1px solid {p.info_border}; border-radius: 8px; }}"
            )
            self.paste_msg_lbl.setStyleSheet(f"color: {p.info_text}; font-weight: 700; font-size: 12px;")

        if hasattr(self, "codex_banner"):
            self.codex_banner.setStyleSheet(
                f"QFrame#CodexAlertBanner {{ background-color: {p.surface_bg}; "
                f"border: 1px solid {p.primary_border}; border-left: 4px solid {p.primary_bg}; "
                f"border-radius: 8px; }}"
            )
            if hasattr(self, "codex_banner_lbl"):
                self.codex_banner_lbl.setStyleSheet(f"color: {p.text_primary}; font-weight: 600; font-size: 12px;")

    def _build_roi_tab(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(10)

        top_bar = QFrame()
        top_bar.setObjectName("ToolbarFrame")
        tb = QHBoxLayout(top_bar)
        tb.setContentsMargins(12, 10, 12, 10)
        tb.setSpacing(12)

        self.roi_summary_lbl = QLabel("渠道存活率与投入成本统计")
        self.roi_summary_lbl.setStyleSheet("font-weight: 700; font-size: 13px;")
        tb.addWidget(self.roi_summary_lbl, 1)

        slip_btn = QPushButton("📋 一键复制异常/封禁号售后凭条")
        slip_btn.setObjectName("PrimaryButton")
        slip_btn.clicked.connect(self._on_copy_after_sales_slip)
        tb.addWidget(slip_btn)
        lay.addWidget(top_bar)

        self.roi_table = QTableWidget()
        self.roi_table.setColumnCount(8)
        self.roi_table.setHorizontalHeaderLabels(
            [
                "来源渠道标签",
                "总购入账号数",
                "正常可用数",
                "已封禁数",
                "封号折损率",
                "累计采购成本",
                "累计5h会话轮次",
                "单轮5h摊销均价",
            ]
        )
        self.roi_table.setAlternatingRowColors(True)
        self.roi_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.roi_table.verticalHeader().setVisible(False)
        self.roi_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.roi_table, 1)
        return tab

    def _build_logs_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        bar = QFrame()
        bar.setObjectName("ToolbarFrame")
        bar_lay = QHBoxLayout(bar)
        bar_lay.setContentsMargins(12, 10, 12, 10)
        bar_lay.setSpacing(10)

        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["全部级别", "INFO", "WARN", "ERROR"])
        self.log_level_combo.currentIndexChanged.connect(self._refresh_log_table)

        self.log_search_input = QLineEdit()
        self.log_search_input.setPlaceholderText("搜索日志事件、账号或详情...")
        self.log_search_input.setMaximumWidth(280)
        self.log_search_input.textChanged.connect(self._refresh_log_table)

        bar_lay.addWidget(QLabel("级别:"))
        bar_lay.addWidget(self.log_level_combo)
        bar_lay.addWidget(self.log_search_input)
        bar_lay.addStretch()

        export_log_btn = QPushButton("导出日志")
        export_log_btn.clicked.connect(self._on_export_logs)
        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.setObjectName("DangerButton")
        clear_log_btn.clicked.connect(self._on_clear_logs)
        bar_lay.addWidget(export_log_btn)
        bar_lay.addWidget(clear_log_btn)
        layout.addWidget(bar)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels(
            ["时间戳", "Trace ID", "级别", "事件类型", "关联账号", "操作与状态详情"]
        )
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.log_table.verticalHeader().setVisible(False)

        lh = self.log_table.horizontalHeader()
        lh.setSectionResizeMode(0, QHeaderView.Fixed)
        lh.setSectionResizeMode(1, QHeaderView.Fixed)
        lh.setSectionResizeMode(2, QHeaderView.Fixed)
        lh.setSectionResizeMode(3, QHeaderView.Fixed)
        lh.setSectionResizeMode(4, QHeaderView.Interactive)
        lh.setSectionResizeMode(5, QHeaderView.Stretch)
        self.log_table.setColumnWidth(0, 155)
        self.log_table.setColumnWidth(1, 90)
        self.log_table.setColumnWidth(2, 70)
        self.log_table.setColumnWidth(3, 185)
        self.log_table.setColumnWidth(4, 190)

        layout.addWidget(self.log_table, 1)
        return tab

    def _on_tab_changed(self, idx: int) -> None:
        if idx == 1:
            self._refresh_roi_tab()
        elif idx == 2:
            self._refresh_log_table()

    def _load_initial_data(self) -> None:
        now = time.time()
        try:
            self.accounts = self.storage.load_accounts()
        except Exception as exc:
            self.accounts = []
            self._record_log("ERROR", "STORAGE_LOAD_ERROR", f"读取本地账号数据失败: {exc}")
            QMessageBox.critical(self, "数据加载异常", f"读取本地数据文件时发生异常：\n{exc}")

        any_reset = False
        for acc in self.accounts:
            triggered = acc.tick(now)
            if triggered:
                any_reset = True
                for ev in triggered:
                    self._log_auto_reset(acc, ev, catch_up=True)

        if any_reset:
            self._save_accounts_safe()

        self._record_log("INFO", "APP_START", f"软件启动完成，共加载 {len(self.accounts)} 个账号。")
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(now)
        self._refresh_log_table()

    def _save_accounts_safe(self) -> None:
        try:
            self.storage.save_accounts(self.accounts)
        except Exception as exc:
            self._record_log("ERROR", "STORAGE_SAVE_ERROR", f"保存本地账号数据失败: {exc}")
            QMessageBox.critical(self, "保存失败", f"写入本地数据文件失败：\n{exc}")

    def _record_log(self, level: str, event: str, detail: str, account: str = "-") -> None:
        self.storage.logger.log(level=level, event=event, detail=detail, account=account)
        if hasattr(self, "log_table"):
            self._refresh_log_table()

    def _log_auto_reset(self, acc: Account, ev_code: str, catch_up: bool) -> None:
        prefix = "离线期间倒计时已到期，" if catch_up else "倒计时结束，"
        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
        if ev_code == "AUTO_RESET_5H":
            self._record_log("INFO", "AUTO_RESET_5H", f"{prefix}5h 额度已自动恢复为 100。", acc_ref)
        elif ev_code == "AUTO_RESET_WEEKLY":
            self._record_log("INFO", "AUTO_RESET_WEEKLY", f"{prefix}周额度已自动恢复为 100。", acc_ref)

    def _filtered_accounts(self) -> List[Account]:
        kw = self.search_input.text().strip().lower()
        prov_sel = self.provider_filter_combo.currentText() if hasattr(self, "provider_filter_combo") else "全部平台"
        mode = self.filter_combo.currentIndex()
        now = time.time()
        out: List[Account] = []
        for acc in self.accounts:
            if prov_sel != "全部平台" and acc.provider != prov_sel:
                continue
            if kw and (
                kw not in acc.name.lower()
                and kw not in acc.email.lower()
                and kw not in acc.vendor_tag.lower()
            ):
                continue
            if mode == 1 and (acc.five_hour_quota <= 0 or acc.health_status == "BANNED"):
                continue
            if mode == 2 and acc.five_hour_reset_at is None:
                continue
            if mode == 3 and acc.weekly_reset_at is None:
                continue
            if mode == 4:
                w_rem = acc.warranty_remaining_seconds(now)
                is_warranty_soon = w_rem is not None and 0 < w_rem <= 48 * 3600
                if acc.health_status == "ACTIVE" and not is_warranty_soon:
                    continue
            out.append(acc)
        return out

    def _rebuild_account_table(self) -> None:
        p = self._palette
        visible = self._filtered_accounts()
        self._row_widgets.clear()
        self.account_table.setRowCount(len(visible))
        now = time.time()
        curr_codex_prof = (
            self.codex_monitor._last_profile if hasattr(self, "codex_monitor") else None
        )
        active_codex_email = (
            (curr_codex_prof.email or "").strip().lower() if curr_codex_prof else ""
        )
        if hasattr(self, "mini_hud") and self.mini_hud.isVisible():
            prov_filter = (
                self.provider_filter_combo.currentText()
                if hasattr(self, "provider_filter_combo")
                else "全部平台"
            )
            self.mini_hud.refresh_snapshot(
                self.accounts,
                self._focused_account_id,
                now_ts=now,
                provider_filter=prov_filter,
            )

        for row_idx, acc in enumerate(visible):
            self.account_table.setRowHeight(row_idx, 54)

            # Col 0: Provider + Name + Health/Proxy badges
            tags: List[str] = [f"[{acc.provider}]"]
            if acc.health_status != "ACTIVE":
                tags.append(f"[{HEALTH_STATUS_LABELS.get(acc.health_status, acc.health_status)}]")
            if acc.proxy_url:
                tags.append("[代理]")
            display_name = f"{''.join(tags)} {acc.name}"
            name_item = QTableWidgetItem(display_name)
            bold_font = QFont()
            bold_font.setBold(True)
            name_item.setFont(bold_font)
            if acc.health_status == "BANNED":
                name_item.setForeground(QColor(p.danger_text))
            elif acc.health_status in ("DEGRADED_POW", "PHONE_VERIFY"):
                name_item.setForeground(QColor(p.warn_text))
            else:
                name_item.setForeground(QColor(p.text_primary))

            tip_parts = [f"平台: {acc.provider}", f"状态: {HEALTH_STATUS_LABELS.get(acc.health_status)}"]
            if acc.vendor_tag:
                tip_parts.append(f"渠道: {acc.vendor_tag} (¥{acc.purchase_price:.2f})")
            if acc.proxy_url:
                tip_parts.append(f"独立代理: {acc.proxy_url}")
            w_rem = acc.warranty_remaining_seconds(now)
            if w_rem is not None:
                tip_parts.append(f"质保剩余: {format_duration(w_rem)}" if w_rem > 0 else "质保: 已过保")
            if acc.notes:
                tip_parts.append(f"备注: {acc.notes}")
            name_item.setToolTip("\n".join(tip_parts))
            self.account_table.setItem(row_idx, 0, name_item)

            # Col 1: Email + copy
            email_cell = self._make_copy_cell(
                acc.email,
                lambda _=False, text=acc.email, a=acc: self._copy_text(text, "邮箱", a),
            )
            self.account_table.setCellWidget(row_idx, 1, email_cell)

            # Col 2: Password
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

            # Col 3: 2FA + expiry-safe copy
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

            # Col 8: Actions (Codex Quick Switch + Launch/Paste Menu + Quota + Edit + Delete)
            act_cell = QWidget()
            act_lay = QHBoxLayout(act_cell)
            act_lay.setContentsMargins(4, 4, 4, 4)
            act_lay.setSpacing(4)

            is_active_codex = bool(
                active_codex_email and acc.email.strip().lower() == active_codex_email
            )
            has_snap = self.codex_mgr.has_snapshot(acc.id)

            switch_btn = QPushButton()
            if is_active_codex:
                switch_btn.setText("🟢 使用中")
                switch_btn.setEnabled(False)
                switch_btn.setStyleSheet(
                    "padding: 3px 6px; font-size: 11px; background-color: #064E3B; "
                    "border: 1px solid #059669; color: #6EE7B7; font-weight: 700; border-radius: 4px;"
                )
                switch_btn.setToolTip("当前本地 ~/.codex 正在使用此账号授权，终端与插件可直接调用")
            elif has_snap:
                switch_btn.setText("⚡ 切为此号")
                switch_btn.setStyleSheet(
                    "padding: 3px 6px; font-size: 11px; background-color: #047857; "
                    "border: 1px solid #10B981; color: #FFFFFF; font-weight: 700; border-radius: 4px;"
                )
                switch_btn.setToolTip("一键将本地 ~/.codex/auth.json 切换为此账号授权（0.05秒原子生效）")
                switch_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_quick_switch_codex(aid))
            else:
                switch_btn.setText("🔗 绑定授权")
                switch_btn.setStyleSheet(
                    f"padding: 3px 6px; font-size: 11px; background-color: {p.surface_bg}; "
                    f"border: 1px dashed {p.border}; color: {p.text_secondary}; border-radius: 4px;"
                )
                switch_btn.setToolTip("该账号尚未保存本地 Codex 授权快照。点击绑定当前已登录授权或调起登录")
                switch_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_quick_bind_codex(aid))

            launch_btn = QPushButton("上号▾")
            launch_btn.setStyleSheet(
                f"padding: 3px 6px; font-size: 11px; background-color: {p.primary_bg}; "
                f"border: none; color: #FFFFFF; font-weight: 700;"
            )
            l_menu = QMenu(launch_btn)
            l_menu.addAction(
                "🌐 隔离浏览器启动 + 顺序吐码",
                lambda aid=acc.id: self._on_launch_isolated_and_paste(aid),
            )
            l_menu.addAction(
                "📋 仅启动三段式顺序吐码队列",
                lambda aid=acc.id: self._on_start_paste_only(aid),
            )
            l_menu.addSeparator()
            snap_mark = " (已绑定)" if has_snap else ""
            l_menu.addAction(
                f"⚡ 切换本地 ~/.codex 授权为此号{snap_mark}",
                lambda aid=acc.id: self._on_activate_codex_auth(aid),
            )
            l_menu.addAction(
                "💾 捕获当前 ~/.codex/auth.json 绑定到此号",
                lambda aid=acc.id: self._on_capture_codex_auth(aid),
            )
            l_menu.addSeparator()
            l_menu.addAction(
                "📡 测速并评估节点 IP / VPN 风险",
                lambda aid=acc.id: self._on_probe_account_network(aid),
            )
            launch_btn.setMenu(l_menu)

            quota_btn = QPushButton("改额度")
            quota_btn.setStyleSheet(
                f"padding: 3px 6px; font-size: 11px; background-color: {p.info_bg}; "
                f"border: 1px solid {p.info_border}; color: {p.info_text};"
            )
            quota_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_quick_quota(aid))

            edit_btn = QPushButton("编辑")
            edit_btn.setStyleSheet("padding: 3px 6px; font-size: 11px;")
            edit_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_edit_account(aid))

            del_btn = QPushButton("删除")
            del_btn.setStyleSheet(
                f"padding: 3px 6px; font-size: 11px; background-color: {p.danger_bg}; "
                f"border: 1px solid {p.danger_border}; color: {p.danger_text};"
            )
            del_btn.clicked.connect(lambda _=False, aid=acc.id: self._on_delete_account(aid))

            act_lay.addWidget(switch_btn)
            act_lay.addWidget(launch_btn)
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
        rw.five_bar.setValue(acc.five_hour_quota)
        self._set_bar_color(rw.five_bar, acc.five_hour_quota)
        rw.five_label.setText(f"{acc.five_hour_quota}%")
        rw.zero_btn.setEnabled(acc.five_hour_quota > 0 and acc.health_status not in ("BANNED", "PHONE_VERIFY"))

        five_rem = acc.five_hour_remaining_seconds(now)
        if five_rem is not None:
            rw.start_5h_btn.setText("计时中")
            rw.start_5h_btn.setEnabled(False)
            rw.start_5h_btn.setToolTip("5h 重置倒计时运行中")
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
            can_start, reason = acc.can_start_five_hour_usage
            if not can_start:
                if acc.health_status == "BANNED":
                    btn_text = "已封禁"
                elif acc.health_status == "PHONE_VERIFY":
                    btn_text = "待接码"
                elif acc.weekly_quota <= 0:
                    btn_text = "无周额度"
                elif acc.five_hour_quota <= 0:
                    btn_text = "额度为0"
                else:
                    btn_text = "不可用"
                rw.start_5h_btn.setText(btn_text)
                rw.start_5h_btn.setEnabled(False)
                rw.start_5h_btn.setToolTip(reason)
                rw.start_5h_btn.setStyleSheet(
                    f"padding: 2px 6px; font-size: 11px; background-color: {p.input_disabled_bg}; "
                    f"color: {p.text_muted}; border: 1px solid {p.border}; border-radius: 4px;"
                )
            else:
                rw.start_5h_btn.setText("开始使用")
                rw.start_5h_btn.setEnabled(True)
                urg = acc.burn_urgency_score(now)
                rw.start_5h_btn.setToolTip(
                    f"立即启动 5 小时倒计时（EEQF 防过期紧急度: {urg:.2f}%/h）"
                )
                rw.start_5h_btn.setStyleSheet(
                    f"padding: 2px 6px; font-size: 11px; background-color: {p.primary_bg}; "
                    f"color: #FFFFFF; border: none; border-radius: 4px; font-weight: 600;"
                )
            rw.five_timer_label.setText("未触发")
            rw.five_timer_label.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")

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

        totp_code, totp_rem = compute_totp(acc.two_fa, now)
        if totp_code is not None:
            rw.two_fa_label.setText(f"{totp_code} ({totp_rem:02d}s)")
            if totp_rem <= 3:
                rw.two_fa_label.setStyleSheet(
                    f"font-family: 'Consolas', monospace; font-weight: 700; color: {p.warn_text};"
                )
            else:
                rw.two_fa_label.setStyleSheet(
                    f"font-family: 'Consolas', monospace; font-weight: 600; color: {p.text_primary};"
                )
            rw.two_fa_label.setToolTip("实时 6 位 TOTP 验证码（点击复制时若剩余 ≤3s 将自动顺延获取下一周期新码）")
        else:
            rw.two_fa_label.setText(acc.two_fa)
            rw.two_fa_label.setToolTip("初始/静态 2FA 验证码")

    def _refresh_kpis(self, now: Optional[float] = None) -> None:
        ts = time.time() if now is None else now
        total = len(self.accounts)
        ready_5h = sum(
            1
            for a in self.accounts
            if a.five_hour_quota > 0
            and a.weekly_quota > 0
            and a.health_status in ("ACTIVE", "DEGRADED_POW")
        )
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
        if self.mini_hud.isVisible():
            prov_filter = (
                self.provider_filter_combo.currentText()
                if hasattr(self, "provider_filter_combo")
                else "全部平台"
            )
            self.mini_hud.refresh_snapshot(
                self.accounts,
                self._focused_account_id,
                now_ts=ts,
                provider_filter=prov_filter,
            )

    def _refresh_roi_tab(self) -> None:
        if not hasattr(self, "roi_table"):
            return
        p = self._palette
        rows = compute_vendor_roi_stats(self.accounts)
        self.roi_table.setRowCount(len(rows))

        total_spend = sum(r.total_cost for r in rows)
        total_accs = len(self.accounts)
        total_banned = sum(r.banned_count for r in rows)
        now = time.time()
        warranty_soon = len(check_warranty_expiring_accounts(self.accounts, hours_threshold=48, now_ts=now))
        self.roi_summary_lbl.setText(
            f"总纳管: {total_accs} 个 | 累计购号成本: ¥{total_spend:.2f} | "
            f"已封禁折损: {total_banned} 个 | 48h内质保临期: {warranty_soon} 个"
        )

        for idx, r in enumerate(rows):
            self.roi_table.setRowHeight(idx, 36)
            cps_str = f"¥{r.cost_per_session:.2f} / 轮" if r.cost_per_session is not None else "-"
            vals = [
                r.vendor,
                str(r.total_count),
                str(r.active_count),
                str(r.banned_count),
                f"{r.ban_rate_pct:.1f}%",
                f"¥{r.total_cost:.2f}",
                str(r.total_5h_sessions),
                cps_str,
            ]
            for c_i, txt in enumerate(vals):
                item = QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignCenter if c_i > 0 else (Qt.AlignLeft | Qt.AlignVCenter))
                if c_i == 4 and r.ban_rate_pct >= 30.0:
                    item.setForeground(QColor(p.danger_text))
                else:
                    item.setForeground(QColor(p.text_primary))
                self.roi_table.setItem(idx, c_i, item)

    # ------------------------------------------------------------------
    # Core Feature Actions: Smart Dispatch, Isolated Browser, Paste, OCR
    # ------------------------------------------------------------------
    def _on_smart_dispatch(self) -> None:
        now = time.time()
        prov_filter = (
            self.provider_filter_combo.currentText()
            if hasattr(self, "provider_filter_combo")
            else "全部平台"
        )
        rec = select_optimal_account(self.accounts, provider=prov_filter, now_ts=now)
        if rec.account is None:
            QMessageBox.information(self, "智能派号结果", rec.reason)
            return

        acc = rec.account
        self._focused_account_id = acc.id
        if rec.status == "READY_NEW_5H":
            acc.start_five_hour_usage(now_ts=now)
            self._save_accounts_safe()
            self._record_log(
                "INFO",
                "EEQF_SMART_DISPATCH",
                f"{rec.reason}；已自动启动 5h 倒计时并装载上号队列。",
                f"[{acc.provider}] {acc.name}",
            )
            self.paste_ctrl.start(acc)
            self._rebuild_account_table()
            self._refresh_kpis(now)
            self._highlight_account_row(acc.id)
            self.status_bar.showMessage(f"⚡ 已派发最优账号「{acc.name}」：{rec.reason}", 8000)
        elif rec.status == "ACTIVE_WINDOW_REUSE":
            self.paste_ctrl.start(acc)
            self._highlight_account_row(acc.id)
            self.status_bar.showMessage(f"⚡ 复用当前活跃会话「{acc.name}」：{rec.reason}", 8000)
        else:
            QMessageBox.information(self, "全部冷却中", rec.reason)

    def _highlight_account_row(self, account_id: str) -> None:
        visible = self._filtered_accounts()
        for r_idx, a in enumerate(visible):
            if a.id == account_id:
                self.account_table.selectRow(r_idx)
                item = self.account_table.item(r_idx, 0)
                if item is not None:
                    self.account_table.scrollToItem(item)
                break

    def _on_paste_queue_state_changed(self, state_code: str, message: str) -> None:
        if state_code == "IDLE":
            self.paste_banner.setVisible(False)
            if message:
                self.status_bar.showMessage(message, 5000)
        else:
            self.paste_msg_lbl.setText(message)
            self.paste_banner.setVisible(True)
        self.mini_hud.update_paste_queue_state(state_code, message)

    def _on_start_paste_only(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        self._focused_account_id = acc.id
        self.paste_ctrl.start(acc)
        self._record_log("INFO", "PASTE_QUEUE_STARTED", "已启动三段式顺序吐码队列。", f"{acc.name} ({acc.email})")

    def _on_launch_isolated_and_paste(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        try:
            prof_dir = launch_isolated_browser(
                acc,
                profiles_root=self.storage.profiles_dir,
                custom_browser_path=self.settings.custom_browser_path,
            )
        except Exception as err:
            self._record_log("ERROR", "BROWSER_LAUNCH_FAILED", str(err), f"{acc.name}")
            QMessageBox.warning(self, "隔离浏览器启动失败", str(err))
            return

        self._focused_account_id = acc.id
        self.paste_ctrl.start(acc)
        proxy_note = f"，独立代理={acc.proxy_url}" if acc.proxy_url else "，直连"
        self._record_log(
            "INFO",
            "ISOLATED_BROWSER_LAUNCHED",
            f"已启动隔离浏览器实例（目录: {prof_dir.name}{proxy_note}）并就绪邮箱粘贴。",
            f"[{acc.provider}] {acc.name}",
        )
        self.status_bar.showMessage(
            f"🌐 已为「{acc.name}」打开独立防关联浏览器窗口，邮箱已自动写入剪贴板！", 7000
        )

    def _on_capture_codex_auth(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        try:
            dest = self.codex_mgr.capture_current_auth(acc.id)
            self._record_log(
                "INFO",
                "CODEX_AUTH_CAPTURED",
                f"已捕获 ~/.codex/auth.json 并通过 DPAPI 加密绑定至快照 ({dest.name})。",
                f"{acc.name}",
            )
            self._rebuild_account_table()
            QMessageBox.information(
                self, "绑定成功", f"已将当前 ~/.codex/auth.json 加密绑定至账号「{acc.name}」。"
            )
        except Exception as err:
            QMessageBox.warning(self, "捕获 Codex 授权失败", str(err))

    def _on_activate_codex_auth(self, account_id: str, quiet: bool = False) -> bool:
        acc = self._find_account(account_id)
        if acc is None:
            return False
        try:
            target_auth = self.codex_mgr.activate_snapshot(acc.id)
            self._focused_account_id = acc.id
            self._record_log(
                "INFO",
                "CODEX_AUTH_SWITCHED",
                f"已原子切换 {target_auth} 为当前账号授权（原文件已备份为 auth.json.bak）。",
                f"{acc.name} ({acc.email})",
            )
            if hasattr(self, "codex_monitor"):
                self.codex_monitor.check_now()
            self._rebuild_account_table()
            msg = f"⚡ 已成功切换本地 Codex 授权为「{acc.name}」({acc.email})，终端与插件已即时生效！"
            self.status_bar.showMessage(msg, 6000)
            if quiet:
                send_windows_toast("Codex 授权切换成功", msg)
            else:
                QMessageBox.information(
                    self, "切换成功", f"已将本地 Codex CLI 授权切换为账号「{acc.name}」。"
                )
            return True
        except Exception as err:
            self._record_log("ERROR", "CODEX_AUTH_SWITCH_FAILED", str(err), f"{acc.name}")
            QMessageBox.warning(self, "切换 Codex 授权失败", str(err))
            return False

    def _on_quick_switch_codex(self, account_id: str) -> None:
        self._on_activate_codex_auth(account_id, quiet=True)

    def _on_quick_bind_codex(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        curr_prof = self.codex_monitor.current_profile if hasattr(self, "codex_monitor") else None
        if curr_prof is not None and curr_prof.email:
            curr_email = curr_prof.email.strip().lower()
            target_email = acc.email.strip().lower()
            if curr_email == target_email:
                try:
                    dest = self.codex_mgr.capture_current_auth(acc.id)
                    self._record_log(
                        "INFO",
                        "CODEX_AUTH_CAPTURED",
                        f"已自动捕获当前 ~/.codex/auth.json 并加密绑定至「{acc.name}」({dest.name})。",
                        acc.name,
                    )
                    self._rebuild_account_table()
                    self.status_bar.showMessage(
                        f"🔗 已成功将宿主机当前 Codex 授权自动绑定至「{acc.name}」！", 5000
                    )
                except Exception as err:
                    QMessageBox.warning(self, "绑定授权失败", str(err))
                return

            reply = QMessageBox.question(
                self,
                "绑定 Codex 授权",
                f"当前宿主机已登录的 Codex 账号为「{curr_prof.email}」，与本账号「{acc.email}」不同。\n\n"
                f"• 点击「是 (Yes)」：调起官方浏览器为「{acc.name}」登录新授权并自动绑定；\n"
                f"• 点击「否 (No)」：强行将当前的「{curr_prof.email}」授权绑定至本号；\n"
                f"• 点击「取消」：放弃操作。",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                self._on_codex_login_ingest()
            elif reply == QMessageBox.No:
                try:
                    self.codex_mgr.capture_current_auth(acc.id)
                    self._rebuild_account_table()
                    self.status_bar.showMessage(
                        f"🔗 已将当前授权快照绑定至账号「{acc.name}」。", 5000
                    )
                except Exception as err:
                    QMessageBox.warning(self, "绑定授权失败", str(err))
        else:
            reply = QMessageBox.question(
                self,
                "未检测到本地登录",
                "本地 ~/.codex/auth.json 尚未登录任何账号。\n\n是否立即调起官方浏览器进行登录？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                self._on_codex_login_ingest()

    def _on_table_cell_double_clicked(self, row: int, col: int) -> None:
        visible = self._filtered_accounts()
        if 0 <= row < len(visible):
            acc = visible[row]
            if self.codex_mgr.has_snapshot(acc.id):
                curr_prof = self.codex_monitor.current_profile if hasattr(self, "codex_monitor") else None
                active_email = (curr_prof.email or "").strip().lower() if curr_prof else ""
                if active_email != acc.email.strip().lower():
                    self._on_quick_switch_codex(acc.id)

    def _on_probe_account_network(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        if hasattr(self, "network_tab"):
            self.tabs.setCurrentWidget(self.network_tab)
            self.network_tab.probe_account_proxy(acc)
            self._record_log(
                "INFO",
                "NETWORK_IP_PROBE",
                f"已为账号「{acc.name}」触发节点测速与 VPN/IP 风险评分。",
                acc.name,
            )

    def _on_codex_profile_changed(self, profile: Optional[CodexProfile]) -> None:
        if profile is None:
            if hasattr(self, "codex_status_badge"):
                self.codex_status_badge.setText("Codex: ⚪ 未登录")
                self.codex_status_badge.setStyleSheet(
                    "color: #94A3B8; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #334155;"
                )
            if hasattr(self, "codex_banner"):
                self.codex_banner.setVisible(False)
            self._pending_codex_profile = None
            self._rebuild_account_table()
            return

        plan_desc = profile.display_plan
        email = profile.email
        if hasattr(self, "codex_status_badge"):
            self.codex_status_badge.setText(f"Codex: 🟢 {email} ({plan_desc})")
            self.codex_status_badge.setStyleSheet(
                "color: #10B981; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 4px; border: 1px solid #059669;"
            )

        # Check if already in accounts
        matched: Optional[Account] = None
        for acc in self.accounts:
            if acc.email.strip().lower() == email.strip().lower():
                matched = acc
                break

        if matched is not None:
            if hasattr(self, "codex_banner"):
                self.codex_banner.setVisible(False)
            self._pending_codex_profile = None
            # Always keep the latest DPAPI-encrypted auth.json snapshot preserved for this account
            if self.codex_mgr.auth_file.exists():
                try:
                    self.codex_mgr.capture_current_auth(matched.id)
                except Exception:
                    pass
            if matched.warranty_expire_at is None and profile.subscription_expire_timestamp is not None:
                matched.warranty_expire_at = profile.subscription_expire_timestamp
                matched.updated_at = time.time()
                self._save_accounts_safe()
            self._rebuild_account_table()
        else:
            self._pending_codex_profile = profile
            if email.lower() not in self._deleted_codex_emails_this_session:
                # Auto-ingest immediately so every logged-in Codex account is preserved without manual action
                self._auto_ingest_codex_profile(profile, silent=True)
            elif email.lower() not in self._dismissed_codex_emails and hasattr(self, "codex_banner"):
                self.codex_banner_lbl.setText(
                    f"🔍 检测到宿主机 Codex 已登录账号：{email} ({plan_desc})，尚未纳入本系统管理。"
                )
                self.codex_banner.setVisible(True)

    def _on_codex_rate_limits_changed(self, rl: Optional[CodexRateLimits]) -> None:
        if rl is None:
            return
        prof = self.codex_monitor.current_profile
        if prof is None:
            return
        matched: Optional[Account] = None
        for acc in self.accounts:
            if acc.email.strip().lower() == prof.email.strip().lower():
                matched = acc
                break
        if matched is None:
            return

        changed = (
            matched.five_hour_quota != rl.five_hour_quota
            or matched.weekly_quota != rl.weekly_quota
            or abs((matched.five_hour_reset_at or 0.0) - (rl.five_hour_reset_at or 0.0)) > 2.0
            or (matched.five_hour_reset_at is None) != (rl.five_hour_reset_at is None)
            or abs((matched.weekly_reset_at or 0.0) - (rl.weekly_reset_at or 0.0)) > 2.0
            or (matched.weekly_reset_at is None) != (rl.weekly_reset_at is None)
        )
        if not changed:
            return

        matched.five_hour_quota = rl.five_hour_quota
        matched.five_hour_reset_at = rl.five_hour_reset_at
        matched.weekly_quota = rl.weekly_quota
        matched.weekly_reset_at = rl.weekly_reset_at
        matched.updated_at = time.time()

        self._save_accounts_safe()
        self._rebuild_account_table()
        self._refresh_kpis()
        self._record_log(
            "INFO",
            "CODEX_QUOTA_SYNCED",
            f"已同步 Codex 实时额度：5h 剩余 {rl.five_hour_quota}%，周剩余 {rl.weekly_quota}%。",
            matched.name,
        )
        if hasattr(self, "status_bar"):
            self.status_bar.showMessage(
                f"🔄 已同步「{matched.name}」Codex 实时额度：5h 剩余 {rl.five_hour_quota}% | 周剩余 {rl.weekly_quota}%",
                6000,
            )

    def _on_ingest_current_codex(self) -> None:
        prof = self._pending_codex_profile or self.codex_monitor.current_profile
        if prof is None:
            QMessageBox.information(self, "未检测到账号", "当前宿主机未检测到有效登录的 Codex 账号。")
            return
        self._auto_ingest_codex_profile(prof, silent=False)

    def _on_dismiss_codex_banner(self) -> None:
        if self._pending_codex_profile:
            self._dismissed_codex_emails.add(self._pending_codex_profile.email.lower())
        if hasattr(self, "codex_banner"):
            self.codex_banner.setVisible(False)

    def _on_codex_login_ingest(self) -> None:
        dlg = CodexLoginDialog(monitor=self.codex_monitor, parent=self, palette=self._palette)
        if dlg.exec_() == QDialog.Accepted and dlg.captured_profile:
            self._deleted_codex_emails_this_session.discard(dlg.captured_profile.email.strip().lower())
            self._auto_ingest_codex_profile(dlg.captured_profile, silent=False)

    def _auto_ingest_codex_profile(self, profile: CodexProfile, silent: bool = False) -> None:
        self._deleted_codex_emails_this_session.discard(profile.email.strip().lower())
        for acc in self.accounts:
            if acc.email.strip().lower() == profile.email.strip().lower():
                try:
                    self.codex_mgr.capture_current_auth(acc.id)
                except Exception:
                    pass
                if hasattr(self, "codex_banner"):
                    self.codex_banner.setVisible(False)
                if not silent:
                    QMessageBox.information(
                        self,
                        "账号已存在",
                        f"账号「{profile.email}」已在管理列表中，名称为「{acc.name}」，已为您自动同步最新授权快照。",
                    )
                return

        new_id = uuid.uuid4().hex[:12]
        display_name = profile.name.strip() if profile.name.strip() else profile.email.split("@")[0]
        acc_name = f"{display_name} (Codex {profile.display_plan})"
        new_acc = Account(
            id=new_id,
            name=acc_name,
            email=profile.email,
            password="[Codex_OAuth_Token]",
            two_fa="CODEX_OAUTH_SESSION",
            five_hour_quota=100,
            weekly_quota=100,
            provider="Codex",
            warranty_expire_at=profile.subscription_expire_timestamp,
            notes=f"从系统 Codex CLI 自动捕获。Plan: {profile.plan_type}, ID: {profile.account_id}",
            created_at=time.time(),
            updated_at=time.time(),
        )

        # Also sync initial Codex rate limits if available for this account
        rl = extract_codex_rate_limits(
            codex_home=self.codex_mgr.codex_dir,
            account_id=profile.account_id,
            user_id=profile.user_id,
        )
        if rl is not None:
            new_acc.five_hour_quota = rl.five_hour_quota
            new_acc.five_hour_reset_at = rl.five_hour_reset_at
            new_acc.weekly_quota = rl.weekly_quota
            new_acc.weekly_reset_at = rl.weekly_reset_at

        try:
            self.codex_mgr.capture_current_auth(new_acc.id)
        except Exception as err:
            self._record_log("WARN", "CODEX_SNAP_WARN", f"绑定 Codex 授权快照警告: {err}")

        self.accounts.append(new_acc)
        self._save_accounts_safe()
        self._focused_account_id = new_acc.id
        self._rebuild_account_table()
        self._refresh_kpis()

        if hasattr(self, "codex_banner"):
            self.codex_banner.setVisible(False)

        self._record_log(
            "INFO",
            "CODEX_AUTO_INGESTED",
            f"已自动保留并纳管系统 Codex 账号「{acc_name}」({profile.email})。",
            f"{acc_name}",
        )

        send_windows_toast(
            "Codex 账号已自动保留纳管",
            f"已自动获取并保留：{profile.email} ({profile.display_plan})\n凭据快照与实时额度已同步！",
        )
        if not silent:
            QMessageBox.information(
                self,
                "自动录入成功",
                f"已成功捕获并纳管 Codex 账号：\n\n"
                f"• 账号名称: {new_acc.name}\n"
                f"• 登录邮箱: {new_acc.email}\n"
                f"• 订阅计划: {profile.display_plan}\n"
                f"• 5h / 周额度: {new_acc.five_hour_quota}% / {new_acc.weekly_quota}%\n"
                f"• 授权凭据: 已通过 DPAPI 系统级密文快照归档\n\n"
                f"您现在可以在账号列表中随时一键切换使用此账号！",
            )

    def _on_start_screen_snip_ocr(self) -> None:
        if not self.accounts:
            QMessageBox.information(self, "提示", "请先添加至少一个账号后再执行 OCR 额度校准。")
            return
        self._snip_overlay = ScreenSnipOverlay(self)
        self._snip_overlay.snip_captured.connect(self._process_ocr_pixmap)
        self._snip_overlay.show()

    def _on_clipboard_ocr(self) -> None:
        if not self.accounts:
            QMessageBox.information(self, "提示", "请先添加至少一个账号。")
            return
        cb = QApplication.clipboard()
        pix = cb.pixmap() if cb is not None else QPixmap()
        if pix.isNull():
            QMessageBox.warning(
                self,
                "剪贴板无图片",
                "当前系统剪贴板中没有图像数据。\n您可以先按 Win+Shift+S 截取网页额度区域，或直接使用「框选屏幕网页区域识别」。",
            )
            return
        self._process_ocr_pixmap(pix)

    def _on_file_ocr(self) -> None:
        if not self.accounts:
            QMessageBox.information(self, "提示", "请先添加至少一个账号。")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "选择包含额度信息的截图文件", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if not path:
            return
        self._run_ocr_on_file(Path(path))

    def _process_ocr_pixmap(self, pixmap: QPixmap) -> None:
        if pixmap.isNull():
            return
        fd_path = Path(tempfile.gettempdir()) / f"gpt_mgr_ocr_{int(time.time() * 1000)}.png"
        try:
            pixmap.save(str(fd_path), "PNG")
            self._run_ocr_on_file(fd_path)
        finally:
            fd_path.unlink(missing_ok=True)

    def _run_ocr_on_file(self, image_path: Path) -> None:
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            raw_text = run_windows_ocr(image_path)
            parsed = parse_quota_from_ocr_text(raw_text)
        except Exception as err:
            QApplication.restoreOverrideCursor()
            self._record_log("ERROR", "OCR_FAILED", str(err))
            QMessageBox.warning(self, "离线 OCR 识别失败", str(err))
            return
        finally:
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

        dlg = OcrConfirmDialog(
            accounts=self.accounts,
            ocr_result=parsed,
            default_account_id=self._focused_account_id,
            parent=self,
            palette=self._palette,
        )
        if dlg.exec_() != QDialog.Accepted or dlg.apply_result is None:
            return

        res = dlg.apply_result
        acc = self._find_account(res.account_id)
        if acc is None:
            return
        now = time.time()
        if res.apply_five_hour:
            acc.update_five_hour_quota(res.five_hour_quota, now_ts=now)
        if res.apply_weekly or res.apply_weekly_timer:
            new_w = res.weekly_quota if res.apply_weekly else acc.weekly_quota
            dur = res.weekly_reset_seconds if res.apply_weekly_timer else None
            acc.set_weekly_quota_and_timer(new_quota=new_w, reset_duration_seconds=dur, now_ts=now)

        self._save_accounts_safe()
        self._record_log(
            "INFO",
            "OCR_QUOTA_SYNCED",
            f"通过离线 WinRT OCR 回填额度：5h={acc.five_hour_quota}%，周={acc.weekly_quota}%。",
            f"[{acc.provider}] {acc.name}",
        )
        self._rebuild_account_table()
        self._refresh_kpis(now)

    def _on_copy_after_sales_slip(self) -> None:
        slip = format_after_sales_slip(self.accounts)
        if not slip:
            QMessageBox.information(
                self, "无异常账号", "当前没有状态为「已封禁 / 待接码 / 疑似降智」的账号记录。"
            )
            return
        QApplication.clipboard().setText(slip)
        self._record_log("INFO", "AFTER_SALES_SLIP_COPIED", "已生成并复制异常账号标准化售后凭条。")
        QMessageBox.information(self, "售后凭条已复制", f"已复制到剪贴板：\n\n{slip[:600]}")

    # ------------------------------------------------------------------
    # Standard Account & Tick Operations
    # ------------------------------------------------------------------
    def _on_start_5h_usage(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        can_start, reason = acc.can_start_five_hour_usage
        if not can_start:
            QMessageBox.warning(self, "无法开始使用", f"账号「{acc.name}」暂无法开始使用：\n{reason}")
            return
        now = time.time()
        try:
            events = acc.start_five_hour_usage(now)
            if events:
                self._focused_account_id = acc.id
                self._save_accounts_safe()
                acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
                self._record_log(
                    "INFO",
                    "USAGE_5H_STARTED",
                    "点击「开始使用」，已启动 5 小时重置倒计时（5 小时后自动恢复为 100 额度）。",
                    acc_ref,
                )
                self._rebuild_account_table()
                self._refresh_roi_tab()
                self._refresh_kpis(now)
        except ValueError as err:
            QMessageBox.warning(self, "无法开始使用", str(err))

    def _on_tick(self) -> None:
        now = time.time()
        self.clock_label.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        any_dirty = False
        for acc in self.accounts:
            triggered = acc.tick(now)
            if triggered:
                any_dirty = True
                for ev in triggered:
                    self._log_auto_reset(acc, ev, catch_up=False)

        # 1. Weekly quota expiry notification check
        if getattr(self, "settings", None) and self.settings.notify_enabled:
            expiring = check_weekly_expiring_accounts(
                self.accounts,
                quota_threshold=self.settings.notify_quota_threshold,
                hours_threshold=self.settings.notify_hours_threshold,
                now_ts=now,
            )
            for acc in expiring:
                acc.weekly_notified_reset_at = acc.weekly_reset_at
                rem_str = format_duration(acc.weekly_remaining_seconds(now) or 0)
                title = f"{acc.provider} 账号周额度即将刷新提醒"
                msg = f"账号「{acc.name}」周额度还剩 {acc.weekly_quota}%，将在 {rem_str} 后重置，请及时使用！"
                self._notify_user(title, msg)
                self._record_log("WARN", "WEEKLY_EXPIRING_NOTIFICATION", msg, f"{acc.name} ({acc.email})")
                any_dirty = True

        # 2. Warranty expiry notification check
        if getattr(self, "settings", None) and self.settings.warranty_notify_enabled:
            w_expiring = check_warranty_expiring_accounts(
                self.accounts,
                hours_threshold=self.settings.warranty_notify_hours,
                now_ts=now,
            )
            for acc in w_expiring:
                acc.warranty_notified_at = acc.warranty_expire_at
                rem_str = format_duration(acc.warranty_remaining_seconds(now) or 0)
                title = "外购账号质保即将到期验号提醒"
                msg = f"账号「{acc.name}」({acc.vendor_tag or '外购'}) 质保仅剩 {rem_str}，请尽快登录验号排查封禁！"
                self._notify_user(title, msg)
                self._record_log("WARN", "WARRANTY_EXPIRING_NOTIFICATION", msg, f"{acc.name} ({acc.email})")
                any_dirty = True

        if any_dirty:
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
        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
        detail = f"已复制{label}到剪贴板。" if sensitive else f"已复制{label} ({text}) 到剪贴板。"
        self._record_log("INFO", "CLIPBOARD_COPY", detail, acc_ref)

    def _copy_two_fa(self, acc: Account) -> None:
        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"

        def _done(val: str, is_totp: bool, waited: bool) -> None:
            kind = "实时 6 位 TOTP 验证码" if is_totp else "2FA 初始验证码"
            wait_note = "（检测到临期 ≤3s，已自动顺延获取全新周期验证码）" if waited else ""
            self._record_log("INFO", "CLIPBOARD_COPY", f"已复制{kind}{wait_note}。", acc_ref)
            self.status_bar.showMessage(f"已复制「{acc.name}」{kind}{wait_note}", 5000)

        copy_two_fa_with_expiry_guard(acc, on_done=_done, min_remaining_sec=3, parent=self)

    def _on_add_account(self) -> None:
        dlg = AccountDialog(self, palette=self._palette)
        if dlg.exec_() != QDialog.Accepted or dlg.result_data is None:
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
            provider=form.provider,
            proxy_url=form.proxy_url,
            purchase_price=form.purchase_price,
            warranty_days=form.warranty_days if form.apply_warranty_timer else 0.0,
            vendor_tag=form.vendor_tag,
            health_status=form.health_status,
            notes=form.notes,
            now_ts=now,
        )
        self.accounts.append(acc)
        self._save_accounts_safe()

        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
        self._record_log(
            "INFO",
            "ACCOUNT_ADDED",
            f"新增账号：平台={acc.provider}，5h={acc.five_hour_quota}%，周={acc.weekly_quota}%。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(now)

    def _on_batch_import(self) -> None:
        dlg = BatchImportDialog(self, palette=self._palette)
        if dlg.exec_() != QDialog.Accepted or not dlg.imported_items:
            return
        now = time.time()
        added_count = 0
        updated_count = 0
        for item in dlg.imported_items:
            item_prov = getattr(item, "provider", "ChatGPT") or "ChatGPT"
            item_vendor = getattr(item, "vendor_tag", "") or ""
            item_price = float(getattr(item, "purchase_price", 0.0) or 0.0)
            item_warranty = float(getattr(item, "warranty_days", 0.0) or 0.0)

            existing = next(
                (
                    a
                    for a in self.accounts
                    if a.email.strip().lower() == item.email.strip().lower()
                    and a.provider.lower() == item_prov.lower()
                ),
                None,
            )
            if existing is not None:
                existing.name = item.name
                existing.password = item.password
                existing.two_fa = item.two_fa
                if item_vendor:
                    existing.vendor_tag = item_vendor
                if item_price > 0:
                    existing.purchase_price = item_price
                if item_warranty > 0:
                    existing.warranty_expire_at = now + item_warranty * 86400.0
                    existing.warranty_notified_at = None
                existing.updated_at = now
                updated_count += 1
                self._record_log(
                    "INFO",
                    "ACCOUNT_BATCH_UPDATED",
                    f"批量更新已有账号凭据：5h={existing.five_hour_quota}%，周={existing.weekly_quota}%。",
                    f"[{existing.provider}] {existing.name} ({existing.email})",
                )
            else:
                acc = Account.create(
                    name=item.name,
                    email=item.email,
                    password=item.password,
                    two_fa=item.two_fa,
                    five_hour_quota=item.five_hour_quota,
                    weekly_quota=item.weekly_quota,
                    weekly_reset_duration_seconds=0,
                    provider=item_prov,
                    vendor_tag=item_vendor,
                    purchase_price=item_price,
                    warranty_days=item_warranty,
                    now_ts=now,
                )
                self.accounts.append(acc)
                added_count += 1
                self._record_log(
                    "INFO",
                    "ACCOUNT_BATCH_IMPORTED",
                    f"批量导入新账号：平台={acc.provider}，5h={acc.five_hour_quota}%，周={acc.weekly_quota}%。",
                    f"[{acc.provider}] {acc.name} ({acc.email})",
                )

        self._save_accounts_safe()
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(now)
        msg_parts = []
        if added_count > 0:
            msg_parts.append(f"新增 {added_count} 个")
        if updated_count > 0:
            msg_parts.append(f"更新 {updated_count} 个已有账号")
        summary_msg = "，".join(msg_parts) if msg_parts else "未识别到变更"
        QMessageBox.information(self, "导入完成", f"批量文本处理完成：{summary_msg}。")

    def _on_edit_account(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        dlg = AccountDialog(self, account=acc, palette=self._palette)
        if dlg.exec_() != QDialog.Accepted or dlg.result_data is None:
            return
        form = dlg.result_data
        now = time.time()

        acc.name = form.name
        acc.email = form.email
        acc.password = form.password
        acc.two_fa = form.two_fa
        acc.provider = form.provider
        acc.proxy_url = form.proxy_url
        acc.purchase_price = form.purchase_price
        acc.vendor_tag = form.vendor_tag
        acc.health_status = form.health_status
        acc.notes = form.notes

        if form.clear_warranty_timer:
            acc.warranty_expire_at = None
            acc.warranty_notified_at = None
        elif form.apply_warranty_timer and form.warranty_days > 0:
            acc.warranty_expire_at = now + form.warranty_days * 86400.0
            acc.warranty_notified_at = None

        events_5h = acc.update_five_hour_quota(
            form.five_hour_quota,
            clear_timer=form.clear_five_hour_timer,
            now_ts=now,
        )
        events_weekly = acc.set_weekly_quota_and_timer(
            new_quota=form.weekly_quota,
            reset_duration_seconds=form.weekly_reset_seconds if form.apply_weekly_timer else None,
            clear_timer=form.clear_weekly_timer,
            now_ts=now,
        )

        self._save_accounts_safe()
        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
        all_events = events_5h + events_weekly
        event_note = f"；触发状态: {', '.join(all_events)}" if all_events else ""
        self._record_log(
            "INFO",
            "ACCOUNT_UPDATED",
            f"编辑账号：状态={acc.health_status}，5h={acc.five_hour_quota}%，周={acc.weekly_quota}%{event_note}。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(now)

    def _on_quick_quota(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        dlg = QuickQuotaDialog(acc, self, palette=self._palette)
        if dlg.exec_() != QDialog.Accepted or dlg.result_data is None:
            return
        res = dlg.result_data
        now = time.time()

        if res.health_status:
            acc.health_status = res.health_status

        events_5h = acc.update_five_hour_quota(
            res.five_hour_quota,
            clear_timer=res.clear_five_hour_timer,
            now_ts=now,
        )
        events_weekly = acc.set_weekly_quota_and_timer(
            new_quota=res.weekly_quota,
            reset_duration_seconds=res.weekly_reset_seconds if res.apply_weekly_timer else None,
            clear_timer=res.clear_weekly_timer,
            now_ts=now,
        )
        self._save_accounts_safe()

        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
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
            f"手动更新额度：状态={acc.health_status}，5h={acc.five_hour_quota}%，周={acc.weekly_quota}%{extra}。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(now)

    def _on_quick_zero_5h(self, account_id: str) -> None:
        acc = self._find_account(account_id)
        if acc is None:
            return
        now = time.time()
        acc.update_five_hour_quota(0, now_ts=now)
        self._save_accounts_safe()

        acc_ref = f"[{acc.provider}] {acc.name} ({acc.email})"
        self._record_log(
            "INFO",
            "QUOTA_5H_ZERO",
            "手动将 5h 额度归 0，已开始 5 小时重置倒计时（5 小时后自动恢复为 100）。",
            acc_ref,
        )
        self._rebuild_account_table()
        self._refresh_roi_tab()
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

        self._deleted_codex_emails_this_session.add(acc.email.strip().lower())
        self.accounts = [a for a in self.accounts if a.id != account_id]
        self._revealed_pwds.discard(account_id)
        if self.paste_ctrl.active_account and self.paste_ctrl.active_account.id == account_id:
            self.paste_ctrl.cancel(burn_now=True)
        self._save_accounts_safe()
        self._record_log("WARN", "ACCOUNT_DELETED", "已删除该账号记录。", f"{acc.name} ({acc.email})")
        self._rebuild_account_table()
        self._refresh_roi_tab()
        self._refresh_kpis(time.time())

    # ------------------------------------------------------------------
    # Encrypted Portable Backup & WebDAV Cloud Sync
    # ------------------------------------------------------------------
    def _on_export_encrypted_backup(self) -> None:
        pw_dlg = PassphraseDialog(
            "导出跨设备 AES-256-GCM 加密备份",
            "设置加密口令后，生成的备份文件采用 PBKDF2-HMAC-SHA256 (60万轮) + AES-256-GCM 端到端加密，可安全存放网盘或跨电脑恢复：",
            require_confirm=True,
            parent=self,
        )
        if pw_dlg.exec_() != QDialog.Accepted:
            return
        default_name = f"ai_accounts_e2ee_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc.json"
        target, _ = QFileDialog.getSaveFileName(
            self, "保存跨设备加密备份", default_name, "Encrypted JSON (*.enc.json *.json)"
        )
        if not target:
            return
        try:
            self.storage.export_portable_backup(self.accounts, Path(target), pw_dlg.passphrase)
            self._record_log("INFO", "ENCRYPTED_BACKUP_EXPORTED", f"已导出 AES-256-GCM 加密备份至: {target}")
            QMessageBox.information(self, "加密导出成功", f"跨设备加密备份已保存至：\n{target}")
        except Exception as err:
            QMessageBox.critical(self, "导出失败", str(err))

    def _on_import_backup_merge(self) -> None:
        src, _ = QFileDialog.getOpenFileName(
            self, "选择备份文件导入合并", "", "Backup Files (*.json *.enc.json)"
        )
        if not src:
            return
        src_path = Path(src)
        is_encrypted = False
        try:
            top_obj = json.loads(src_path.read_text(encoding="utf-8").strip() or "{}")
            if isinstance(top_obj, dict) and (
                top_obj.get("magic") == "GPT_MANAGER_ENCRYPTED_BACKUP_V2"
                or ("kdf" in top_obj and "ciphertext" in top_obj)
            ):
                is_encrypted = True
        except Exception:
            is_encrypted = False

        passphrase = ""
        if is_encrypted:
            pw_dlg = PassphraseDialog(
                "输入解密口令",
                "检测到 AES-256-GCM 跨设备加密备份，请输入导出时设置的加密口令：",
                require_confirm=False,
                parent=self,
            )
            if pw_dlg.exec_() != QDialog.Accepted:
                return
            passphrase = pw_dlg.passphrase

        try:
            merged, added, updated, kept = self.storage.import_backup_merge(
                src_path, self.accounts, passphrase=passphrase
            )
            self.accounts = merged
            self._record_log(
                "INFO",
                "BACKUP_IMPORT_MERGED",
                f"成功合并备份：新增 {added} 个，更新 {updated} 个，保留本地较新记录 {kept} 个。",
            )
            self._rebuild_account_table()
            self._refresh_roi_tab()
            self._refresh_kpis(time.time())
            QMessageBox.information(
                self,
                "备份合并成功",
                f"智能合并完成（基于 updated_at 最新状态优先）：\n"
                f"• 新增账号：{added} 个\n• 更新账号：{updated} 个\n• 保留本地较新状态：{kept} 个",
            )
        except (SecurityError, ValueError, Exception) as err:
            QMessageBox.warning(self, "导入备份失败", str(err))

    def _on_export_backup(self) -> None:
        default_name = f"gpt_accounts_local_dpapi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        target, _ = QFileDialog.getSaveFileName(
            self, "导出本机 DPAPI 备份副本", default_name, "JSON Files (*.json)"
        )
        if not target:
            return
        self._save_accounts_safe()
        shutil.copy2(self.storage.accounts_file, target)
        self._record_log("INFO", "BACKUP_EXPORTED", f"已导出本机 DPAPI 数据备份至: {target}")
        QMessageBox.information(self, "导出成功", f"本机备份已保存至：\n{target}")

    def _handle_webdav_push(self, draft_settings: AppSettings) -> None:
        pw_dlg = PassphraseDialog(
            "WebDAV 端到端加密上传",
            "请输入端到端加密同步口令（云端服务器仅存储 AES-256-GCM 密文，无法窥探您的账号密码）：",
            require_confirm=False,
            parent=self,
        )
        if pw_dlg.exec_() != QDialog.Accepted:
            return
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            remote_url = self.storage.push_to_webdav(self.accounts, draft_settings, pw_dlg.passphrase)
            QApplication.restoreOverrideCursor()
            self._record_log("INFO", "WEBDAV_PUSH_OK", f"已加密上传 {len(self.accounts)} 个账号至 {remote_url}")
            QMessageBox.information(self, "云端上传成功", f"已加密同步至：\n{remote_url}")
        except Exception as err:
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "WebDAV 上传失败", str(err))

    def _handle_webdav_pull(self, draft_settings: AppSettings) -> None:
        pw_dlg = PassphraseDialog(
            "WebDAV 端到端解密拉取合并",
            "请输入上传时使用的端到端加密同步口令：",
            require_confirm=False,
            parent=self,
        )
        if pw_dlg.exec_() != QDialog.Accepted:
            return
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            merged, added, updated, kept = self.storage.pull_from_webdav(
                self.accounts, draft_settings, pw_dlg.passphrase
            )
            QApplication.restoreOverrideCursor()
            self.accounts = merged
            self._record_log(
                "INFO",
                "WEBDAV_PULL_OK",
                f"从 WebDAV 拉取合并完成：新增={added}，更新={updated}，保留本地={kept}。",
            )
            self._rebuild_account_table()
            self._refresh_roi_tab()
            self._refresh_kpis(time.time())
            QMessageBox.information(
                self,
                "WebDAV 同步合并完成",
                f"新增账号：{added} 个\n更新账号：{updated} 个\n保留本地较新记录：{kept} 个",
            )
        except Exception as err:
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "WebDAV 拉取失败", str(err))

    # ------------------------------------------------------------------
    # Logs, Tray & Settings
    # ------------------------------------------------------------------
    def _refresh_log_table(self) -> None:
        p = self._palette
        entries = list(reversed(self.storage.logger.read_recent(limit=500)))
        level_filter = self.log_level_combo.currentText()
        kw = self.log_search_input.text().strip().lower()

        filtered: List[LogEntry] = []
        for entry in entries:
            if level_filter != "全部级别" and entry.level != level_filter:
                continue
            if (
                kw
                and kw not in entry.detail.lower()
                and kw not in entry.account.lower()
                and kw not in entry.event.lower()
            ):
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
            Path(target).write_text("", encoding="utf-8")
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
        self.tray_icon.setToolTip("AI 账号额度与防关联调度控制台")

        tray_menu = QMenu(self)
        tray_menu.addAction("⚡ 智能派发最优账号", self._on_smart_dispatch)
        tray_menu.addAction("🗔 切换置顶胶囊窗", self._on_toggle_mini_hud)
        tray_menu.addAction("📷 框选屏幕 OCR 校准", self._on_start_screen_snip_ocr)
        tray_menu.addSeparator()
        tray_menu.addAction("显示主窗口", self._restore_from_tray)
        tray_menu.addAction("系统设置与云同步", self._on_open_settings)
        tray_menu.addSeparator()
        tray_menu.addAction("退出程序", self._on_force_quit)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.activateWindow()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._restore_from_tray()

    def _on_force_quit(self) -> None:
        self._is_force_quitting = True
        self.paste_ctrl.cancel(burn_now=True)
        if hasattr(self, "network_tab"):
            self.network_tab.shutdown()
        self.mini_hud.close()
        if hasattr(self, "tray_icon"):
            self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event) -> None:
        if getattr(self, "_is_force_quitting", False) or not self.isVisible():
            self.paste_ctrl.cancel(burn_now=True)
            if hasattr(self, "_tick_timer"):
                self._tick_timer.stop()
            if hasattr(self, "_startup_codex_timer"):
                self._startup_codex_timer.stop()
            if hasattr(self, "codex_monitor"):
                self.codex_monitor._poll_timer.stop()
            if hasattr(self, "network_tab"):
                self.network_tab.shutdown()
            self.mini_hud.close()
            event.accept()
            return
        if getattr(self, "settings", None) and self.settings.minimize_to_tray and self.tray_icon.isVisible():
            event.ignore()
            self.hide()
            self.tray_icon.showMessage(
                "AI 账号调度控制台",
                "已最小化到系统托盘，后台持续运行倒计时、质保与即将刷新提醒。",
                QSystemTrayIcon.Information,
                3000,
            )
        else:
            self.paste_ctrl.cancel(burn_now=True)
            if hasattr(self, "network_tab"):
                self.network_tab.shutdown()
            self.mini_hud.close()
            event.accept()

    def _notify_user(self, title: str, message: str) -> None:
        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Warning, 7000)
        send_windows_toast(title, message)

    def _on_open_settings(self) -> None:
        dlg = SettingsDialog(
            self.settings,
            self,
            palette=self._palette,
            on_webdav_push=self._handle_webdav_push,
            on_webdav_pull=self._handle_webdav_pull,
        )
        if dlg.exec_() == QDialog.Accepted and dlg.saved_settings is not None:
            self.settings = dlg.saved_settings
            self.paste_ctrl.burn_seconds = self.settings.clipboard_burn_seconds
            self.storage.save_settings(self.settings)

            task_status = "已开启" if self.settings.background_task_enabled else "已关闭"
            self._record_log(
                "INFO",
                "SETTINGS_UPDATED",
                f"设置已更新：周额度预警={self.settings.notify_enabled}，质保预警={self.settings.warranty_notify_enabled}，"
                f"阅后即焚={self.settings.clipboard_burn_seconds}s，后台任务={task_status}。",
            )
