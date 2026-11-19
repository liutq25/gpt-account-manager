from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.models import (
    HEALTH_STATUS_LABELS,
    MAX_QUOTA,
    VALID_HEALTH_STATUSES,
    VALID_PROVIDERS,
    Account,
    ParsedAccount,
    format_duration,
    parse_accounts_from_text,
    validate_proxy_url,
)
from src.notifier import send_windows_toast
from src.ocr_sync import OcrQuotaResult
from src.storage import (
    AppSettings,
    configure_windows_scheduled_task,
    is_windows_scheduled_task_installed,
)
from src.ui_styles import LIGHT_PALETTE, ThemePalette
from src.codex_detector import (
    CodexLoginController,
    CodexMonitor,
    CodexProfile,
    extract_codex_profile,
)


@dataclass
class AccountFormResult:
    name: str
    email: str
    password: str
    two_fa: str
    five_hour_quota: int
    weekly_quota: int
    apply_weekly_timer: bool
    weekly_reset_seconds: int
    clear_weekly_timer: bool
    clear_five_hour_timer: bool = False
    provider: str = "ChatGPT"
    proxy_url: str = ""
    purchase_price: float = 0.0
    apply_warranty_timer: bool = False
    warranty_days: float = 0.0
    clear_warranty_timer: bool = False
    vendor_tag: str = ""
    health_status: str = "ACTIVE"
    notes: str = ""


@dataclass
class QuickQuotaResult:
    five_hour_quota: int
    weekly_quota: int
    apply_weekly_timer: bool
    weekly_reset_seconds: int
    clear_weekly_timer: bool
    clear_five_hour_timer: bool = False
    health_status: Optional[str] = None


@dataclass
class BatchImportItem:
    name: str
    email: str
    password: str
    two_fa: str
    five_hour_quota: int
    weekly_quota: int
    provider: str = "ChatGPT"
    vendor_tag: str = ""
    purchase_price: float = 0.0
    warranty_days: float = 0.0


@dataclass
class OcrApplyResult:
    account_id: str
    apply_five_hour: bool
    five_hour_quota: int
    apply_weekly: bool
    weekly_quota: int
    apply_weekly_timer: bool
    weekly_reset_seconds: int


def _build_hms_spinboxes() -> tuple[QWidget, QSpinBox, QSpinBox, QSpinBox]:
    container = QWidget()
    layout = QHBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)

    days_spin = QSpinBox()
    days_spin.setRange(0, 31)
    days_spin.setSuffix(" 天")
    days_spin.setMinimumWidth(75)

    hours_spin = QSpinBox()
    hours_spin.setRange(0, 23)
    hours_spin.setSuffix(" 时")
    hours_spin.setMinimumWidth(75)

    mins_spin = QSpinBox()
    mins_spin.setRange(0, 59)
    mins_spin.setSuffix(" 分")
    mins_spin.setMinimumWidth(75)

    layout.addWidget(days_spin)
    layout.addWidget(hours_spin)
    layout.addWidget(mins_spin)
    layout.addStretch()
    return container, days_spin, hours_spin, mins_spin


class AccountDialog(QDialog):
    def __init__(
        self,
        parent: Optional[QWidget] = None,
        account: Optional[Account] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self._account = account
        self._is_edit = account is not None
        self._palette = palette
        self.result_data: Optional[AccountFormResult] = None

        self.setWindowTitle("编辑账号与防关联/质保配置" if self._is_edit else "添加多平台 AI 账号")
        self.setMinimumWidth(580)
        self.setModal(True)

        screen = QApplication.primaryScreen()
        avail_h = screen.availableGeometry().height() if screen else 800
        # 严格保持紧凑高度 <= 480，防任务栏遮挡，内部全滚轮承载
        target_h = min(480, max(360, int(avail_h * 0.62)))
        self.resize(600, target_h)
        self.setMinimumHeight(340)
        self.setMaximumHeight(min(avail_h - 40, 680))

        self._build_ui()
        if account is not None:
            self._populate(account)

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 14)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setObjectName("AccountDialogScrollArea")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 8, 0)
        scroll_layout.setSpacing(10)

        # 1. Smart Text Parse Group
        parse_group = QGroupBox("智能文本识别填充（支持整段发货文本自动去噪提取）")
        parse_layout = QVBoxLayout(parse_group)
        parse_layout.setSpacing(8)

        self.raw_text_edit = QPlainTextEdit()
        self.raw_text_edit.setPlaceholderText(
            "直接粘贴整段文本，例如：\n"
            "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "郑重声明上号不要去关掉2FA...（自动忽略声明与链接）"
        )
        self.raw_text_edit.setMaximumHeight(74)

        parse_bar = QHBoxLayout()
        self.parse_status_label = QLabel("支持「邮箱----密码----2FA」及冒号/竖线混合格式")
        self.parse_status_label.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        parse_btn = QPushButton("一键识别填充")
        parse_btn.setObjectName("PrimaryButton")
        parse_btn.setStyleSheet(
            f"padding: 5px 12px; font-size: 12px; background-color: {p.primary_bg}; "
            f"border: 1px solid {p.primary_border}; color: #FFFFFF;"
        )
        parse_btn.clicked.connect(self._on_smart_parse)

        codex_pull_btn = QPushButton("⚡ 从系统 Codex 提取")
        codex_pull_btn.setToolTip("自动从本地 ~/.codex/auth.json 读取当前登录账号、会员等级与有效期")
        codex_pull_btn.setStyleSheet(
            f"padding: 5px 10px; font-size: 12px; background-color: {p.surface_bg}; "
            f"border: 1px solid {p.border}; color: {p.text_primary};"
        )
        codex_pull_btn.clicked.connect(self._on_pull_from_codex)

        parse_bar.addWidget(self.parse_status_label, 1)
        parse_bar.addWidget(codex_pull_btn)
        parse_bar.addWidget(parse_btn)

        parse_layout.addWidget(self.raw_text_edit)
        parse_layout.addLayout(parse_bar)
        scroll_layout.addWidget(parse_group)

        # 2. Platform & Credentials Group
        cred_group = QGroupBox("平台与账号凭据（本地采用 Windows DPAPI 系统级密文落盘）")
        cred_form = QFormLayout(cred_group)
        cred_form.setSpacing(10)
        cred_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        top_meta_row = QWidget()
        top_meta_lay = QHBoxLayout(top_meta_row)
        top_meta_lay.setContentsMargins(0, 0, 0, 0)
        top_meta_lay.setSpacing(8)

        self.provider_combo = QComboBox()
        self.provider_combo.addItems(list(VALID_PROVIDERS))
        self.provider_combo.setMinimumWidth(120)

        self.health_combo = QComboBox()
        for code in VALID_HEALTH_STATUSES:
            self.health_combo.addItem(f"{HEALTH_STATUS_LABELS[code]} ({code})", code)
        self.health_combo.setMinimumWidth(160)

        top_meta_lay.addWidget(self.provider_combo)
        top_meta_lay.addWidget(QLabel("状态:"))
        top_meta_lay.addWidget(self.health_combo)
        top_meta_lay.addStretch()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如：主力Plus-01 / ClaudePro-A（智能识别时留空自动填入邮箱前缀）")

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("例如：user@example.com")

        pwd_row = QWidget()
        pwd_layout = QHBoxLayout(pwd_row)
        pwd_layout.setContentsMargins(0, 0, 0, 0)
        pwd_layout.setSpacing(6)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("输入登录密码")
        self.toggle_pwd_btn = QPushButton("显示")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.setFixedWidth(64)
        self.toggle_pwd_btn.toggled.connect(self._on_toggle_password)
        pwd_layout.addWidget(self.password_edit)
        pwd_layout.addWidget(self.toggle_pwd_btn)

        self.two_fa_edit = QLineEdit()
        self.two_fa_edit.setPlaceholderText("输入 2FA 初始验证码或 Base32 动态密钥")

        cred_form.addRow("所属平台 *:", top_meta_row)
        cred_form.addRow("账号名称 *:", self.name_edit)
        cred_form.addRow("账号邮箱 *:", self.email_edit)
        cred_form.addRow("登录密码 *:", pwd_row)
        cred_form.addRow("2FA 密钥/码 *:", self.two_fa_edit)
        scroll_layout.addWidget(cred_group)

        # 3. Quota Group
        quota_group = QGroupBox("双窗口额度与重置倒计时")
        quota_form = QFormLayout(quota_group)
        quota_form.setSpacing(10)
        quota_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.five_spin = QSpinBox()
        self.five_spin.setRange(0, MAX_QUOTA)
        self.five_spin.setValue(MAX_QUOTA)
        self.five_spin.setSuffix(" %")
        self.five_spin.setFixedWidth(120)

        self.five_status_label = QLabel("")
        self.five_status_label.setStyleSheet(f"color: {p.warn_text}; font-size: 12px; font-weight: 600;")
        self.clear_five_chk = QCheckBox("取消当前 5h 重置倒计时")

        self.weekly_spin = QSpinBox()
        self.weekly_spin.setRange(0, MAX_QUOTA)
        self.weekly_spin.setValue(MAX_QUOTA)
        self.weekly_spin.setSuffix(" %")
        self.weekly_spin.setFixedWidth(120)

        self.weekly_status_label = QLabel("")
        self.weekly_status_label.setStyleSheet(f"color: {p.info_text}; font-size: 12px; font-weight: 600;")

        self.reset_weekly_chk = QCheckBox("重新设置周额度剩余重置时间")
        self.reset_weekly_chk.toggled.connect(self._on_weekly_chk_toggled)

        self.clear_weekly_chk = QCheckBox("清除现有周倒计时")
        self.clear_weekly_chk.toggled.connect(self._on_clear_weekly_toggled)

        hms_widget, self.days_spin, self.hours_spin, self.mins_spin = _build_hms_spinboxes()

        quota_form.addRow("5h 剩余额度:", self.five_spin)
        if self._is_edit:
            quota_form.addRow("当前 5h 倒计时:", self.five_status_label)
            quota_form.addRow("", self.clear_five_chk)
        else:
            self.clear_five_chk.setVisible(False)

        quota_form.addRow("周剩余额度:", self.weekly_spin)
        if self._is_edit:
            quota_form.addRow("当前周倒计时:", self.weekly_status_label)
            quota_form.addRow("", self.reset_weekly_chk)
            quota_form.addRow("", self.clear_weekly_chk)
        else:
            self.reset_weekly_chk.setChecked(True)
            self.reset_weekly_chk.setVisible(False)
            self.clear_weekly_chk.setVisible(False)

        quota_form.addRow("周剩余重置时间:", hms_widget)
        scroll_layout.addWidget(quota_group)

        # 4. Anti-Association Proxy & Asset Warranty Group
        asset_group = QGroupBox("防关联独立代理与外购质保账本（可选）")
        asset_form = QFormLayout(asset_group)
        asset_form.setSpacing(10)
        asset_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("例如：socks5://127.0.0.1:10808 或 http://127.0.0.1:7890（留空直连）")

        vendor_price_row = QWidget()
        vp_lay = QHBoxLayout(vendor_price_row)
        vp_lay.setContentsMargins(0, 0, 0, 0)
        vp_lay.setSpacing(8)

        self.vendor_edit = QLineEdit()
        self.vendor_edit.setPlaceholderText("如：发卡网A / 自绑Plus")

        self.price_spin = QDoubleSpinBox()
        self.price_spin.setRange(0.0, 999999.0)
        self.price_spin.setDecimals(2)
        self.price_spin.setPrefix("¥ ")
        self.price_spin.setMinimumWidth(110)

        vp_lay.addWidget(self.vendor_edit, 1)
        vp_lay.addWidget(QLabel("单价:"))
        vp_lay.addWidget(self.price_spin)

        warranty_row = QWidget()
        w_lay = QHBoxLayout(warranty_row)
        w_lay.setContentsMargins(0, 0, 0, 0)
        w_lay.setSpacing(8)

        self.warranty_days_spin = QDoubleSpinBox()
        self.warranty_days_spin.setRange(0.0, 3650.0)
        self.warranty_days_spin.setDecimals(1)
        self.warranty_days_spin.setSuffix(" 天")
        self.warranty_days_spin.setMinimumWidth(100)

        self.warranty_status_lbl = QLabel("")
        self.warranty_status_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")

        self.reset_warranty_chk = QCheckBox("重设质保天数")
        self.clear_warranty_chk = QCheckBox("清除质保")
        self.reset_warranty_chk.toggled.connect(self._on_warranty_chk_toggled)
        self.clear_warranty_chk.toggled.connect(self._on_clear_warranty_toggled)

        w_lay.addWidget(self.warranty_days_spin)
        w_lay.addWidget(self.warranty_status_lbl, 1)

        self.notes_edit = QLineEdit()
        self.notes_edit.setPlaceholderText("可选备注（如：未接码网页号 / 绑定虚拟卡尾号 8821）")

        asset_form.addRow("独立代理地址:", self.proxy_edit)
        asset_form.addRow("来源渠道:", vendor_price_row)
        asset_form.addRow("质保剩余周期:", warranty_row)
        if self._is_edit:
            w_chk_row = QWidget()
            wc_lay = QHBoxLayout(w_chk_row)
            wc_lay.setContentsMargins(0, 0, 0, 0)
            wc_lay.addWidget(self.reset_warranty_chk)
            wc_lay.addWidget(self.clear_warranty_chk)
            wc_lay.addStretch()
            asset_form.addRow("", w_chk_row)
        else:
            self.reset_warranty_chk.setChecked(True)
            self.reset_warranty_chk.setVisible(False)
            self.clear_warranty_chk.setVisible(False)
        asset_form.addRow("账号备注:", self.notes_edit)

        scroll_layout.addWidget(asset_group)
        scroll_layout.addStretch()

        self.scroll_area.setWidget(scroll_content)
        root.addWidget(self.scroll_area, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("保存账号" if self._is_edit else "确认添加")
        save_btn.setObjectName("PrimaryButton")
        save_btn.clicked.connect(self._on_submit)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

    def _on_smart_parse(self) -> None:
        raw = self.raw_text_edit.toPlainText()
        parsed = parse_accounts_from_text(raw)
        if not parsed:
            self.parse_status_label.setText("未识别到有效的「邮箱----密码----2FA」记录，请检查输入文本。")
            self.parse_status_label.setStyleSheet(
                f"color: {self._palette.danger_text}; font-size: 11px; font-weight: 600;"
            )
            return

        first = parsed[0]
        if not self.name_edit.text().strip():
            self.name_edit.setText(first.suggested_name)
        self.email_edit.setText(first.email)
        self.password_edit.setText(first.password)
        self.two_fa_edit.setText(first.two_fa)

        if len(parsed) > 1:
            self.parse_status_label.setText(
                f"共检测到 {len(parsed)} 条账号，已填充第 1 条；多账号建议使用「批量文本识别导入」。"
            )
        else:
            self.parse_status_label.setText(f"已成功识别并填充：{first.email}")
        self.parse_status_label.setStyleSheet(
            f"color: {self._palette.kpi_5h_ready_accent}; font-size: 11px; font-weight: 600;"
        )

    def _on_pull_from_codex(self) -> None:
        prof = extract_codex_profile()
        if prof is None:
            self.parse_status_label.setText("未在系统 ~/.codex/auth.json 中检测到已登录的有效账号。")
            self.parse_status_label.setStyleSheet(
                f"color: {self._palette.danger_text}; font-size: 11px; font-weight: 600;"
            )
            return

        c_idx = self.provider_combo.findText("Codex")
        if c_idx >= 0:
            self.provider_combo.setCurrentIndex(c_idx)

        display_name = prof.name if prof.name else prof.email.split("@")[0]
        self.name_edit.setText(f"{display_name} (Codex {prof.display_plan})")
        self.email_edit.setText(prof.email)
        self.password_edit.setText("[Codex_OAuth_Token]")
        self.two_fa_edit.setText("CODEX_OAUTH_SESSION")
        if prof.subscription_expire_timestamp is not None:
            now = time.time()
            rem_days = max(0.0, (prof.subscription_expire_timestamp - now) / 86400.0)
            self.warranty_days_spin.setValue(round(rem_days, 1))
            self.reset_warranty_chk.setChecked(True)
        self.notes_edit.setText(f"从系统 Codex CLI 自动提取。Plan: {prof.plan_type}, ID: {prof.account_id}")

        self.parse_status_label.setText(f"已成功提取系统 Codex 账号：{prof.email} ({prof.display_plan})")
        self.parse_status_label.setStyleSheet(
            f"color: {self._palette.kpi_5h_ready_accent}; font-size: 11px; font-weight: 600;"
        )

    def _populate(self, account: Account) -> None:
        now = time.time()
        p_idx = self.provider_combo.findText(account.provider)
        if p_idx >= 0:
            self.provider_combo.setCurrentIndex(p_idx)
        h_idx = self.health_combo.findData(account.health_status)
        if h_idx >= 0:
            self.health_combo.setCurrentIndex(h_idx)

        self.name_edit.setText(account.name)
        self.email_edit.setText(account.email)
        self.password_edit.setText(account.password)
        self.two_fa_edit.setText(account.two_fa)
        self.five_spin.setValue(account.five_hour_quota)
        self.weekly_spin.setValue(account.weekly_quota)
        self.proxy_edit.setText(account.proxy_url)
        self.vendor_edit.setText(account.vendor_tag)
        self.price_spin.setValue(account.purchase_price)
        self.notes_edit.setText(account.notes)

        five_rem = account.five_hour_remaining_seconds(now)
        if five_rem is not None and five_rem > 0:
            self.five_status_label.setText(f"倒计时运行中（剩余 {format_duration(five_rem)}）")
            self.clear_five_chk.setVisible(True)
            self.clear_five_chk.setChecked(False)
        else:
            self.five_status_label.setText("未启动 5h 倒计时")
            self.clear_five_chk.setVisible(False)

        rem = account.weekly_remaining_seconds(now)
        if rem is not None and rem > 0:
            self.weekly_status_label.setText(f"倒计时运行中（剩余 {format_duration(rem)}）")
            self.reset_weekly_chk.setChecked(False)
            self.clear_weekly_chk.setVisible(True)
            self._set_hms_enabled(False)
        else:
            self.weekly_status_label.setText("未启动倒计时")
            self.reset_weekly_chk.setChecked(True)
            self.reset_weekly_chk.setVisible(False)
            self.clear_weekly_chk.setVisible(False)
            self._set_hms_enabled(True)

        w_rem = account.warranty_remaining_seconds(now)
        if w_rem is not None and w_rem > 0:
            self.warranty_status_lbl.setText(f"质保中（剩余 {format_duration(w_rem)}）")
            self.reset_warranty_chk.setChecked(False)
            self.warranty_days_spin.setEnabled(False)
            self.clear_warranty_chk.setVisible(True)
        else:
            self.warranty_status_lbl.setText("未设质保或已到期")
            self.reset_warranty_chk.setChecked(True)
            self.reset_warranty_chk.setVisible(False)
            self.clear_warranty_chk.setVisible(False)
            self.warranty_days_spin.setEnabled(True)

    def _set_hms_enabled(self, enabled: bool) -> None:
        self.days_spin.setEnabled(enabled)
        self.hours_spin.setEnabled(enabled)
        self.mins_spin.setEnabled(enabled)

    def _on_weekly_chk_toggled(self, checked: bool) -> None:
        if checked:
            self.clear_weekly_chk.setChecked(False)
        self._set_hms_enabled(checked)

    def _on_clear_weekly_toggled(self, checked: bool) -> None:
        if checked:
            self.reset_weekly_chk.setChecked(False)
            self._set_hms_enabled(False)

    def _on_warranty_chk_toggled(self, checked: bool) -> None:
        if checked:
            self.clear_warranty_chk.setChecked(False)
        self.warranty_days_spin.setEnabled(checked)

    def _on_clear_warranty_toggled(self, checked: bool) -> None:
        if checked:
            self.reset_warranty_chk.setChecked(False)
            self.warranty_days_spin.setEnabled(False)

    def _on_toggle_password(self, checked: bool) -> None:
        self.password_edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.toggle_pwd_btn.setText("隐藏" if checked else "显示")

    def _on_submit(self) -> None:
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        password = self.password_edit.text()
        two_fa = self.two_fa_edit.text().strip()
        raw_proxy = self.proxy_edit.text().strip()

        if not name:
            QMessageBox.warning(self, "校验失败", "请输入账号名称。")
            self.name_edit.setFocus()
            return
        if not email or "@" not in email:
            QMessageBox.warning(self, "校验失败", "请输入有效的账号邮箱地址。")
            self.email_edit.setFocus()
            return
        if not password:
            QMessageBox.warning(self, "校验失败", "请输入登录密码。")
            self.password_edit.setFocus()
            return
        if not two_fa:
            QMessageBox.warning(self, "校验失败", "请输入 2FA 初始验证码或密钥。")
            self.two_fa_edit.setFocus()
            return

        try:
            valid_proxy = validate_proxy_url(raw_proxy)
        except ValueError as err:
            QMessageBox.warning(self, "代理地址格式错误", str(err))
            self.proxy_edit.setFocus()
            return

        duration_sec = (
            self.days_spin.value() * 86400
            + self.hours_spin.value() * 3600
            + self.mins_spin.value() * 60
        )

        self.result_data = AccountFormResult(
            name=name,
            email=email,
            password=password,
            two_fa=two_fa,
            five_hour_quota=self.five_spin.value(),
            weekly_quota=self.weekly_spin.value(),
            apply_weekly_timer=self.reset_weekly_chk.isChecked(),
            weekly_reset_seconds=duration_sec,
            clear_weekly_timer=self.clear_weekly_chk.isChecked(),
            clear_five_hour_timer=self.clear_five_chk.isChecked() if self._is_edit else False,
            provider=self.provider_combo.currentText(),
            proxy_url=valid_proxy,
            purchase_price=round(self.price_spin.value(), 2),
            apply_warranty_timer=self.reset_warranty_chk.isChecked(),
            warranty_days=self.warranty_days_spin.value(),
            clear_warranty_timer=self.clear_warranty_chk.isChecked() if self._is_edit else False,
            vendor_tag=self.vendor_edit.text().strip(),
            health_status=str(self.health_combo.currentData()),
            notes=self.notes_edit.text().strip(),
        )
        self.accept()


class BatchImportDialog(QDialog):
    def __init__(
        self,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self._palette = palette
        self.parsed_items: List[ParsedAccount] = []
        self.imported_items: List[BatchImportItem] = []

        self.setWindowTitle("批量智能文本识别导入（支持批次平台与质保设置）")
        self.resize(860, 580)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(18, 16, 18, 16)

        hint = QLabel(
            "粘贴包含一个或多个账号的整段文本（自动过滤售后声明、链接、emoji，按原文顺序提取邮箱、密码与 2FA）："
        )
        hint.setStyleSheet(f"color: {p.text_secondary}; font-size: 12px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText(
            "粘贴整段文本，支持 ----、——、冒号、竖线等分隔格式，例如：\n"
            "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "emeries.gloss-1i+shlf@icloud.com----#uWOE^riLIPD9dLN----HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF"
        )
        self.input_text.setMinimumHeight(115)
        root.addWidget(self.input_text)

        # Batch Metadata Row (Provider, Vendor, Price, Warranty Days)
        batch_meta_box = QGroupBox("本批次默认资产属性（自动应用到下方全部导入账号）")
        bm_lay = QHBoxLayout(batch_meta_box)
        bm_lay.setContentsMargins(10, 8, 10, 8)
        bm_lay.setSpacing(10)

        self.batch_provider_combo = QComboBox()
        self.batch_provider_combo.addItems(list(VALID_PROVIDERS))

        self.batch_vendor_edit = QLineEdit()
        self.batch_vendor_edit.setPlaceholderText("渠道标签（如：发卡网A）")
        self.batch_vendor_edit.setMaximumWidth(160)

        self.batch_price_spin = QDoubleSpinBox()
        self.batch_price_spin.setRange(0.0, 999999.0)
        self.batch_price_spin.setDecimals(2)
        self.batch_price_spin.setPrefix("¥ ")

        self.batch_warranty_spin = QDoubleSpinBox()
        self.batch_warranty_spin.setRange(0.0, 3650.0)
        self.batch_warranty_spin.setDecimals(1)
        self.batch_warranty_spin.setSuffix(" 天")

        bm_lay.addWidget(QLabel("平台:"))
        bm_lay.addWidget(self.batch_provider_combo)
        bm_lay.addWidget(QLabel("渠道:"))
        bm_lay.addWidget(self.batch_vendor_edit)
        bm_lay.addWidget(QLabel("单价:"))
        bm_lay.addWidget(self.batch_price_spin)
        bm_lay.addWidget(QLabel("质保期:"))
        bm_lay.addWidget(self.batch_warranty_spin)
        bm_lay.addStretch()
        root.addWidget(batch_meta_box)

        ctrl_row = QHBoxLayout()
        self.status_lbl = QLabel("等待解析...")
        self.status_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")
        parse_btn = QPushButton("识别解析")
        parse_btn.setObjectName("PrimaryButton")
        parse_btn.clicked.connect(self._on_parse)
        ctrl_row.addWidget(self.status_lbl, 1)
        ctrl_row.addWidget(parse_btn)
        root.addLayout(ctrl_row)

        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(6)
        self.preview_table.setHorizontalHeaderLabels(
            ["账号名称（可编辑）", "账号邮箱", "登录密码", "2FA 初始验证码", "5h 初始额度", "周初始额度"]
        )
        self.preview_table.setAlternatingRowColors(True)
        self.preview_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.preview_table.verticalHeader().setVisible(False)
        hdr = self.preview_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.Interactive)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        self.preview_table.setColumnWidth(0, 140)
        self.preview_table.setColumnWidth(2, 145)
        self.preview_table.setColumnWidth(4, 95)
        self.preview_table.setColumnWidth(5, 95)
        root.addWidget(self.preview_table, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        self.import_btn = QPushButton("确认导入 (0)")
        self.import_btn.setObjectName("PrimaryButton")
        self.import_btn.setEnabled(False)
        self.import_btn.clicked.connect(self._on_confirm_import)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.import_btn)
        root.addLayout(btn_row)

    def _on_parse(self) -> None:
        raw = self.input_text.toPlainText()
        self.parsed_items = parse_accounts_from_text(raw)
        self.preview_table.setRowCount(len(self.parsed_items))

        for idx, item in enumerate(self.parsed_items):
            self.preview_table.setRowHeight(idx, 36)
            self.preview_table.setItem(idx, 0, QTableWidgetItem(item.suggested_name))
            self.preview_table.setItem(idx, 1, QTableWidgetItem(item.email))
            self.preview_table.setItem(idx, 2, QTableWidgetItem(item.password))
            self.preview_table.setItem(idx, 3, QTableWidgetItem(item.two_fa))

            five_spin = QSpinBox()
            five_spin.setRange(0, MAX_QUOTA)
            five_spin.setValue(MAX_QUOTA)
            self.preview_table.setCellWidget(idx, 4, five_spin)

            weekly_spin = QSpinBox()
            weekly_spin.setRange(0, MAX_QUOTA)
            weekly_spin.setValue(MAX_QUOTA)
            self.preview_table.setCellWidget(idx, 5, weekly_spin)

        count = len(self.parsed_items)
        if count == 0:
            self.status_lbl.setText("未识别到有效账号，请检查文本是否包含「邮箱----密码----2FA」。")
            self.status_lbl.setStyleSheet(
                f"color: {self._palette.danger_text}; font-size: 12px; font-weight: 600;"
            )
            self.import_btn.setEnabled(False)
            self.import_btn.setText("确认导入 (0)")
        else:
            self.status_lbl.setText(f"成功解析 {count} 个账号（可在下表直接修改名称或初始额度）。")
            self.status_lbl.setStyleSheet(
                f"color: {self._palette.kpi_5h_ready_accent}; font-size: 12px; font-weight: 600;"
            )
            self.import_btn.setEnabled(True)
            self.import_btn.setText(f"确认导入 ({count})")

    def _on_confirm_import(self) -> None:
        collected: List[BatchImportItem] = []
        prov = self.batch_provider_combo.currentText()
        vendor = self.batch_vendor_edit.text().strip()
        price = round(self.batch_price_spin.value(), 2)
        w_days = self.batch_warranty_spin.value()

        for idx in range(self.preview_table.rowCount()):
            name = (self.preview_table.item(idx, 0).text() or "").strip()
            email = (self.preview_table.item(idx, 1).text() or "").strip()
            password = self.preview_table.item(idx, 2).text() or ""
            two_fa = (self.preview_table.item(idx, 3).text() or "").strip()
            if not email or "@" not in email or not password or not two_fa:
                QMessageBox.warning(self, "校验失败", f"第 {idx + 1} 行邮箱、密码或 2FA 不能为空。")
                return
            five_spin = self.preview_table.cellWidget(idx, 4)
            weekly_spin = self.preview_table.cellWidget(idx, 5)
            if not name:
                name = email.split("@", 1)[0]
            collected.append(
                BatchImportItem(
                    name=name,
                    email=email,
                    password=password,
                    two_fa=two_fa,
                    five_hour_quota=five_spin.value() if isinstance(five_spin, QSpinBox) else MAX_QUOTA,
                    weekly_quota=weekly_spin.value() if isinstance(weekly_spin, QSpinBox) else MAX_QUOTA,
                    provider=prov,
                    vendor_tag=vendor,
                    purchase_price=price,
                    warranty_days=w_days,
                )
            )
        self.imported_items = collected
        self.accept()


class QuickQuotaDialog(QDialog):
    def __init__(
        self,
        account: Account,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self._account = account
        self._palette = palette
        self.result_data: Optional[QuickQuotaResult] = None

        self.setWindowTitle(f"更新额度与状态 - [{account.provider}] {account.name}")
        self.setMinimumWidth(460)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        info = QLabel(f"账号：[{self._account.provider}] {self._account.name}  ({self._account.email})")
        info.setStyleSheet(f"font-weight: 700; color: {p.text_primary}; font-size: 13px;")
        root.addWidget(info)

        group = QGroupBox("快速录入剩余额度与健康状态")
        form = QFormLayout(group)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.health_combo = QComboBox()
        for code in VALID_HEALTH_STATUSES:
            self.health_combo.addItem(f"{HEALTH_STATUS_LABELS[code]} ({code})", code)
        h_idx = self.health_combo.findData(self._account.health_status)
        if h_idx >= 0:
            self.health_combo.setCurrentIndex(h_idx)

        self.five_spin = QSpinBox()
        self.five_spin.setRange(0, MAX_QUOTA)
        self.five_spin.setValue(self._account.five_hour_quota)
        self.five_spin.setSuffix(" / 100")
        self.five_spin.setFixedWidth(120)

        five_rem = self._account.five_hour_remaining_seconds(time.time())
        self.five_status_label = QLabel()
        self.clear_5h_chk = QCheckBox("取消当前 5h 重置倒计时")
        if five_rem is not None and five_rem > 0:
            self.five_status_label.setText(f"倒计时运行中（剩余 {format_duration(five_rem)}）")
            self.five_status_label.setStyleSheet(f"color: {p.warn_text}; font-size: 12px; font-weight: 600;")
            self.clear_5h_chk.setVisible(True)
        else:
            self.five_status_label.setText("未启动 5h 倒计时")
            self.five_status_label.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")
            self.clear_5h_chk.setVisible(False)

        self.weekly_spin = QSpinBox()
        self.weekly_spin.setRange(0, MAX_QUOTA)
        self.weekly_spin.setValue(self._account.weekly_quota)
        self.weekly_spin.setSuffix(" / 100")
        self.weekly_spin.setFixedWidth(120)

        self.weekly_status_label = QLabel()
        self.weekly_status_label.setStyleSheet(f"color: {p.info_text}; font-size: 12px; font-weight: 600;")

        self.reset_weekly_chk = QCheckBox("重新设定周重置倒计时")
        self.reset_weekly_chk.toggled.connect(self._on_weekly_chk_toggled)

        self.clear_weekly_chk = QCheckBox("清除现有周倒计时")
        self.clear_weekly_chk.toggled.connect(self._on_clear_weekly_toggled)

        hms_widget, self.days_spin, self.hours_spin, self.mins_spin = _build_hms_spinboxes()

        rem = self._account.weekly_remaining_seconds(time.time())
        if rem is not None and rem > 0:
            self.weekly_status_label.setText(f"倒计时运行中（剩余 {format_duration(rem)}）")
            self.reset_weekly_chk.setChecked(False)
            self._set_hms_enabled(False)
        else:
            self.weekly_status_label.setText("未启动倒计时")
            self.reset_weekly_chk.setChecked(True)
            self.reset_weekly_chk.setVisible(False)
            self.clear_weekly_chk.setVisible(False)
            self._set_hms_enabled(True)

        form.addRow("健康状态:", self.health_combo)
        form.addRow("5h 剩余额度:", self.five_spin)
        form.addRow("5h 倒计时状态:", self.five_status_label)
        if self.clear_5h_chk.isVisible():
            form.addRow("", self.clear_5h_chk)
        form.addRow("周剩余额度:", self.weekly_spin)
        form.addRow("周倒计时状态:", self.weekly_status_label)
        if self.reset_weekly_chk.isVisible():
            form.addRow("", self.reset_weekly_chk)
            form.addRow("", self.clear_weekly_chk)
        form.addRow("周剩余重置时间:", hms_widget)

        root.addWidget(group)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("保存更新")
        save_btn.setObjectName("PrimaryButton")
        save_btn.clicked.connect(self._on_submit)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

    def _set_hms_enabled(self, enabled: bool) -> None:
        self.days_spin.setEnabled(enabled)
        self.hours_spin.setEnabled(enabled)
        self.mins_spin.setEnabled(enabled)

    def _on_weekly_chk_toggled(self, checked: bool) -> None:
        if checked:
            self.clear_weekly_chk.setChecked(False)
        self._set_hms_enabled(checked)

    def _on_clear_weekly_toggled(self, checked: bool) -> None:
        if checked:
            self.reset_weekly_chk.setChecked(False)
            self._set_hms_enabled(False)

    def _on_submit(self) -> None:
        duration_sec = (
            self.days_spin.value() * 86400
            + self.hours_spin.value() * 3600
            + self.mins_spin.value() * 60
        )
        self.result_data = QuickQuotaResult(
            five_hour_quota=self.five_spin.value(),
            weekly_quota=self.weekly_spin.value(),
            apply_weekly_timer=self.reset_weekly_chk.isChecked(),
            weekly_reset_seconds=duration_sec,
            clear_weekly_timer=self.clear_weekly_chk.isChecked(),
            clear_five_hour_timer=self.clear_5h_chk.isChecked(),
            health_status=str(self.health_combo.currentData()),
        )
        self.accept()


class OcrConfirmDialog(QDialog):
    """Preview and confirm quota fields extracted offline by Windows WinRT OCR."""

    def __init__(
        self,
        accounts: List[Account],
        ocr_result: OcrQuotaResult,
        default_account_id: Optional[str] = None,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self._accounts = accounts
        self._ocr = ocr_result
        self._palette = palette
        self.apply_result: Optional[OcrApplyResult] = None

        self.setWindowTitle("离线 OCR 额度识别结果确认与一键回填")
        self.resize(520, 440)
        self.setModal(True)
        self._build_ui(default_account_id)

    def _build_ui(self, default_account_id: Optional[str]) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 16)

        form_box = QGroupBox("选择目标账号并核对提取结果（仅勾选的字段会被更新）")
        form = QFormLayout(form_box)
        form.setSpacing(10)

        self.acc_combo = QComboBox()
        sel_idx = 0
        for idx, acc in enumerate(self._accounts):
            self.acc_combo.addItem(f"[{acc.provider}] {acc.name} ({acc.email})", acc.id)
            if default_account_id and acc.id == default_account_id:
                sel_idx = idx
        if self._accounts:
            self.acc_combo.setCurrentIndex(sel_idx)

        # 5h row
        five_row = QWidget()
        f_lay = QHBoxLayout(five_row)
        f_lay.setContentsMargins(0, 0, 0, 0)
        self.apply_five_chk = QCheckBox("更新 5h 剩余额度:")
        self.five_spin = QSpinBox()
        self.five_spin.setRange(0, MAX_QUOTA)
        self.five_spin.setSuffix(" %")
        if self._ocr.five_hour_quota is not None:
            self.apply_five_chk.setChecked(True)
            self.five_spin.setValue(self._ocr.five_hour_quota)
        else:
            self.apply_five_chk.setChecked(False)
            self.five_spin.setValue(MAX_QUOTA)
        f_lay.addWidget(self.apply_five_chk)
        f_lay.addWidget(self.five_spin)
        if self._ocr.five_hour_was_used_mode:
            tag = QLabel("(已从“已用%”自动换算为剩余%)")
            tag.setStyleSheet(f"color: {p.info_text}; font-size: 11px;")
            f_lay.addWidget(tag)
        f_lay.addStretch()

        # Weekly row
        week_row = QWidget()
        w_lay = QHBoxLayout(week_row)
        w_lay.setContentsMargins(0, 0, 0, 0)
        self.apply_week_chk = QCheckBox("更新周剩余额度:")
        self.week_spin = QSpinBox()
        self.week_spin.setRange(0, MAX_QUOTA)
        self.week_spin.setSuffix(" %")
        if self._ocr.weekly_quota is not None:
            self.apply_week_chk.setChecked(True)
            self.week_spin.setValue(self._ocr.weekly_quota)
        else:
            self.apply_week_chk.setChecked(False)
            self.week_spin.setValue(MAX_QUOTA)
        w_lay.addWidget(self.apply_week_chk)
        w_lay.addWidget(self.week_spin)
        if self._ocr.weekly_was_used_mode:
            tag_w = QLabel("(已从“已用%”自动换算为剩余%)")
            tag_w.setStyleSheet(f"color: {p.info_text}; font-size: 11px;")
            w_lay.addWidget(tag_w)
        w_lay.addStretch()

        # Weekly reset duration row
        self.apply_timer_chk = QCheckBox("同步更新周重置倒计时:")
        hms_widget, self.days_spin, self.hours_spin, self.mins_spin = _build_hms_spinboxes()
        if self._ocr.weekly_reset_seconds is not None and self._ocr.weekly_reset_seconds > 0:
            self.apply_timer_chk.setChecked(True)
            sec = self._ocr.weekly_reset_seconds
            d, rem = divmod(sec, 86400)
            h, rem = divmod(rem, 3600)
            m, _ = divmod(rem, 60)
            self.days_spin.setValue(min(31, d))
            self.hours_spin.setValue(min(23, h))
            self.mins_spin.setValue(min(59, m))
        else:
            self.apply_timer_chk.setChecked(False)

        form.addRow("目标账号:", self.acc_combo)
        form.addRow("", five_row)
        form.addRow("", week_row)
        form.addRow("", self.apply_timer_chk)
        form.addRow("重置倒计时:", hms_widget)
        root.addWidget(form_box)

        raw_box = QGroupBox("离线 OCR 识别原始文本")
        raw_lay = QVBoxLayout(raw_box)
        self.raw_view = QPlainTextEdit()
        self.raw_view.setPlainText(self._ocr.raw_text or "（未提取到文字）")
        self.raw_view.setReadOnly(True)
        self.raw_view.setMaximumHeight(110)
        raw_lay.addWidget(self.raw_view)
        root.addWidget(raw_box)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        ok_btn = QPushButton("确认回填")
        ok_btn.setObjectName("PrimaryButton")
        ok_btn.setEnabled(len(self._accounts) > 0)
        ok_btn.clicked.connect(self._on_confirm)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(ok_btn)
        root.addLayout(btn_row)

    def _on_confirm(self) -> None:
        aid = self.acc_combo.currentData()
        if not aid:
            return
        dur_sec = (
            self.days_spin.value() * 86400
            + self.hours_spin.value() * 3600
            + self.mins_spin.value() * 60
        )
        self.apply_result = OcrApplyResult(
            account_id=str(aid),
            apply_five_hour=self.apply_five_chk.isChecked(),
            five_hour_quota=self.five_spin.value(),
            apply_weekly=self.apply_week_chk.isChecked(),
            weekly_quota=self.week_spin.value(),
            apply_weekly_timer=self.apply_timer_chk.isChecked() and dur_sec > 0,
            weekly_reset_seconds=dur_sec,
        )
        self.accept()


class PassphraseDialog(QDialog):
    """Prompt for AES-256-GCM encryption/decryption passphrase."""

    def __init__(
        self,
        title: str,
        prompt_text: str,
        require_confirm: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._require_confirm = require_confirm
        self.passphrase: str = ""
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.setModal(True)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(16, 16, 16, 16)

        lbl = QLabel(prompt_text)
        lbl.setWordWrap(True)
        lay.addWidget(lbl)

        form = QFormLayout()
        self.pwd1 = QLineEdit()
        self.pwd1.setEchoMode(QLineEdit.Password)
        self.pwd1.setPlaceholderText("至少 4 个字符的加密口令")
        form.addRow("加密口令:", self.pwd1)

        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.Password)
        self.pwd2.setPlaceholderText("再次输入相同口令以防误输")
        if require_confirm:
            form.addRow("确认口令:", self.pwd2)
        else:
            self.pwd2.setVisible(False)

        lay.addLayout(form)

        btns = QHBoxLayout()
        btns.addStretch()
        c_btn = QPushButton("取消")
        c_btn.clicked.connect(self.reject)
        ok_btn = QPushButton("确定")
        ok_btn.setObjectName("PrimaryButton")
        ok_btn.clicked.connect(self._on_ok)
        btns.addWidget(c_btn)
        btns.addWidget(ok_btn)
        lay.addLayout(btns)

    def _on_ok(self) -> None:
        p1 = self.pwd1.text().strip()
        if len(p1) < 4:
            QMessageBox.warning(self, "口令过短", "加密口令至少需要 4 个非空白字符。")
            return
        if self._require_confirm and p1 != self.pwd2.text().strip():
            QMessageBox.warning(self, "口令不一致", "两次输入的加密口令不一致，请重新输入。")
            return
        self.passphrase = p1
        self.accept()


class SettingsDialog(QDialog):
    def __init__(
        self,
        settings: AppSettings,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
        on_webdav_push: Optional[Callable[[AppSettings], None]] = None,
        on_webdav_pull: Optional[Callable[[AppSettings], None]] = None,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self._palette = palette
        self._on_webdav_push = on_webdav_push
        self._on_webdav_pull = on_webdav_pull
        self.saved_settings: Optional[AppSettings] = None

        self.setWindowTitle("系统设置：预警、安全隔离与 WebDAV 云同步")
        self.setMinimumWidth(560)
        screen = QApplication.primaryScreen()
        avail_h = screen.availableGeometry().height() if screen else 800
        self.resize(590, min(520, max(380, int(avail_h * 0.68))))
        self.setModal(True)
        self._build_ui()
        self._populate()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 14)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        c_lay = QVBoxLayout(content)
        c_lay.setContentsMargins(0, 0, 8, 0)
        c_lay.setSpacing(12)

        # 1. Weekly & Warranty Expiry Notification Group
        notify_group = QGroupBox("周额度刷新与外购质保临期提醒")
        notify_form = QFormLayout(notify_group)
        notify_form.setSpacing(10)
        notify_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.notify_chk = QCheckBox("启用周额度剩余预警通知")
        self.notify_chk.toggled.connect(self._on_notify_chk_toggled)

        self.quota_spin = QSpinBox()
        self.quota_spin.setRange(1, 99)
        self.quota_spin.setSuffix(" % 及以上")
        self.quota_spin.setMinimumWidth(120)

        self.hours_spin = QSpinBox()
        self.hours_spin.setRange(1, 168)
        self.hours_spin.setSuffix(" 小时以内")
        self.hours_spin.setMinimumWidth(120)

        self.warranty_notify_chk = QCheckBox("启用外购账号质保临期验号提醒")
        self.warranty_hours_spin = QSpinBox()
        self.warranty_hours_spin.setRange(1, 168)
        self.warranty_hours_spin.setSuffix(" 小时以内")
        self.warranty_hours_spin.setMinimumWidth(120)

        notify_form.addRow("", self.notify_chk)
        notify_form.addRow("周额度剩余判定:", self.quota_spin)
        notify_form.addRow("离周刷新不足:", self.hours_spin)
        notify_form.addRow("", self.warranty_notify_chk)
        notify_form.addRow("离质保到期不足:", self.warranty_hours_spin)
        c_lay.addWidget(notify_group)

        # 2. Background Task Group
        bg_group = QGroupBox("未打开软件时的后台提醒（Windows 计划任务）")
        bg_layout = QVBoxLayout(bg_group)
        bg_layout.setSpacing(6)

        self.bg_chk = QCheckBox("开启系统后台静默提醒（关闭本 exe 后仍每小时检测周额度与质保期）")
        self.task_status_lbl = QLabel()
        self.task_status_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")
        bg_layout.addWidget(self.bg_chk)
        bg_layout.addWidget(self.task_status_lbl)
        c_lay.addWidget(bg_group)

        # 3. Browser Isolation & Clipboard Security Group
        sec_group = QGroupBox("防关联浏览器路径与剪贴板安全")
        sec_form = QFormLayout(sec_group)
        sec_form.setSpacing(10)

        br_row = QWidget()
        br_lay = QHBoxLayout(br_row)
        br_lay.setContentsMargins(0, 0, 0, 0)
        br_lay.setSpacing(6)
        self.browser_path_edit = QLineEdit()
        self.browser_path_edit.setPlaceholderText("留空则自动探测系统 Edge / Chrome / Brave")
        br_btn = QPushButton("浏览...")
        br_btn.clicked.connect(self._on_browse_exe)
        br_lay.addWidget(self.browser_path_edit, 1)
        br_lay.addWidget(br_btn)

        self.burn_spin = QSpinBox()
        self.burn_spin.setRange(3, 120)
        self.burn_spin.setSuffix(" 秒后自动清空剪贴板敏感凭据")

        self.tray_chk = QCheckBox("关闭主窗口时最小化到系统托盘")

        sec_form.addRow("隔离浏览器路径:", br_row)
        sec_form.addRow("阅后即焚定时:", self.burn_spin)
        sec_form.addRow("", self.tray_chk)

        test_btn = QPushButton("发送一条测试 Windows 桌面通知")
        test_btn.clicked.connect(self._on_send_test_toast)
        sec_form.addRow("", test_btn)
        c_lay.addWidget(sec_group)

        # 4. WebDAV E2EE Cloud Sync Group
        wd_group = QGroupBox("WebDAV 跨设备端到端加密同步（支持坚果云 / Nextcloud）")
        wd_form = QFormLayout(wd_group)
        wd_form.setSpacing(8)

        self.wd_url_edit = QLineEdit()
        self.wd_url_edit.setPlaceholderText("例如：https://dav.jianguoyun.com/dav/GPTManager/")
        self.wd_user_edit = QLineEdit()
        self.wd_user_edit.setPlaceholderText("WebDAV 账号/邮箱")
        self.wd_pwd_edit = QLineEdit()
        self.wd_pwd_edit.setEchoMode(QLineEdit.Password)
        self.wd_pwd_edit.setPlaceholderText("WebDAV 应用专用密码（本地 DPAPI 加密保存）")

        wd_form.addRow("WebDAV 地址:", self.wd_url_edit)
        wd_form.addRow("WebDAV 用户名:", self.wd_user_edit)
        wd_form.addRow("WebDAV 密码:", self.wd_pwd_edit)

        if self._on_webdav_push or self._on_webdav_pull:
            sync_row = QWidget()
            s_lay = QHBoxLayout(sync_row)
            s_lay.setContentsMargins(0, 0, 0, 0)
            s_lay.setSpacing(8)
            push_btn = QPushButton("☁ 加密上传至云端")
            pull_btn = QPushButton("⬇ 从云端拉取合并")
            push_btn.clicked.connect(self._trigger_push)
            pull_btn.clicked.connect(self._trigger_pull)
            s_lay.addWidget(push_btn)
            s_lay.addWidget(pull_btn)
            s_lay.addStretch()
            wd_form.addRow("立即同步:", sync_row)

        c_lay.addWidget(wd_group)
        c_lay.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("保存设置")
        save_btn.setObjectName("PrimaryButton")
        save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

    def _populate(self) -> None:
        s = self._settings
        self.notify_chk.setChecked(s.notify_enabled)
        self.quota_spin.setValue(s.notify_quota_threshold)
        self.hours_spin.setValue(s.notify_hours_threshold)
        self.warranty_notify_chk.setChecked(s.warranty_notify_enabled)
        self.warranty_hours_spin.setValue(s.warranty_notify_hours)
        self.bg_chk.setChecked(s.background_task_enabled)
        self.tray_chk.setChecked(s.minimize_to_tray)
        self.browser_path_edit.setText(s.custom_browser_path)
        self.burn_spin.setValue(s.clipboard_burn_seconds)
        self.wd_url_edit.setText(s.webdav_url)
        self.wd_user_edit.setText(s.webdav_username)
        self.wd_pwd_edit.setText(s.webdav_password)
        self._on_notify_chk_toggled(s.notify_enabled)

        installed = is_windows_scheduled_task_installed()
        if installed:
            self.task_status_lbl.setText("当前系统状态：Windows 计划任务已就绪（每小时后台检查）")
            self.task_status_lbl.setStyleSheet(f"color: {self._palette.kpi_5h_ready_accent}; font-size: 11px;")
        else:
            self.task_status_lbl.setText("当前系统状态：未注册计划任务")
            self.task_status_lbl.setStyleSheet(f"color: {self._palette.text_muted}; font-size: 11px;")

    def _on_notify_chk_toggled(self, checked: bool) -> None:
        self.quota_spin.setEnabled(checked)
        self.hours_spin.setEnabled(checked)

    def _on_browse_exe(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 Chromium 内核浏览器可执行文件", "", "Executable (*.exe)"
        )
        if path:
            self.browser_path_edit.setText(str(Path(path).resolve()))

    def _collect_draft_settings(self) -> AppSettings:
        any_notify = self.notify_chk.isChecked() or self.warranty_notify_chk.isChecked()
        wd_pwd = self.wd_pwd_edit.text()
        return AppSettings(
            theme=self._settings.theme,
            notify_enabled=self.notify_chk.isChecked(),
            notify_quota_threshold=self.quota_spin.value(),
            notify_hours_threshold=self.hours_spin.value(),
            background_task_enabled=self.bg_chk.isChecked() and any_notify,
            minimize_to_tray=self.tray_chk.isChecked(),
            warranty_notify_enabled=self.warranty_notify_chk.isChecked(),
            warranty_notify_hours=self.warranty_hours_spin.value(),
            custom_browser_path=self.browser_path_edit.text().strip(),
            clipboard_burn_seconds=self.burn_spin.value(),
            webdav_url=self.wd_url_edit.text().strip(),
            webdav_username=self.wd_user_edit.text().strip(),
            webdav_password=wd_pwd,
            _preserved_encrypted_webdav_password=(
                self._settings._preserved_encrypted_webdav_password if not wd_pwd.strip() else ""
            ),
        )

    def _trigger_push(self) -> None:
        if self._on_webdav_push:
            self._on_webdav_push(self._collect_draft_settings())

    def _trigger_pull(self) -> None:
        if self._on_webdav_pull:
            self._on_webdav_pull(self._collect_draft_settings())

    def _on_send_test_toast(self) -> None:
        success = send_windows_toast(
            "AI 账号额度与质保通知测试",
            "测试通过：当周额度或外购质保期进入预警窗口时，系统将发出此原生通知。",
        )
        if success:
            QMessageBox.information(self, "通知发送成功", "已通过 Windows 原生通知接口发出测试气泡。")
        else:
            QMessageBox.warning(self, "通知未触发", "无法触发 Windows 原生通知，请检查系统通知权限。")

    def _on_save(self) -> None:
        new_settings = self._collect_draft_settings()
        if new_settings.background_task_enabled != self._settings.background_task_enabled:
            ok, msg = configure_windows_scheduled_task(new_settings.background_task_enabled)
            if not ok:
                QMessageBox.warning(self, "计划任务配置失败", f"更新系统后台计划任务遇到错误：\n{msg}")

        self.saved_settings = new_settings
        self.accept()


class CodexLoginDialog(QDialog):
    """
    Dialog guiding official browser login via `codex login` and capturing credentials automatically.
    """

    def __init__(
        self,
        monitor: CodexMonitor,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self.monitor = monitor
        self._palette = palette
        self.captured_profile: Optional[CodexProfile] = None

        self.setWindowTitle("官方 Codex 网页登录与自动录入")
        self.setMinimumWidth(500)
        self.resize(520, 360)
        self.setModal(True)

        self.controller = CodexLoginController(monitor=self.monitor, parent=self)
        self.controller.status_message.connect(self._on_status_message)
        self.controller.login_succeeded.connect(self._on_login_succeeded)
        self.controller.login_failed.connect(self._on_login_failed)

        self._build_ui()

    def _build_ui(self) -> None:
        p = self._palette
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(18, 18, 18, 18)

        # Guidance card
        guide_card = QFrame()
        guide_card.setStyleSheet(
            f"background-color: {p.surface_bg}; border: 1px solid {p.border}; "
            f"border-left: 4px solid {p.primary_bg}; border-radius: 6px; padding: 10px;"
        )
        g_lay = QVBoxLayout(guide_card)
        g_lay.setSpacing(6)

        t_lbl = QLabel("全自动登录与账号捕获向导")
        t_lbl.setStyleSheet("font-weight: 700; font-size: 13px;")
        desc_lbl = QLabel(
            "1. 点击下方「调起官方浏览器登录」按钮，软件将调起官方 OAuth 流程；\n"
            "2. 在弹出的浏览器页面中完成登录（支持 Google/Apple 快捷登录或邮箱密码 2FA）；\n"
            "3. 登录完成后，本软件自动监听截获 Token、邮箱、用户名及会员有效期并加密保存，全程无需手动输入！"
        )
        desc_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 12px; line-height: 1.4;")
        desc_lbl.setWordWrap(True)
        g_lay.addWidget(t_lbl)
        g_lay.addWidget(desc_lbl)
        layout.addWidget(guide_card)

        # Status & radar card
        self.status_box = QFrame()
        self.status_box.setStyleSheet(
            f"background-color: {p.input_bg}; border: 1px dashed {p.border}; border-radius: 6px; padding: 12px;"
        )
        sb_lay = QVBoxLayout(self.status_box)
        sb_lay.setSpacing(8)
        self.status_icon_lbl = QLabel("⚪ 准备就绪")
        self.status_icon_lbl.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {p.text_primary};")
        self.detail_lbl = QLabel("请点击下方按钮启动登录，或直接提取宿主机当前已登录的账号。")
        self.detail_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 12px;")
        self.detail_lbl.setWordWrap(True)
        sb_lay.addWidget(self.status_icon_lbl)
        sb_lay.addWidget(self.detail_lbl)
        layout.addWidget(self.status_box)

        layout.addStretch()

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.pull_existing_btn = QPushButton("⚡ 直接从系统提取当前号")
        self.pull_existing_btn.setToolTip("如果宿主机已经登录了 Codex，直接提取无需再次登录")
        self.pull_existing_btn.clicked.connect(self._on_pull_existing)
        btn_layout.addWidget(self.pull_existing_btn)

        btn_layout.addStretch()

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self._on_cancel)
        btn_layout.addWidget(self.cancel_btn)

        self.start_login_btn = QPushButton("🌐 调起官方浏览器登录")
        self.start_login_btn.setObjectName("PrimaryButton")
        self.start_login_btn.setStyleSheet(
            f"padding: 8px 16px; font-size: 12px; font-weight: 600; "
            f"background-color: {p.primary_bg}; border: 1px solid {p.primary_border}; color: #FFFFFF;"
        )
        self.start_login_btn.clicked.connect(self._on_start_login)
        btn_layout.addWidget(self.start_login_btn)

        layout.addLayout(btn_layout)

    def _on_start_login(self) -> None:
        self.start_login_btn.setEnabled(False)
        self.status_icon_lbl.setText("🟡 正在监听官方授权...")
        self.detail_lbl.setText("已向系统发送官方登录指令，正在打开浏览器... 完成登录后软件将自动捕获！")
        ok = self.controller.start_login()
        if not ok:
            self.start_login_btn.setEnabled(True)

    def _on_pull_existing(self) -> None:
        prof = self.monitor.check_now()
        if prof is None:
            QMessageBox.information(
                self,
                "未检测到登录",
                "系统 ~/.codex/auth.json 中未检测到已登录的账号，请点击「调起官方浏览器登录」完成登录。",
            )
            return
        self.captured_profile = prof
        self.accept()

    def _on_status_message(self, msg: str) -> None:
        self.detail_lbl.setText(msg)

    def _on_login_succeeded(self, profile: CodexProfile) -> None:
        self.captured_profile = profile
        self.status_icon_lbl.setText("🟢 账号捕获成功！")
        self.detail_lbl.setText(f"已成功捕获：{profile.email} ({profile.display_plan})，正在写入数据仓...")
        self.accept()

    def _on_login_failed(self, err: str) -> None:
        self.start_login_btn.setEnabled(True)
        self.status_icon_lbl.setText("❌ 登录未完成")
        self.detail_lbl.setText(err)
        QMessageBox.warning(self, "登录未成功", err)

    def _on_cancel(self) -> None:
        self.controller.cancel_login()
        self.reject()

    def closeEvent(self, event) -> None:
        self.controller.cancel_login()
        super().closeEvent(event)

