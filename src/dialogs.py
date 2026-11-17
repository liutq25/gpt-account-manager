from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
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
    Account,
    MAX_QUOTA,
    ParsedAccount,
    format_duration,
    parse_accounts_from_text,
)
from src.notifier import send_windows_toast
from src.storage import (
    AppSettings,
    configure_windows_scheduled_task,
    is_windows_scheduled_task_installed,
)
from src.ui_styles import LIGHT_PALETTE, ThemePalette


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


@dataclass
class QuickQuotaResult:
    five_hour_quota: int
    weekly_quota: int
    apply_weekly_timer: bool
    weekly_reset_seconds: int
    clear_weekly_timer: bool


@dataclass
class BatchImportItem:
    name: str
    email: str
    password: str
    two_fa: str
    five_hour_quota: int
    weekly_quota: int


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

        self.setWindowTitle("编辑 GPT 账号" if self._is_edit else "添加 GPT 账号")
        self.setMinimumWidth(560)
        self.setModal(True)

        screen = QApplication.primaryScreen()
        avail_h = screen.availableGeometry().height() if screen else 800
        # 页面高度紧凑化，默认 480，防止被 Windows 底边任务栏遮挡，支持鼠标滚轮滚动
        target_h = min(480, max(360, int(avail_h * 0.62)))
        self.resize(580, target_h)
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

        # 鼠标滚轮滚动区域（允许内容通过滚轮上下滚动，无需一次全部呈现）
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setObjectName("AccountDialogScrollArea")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 6, 0)
        scroll_layout.setSpacing(10)

        # Smart Text Parse Group
        parse_group = QGroupBox("智能文本识别填充（可直接粘贴整段发货文本）")
        parse_layout = QVBoxLayout(parse_group)
        parse_layout.setSpacing(8)

        self.raw_text_edit = QPlainTextEdit()
        self.raw_text_edit.setPlaceholderText(
            "直接粘贴整段文本，例如：\n"
            "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "郑重声明上号不要去关掉2FA...（会自动忽略声明与链接，提取邮箱、密码与2FA）"
        )
        self.raw_text_edit.setMaximumHeight(80)

        parse_bar = QHBoxLayout()
        self.parse_status_label = QLabel("支持「邮箱----密码----2FA」格式及混合长文本自动提取")
        self.parse_status_label.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        parse_btn = QPushButton("一键识别填充")
        parse_btn.setObjectName("PrimaryButton")
        parse_btn.setStyleSheet(
            f"padding: 5px 12px; font-size: 12px; background-color: {p.primary_bg}; "
            f"border: 1px solid {p.primary_border}; color: #FFFFFF;"
        )
        parse_btn.clicked.connect(self._on_smart_parse)
        parse_bar.addWidget(self.parse_status_label, 1)
        parse_bar.addWidget(parse_btn)

        parse_layout.addWidget(self.raw_text_edit)
        parse_layout.addLayout(parse_bar)
        scroll_layout.addWidget(parse_group)

        # Credentials Group
        cred_group = QGroupBox("账号凭据信息")
        cred_form = QFormLayout(cred_group)
        cred_form.setSpacing(10)
        cred_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如：主力Plus-01 / 团队号A（智能识别时留空会自动填入邮箱前缀）")

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("例如：user@example.com")

        pwd_row = QWidget()
        pwd_layout = QHBoxLayout(pwd_row)
        pwd_layout.setContentsMargins(0, 0, 0, 0)
        pwd_layout.setSpacing(6)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("输入账号密码")
        self.toggle_pwd_btn = QPushButton("显示")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.setFixedWidth(64)
        self.toggle_pwd_btn.toggled.connect(self._on_toggle_password)
        pwd_layout.addWidget(self.password_edit)
        pwd_layout.addWidget(self.toggle_pwd_btn)

        self.two_fa_edit = QLineEdit()
        self.two_fa_edit.setPlaceholderText("输入2FA初始验证码或Base32密钥")

        two_fa_hint = QLabel("支持保存静态初始验证码，或输入Base32密钥自动生成实时6位动态验证码。")
        two_fa_hint.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        two_fa_hint.setWordWrap(True)

        cred_form.addRow("账号名称 *:", self.name_edit)
        cred_form.addRow("账号邮箱 *:", self.email_edit)
        cred_form.addRow("登录密码 *:", pwd_row)
        cred_form.addRow("2FA 验证码 *:", self.two_fa_edit)
        cred_form.addRow("", two_fa_hint)
        scroll_layout.addWidget(cred_group)

        # Quota Group
        quota_group = QGroupBox("额度与重置规则设置")
        quota_form = QFormLayout(quota_group)
        quota_form.setSpacing(10)
        quota_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.five_spin = QSpinBox()
        self.five_spin.setRange(0, MAX_QUOTA)
        self.five_spin.setValue(MAX_QUOTA)
        self.five_spin.setSuffix(" / 100")
        self.five_spin.setFixedWidth(120)

        five_hint = QLabel("5小时额度无需输入重置时间：当额度为 0 时自动开始 5 小时倒计时，结束后自动恢复为 100。")
        five_hint.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        five_hint.setWordWrap(True)

        self.weekly_spin = QSpinBox()
        self.weekly_spin.setRange(0, MAX_QUOTA)
        self.weekly_spin.setValue(MAX_QUOTA)
        self.weekly_spin.setSuffix(" / 100")
        self.weekly_spin.setFixedWidth(120)

        self.weekly_status_label = QLabel("")
        self.weekly_status_label.setStyleSheet(f"color: {p.info_text}; font-size: 12px; font-weight: 600;")

        self.reset_weekly_chk = QCheckBox("重新设置周额度剩余重置时间")
        self.reset_weekly_chk.toggled.connect(self._on_weekly_chk_toggled)

        self.clear_weekly_chk = QCheckBox("清除现有周倒计时")
        self.clear_weekly_chk.toggled.connect(self._on_clear_weekly_toggled)

        hms_widget, self.days_spin, self.hours_spin, self.mins_spin = _build_hms_spinboxes()

        weekly_hint = QLabel("输入剩余重置时间 (> 0) 保存后立即开始倒计时，倒计时结束周额度自动恢复为 100。")
        weekly_hint.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        weekly_hint.setWordWrap(True)

        quota_form.addRow("5h 剩余额度:", self.five_spin)
        quota_form.addRow("", five_hint)
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
        quota_form.addRow("", weekly_hint)
        scroll_layout.addWidget(quota_group)
        scroll_layout.addStretch()

        self.scroll_area.setWidget(scroll_content)
        root.addWidget(self.scroll_area, 1)

        # Action Buttons 固定在底部
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
            self.parse_status_label.setStyleSheet(f"color: {self._palette.danger_text}; font-size: 11px; font-weight: 600;")
            return

        first = parsed[0]
        if not self.name_edit.text().strip():
            self.name_edit.setText(first.suggested_name)
        self.email_edit.setText(first.email)
        self.password_edit.setText(first.password)
        self.two_fa_edit.setText(first.two_fa)

        if len(parsed) > 1:
            self.parse_status_label.setText(
                f"共检测到 {len(parsed)} 条账号，已自动填充第 1 条；多账号建议使用主界面的「批量文本导入」。"
            )
        else:
            self.parse_status_label.setText(f"已成功识别并填充：{first.email}")
        self.parse_status_label.setStyleSheet(f"color: {self._palette.kpi_5h_ready_accent}; font-size: 11px; font-weight: 600;")

    def _populate(self, account: Account) -> None:
        self.name_edit.setText(account.name)
        self.email_edit.setText(account.email)
        self.password_edit.setText(account.password)
        self.two_fa_edit.setText(account.two_fa)
        self.five_spin.setValue(account.five_hour_quota)
        self.weekly_spin.setValue(account.weekly_quota)

        rem = account.weekly_remaining_seconds(time.time())
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

    def _on_toggle_password(self, checked: bool) -> None:
        self.password_edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.toggle_pwd_btn.setText("隐藏" if checked else "显示")

    def _on_submit(self) -> None:
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        password = self.password_edit.text()
        two_fa = self.two_fa_edit.text().strip()

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

        self.setWindowTitle("批量智能文本识别导入")
        self.resize(820, 560)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        hint = QLabel(
            "将包含一个或多个账号的整段文本粘贴到下方（支持混合售后声明、网址、emoji），点击「识别解析」自动提取邮箱、密码和 2FA 初始验证码："
        )
        hint.setStyleSheet(f"color: {p.text_secondary}; font-size: 12px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText(
            "粘贴整段文本，支持单条或多条混合文本，例如：\n"
            "graph.57chap@icloud.com----V198jmeE&N6a@4x!----L7CM2UJJV65TCH5CXL3PURLX7GJC554D\n"
            "emeries.gloss-1i+shlf@icloud.com----#uWOE^riLIPD9dLN----HFZM22U7X2RABCDYDUHNPAYGD2QVI4GF"
        )
        self.input_text.setMinimumHeight(130)
        root.addWidget(self.input_text)

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
            name_item = QTableWidgetItem(item.suggested_name)
            email_item = QTableWidgetItem(item.email)
            pwd_item = QTableWidgetItem(item.password)
            tfa_item = QTableWidgetItem(item.two_fa)
            self.preview_table.setItem(idx, 0, name_item)
            self.preview_table.setItem(idx, 1, email_item)
            self.preview_table.setItem(idx, 2, pwd_item)
            self.preview_table.setItem(idx, 3, tfa_item)

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
            self.status_lbl.setStyleSheet(f"color: {self._palette.danger_text}; font-size: 12px; font-weight: 600;")
            self.import_btn.setEnabled(False)
            self.import_btn.setText("确认导入 (0)")
        else:
            self.status_lbl.setText(f"成功解析 {count} 个账号（可在下表直接双击修改名称或调整初始额度）。")
            self.status_lbl.setStyleSheet(f"color: {self._palette.kpi_5h_ready_accent}; font-size: 12px; font-weight: 600;")
            self.import_btn.setEnabled(True)
            self.import_btn.setText(f"确认导入 ({count})")

    def _on_confirm_import(self) -> None:
        collected: List[BatchImportItem] = []
        for idx in range(self.preview_table.rowCount()):
            name = (self.preview_table.item(idx, 0).text() or "").strip()
            email = (self.preview_table.item(idx, 1).text() or "").strip()
            password = self.preview_table.item(idx, 2).text() or ""
            two_fa = (self.preview_table.item(idx, 3).text() or "").strip()
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

        self.setWindowTitle(f"更新额度 - {account.name}")
        self.setMinimumWidth(460)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        info = QLabel(f"账号：{self._account.name}  ({self._account.email})")
        info.setStyleSheet(f"font-weight: 700; color: {p.text_primary}; font-size: 13px;")
        root.addWidget(info)

        group = QGroupBox("手动录入剩余额度")
        form = QFormLayout(group)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.five_spin = QSpinBox()
        self.five_spin.setRange(0, MAX_QUOTA)
        self.five_spin.setValue(self._account.five_hour_quota)
        self.five_spin.setSuffix(" / 100")
        self.five_spin.setFixedWidth(120)

        five_note = QLabel("设为 0 后自动开始 5h 倒计时，5h 后自动恢复为 100。")
        five_note.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")

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

        form.addRow("5h 剩余额度:", self.five_spin)
        form.addRow("", five_note)
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
        )
        self.accept()


class SettingsDialog(QDialog):
    def __init__(
        self,
        settings: AppSettings,
        parent: Optional[QWidget] = None,
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self._palette = palette
        self.saved_settings: Optional[AppSettings] = None

        self.setWindowTitle("系统通知与提醒设置")
        self.setMinimumWidth(500)
        self.setModal(True)
        self._build_ui()
        self._populate()

    def _build_ui(self) -> None:
        p = self._palette
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(18, 18, 18, 18)

        # Weekly Quota Expiry Notification Group
        notify_group = QGroupBox("周额度即将刷新提醒设置")
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

        quota_hint = QLabel("当某个账号周额度还有较多剩余（≥设定值），且倒计时快要结束时触发提醒，避免额度浪费。")
        quota_hint.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        quota_hint.setWordWrap(True)

        notify_form.addRow("", self.notify_chk)
        notify_form.addRow("周额度剩余判定:", self.quota_spin)
        notify_form.addRow("离刷新时间不足:", self.hours_spin)
        notify_form.addRow("", quota_hint)
        root.addWidget(notify_group)

        # Background Task / Offline Notification Group
        bg_group = QGroupBox("未打开软件时的后台提醒（Windows 计划任务）")
        bg_layout = QVBoxLayout(bg_group)
        bg_layout.setSpacing(8)

        self.bg_chk = QCheckBox("开启系统后台静默提醒（未打开此 exe 也能提醒）")
        self.bg_chk.setToolTip("通过 Windows 计划任务每小时唤起静默检测，发现即将刷新的账号直接弹出桌面通知")

        bg_hint = QLabel(
            "说明：勾选后将自动向 Windows 计划任务注册「GPTManager_QuotaNotifier」，系统每小时自动静默检测 0.1 秒，"
            "即使您完全关闭了本软件，快到期时系统也会直接弹出桌面 Windows 原生通知；取消勾选将彻底删除该任务。"
        )
        bg_hint.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        bg_hint.setWordWrap(True)

        self.task_status_lbl = QLabel()
        self.task_status_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")

        bg_layout.addWidget(self.bg_chk)
        bg_layout.addWidget(bg_hint)
        bg_layout.addWidget(self.task_status_lbl)
        root.addWidget(bg_group)

        # App Behavior Group
        app_group = QGroupBox("应用程序运行与托盘")
        app_layout = QVBoxLayout(app_group)
        app_layout.setSpacing(8)

        self.tray_chk = QCheckBox("关闭主窗口时最小化到系统托盘（在后台继续倒计时与提醒）")
        app_layout.addWidget(self.tray_chk)

        test_row = QHBoxLayout()
        test_btn = QPushButton("发送一条测试 Windows 桌面通知")
        test_btn.clicked.connect(self._on_send_test_toast)
        test_row.addWidget(test_btn)
        test_row.addStretch()
        app_layout.addLayout(test_row)
        root.addWidget(app_group)

        # Bottom Buttons
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
        self.bg_chk.setChecked(s.background_task_enabled)
        self.tray_chk.setChecked(s.minimize_to_tray)
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
        self.bg_chk.setEnabled(checked)

    def _on_send_test_toast(self) -> None:
        success = send_windows_toast(
            "GPT 账号额度通知测试",
            "这是一条测试通知：周额度还有剩余且即将在 1 天内刷新时，系统将发出此类通知！",
        )
        if success:
            QMessageBox.information(self, "通知发送成功", "已通过 Windows 原生通知接口成功发出测试气泡。")
        else:
            QMessageBox.warning(self, "通知未触发", "无法触发 Windows 原生通知，请检查系统的通知设置是否允许通知。")

    def _on_save(self) -> None:
        new_settings = AppSettings(
            theme=self._settings.theme,
            notify_enabled=self.notify_chk.isChecked(),
            notify_quota_threshold=self.quota_spin.value(),
            notify_hours_threshold=self.hours_spin.value(),
            background_task_enabled=self.bg_chk.isChecked() and self.notify_chk.isChecked(),
            minimize_to_tray=self.tray_chk.isChecked(),
        )

        # Synchronize Windows Scheduled Task
        if new_settings.background_task_enabled != self._settings.background_task_enabled:
            ok, msg = configure_windows_scheduled_task(new_settings.background_task_enabled)
            if not ok:
                QMessageBox.warning(self, "计划任务配置失败", f"更新系统后台计划任务遇到错误：\n{msg}")

        self.saved_settings = new_settings
        self.accept()

