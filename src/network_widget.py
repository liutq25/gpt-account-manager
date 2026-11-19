"""
PyQt5 Tab Widget for Network Speed Testing, Exit IP Geo-Lookup,
VPN Likelihood Detection, and IP Purity Risk Scoring (0-100, higher = lower risk).
"""

from __future__ import annotations

import queue
import re
import statistics
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.models import Account
from src.network_lab import (
    DEFAULT_DNS_SERVER,
    PROTOCOLS,
    PROXY_MODES,
    GeoRiskService,
    IpRiskReport,
    NetworkConfig,
    NetworkSpeedEngine,
    ProxyClient,
    detect_system_proxy,
    get_local_ip,
    parse_target,
)
from src.ui_styles import LIGHT_PALETTE, ThemePalette


class NetworkLabTab(QWidget):
    """
    Integrated Network Speed & IP Risk Assessment Lab.
    Thread-safe via internal queue polled on a 100ms QTimer.
    """

    def __init__(
        self,
        config_path: Path,
        get_accounts_fn: Optional[Callable[[], List[Account]]] = None,
        palette: ThemePalette = LIGHT_PALETTE,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.config_path = config_path
        self._get_accounts_fn = get_accounts_fn
        self._palette = palette
        self.cfg = NetworkConfig.load(config_path)
        self.geo = GeoRiskService()

        self._ui_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._running_count = 0
        self._auto_remaining = 0
        self._hosts: Dict[str, Dict[str, Any]] = {}
        self._row_index: Dict[str, int] = {}

        self._build_ui()
        self._load_targets_into_table()
        self.apply_palette(self._palette)

        self._queue_timer = QTimer(self)
        self._queue_timer.setInterval(100)
        self._queue_timer.timeout.connect(self._process_queue)
        self._queue_timer.start()

        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(1000)
        self._auto_timer.timeout.connect(self._on_auto_tick)
        self._auto_timer.start()

        self._ip_refresh_timer = QTimer(self)
        self._ip_refresh_timer.setInterval(60000)
        self._ip_refresh_timer.timeout.connect(self.refresh_exit_ip)
        self._ip_refresh_timer.start()

        # Defer initial exit IP lookup slightly so window opens instantaneously
        self._init_probe_timer = QTimer(self)
        self._init_probe_timer.setSingleShot(True)
        self._init_probe_timer.timeout.connect(self._on_initial_probe)
        self._init_probe_timer.start(350)

    def _on_initial_probe(self) -> None:
        self._redetect_system_proxy(silent=True)
        self.refresh_exit_ip()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # 1. Exit IP & VPN Risk Assessment Card
        self.ip_card = QFrame()
        self.ip_card.setObjectName("ToolbarFrame")
        ip_lay = QVBoxLayout(self.ip_card)
        ip_lay.setContentsMargins(14, 10, 14, 10)
        ip_lay.setSpacing(8)

        top_info = QHBoxLayout()
        top_info.setSpacing(18)

        self.lbl_pub_ip = QLabel("出口公网 IP: 检测中…")
        self.lbl_pub_ip.setStyleSheet("font-weight: 700; font-size: 13px;")
        self.lbl_pub_geo = QLabel("归属地: -")
        self.lbl_pub_isp = QLabel("运营商/ASN: -")
        self.lbl_local_ip = QLabel(f"内网 IP: {get_local_ip()}")

        top_info.addWidget(self.lbl_pub_ip)
        top_info.addWidget(self.lbl_pub_geo)
        top_info.addWidget(self.lbl_pub_isp, 1)
        top_info.addWidget(self.lbl_local_ip)

        self.refresh_ip_btn = QPushButton("🔄 检测出口 IP 与 VPN 风险")
        self.refresh_ip_btn.setObjectName("PrimaryButton")
        self.refresh_ip_btn.clicked.connect(self.refresh_exit_ip)
        top_info.addWidget(self.refresh_ip_btn)
        ip_lay.addLayout(top_info)

        # Risk Score Row
        risk_row = QHBoxLayout()
        risk_row.setSpacing(12)

        self.lbl_vpn_prob = QLabel("VPN 可能性: --%")
        self.lbl_vpn_prob.setStyleSheet("font-weight: 700; font-size: 12px;")

        self.lbl_risk_score = QLabel("IP 安全评分: -- / 100")
        self.lbl_risk_score.setStyleSheet("font-weight: 700; font-size: 13px;")

        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setValue(0)
        self.risk_bar.setTextVisible(False)
        self.risk_bar.setFixedWidth(160)
        self.risk_bar.setFixedHeight(10)

        self.lbl_risk_level = QLabel("等待检测")
        self.lbl_risk_detail = QLabel("提示：评分越高风险越低（85+ 为纯净原生/住宅链路）")
        self.lbl_risk_detail.setWordWrap(True)

        risk_row.addWidget(self.lbl_vpn_prob)
        risk_row.addWidget(self.lbl_risk_score)
        risk_row.addWidget(self.risk_bar)
        risk_row.addWidget(self.lbl_risk_level)
        risk_row.addWidget(self.lbl_risk_detail, 1)
        ip_lay.addLayout(risk_row)

        root.addWidget(self.ip_card)

        # 2. Proxy & Protocol Bar
        self.proxy_bar = QFrame()
        self.proxy_bar.setObjectName("ToolbarFrame")
        pb_lay = QHBoxLayout(self.proxy_bar)
        pb_lay.setContentsMargins(12, 8, 12, 8)
        pb_lay.setSpacing(8)

        pb_lay.addWidget(QLabel("代理模式:"))
        self.proxy_mode_combo = QComboBox()
        self.proxy_mode_combo.addItems([*PROXY_MODES, "从账号导入代理"])
        idx = self.proxy_mode_combo.findText(self.cfg.proxy_mode)
        if idx >= 0:
            self.proxy_mode_combo.setCurrentIndex(idx)
        self.proxy_mode_combo.currentIndexChanged.connect(self._on_proxy_mode_changed)
        pb_lay.addWidget(self.proxy_mode_combo)

        self.manual_proxy_edit = QLineEdit(self.cfg.manual_proxy)
        self.manual_proxy_edit.setPlaceholderText("127.0.0.1:7897 或 socks5://127.0.0.1:7897")
        self.manual_proxy_edit.setMaximumWidth(230)
        self.manual_proxy_edit.editingFinished.connect(self._on_manual_proxy_edited)
        pb_lay.addWidget(self.manual_proxy_edit)

        self.account_proxy_combo = QComboBox()
        self.account_proxy_combo.setMaximumWidth(200)
        self.account_proxy_combo.setVisible(False)
        self.account_proxy_combo.currentIndexChanged.connect(self._on_account_proxy_selected)
        pb_lay.addWidget(self.account_proxy_combo)

        self.redetect_btn = QPushButton("检测系统代理")
        self.redetect_btn.clicked.connect(lambda: self._redetect_system_proxy(silent=False))
        pb_lay.addWidget(self.redetect_btn)

        self.lbl_proxy_status = QLabel("")
        pb_lay.addWidget(self.lbl_proxy_status, 1)

        pb_lay.addWidget(QLabel("协议:"))
        self.proto_combo = QComboBox()
        for code, label in PROTOCOLS:
            self.proto_combo.addItem(label, code)
        p_idx = self.proto_combo.findData(self.cfg.protocol)
        if p_idx >= 0:
            self.proto_combo.setCurrentIndex(p_idx)
        self.proto_combo.currentIndexChanged.connect(self._save_cfg_from_ui)
        pb_lay.addWidget(self.proto_combo)

        dns_btn = QPushButton("DNS")
        dns_btn.setToolTip("设置 DNS 查询服务器")
        dns_btn.clicked.connect(self._on_edit_dns)
        pb_lay.addWidget(dns_btn)

        root.addWidget(self.proxy_bar)

        # 3. Action & Auto-Loop Toolbar
        self.action_bar = QFrame()
        self.action_bar.setObjectName("ToolbarFrame")
        ab_lay = QHBoxLayout(self.action_bar)
        ab_lay.setContentsMargins(12, 8, 12, 8)
        ab_lay.setSpacing(8)

        self.btn_test_all = QPushButton("▶ 全部同时测试")
        self.btn_test_all.setObjectName("PrimaryButton")
        self.btn_test_all.clicked.connect(self.start_all_tests)

        self.btn_test_sel = QPushButton("🎯 测试选中")
        self.btn_test_sel.clicked.connect(self.start_selected_test)

        self.btn_stop = QPushButton("⏹ 停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_all_tests)

        self.btn_add_target = QPushButton("+ 添加网址")
        self.btn_add_target.clicked.connect(self._on_add_target)

        self.btn_del_target = QPushButton("🗑 删除选中")
        self.btn_del_target.clicked.connect(self._on_delete_selected)

        ab_lay.addWidget(self.btn_test_all)
        ab_lay.addWidget(self.btn_test_sel)
        ab_lay.addWidget(self.btn_stop)
        ab_lay.addWidget(self.btn_add_target)
        ab_lay.addWidget(self.btn_del_target)
        ab_lay.addStretch()

        self.auto_loop_chk = QCheckBox("自动循环测试")
        self.auto_loop_chk.setChecked(self.cfg.auto_loop)
        self.auto_loop_chk.toggled.connect(self._on_auto_loop_toggled)
        ab_lay.addWidget(self.auto_loop_chk)

        ab_lay.addWidget(QLabel("间隔(秒):"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 600)
        self.interval_spin.setValue(self.cfg.interval)
        self.interval_spin.valueChanged.connect(self._save_cfg_from_ui)
        ab_lay.addWidget(self.interval_spin)

        self.lbl_auto_countdown = QLabel("")
        ab_lay.addWidget(self.lbl_auto_countdown)

        root.addWidget(self.action_bar)

        # 4. Target Speed & IP Risk Table
        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "目标网址",
            "解析 IP",
            "归属地 / 运营商",
            "VPN可能性 / IP评分",
            "最新(ms)",
            "最小(ms)",
            "平均(ms)",
            "最大(ms)",
            "丢包率",
            "状态",
            "最后测试",
        ])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self.start_selected_test)

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        for col in range(4, 11):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeToContents)

        root.addWidget(self.table, 1)

        # 5. Compact Log Panel
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(110)
        self.log_box.setPlaceholderText("节点测速与 IP 风险评估日志...")
        root.addWidget(self.log_box)

        self._update_proxy_controls_visibility()

    def apply_palette(self, palette: ThemePalette) -> None:
        self._palette = palette
        self.lbl_pub_geo.setStyleSheet(f"color: {palette.text_secondary}; font-size: 12px;")
        self.lbl_pub_isp.setStyleSheet(f"color: {palette.text_secondary}; font-size: 12px;")
        self.lbl_local_ip.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        self.lbl_risk_detail.setStyleSheet(f"color: {palette.text_muted}; font-size: 11px;")
        self.lbl_proxy_status.setStyleSheet(f"color: {palette.text_muted}; font-size: 11px;")
        self.lbl_auto_countdown.setStyleSheet(f"color: {palette.text_muted}; font-size: 11px;")

    def _log(self, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"[{stamp}] {msg}")

    def _save_cfg_from_ui(self) -> None:
        self.cfg.protocol = str(self.proto_combo.currentData() or "tcp")
        mode = self.proxy_mode_combo.currentText()
        if mode in PROXY_MODES:
            self.cfg.proxy_mode = mode
        elif mode == "从账号导入代理":
            self.cfg.proxy_mode = "手动代理"
        self.cfg.manual_proxy = self.manual_proxy_edit.text().strip() or self.cfg.manual_proxy
        self.cfg.interval = int(self.interval_spin.value())
        self.cfg.auto_loop = bool(self.auto_loop_chk.isChecked())
        self.cfg.targets = [entry["raw"] for entry in self._hosts.values()]
        try:
            self.cfg.save(self.config_path)
        except Exception:
            pass

    def _update_proxy_controls_visibility(self) -> None:
        mode = self.proxy_mode_combo.currentText()
        self.manual_proxy_edit.setVisible(mode == "手动代理")
        self.account_proxy_combo.setVisible(mode == "从账号导入代理")
        self.redetect_btn.setVisible(mode == "系统代理（自动）")

        if mode == "直连":
            self.lbl_proxy_status.setText("直连（不使用代理）")
        elif mode == "系统代理（自动）":
            sys_p = detect_system_proxy()
            self.lbl_proxy_status.setText(f"已检测到: {sys_p}" if sys_p else "未检测到系统代理（将按直连运行）")
        elif mode == "手动代理":
            self.lbl_proxy_status.setText("使用手动代理")
        elif mode == "从账号导入代理":
            self._populate_account_proxy_combo()

    def _populate_account_proxy_combo(self) -> None:
        self.account_proxy_combo.blockSignals(True)
        self.account_proxy_combo.clear()
        accounts = self._get_accounts_fn() if self._get_accounts_fn else []
        added = 0
        for acc in accounts:
            if acc.proxy_url.strip():
                self.account_proxy_combo.addItem(f"{acc.name} ({acc.proxy_url})", acc.proxy_url.strip())
                added += 1
        if added == 0:
            self.account_proxy_combo.addItem("（暂无已配置代理的账号）", "")
        self.account_proxy_combo.blockSignals(False)
        self._on_account_proxy_selected()

    def _on_account_proxy_selected(self) -> None:
        proxy_url = str(self.account_proxy_combo.currentData() or "").strip()
        if proxy_url:
            self.manual_proxy_edit.setText(proxy_url)
            self.lbl_proxy_status.setText(f"已载入账号代理: {proxy_url}")
        else:
            self.lbl_proxy_status.setText("该账号未设置独立代理")

    def _on_proxy_mode_changed(self) -> None:
        self._update_proxy_controls_visibility()
        self._save_cfg_from_ui()
        self.refresh_exit_ip()

    def _on_manual_proxy_edited(self) -> None:
        self._save_cfg_from_ui()

    def _redetect_system_proxy(self, silent: bool = False) -> None:
        sys_p = detect_system_proxy()
        if self.proxy_mode_combo.currentText() == "系统代理（自动）":
            self.lbl_proxy_status.setText(f"已检测到: {sys_p}" if sys_p else "未检测到系统代理（将按直连运行）")
        if not silent:
            self._log(f"系统代理检测结果: {sys_p or '无（直连）'}")

    def _resolve_active_proxy(self) -> Optional[ProxyClient]:
        mode = self.proxy_mode_combo.currentText()
        if mode == "直连":
            return None
        if mode == "系统代理（自动）":
            sys_p = detect_system_proxy()
            if not sys_p:
                return None
            return ProxyClient(sys_p)
        if mode == "从账号导入代理":
            raw = str(self.account_proxy_combo.currentData() or "").strip()
            return ProxyClient(raw) if raw else None
        raw = self.manual_proxy_edit.text().strip()
        return ProxyClient(raw) if raw else None

    def probe_account_proxy(self, account: Account) -> None:
        """Called from Account Table to immediately evaluate an account's node/proxy IP & risk."""
        if account.proxy_url.strip():
            idx = self.proxy_mode_combo.findText("手动代理")
            if idx >= 0:
                self.proxy_mode_combo.setCurrentIndex(idx)
            self.manual_proxy_edit.setText(account.proxy_url.strip())
            self.lbl_proxy_status.setText(f"已载入「{account.name}」代理: {account.proxy_url}")
        else:
            idx = self.proxy_mode_combo.findText("系统代理（自动）")
            if idx >= 0:
                self.proxy_mode_combo.setCurrentIndex(idx)
            self._redetect_system_proxy(silent=True)
        self._save_cfg_from_ui()
        self._log(f"开始为账号「{account.name}」检测出口 IP、VPN 可能性与线路延迟...")
        self.refresh_exit_ip()
        self.start_all_tests()

    def _on_edit_dns(self) -> None:
        val, ok = QInputDialog.getText(
            self,
            "设置 DNS 服务器",
            f"请输入用于 DNS 测速的服务器 IPv4 地址（默认 {DEFAULT_DNS_SERVER}）：",
            text=self.cfg.dns_server,
        )
        if not ok:
            return
        clean = val.strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", clean):
            self.cfg.dns_server = clean
            self._save_cfg_from_ui()
            self._log(f"DNS 服务器已设置为 {clean}")
        else:
            QMessageBox.warning(self, "格式错误", "请输入合法的 IPv4 地址")

    def _load_targets_into_table(self) -> None:
        for raw in self.cfg.targets:
            try:
                self._add_target_entry(raw, save=False)
            except ValueError:
                pass

    def _add_target_entry(self, raw: str, save: bool = True) -> None:
        parsed = parse_target(raw)
        key = raw.strip()
        if key in self._hosts:
            return
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._row_index[key] = row
        self._hosts[key] = {
            "raw": key,
            **parsed,
            "ip": "-",
            "geo_text": "-",
            "risk_text": "-",
            "risk_score": None,
            "last": "-",
            "min": "-",
            "avg": "-",
            "max": "-",
            "loss": "-",
            "status": "待测试",
            "updated": "-",
        }
        self._render_row(key)
        if save:
            self._save_cfg_from_ui()

    def _render_row(self, key: str) -> None:
        row = self._row_index.get(key)
        entry = self._hosts.get(key)
        if row is None or entry is None:
            return
        cols = [
            entry["raw"],
            entry["ip"],
            entry["geo_text"],
            entry["risk_text"],
            entry["last"],
            entry["min"],
            entry["avg"],
            entry["max"],
            entry["loss"],
            entry["status"],
            entry["updated"],
        ]
        p = self._palette
        status = entry["status"]
        for c, text in enumerate(cols):
            item = self.table.item(row, c)
            if item is None:
                item = QTableWidgetItem(str(text))
                self.table.setItem(row, c, item)
            else:
                item.setText(str(text))

            if c in (1, 4, 5, 6, 7, 8, 10):
                item.setTextAlignment(Qt.AlignCenter)

            # Color hints
            if c == 3 and entry["risk_score"] is not None:
                sc = entry["risk_score"]
                if sc >= 85:
                    item.setForeground(QColor(p.kpi_5h_ready_accent))
                elif sc >= 65:
                    item.setForeground(QColor(p.kpi_weekly_cool_accent))
                elif sc >= 40:
                    item.setForeground(QColor(p.warn_text))
                else:
                    item.setForeground(QColor(p.danger_text))
            elif c == 9:
                if "正常" in status:
                    item.setForeground(QColor(p.kpi_5h_ready_accent))
                elif "不可达" in status or "失败" in status or "超时" in status:
                    item.setForeground(QColor(p.danger_text))
                elif "测试中" in status:
                    item.setForeground(QColor(p.primary_bg))
                else:
                    item.setForeground(QColor(p.text_muted))

    def _on_add_target(self) -> None:
        text, ok = QInputDialog.getMultiLineText(
            self,
            "添加测速目标",
            "每行一个网址、域名或 IP:端口（例如 chatgpt.com、https://claude.ai、1.1.1.1:443）：",
        )
        if not ok or not text.strip():
            return
        added = 0
        for line in text.splitlines():
            clean = line.strip()
            if not clean:
                continue
            try:
                self._add_target_entry(clean, save=False)
                added += 1
            except ValueError as err:
                self._log(f"跳过无效目标 {clean!r}: {err}")
        if added > 0:
            self._save_cfg_from_ui()
            self._log(f"已添加 {added} 个测速目标")

    def _on_delete_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        target_item = self.table.item(row, 0)
        if target_item is None:
            return
        key = target_item.text()
        self._hosts.pop(key, None)
        self.table.removeRow(row)
        # Rebuild row index map
        self._row_index.clear()
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it is not None:
                self._row_index[it.text()] = r
        self._save_cfg_from_ui()

    def refresh_exit_ip(self) -> None:
        try:
            proxy = self._resolve_active_proxy()
        except Exception as err:
            self.lbl_pub_ip.setText("出口公网 IP: 代理格式错误")
            self.lbl_risk_detail.setText(str(err))
            return

        self.refresh_ip_btn.setEnabled(False)
        self.lbl_pub_ip.setText("出口公网 IP: 检测中…")

        def worker() -> None:
            try:
                report = self.geo.fetch_exit_ip_report(proxy=proxy)
                self._ui_queue.put(("exit_ip", report))
            except Exception as exc:
                self._ui_queue.put(("exit_ip_err", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def start_selected_test(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        it = self.table.item(row, 0)
        if it is not None:
            self._launch_tests([it.text()])

    def start_all_tests(self) -> None:
        keys = list(self._hosts.keys())
        if keys:
            self._launch_tests(keys)

    def stop_all_tests(self) -> None:
        self._stop_event.set()
        self._log("正在停止全部测速任务...")

    def _launch_tests(self, keys: List[str]) -> None:
        try:
            proxy = self._resolve_active_proxy()
        except Exception as err:
            QMessageBox.warning(self, "代理配置错误", str(err))
            return

        proto = str(self.proto_combo.currentData() or "tcp")
        samples = self.cfg.samples
        timeout = self.cfg.timeout
        dns_server = self.cfg.dns_server

        self._stop_event.clear()
        self.btn_stop.setEnabled(True)
        for key in keys:
            entry = self._hosts.get(key)
            if entry is None:
                continue
            entry["status"] = "测试中…"
            self._render_row(key)
            self._running_count += 1
            threading.Thread(
                target=self._test_worker,
                args=(key, dict(entry), proto, samples, timeout, dns_server, proxy),
                daemon=True,
            ).start()

    def _test_worker(
        self,
        key: str,
        entry: Dict[str, Any],
        proto: str,
        samples: int,
        timeout: float,
        dns_server: str,
        proxy: Optional[ProxyClient],
    ) -> None:
        host = entry["host"]
        port = entry["port"]
        scheme = entry["scheme"]
        path = entry["path"]
        ip = "-"
        risk_report: Optional[IpRiskReport] = None

        try:
            ip = NetworkSpeedEngine.resolve(host, port)
        except Exception:
            ip = "代理远程解析" if proxy is not None else "-"

        if ip not in ("-", "代理远程解析"):
            try:
                reports = self.geo.query_ips([ip], proxy=proxy)
                risk_report = reports.get(ip)
            except Exception:
                risk_report = None

        latencies: List[float] = []
        losses = 0
        last_err = ""
        http_code: Optional[int] = None

        if proto == "icmp":
            try:
                raw_samples = NetworkSpeedEngine.icmp_ping(host, count=samples, timeout_ms=int(timeout * 1000))
                for s in raw_samples:
                    if s is None:
                        losses += 1
                    else:
                        latencies.append(s)
                if not raw_samples:
                    losses = samples
                    last_err = "Ping 无回包"
            except Exception as exc:
                losses = samples
                last_err = str(exc)
        else:
            for _ in range(samples):
                if self._stop_event.is_set():
                    break
                try:
                    if proto == "tcp":
                        ms = NetworkSpeedEngine.tcp_measure(host, port, timeout, proxy)
                        latencies.append(ms)
                    elif proto == "http":
                        ms, code = NetworkSpeedEngine.http_probe(scheme, host, port, path, timeout, proxy)
                        http_code = code
                        latencies.append(ms)
                    elif proto == "dns":
                        ms, ans_cnt, rcode = NetworkSpeedEngine.dns_measure(dns_server, host, timeout, proxy)
                        if rcode != 0 or ans_cnt == 0:
                            losses += 1
                            last_err = f"DNS rcode={rcode}"
                        else:
                            latencies.append(ms)
                except Exception as exc:
                    losses += 1
                    last_err = str(exc)

        total_done = len(latencies) + losses
        loss_pct = (losses / total_done * 100.0) if total_done > 0 else 100.0
        if self._stop_event.is_set():
            status = "已停止"
        elif latencies:
            if proto == "http" and http_code is not None:
                status = f"正常 (HTTP {http_code})" if http_code < 500 else f"异常 (HTTP {http_code})"
            elif losses > 0:
                status = f"波动 ({losses}/{total_done} 丢包)"
            else:
                status = "正常"
        else:
            status = f"不可达 ({last_err[:24]})" if last_err else "不可达"

        self._ui_queue.put((
            "test_done",
            {
                "key": key,
                "ip": ip,
                "report": risk_report,
                "latencies": latencies,
                "loss_pct": loss_pct,
                "status": status,
                "updated": time.strftime("%H:%M:%S"),
            },
        ))

    def _process_queue(self) -> None:
        while True:
            try:
                kind, payload = self._ui_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "exit_ip":
                self.refresh_ip_btn.setEnabled(True)
                self._apply_exit_ip_report(payload)
            elif kind == "exit_ip_err":
                self.refresh_ip_btn.setEnabled(True)
                self.lbl_pub_ip.setText("出口公网 IP: 查询失败")
                self.lbl_risk_detail.setText(str(payload))
                self._log(f"出口 IP 检测失败: {payload}")
            elif kind == "test_done":
                self._running_count = max(0, self._running_count - 1)
                if self._running_count == 0:
                    self.btn_stop.setEnabled(False)
                self._apply_test_result(payload)

    def _apply_exit_ip_report(self, report: IpRiskReport) -> None:
        p = self._palette
        src_tag = f" ({report.source})" if report.source else ""
        self.lbl_pub_ip.setText(f"出口公网 IP: {report.ip}{src_tag}")
        self.lbl_pub_geo.setText(f"归属地: {report.location_text}")
        isp_str = report.asn or report.isp or report.org or "-"
        self.lbl_pub_isp.setText(f"运营商/ASN: {isp_str}")

        self.lbl_vpn_prob.setText(f"VPN 可能性: {report.vpn_probability}%")
        self.lbl_risk_score.setText(f"IP 安全评分: {report.risk_score} / 100")
        self.risk_bar.setValue(report.risk_score)
        self.lbl_risk_level.setText(report.risk_level)
        self.lbl_risk_detail.setText(report.risk_summary)

        if report.risk_score >= 85:
            color = p.kpi_5h_ready_accent
        elif report.risk_score >= 65:
            color = p.kpi_weekly_cool_accent
        elif report.risk_score >= 40:
            color = p.warn_text
        else:
            color = p.danger_text

        self.lbl_risk_score.setStyleSheet(f"font-weight: 700; font-size: 13px; color: {color};")
        self.lbl_risk_level.setStyleSheet(f"font-weight: 700; font-size: 12px; color: {color};")
        self.risk_bar.setStyleSheet(
            f"QProgressBar {{ background-color: {p.progress_track}; border-radius: 4px; border: none; }}"
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}"
        )

        self._log(
            f"出口 IP: {report.ip} | {report.location_text} | {isp_str} | "
            f"VPN可能性: {report.vpn_probability}% | IP评分: {report.risk_score}/100 ({report.risk_level})"
        )

    def _apply_test_result(self, res: Dict[str, Any]) -> None:
        key = res["key"]
        entry = self._hosts.get(key)
        if entry is None:
            return
        entry["ip"] = res["ip"]
        report: Optional[IpRiskReport] = res.get("report")
        if report is not None:
            isp_part = report.isp or report.org or ""
            entry["geo_text"] = f"{report.location_text} ({isp_part})" if isp_part else report.location_text
            entry["risk_text"] = f"VPN {report.vpn_probability}% | {report.risk_score}分"
            entry["risk_score"] = report.risk_score
        else:
            entry["geo_text"] = "-"
            entry["risk_text"] = "-"
            entry["risk_score"] = None

        lats: List[float] = res["latencies"]
        if lats:
            entry["last"] = f"{lats[-1]:.1f}"
            entry["min"] = f"{min(lats):.1f}"
            entry["avg"] = f"{statistics.mean(lats):.1f}"
            entry["max"] = f"{max(lats):.1f}"
        else:
            entry["last"] = entry["min"] = entry["avg"] = entry["max"] = "-"
        entry["loss"] = f"{res['loss_pct']:.0f}%"
        entry["status"] = res["status"]
        entry["updated"] = res["updated"]
        self._render_row(key)

    def _on_auto_loop_toggled(self, checked: bool) -> None:
        self._auto_remaining = int(self.interval_spin.value()) if checked else 0
        if not checked:
            self.lbl_auto_countdown.setText("")
        self._save_cfg_from_ui()

    def _on_auto_tick(self) -> None:
        if not self.auto_loop_chk.isChecked():
            return
        if self._running_count > 0:
            self.lbl_auto_countdown.setText("测速运行中…")
            return
        if self._auto_remaining <= 0:
            self._auto_remaining = int(self.interval_spin.value())
            self.start_all_tests()
        else:
            self._auto_remaining -= 1
            self.lbl_auto_countdown.setText(f"下一轮: {self._auto_remaining}s")

    def shutdown(self) -> None:
        self._stop_event.set()
        self._queue_timer.stop()
        self._auto_timer.stop()
        self._ip_refresh_timer.stop()
        self._init_probe_timer.stop()
