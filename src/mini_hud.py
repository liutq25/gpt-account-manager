"""
Always-on-top compact Mini HUD capsule window and full-screen rubber-band snip overlay for OCR.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional

from PyQt5.QtCore import QPoint, QRect, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QGuiApplication, QPainter, QPen, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.models import Account, format_duration, select_optimal_account
from src.ui_styles import LIGHT_PALETTE, ThemePalette


class ScreenSnipOverlay(QWidget):
    """
    Full-screen translucent overlay allowing the user to drag-select a screen region for offline OCR.
    Handles HiDPI scaling (`devicePixelRatio`) and guards against tiny accidental clicks (< 16px).
    """

    snip_captured = pyqtSignal(QPixmap)
    snip_cancelled = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(None)
        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool
        )
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.setCursor(Qt.CrossCursor)

        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            self._virtual_geo = screen.virtualGeometry()
            self._full_pixmap = screen.grabWindow(
                0,
                self._virtual_geo.x(),
                self._virtual_geo.y(),
                self._virtual_geo.width(),
                self._virtual_geo.height(),
            )
            self.setGeometry(self._virtual_geo)
        else:
            self._virtual_geo = QRect(0, 0, 800, 600)
            self._full_pixmap = QPixmap(800, 600)
            self._full_pixmap.fill(Qt.black)

        self._origin: Optional[QPoint] = None
        self._current: Optional[QPoint] = None
        self._is_dragging = False

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.drawPixmap(0, 0, self._full_pixmap)
        painter.fillRect(self.rect(), QColor(15, 23, 42, 120))

        if self._origin is not None and self._current is not None:
            sel_rect = QRect(self._origin, self._current).normalized()
            if sel_rect.width() > 2 and sel_rect.height() > 2:
                dpr = self._full_pixmap.devicePixelRatio()
                src_rect = QRect(
                    int(sel_rect.x() * dpr),
                    int(sel_rect.y() * dpr),
                    int(sel_rect.width() * dpr),
                    int(sel_rect.height() * dpr),
                )
                painter.drawPixmap(sel_rect, self._full_pixmap, src_rect)
                pen = QPen(QColor("#3B82F6"), 2)
                painter.setPen(pen)
                painter.drawRect(sel_rect)

        painter.setPen(QColor("#F8FAFC"))
        painter.drawText(
            24,
            36,
            "按住鼠标左键框选网页上的「5h额度 / 周额度 / 重置时间」区域（按 Esc 或右键取消）",
        )

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.RightButton:
            self.snip_cancelled.emit()
            self.close()
            return
        if event.button() == Qt.LeftButton:
            self._origin = event.pos()
            self._current = event.pos()
            self._is_dragging = True
            self.update()

    def mouseMoveEvent(self, event) -> None:
        if self._is_dragging:
            self._current = event.pos()
            self.update()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self._is_dragging:
            self._is_dragging = False
            self._current = event.pos()
            if self._origin is None or self._current is None:
                self.snip_cancelled.emit()
                self.close()
                return
            sel_rect = QRect(self._origin, self._current).normalized()
            if sel_rect.width() < 16 or sel_rect.height() < 16:
                self.snip_cancelled.emit()
                self.close()
                return

            dpr = self._full_pixmap.devicePixelRatio()
            crop_rect = QRect(
                int(sel_rect.x() * dpr),
                int(sel_rect.y() * dpr),
                int(sel_rect.width() * dpr),
                int(sel_rect.height() * dpr),
            )
            cropped = self._full_pixmap.copy(crop_rect)
            self.hide()
            self.snip_captured.emit(cropped)
            self.close()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.snip_cancelled.emit()
            self.close()


class MiniHudWindow(QWidget):
    """
    Compact 340x104 always-on-top floating capsule widget for rapid multi-account operations.
    """

    def __init__(
        self,
        on_dispatch: Callable[[], None],
        on_advance_paste: Callable[[], None],
        on_snip_ocr: Callable[[], None],
        on_expand_main: Callable[[], None],
        palette: ThemePalette = LIGHT_PALETTE,
    ) -> None:
        super().__init__(None)
        self._on_dispatch = on_dispatch
        self._on_advance_paste = on_advance_paste
        self._on_snip_ocr = on_snip_ocr
        self._on_expand_main = on_expand_main
        self._palette = palette
        self._drag_offset: Optional[QPoint] = None
        self._paste_state: str = "IDLE"

        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFixedSize(356, 106)

        self._build_ui()
        self.apply_palette(palette)
        self._move_to_default_corner()

    def _move_to_default_corner(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(geo.right() - self.width() - 24, geo.top() + 36)

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)

        self.card = QFrame()
        self.card.setObjectName("MiniHudCard")
        lay = QVBoxLayout(self.card)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(6)

        # Top row: active account badge + timer + expand/close
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        self.title_lbl = QLabel("暂无活跃账号")
        self.title_lbl.setStyleSheet("font-weight: 700; font-size: 12px;")
        self.timer_lbl = QLabel("--:--:--")
        self.timer_lbl.setStyleSheet("font-family: 'Consolas', monospace; font-size: 12px; font-weight: 700;")

        self.expand_btn = QPushButton("主窗")
        self.expand_btn.setFixedWidth(44)
        self.expand_btn.setToolTip("展开主控制台窗口")
        self.expand_btn.clicked.connect(self._on_expand_main)

        self.close_btn = QPushButton("×")
        self.close_btn.setFixedWidth(26)
        self.close_btn.setToolTip("隐藏置顶胶囊窗")
        self.close_btn.clicked.connect(self.hide)

        top_row.addWidget(self.title_lbl, 1)
        top_row.addWidget(self.timer_lbl)
        top_row.addWidget(self.expand_btn)
        top_row.addWidget(self.close_btn)
        lay.addLayout(top_row)

        # Sub-status line
        self.sub_lbl = QLabel("就绪 · 可按住此胶囊任意拖动")
        self.sub_lbl.setStyleSheet("font-size: 11px;")
        lay.addWidget(self.sub_lbl)

        # Bottom quick actions
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        self.dispatch_btn = QPushButton("⚡ 最优派号")
        self.dispatch_btn.setToolTip("按 EEQF 防作废算法选出当前最紧急账号并开始使用")
        self.dispatch_btn.clicked.connect(self._on_dispatch)

        self.paste_btn = QPushButton("下一步吐码")
        self.paste_btn.setToolTip("推进三段式剪贴板登录队列（邮箱 -> 密码 -> 防过期2FA）")
        self.paste_btn.setEnabled(False)
        self.paste_btn.clicked.connect(self._on_advance_paste)

        self.ocr_btn = QPushButton("📷 框选OCR")
        self.ocr_btn.setToolTip("框选网页额度区域离线自动识别回填")
        self.ocr_btn.clicked.connect(self._on_snip_ocr)

        btn_row.addWidget(self.dispatch_btn)
        btn_row.addWidget(self.paste_btn)
        btn_row.addWidget(self.ocr_btn)
        lay.addLayout(btn_row)

        outer.addWidget(self.card)

    def apply_palette(self, palette: ThemePalette) -> None:
        self._palette = palette
        p = palette
        self.card.setStyleSheet(
            f"QFrame#MiniHudCard {{ background-color: {p.surface_bg}; "
            f"border: 2px solid {p.primary_bg}; border-radius: 12px; }}"
        )
        self.title_lbl.setStyleSheet(f"color: {p.text_primary}; font-weight: 700; font-size: 12px;")
        self.timer_lbl.setStyleSheet(
            f"color: {p.warn_text}; font-family: 'Consolas', monospace; font-size: 12px; font-weight: 700;"
        )
        self.sub_lbl.setStyleSheet(f"color: {p.text_muted}; font-size: 11px;")
        btn_css = (
            f"QPushButton {{ background-color: {p.btn_bg}; color: {p.btn_text}; "
            f"border: 1px solid {p.border_strong}; border-radius: 5px; padding: 3px 6px; font-size: 11px; }}"
            f"QPushButton:hover {{ background-color: {p.btn_hover}; }}"
            f"QPushButton:disabled {{ color: {p.text_muted}; border-color: {p.border}; }}"
        )
        for b in (self.expand_btn, self.close_btn, self.paste_btn, self.ocr_btn):
            b.setStyleSheet(btn_css)
        self.dispatch_btn.setStyleSheet(
            f"QPushButton {{ background-color: {p.primary_bg}; color: #FFFFFF; "
            f"border: none; border-radius: 5px; padding: 3px 8px; font-size: 11px; font-weight: 700; }}"
            f"QPushButton:hover {{ background-color: {p.primary_hover}; }}"
        )

    def update_paste_queue_state(self, state_code: str, message: str) -> None:
        self._paste_state = state_code
        if state_code == "STEP_1_EMAIL":
            self.paste_btn.setEnabled(True)
            self.paste_btn.setText("▶ 复制密码(2/3)")
            self.sub_lbl.setText("1/3 邮箱已复制 -> 粘贴后点右侧按钮")
        elif state_code == "STEP_2_PASSWORD":
            self.paste_btn.setEnabled(True)
            self.paste_btn.setText("▶ 复制2FA(3/3)")
            self.sub_lbl.setText("2/3 密码已复制 -> 粘贴后点右侧取2FA")
        elif state_code == "STEP_3_TOTP_WAIT":
            self.paste_btn.setEnabled(False)
            self.paste_btn.setText("⏳ 等新2FA...")
            self.sub_lbl.setText("验证码临期，正在自动顺延新周期...")
        elif state_code == "BURNING":
            self.paste_btn.setEnabled(True)
            self.paste_btn.setText("🔥 立即焚毁")
            self.sub_lbl.setText("3/3 2FA已复制！即将自动清空剪贴板")
        else:
            self.paste_btn.setEnabled(False)
            self.paste_btn.setText("吐码空闲")
            if message:
                self.sub_lbl.setText(message[:28])

    def refresh_snapshot(
        self,
        accounts: List[Account],
        focused_account_id: Optional[str] = None,
        now_ts: Optional[float] = None,
        provider_filter: Optional[str] = None,
    ) -> None:
        now = time.time() if now_ts is None else now_ts
        pool = list(accounts)
        if provider_filter and provider_filter != "全部平台":
            clean_prov = provider_filter.strip().lower()
            if clean_prov:
                pool = [a for a in pool if a.provider.lower() == clean_prov]

        target: Optional[Account] = None
        if focused_account_id:
            cand = next((a for a in pool if a.id == focused_account_id), None)
            if cand is not None and cand.health_status not in ("BANNED", "DISABLED", "PHONE_VERIFY"):
                target = cand

        # Prefer actively counting-down healthy account if no focused account
        if target is None:
            cooling = [
                a
                for a in pool
                if a.five_hour_reset_at is not None
                and a.five_hour_reset_at > now
                and a.health_status in ("ACTIVE", "DEGRADED_POW")
            ]
            if cooling:
                cooling.sort(key=lambda a: a.five_hour_reset_at or 0.0)
                target = cooling[0]

        if target is None:
            try:
                rec = select_optimal_account(pool, provider=provider_filter, now_ts=now)
                target = rec.account
            except ValueError:
                target = None

        if target is None:
            self.title_lbl.setText("无可用账号")
            self.timer_lbl.setText("--:--:--")
            if self._paste_state == "IDLE":
                self.sub_lbl.setText("点击主窗添加账号或批量导入")
            return

        badge = f"[{target.provider}] {target.name}"
        self.title_lbl.setText(badge[:18])
        rem_5h = target.five_hour_remaining_seconds(now)
        if rem_5h is not None:
            self.timer_lbl.setText(format_duration(rem_5h))
        else:
            self.timer_lbl.setText(f"5h:{target.five_hour_quota}%")

        if self._paste_state == "IDLE":
            ready_cnt = sum(1 for a in pool if a.can_start_five_hour_usage[0])
            self.sub_lbl.setText(
                f"周余:{target.weekly_quota}% | 空闲可派发:{ready_cnt}/{len(pool)}个"
            )

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_offset = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event) -> None:
        if self._drag_offset is not None and (event.buttons() & Qt.LeftButton):
            self.move(event.globalPos() - self._drag_offset)
            event.accept()

    def mouseReleaseEvent(self, _event) -> None:
        self._drag_offset = None
