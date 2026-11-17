"""Formal enterprise Light & Dark theme palettes and Qt stylesheets."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThemePalette:
    name: str
    window_bg: str
    surface_bg: str
    surface_alt_bg: str
    header_bg: str
    header_border: str
    header_title: str
    header_subtitle: str
    input_bg: str
    input_disabled_bg: str
    border: str
    border_strong: str
    text_primary: str
    text_secondary: str
    text_muted: str
    selection_bg: str
    btn_bg: str
    btn_hover: str
    btn_pressed: str
    btn_text: str
    primary_bg: str
    primary_border: str
    primary_hover: str
    primary_pressed: str
    danger_bg: str
    danger_border: str
    danger_text: str
    danger_hover: str
    warn_bg: str
    warn_border: str
    warn_text: str
    warn_hover: str
    info_bg: str
    info_border: str
    info_text: str
    info_hover: str
    tab_bg: str
    tab_text: str
    progress_track: str
    kpi_total_accent: str
    kpi_5h_ready_accent: str
    kpi_5h_cool_accent: str
    kpi_weekly_cool_accent: str
    log_info_color: str
    log_warn_color: str
    log_error_color: str


LIGHT_PALETTE = ThemePalette(
    name="light",
    window_bg="#F4F6F9",
    surface_bg="#FFFFFF",
    surface_alt_bg="#F8FAFC",
    header_bg="#0F172A",
    header_border="#1E293B",
    header_title="#F8FAFC",
    header_subtitle="#94A3B8",
    input_bg="#FFFFFF",
    input_disabled_bg="#F1F5F9",
    border="#E2E8F0",
    border_strong="#CBD5E1",
    text_primary="#0F172A",
    text_secondary="#334155",
    text_muted="#64748B",
    selection_bg="#EFF6FF",
    btn_bg="#FFFFFF",
    btn_hover="#F8FAFC",
    btn_pressed="#E2E8F0",
    btn_text="#1E293B",
    primary_bg="#2563EB",
    primary_border="#1D4ED8",
    primary_hover="#1D4ED8",
    primary_pressed="#1E40AF",
    danger_bg="#FEF2F2",
    danger_border="#FECACA",
    danger_text="#DC2626",
    danger_hover="#FEE2E2",
    warn_bg="#FFFBEB",
    warn_border="#FDE68A",
    warn_text="#B45309",
    warn_hover="#FEF3C7",
    info_bg="#EFF6FF",
    info_border="#BFDBFE",
    info_text="#1D4ED8",
    info_hover="#DBEAFE",
    tab_bg="#E2E8F0",
    tab_text="#475569",
    progress_track="#E2E8F0",
    kpi_total_accent="#0F172A",
    kpi_5h_ready_accent="#16A34A",
    kpi_5h_cool_accent="#D97706",
    kpi_weekly_cool_accent="#2563EB",
    log_info_color="#16A34A",
    log_warn_color="#D97706",
    log_error_color="#DC2626",
)

DARK_PALETTE = ThemePalette(
    name="dark",
    window_bg="#0B1120",
    surface_bg="#111827",
    surface_alt_bg="#162033",
    header_bg="#020617",
    header_border="#1E293B",
    header_title="#F8FAFC",
    header_subtitle="#94A3B8",
    input_bg="#1E293B",
    input_disabled_bg="#0F172A",
    border="#1F2937",
    border_strong="#334155",
    text_primary="#F1F5F9",
    text_secondary="#CBD5E1",
    text_muted="#94A3B8",
    selection_bg="#1E3A5F",
    btn_bg="#1E293B",
    btn_hover="#334155",
    btn_pressed="#475569",
    btn_text="#F1F5F9",
    primary_bg="#2563EB",
    primary_border="#3B82F6",
    primary_hover="#1D4ED8",
    primary_pressed="#1E40AF",
    danger_bg="#450A0A",
    danger_border="#991B1B",
    danger_text="#FCA5A5",
    danger_hover="#7F1D1D",
    warn_bg="#451A03",
    warn_border="#92400E",
    warn_text="#FCD34D",
    warn_hover="#78350F",
    info_bg="#172554",
    info_border="#1E40AF",
    info_text="#93C5FD",
    info_hover="#1E3A8A",
    tab_bg="#1E293B",
    tab_text="#94A3B8",
    progress_track="#334155",
    kpi_total_accent="#F8FAFC",
    kpi_5h_ready_accent="#4ADE80",
    kpi_5h_cool_accent="#FBBF24",
    kpi_weekly_cool_accent="#60A5FA",
    log_info_color="#4ADE80",
    log_warn_color="#FBBF24",
    log_error_color="#F87171",
)


def get_palette(theme_name: str) -> ThemePalette:
    return DARK_PALETTE if theme_name == "dark" else LIGHT_PALETTE


def build_stylesheet(theme_name: str) -> str:
    p = get_palette(theme_name)
    return f"""
QMainWindow, QDialog, QMessageBox {{
    background-color: {p.window_bg};
    color: {p.text_primary};
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 13px;
}}

QLabel {{
    color: {p.text_primary};
    background-color: transparent;
}}

QCheckBox {{
    color: {p.text_primary};
    spacing: 6px;
}}

QWidget#HeaderBar {{
    background-color: {p.header_bg};
    border-bottom: 1px solid {p.header_border};
}}

QLabel#AppTitle {{
    color: {p.header_title};
    font-size: 18px;
    font-weight: 700;
}}

QLabel#AppSubtitle {{
    color: {p.header_subtitle};
    font-size: 12px;
}}

QFrame#ToolbarFrame, QFrame#TableContainer, QFrame#LogContainer {{
    background-color: {p.surface_bg};
    border: 1px solid {p.border};
    border-radius: 8px;
}}

QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background-color: {p.input_bg};
    border: 1px solid {p.border_strong};
    border-radius: 6px;
    padding: 6px 10px;
    color: {p.text_primary};
    selection-background-color: {p.primary_bg};
    selection-color: #FFFFFF;
}}

QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {p.primary_bg};
}}

QLineEdit:disabled, QPlainTextEdit:disabled, QSpinBox:disabled {{
    background-color: {p.input_disabled_bg};
    color: {p.text_muted};
}}

QComboBox QAbstractItemView {{
    background-color: {p.surface_bg};
    color: {p.text_primary};
    border: 1px solid {p.border_strong};
    selection-background-color: {p.selection_bg};
    selection-color: {p.text_primary};
}}

QPushButton {{
    background-color: {p.btn_bg};
    border: 1px solid {p.border_strong};
    border-radius: 6px;
    padding: 6px 12px;
    color: {p.btn_text};
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {p.btn_hover};
}}

QPushButton:pressed {{
    background-color: {p.btn_pressed};
}}

QPushButton:disabled {{
    color: {p.text_muted};
    border-color: {p.border};
}}

QPushButton#PrimaryButton {{
    background-color: {p.primary_bg};
    border: 1px solid {p.primary_border};
    color: #FFFFFF;
    padding: 7px 16px;
}}

QPushButton#PrimaryButton:hover {{
    background-color: {p.primary_hover};
}}

QPushButton#PrimaryButton:pressed {{
    background-color: {p.primary_pressed};
}}

QPushButton#DangerButton {{
    background-color: {p.danger_bg};
    border: 1px solid {p.danger_border};
    color: {p.danger_text};
}}

QPushButton#DangerButton:hover {{
    background-color: {p.danger_hover};
}}

QPushButton#ThemeToggleBtn {{
    background-color: #1E293B;
    border: 1px solid #475569;
    color: #F8FAFC;
    padding: 6px 14px;
}}

QPushButton#ThemeToggleBtn:hover {{
    background-color: #334155;
    border-color: #64748B;
}}

QPushButton#SettingsBtn {{
    background-color: #1E293B;
    border: 1px solid #475569;
    color: #F8FAFC;
    padding: 6px 14px;
}}

QPushButton#SettingsBtn:hover {{
    background-color: #334155;
    border-color: #64748B;
}}

QTableWidget {{
    background-color: {p.surface_bg};
    alternate-background-color: {p.surface_alt_bg};
    color: {p.text_primary};
    border: 1px solid {p.border};
    gridline-color: {p.border};
    selection-background-color: {p.selection_bg};
    selection-color: {p.text_primary};
}}

QTableWidget::item {{
    padding: 6px 8px;
    color: {p.text_primary};
    border-bottom: 1px solid {p.border};
}}

QHeaderView::section {{
    background-color: {p.surface_alt_bg};
    color: {p.text_secondary};
    font-weight: 700;
    font-size: 12px;
    padding: 8px 8px;
    border: none;
    border-bottom: 1px solid {p.border_strong};
    border-right: 1px solid {p.border};
}}

QTabWidget::pane {{
    border: 1px solid {p.border};
    border-radius: 8px;
    background-color: {p.surface_bg};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {p.tab_bg};
    color: {p.tab_text};
    padding: 8px 18px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}}

QTabBar::tab:selected {{
    background-color: {p.surface_bg};
    color: {p.text_primary};
    border: 1px solid {p.border};
    border-bottom: 2px solid {p.primary_bg};
}}

QGroupBox {{
    font-weight: 700;
    color: {p.text_secondary};
    border: 1px solid {p.border_strong};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 12px;
    background-color: {p.surface_bg};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {p.text_secondary};
}}

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollBar:vertical {{
    background-color: {p.surface_bg};
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical {{
    background-color: {p.border_strong};
    min-height: 24px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {p.primary_bg};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
    background: none;
    border: none;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none;
}}

QStatusBar {{
    background-color: {p.surface_bg};
    border-top: 1px solid {p.border};
    color: {p.text_secondary};
    font-size: 12px;
}}
"""


APP_STYLESHEET = build_stylesheet("light")
