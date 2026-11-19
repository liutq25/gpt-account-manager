import time
from pathlib import Path
from unittest.mock import patch

import pytest
from PyQt5.QtWidgets import QApplication

from src.main_window import MainWindow
from src.models import Account
from src.network_lab import (
    IpRiskReport,
    NetworkConfig,
    NetworkSpeedEngine,
    ProxyClient,
    evaluate_ip_risk,
    is_public_ip,
    parse_target,
)
from src.network_widget import NetworkLabTab
from src.storage import AccountStorage


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_parse_target_and_proxy_client():
    t1 = parse_target("chatgpt.com")
    assert t1["host"] == "chatgpt.com"
    assert t1["port"] == 443
    assert t1["scheme"] == "https"

    t2 = parse_target("http://1.1.1.1:8080/health")
    assert t2["host"] == "1.1.1.1"
    assert t2["port"] == 8080
    assert t2["path"] == "/health"

    with pytest.raises(ValueError):
        parse_target("   ")

    p1 = ProxyClient("127.0.0.1:7897")
    assert p1.scheme == "http"
    assert p1.host == "127.0.0.1"
    assert p1.port == 7897

    p2 = ProxyClient("socks5h://user1:pass%202@10.0.0.2:1080")
    assert p2.scheme == "socks5h"
    assert p2.host == "10.0.0.2"
    assert p2.port == 1080
    assert p2.username == "user1"
    assert p2.password == "pass 2"


def test_evaluate_ip_risk_scoring_invariants():
    # 1. Clean US residential ISP
    res = evaluate_ip_risk({
        "ip": "73.15.20.1",
        "country": "美国",
        "country_code": "US",
        "isp": "Comcast Cable Communications",
        "org": "Comcast",
        "as": "AS7922 Comcast Cable",
        "reverse": "c-73-15-20-1.hsd1.ca.comcast.net",
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
    })
    assert res.risk_score >= 90
    assert res.vpn_probability <= 10
    assert "极低风险" in res.risk_level

    # 2. Cloud / Datacenter node (e.g. AWS)
    dc = evaluate_ip_risk({
        "ip": "52.196.81.7",
        "country": "日本",
        "country_code": "JP",
        "isp": "Amazon Technologies Inc.",
        "org": "AWS EC2",
        "as": "AS16509 Amazon.com, Inc.",
        "reverse": "ec2-52-196-81-7.ap-northeast-1.compute.amazonaws.com",
        "is_proxy": False,
        "is_hosting": True,
    })
    assert 60 <= dc.risk_score < res.risk_score
    assert dc.vpn_probability >= 35

    # 3. Commercial VPN exit node
    vpn = evaluate_ip_risk({
        "ip": "185.220.101.1",
        "country": "德国",
        "country_code": "DE",
        "isp": "Mullvad VPN",
        "org": "M247 Europe",
        "as": "AS9009 M247 Ltd",
        "reverse": "",
        "is_proxy": True,
        "is_hosting": True,
    })
    assert vpn.risk_score < 40
    assert vpn.vpn_probability >= 85
    assert "极高风险" in vpn.risk_level

    # 4. Restricted region (HK) + proxy
    hk_vpn = evaluate_ip_risk({
        "ip": "45.64.240.1",
        "country": "中国香港",
        "country_code": "HK",
        "isp": "CloudVPS Hosting",
        "is_proxy": True,
        "is_hosting": True,
    })
    assert hk_vpn.risk_score <= 20
    assert any("受AI平台访问限制" in d for d in hk_vpn.deductions)

    # 5. Private LAN IP
    lan = evaluate_ip_risk({"ip": "192.168.1.10"})
    assert not is_public_ip("192.168.1.10")
    assert lan.risk_level == "内网地址"
    assert lan.risk_score == 100


def test_network_config_persistence(tmp_path: Path):
    cfg_path = tmp_path / "network_config.json"
    cfg = NetworkConfig(
        targets=["chatgpt.com", "claude.ai"],
        protocol="http",
        proxy_mode="手动代理",
        manual_proxy="socks5://127.0.0.1:1080",
        dns_server="8.8.8.8",
        interval=45,
        auto_loop=True,
    )
    cfg.save(cfg_path)
    loaded = NetworkConfig.load(cfg_path)
    assert loaded.targets == ["chatgpt.com", "claude.ai"]
    assert loaded.protocol == "http"
    assert loaded.proxy_mode == "手动代理"
    assert loaded.manual_proxy == "socks5://127.0.0.1:1080"
    assert loaded.dns_server == "8.8.8.8"
    assert loaded.interval == 45
    assert loaded.auto_loop is True


def test_network_lab_tab_and_mainwindow_integration(qapp, tmp_path: Path):
    storage = AccountStorage(base_dir=tmp_path)
    acc = Account.create(
        name="美区住宅号",
        email="us_res@example.com",
        password="pw",
        two_fa="123456",
        proxy_url="socks5://127.0.0.1:7897",
    )
    storage.save_accounts([acc])

    win = MainWindow(storage=storage, codex_home=tmp_path / ".codex")
    try:
        assert win.tabs.count() == 4
        assert "节点测速" in win.tabs.tabText(3)
        tab: NetworkLabTab = win.network_tab

        # Verify _apply_exit_ip_report updates UI cleanly
        rep = IpRiskReport(
            ip="73.15.20.1",
            country="美国",
            country_code="US",
            city="San Jose",
            isp="Comcast",
            vpn_probability=5,
            risk_score=95,
            risk_level="极低风险（纯净住宅/原生）",
            source="ip-api",
        )
        tab._apply_exit_ip_report(rep)
        assert "73.15.20.1" in tab.lbl_pub_ip.text()
        assert "5%" in tab.lbl_vpn_prob.text()
        assert "95 / 100" in tab.lbl_risk_score.text()
        assert tab.risk_bar.value() == 95

        # Probe account proxy switches to Tab 4 and populates account proxy_url
        with patch.object(tab, "refresh_exit_ip") as mock_ref, \
             patch.object(tab, "start_all_tests") as mock_start:
            win._on_probe_account_network(acc.id)
            assert win.tabs.currentWidget() is tab
            assert tab.proxy_mode_combo.currentText() == "手动代理"
            assert tab.manual_proxy_edit.text() == "socks5://127.0.0.1:7897"
            assert mock_ref.called
            assert mock_start.called
    finally:
        win.network_tab.shutdown()
        win.close()
