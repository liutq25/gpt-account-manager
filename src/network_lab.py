"""
Network speed tester, proxy tunnel (HTTP CONNECT / SOCKS5), exit IP geo-lookup,
VPN likelihood estimation, and IP purity risk scoring (0-100, higher = lower risk).
Pure Python standard library implementation with zero third-party network dependencies.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GPTManagerSpeedLab/3.1"

PROTOCOLS: List[Tuple[str, str]] = [
    ("tcp", "TCP 连接"),
    ("icmp", "系统 Ping"),
    ("http", "HTTP(S) 响应"),
    ("dns", "DNS 查询"),
]
PROXY_MODES: List[str] = ["直连", "系统代理（自动）", "手动代理"]
DEFAULT_DNS_SERVER = "223.5.5.5"
DEFAULT_MANUAL_PROXY = "127.0.0.1:7897"
DEFAULT_TARGETS: List[str] = [
    "chatgpt.com",
    "api.openai.com",
    "auth.openai.com",
    "claude.ai",
    "google.com",
]

COUNTRY_ZH: Dict[str, str] = {
    "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
    "JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚", "TH": "泰国",
    "VN": "越南", "ID": "印度尼西亚", "PH": "菲律宾", "IN": "印度", "AE": "阿联酋",
    "SA": "沙特阿拉伯", "IL": "以色列", "TR": "土耳其", "KZ": "哈萨克斯坦",
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷",
    "CL": "智利", "AU": "澳大利亚", "NZ": "新西兰", "GB": "英国", "IE": "爱尔兰",
    "FR": "法国", "DE": "德国", "NL": "荷兰", "BE": "比利时", "LU": "卢森堡",
    "CH": "瑞士", "AT": "奥地利", "IT": "意大利", "ES": "西班牙", "PT": "葡萄牙",
    "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "DK": "丹麦", "IS": "冰岛",
    "PL": "波兰", "CZ": "捷克", "RU": "俄罗斯", "UA": "乌克兰", "ZA": "南非",
    "EG": "埃及", "NG": "尼日利亚", "KE": "肯尼亚", "GR": "希腊", "HU": "匈牙利",
    "RO": "罗马尼亚", "BG": "保加利亚", "HR": "克罗地亚", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚",
}

_VPN_KEYWORDS = (
    "vpn", "proxy", "mullvad", "nordvpn", "expressvpn", "surfshark", "proton",
    "tor exit", "torexit", "tunnel", "shadowsocks", "v2ray", "trojan", "wireguard",
    "openvpn", "private internet access", "cyberghost", "windscribe", "hide.me",
    "astrill", "ipvanish", "purevpn", "anonymizer",
)

_DATACENTER_KEYWORDS = (
    "amazon", "aws", "ec2", "google", "gcp", "microsoft", "azure", "digitalocean",
    "linode", "akamai", "vultr", "choopa", "hetzner", "ovh", "oracle", "alibaba",
    "aliyun", "tencent", "qcloud", "cloudflare", "leaseweb", "contabo", "datacamp",
    "cdn77", "hostinger", "ionos", "godaddy", "rackspace", "softlayer", "zenlayer",
    "dmit", "bandwagon", "bwh", "it7", "racknerd", "server", "hosting", "datacenter",
    "data center", "vps", "colocation", "colo", "cloud",
)

_RESIDENTIAL_KEYWORDS = (
    "comcast", "verizon", "at&t", "t-mobile", "charter", "spectrum", "cox",
    "ntt", "softbank", "kddi", "docomo", "kt corp", "sk broadband", "lg uplus",
    "british telecom", "bt ", "vodafone", "orange", "deutsche telekom", "rogers",
    "bell canada", "telstra", "optus", "singtel", "starhub", "chunghwa", "hinet",
    "chinanet", "china telecom", "unicom", "china mobile", "cmcc",
)

# Regions typically restricted or geo-blocked by OpenAI / Claude
_AI_RESTRICTED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "AF"}


def country_zh(code: str, fallback: str = "") -> str:
    if not code:
        return fallback or "未知"
    return COUNTRY_ZH.get(code.upper(), fallback or code.upper())


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def get_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def parse_target(raw: str) -> Dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("地址为空")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    host = parsed.hostname
    if not host:
        raise ValueError(f"无法从“{raw}”中解析主机名")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return {
        "url": candidate,
        "host": host,
        "port": port,
        "scheme": parsed.scheme,
        "path": parsed.path or "/",
    }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("连接意外中断")
        data += chunk
    return data


def detect_system_proxy() -> Optional[str]:
    """Detect Windows registry or environment proxy URL, or None."""
    try:
        import urllib.request
        proxies = urllib.request.getproxies()
        for key in ("https", "http", "all"):
            url = proxies.get(key)
            if url:
                return url if "://" in url else "http://" + url
    except Exception:
        pass

    if sys.platform.startswith("win"):
        server = None
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            with key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if enabled:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
            if server:
                server = str(server).strip()
                m = re.search(r"https?=([^;]+)", server)
                server = m.group(1) if m else server
                if server:
                    return server if "://" in server else "http://" + server
        except OSError:
            pass
    return None


class ProxyClient:
    """HTTP CONNECT and SOCKS5 tunnel client with optional username/password auth."""

    def __init__(self, url: str) -> None:
        raw = (url or "").strip()
        if not raw:
            raise ValueError("代理地址为空")
        full = raw if "://" in raw else "http://" + raw
        p = urlparse(full)
        if not p.hostname:
            raise ValueError(f"代理地址格式错误：{url}")
        self.scheme = (p.scheme or "http").lower()
        self.host = p.hostname
        self.port = p.port or (1080 if "socks" in self.scheme else 7890)
        self.username = unquote(p.username) if p.username else ""
        self.password = unquote(p.password) if p.password else ""
        self.text = f"{self.scheme}://{self.host}:{self.port}"

    def connect(self, target_host: str, target_port: int, timeout: float) -> socket.socket:
        if self.scheme in ("socks5", "socks5h", "socks"):
            return self._socks5(target_host, target_port, timeout)
        return self._http_connect(target_host, target_port, timeout)

    def _http_connect(self, host: str, port: int, timeout: float) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            auth_header = ""
            if self.username or self.password:
                cred = f"{self.username}:{self.password}".encode("utf-8")
                token = base64.b64encode(cred).decode("ascii")
                auth_header = f"Proxy-Authorization: Basic {token}\r\n"
            request = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"{auth_header}"
                f"Proxy-Connection: keep-alive\r\n\r\n"
            )
            sock.sendall(request.encode("ascii"))
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise OSError("代理提前关闭连接")
                buf += chunk
            status_line = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
            m = re.search(r"HTTP/1\.[01]\s+(\d{3})", status_line)
            if not m or m.group(1) != "200":
                raise OSError(f"代理拒绝隧道请求：{status_line}")
            return sock
        except Exception:
            sock.close()
            raise

    def _socks5(self, host: str, port: int, timeout: float) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            if self.username or self.password:
                sock.sendall(b"\x05\x02\x00\x02")
                resp = _recv_exact(sock, 2)
                if resp[0] != 5 or resp[1] not in (0, 2):
                    raise OSError("SOCKS5 握手失败")
                if resp[1] == 2:
                    u_bytes = self.username.encode("utf-8")
                    p_bytes = self.password.encode("utf-8")
                    sock.sendall(
                        b"\x01"
                        + bytes([len(u_bytes)])
                        + u_bytes
                        + bytes([len(p_bytes)])
                        + p_bytes
                    )
                    auth_resp = _recv_exact(sock, 2)
                    if len(auth_resp) < 2 or auth_resp[1] != 0:
                        raise OSError("SOCKS5 用户名/密码认证失败")
            else:
                sock.sendall(b"\x05\x01\x00")
                if _recv_exact(sock, 2) != b"\x05\x00":
                    raise OSError("SOCKS5 握手失败或代理要求认证")

            host_bytes = host.encode("idna")
            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + port.to_bytes(2, "big")
            )
            reply = _recv_exact(sock, 4)
            if reply[0] != 5 or reply[1] != 0:
                raise OSError(f"SOCKS5 连接被拒，错误码 {reply[1]}")
            atyp = reply[3]
            if atyp == 1:
                _recv_exact(sock, 4)
            elif atyp == 3:
                length = _recv_exact(sock, 1)[0]
                _recv_exact(sock, length)
            elif atyp == 4:
                _recv_exact(sock, 16)
            _recv_exact(sock, 2)
            return sock
        except Exception:
            sock.close()
            raise


@dataclass
class IpRiskReport:
    ip: str
    country: str = "未知"
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    reverse: str = ""
    is_proxy: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    vpn_probability: int = 0   # 0-100%, higher = more likely to be VPN/proxy
    risk_score: int = 100      # 0-100, higher = lower risk (cleaner IP)
    risk_level: str = "极低风险（纯净原生）"
    deductions: List[str] = field(default_factory=list)
    source: str = ""

    @property
    def location_text(self) -> str:
        parts = [p for p in (self.country, self.region, self.city) if p and p != self.country]
        if self.country and (not parts or parts[0] != self.country):
            parts.insert(0, self.country)
        return " · ".join(parts) if parts else "未知"

    @property
    def risk_summary(self) -> str:
        if not self.deductions:
            return "未命中代理/机房特征，链路纯净"
        return "；".join(self.deductions)


def evaluate_ip_risk(info: Dict[str, Any]) -> IpRiskReport:
    """
    Compute VPN probability (0-100%) and IP safety score (0-100, higher = lower risk)
    from IP intelligence fields and ASN/ISP/rDNS heuristics.
    """
    ip = str(info.get("ip") or "").strip()
    country = str(info.get("country") or "未知").strip()
    cc = str(info.get("country_code") or "").strip().upper()
    region = str(info.get("region") or "").strip()
    city = str(info.get("city") or "").strip()
    isp = str(info.get("isp") or "").strip()
    org = str(info.get("org") or "").strip()
    asn = str(info.get("asn") or "").strip()
    reverse = str(info.get("reverse") or "").strip()
    is_proxy = bool(info.get("is_proxy", False))
    is_hosting = bool(info.get("is_hosting", False))
    is_mobile = bool(info.get("is_mobile", False))
    source = str(info.get("source") or "").strip()

    if ip and not is_public_ip(ip):
        return IpRiskReport(
            ip=ip,
            country="内网地址",
            country_code="",
            isp="LAN",
            vpn_probability=0,
            risk_score=100,
            risk_level="内网地址",
            deductions=[],
            source=source,
        )

    score = 100
    vpn_prob = 5
    deductions: List[str] = []

    blob = " ".join([isp, org, asn, reverse]).lower()
    has_vpn_kw = any(kw in blob for kw in _VPN_KEYWORDS)
    has_dc_kw = any(kw in blob for kw in _DATACENTER_KEYWORDS)
    has_res_kw = any(kw in blob for kw in _RESIDENTIAL_KEYWORDS)

    if is_proxy:
        score -= 38
        vpn_prob += 55
        deductions.append("IP库标记为已知 VPN/代理出口 (-38)")

    if is_hosting:
        score -= 22
        vpn_prob += 25
        deductions.append("数据中心/云主机网段 (-22)")

    if has_vpn_kw:
        penalty = 12 if is_proxy else 24
        score -= penalty
        vpn_prob += 20 if is_proxy else 40
        deductions.append(f"运营商/rDNS含VPN代理特征 (-{penalty})")

    if has_dc_kw:
        if is_hosting:
            score -= 5
            vpn_prob += 10
            deductions.append("知名云厂商/VPS段确认 (-5)")
        else:
            score -= 18
            vpn_prob += 25
            deductions.append("ASN/组织含机房VPS特征 (-18)")

    if is_hosting and not reverse:
        score -= 5
        vpn_prob += 5
        deductions.append("机房IP缺少rDNS反向解析 (-5)")

    if cc and cc in _AI_RESTRICTED_COUNTRIES:
        score -= 25
        deductions.append(f"归属地({country})受AI平台访问限制 (-25)")

    if is_mobile and not is_proxy and not is_hosting:
        vpn_prob = max(2, vpn_prob - 3)
    elif has_res_kw and not is_proxy and not is_hosting and not has_dc_kw and not has_vpn_kw:
        vpn_prob = max(3, vpn_prob - 2)

    score = max(0, min(100, int(score)))
    vpn_prob = max(0, min(99 if (is_proxy or has_vpn_kw) else 95, int(vpn_prob)))

    if score >= 85:
        level = "极低风险（纯净住宅/原生）"
    elif score >= 65:
        level = "低-中风险（轻度共享/机房）"
    elif score >= 40:
        level = "中-高风险（高概率VPN节点）"
    else:
        level = "极高风险（高危代理/受限区）"

    return IpRiskReport(
        ip=ip,
        country=country,
        country_code=cc,
        region=region,
        city=city,
        isp=isp,
        org=org,
        asn=asn,
        reverse=reverse,
        is_proxy=is_proxy,
        is_hosting=is_hosting,
        is_mobile=is_mobile,
        vpn_probability=vpn_prob,
        risk_score=score,
        risk_level=level,
        deductions=deductions,
        source=source,
    )


def _http_json_raw(
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float = 8.0,
    payload: Any = None,
    proxy: Optional[ProxyClient] = None,
) -> Any:
    """
    Execute HTTP/HTTPS JSON request via http.client + optional ProxyClient tunnel.
    Avoids urllib's system proxy handler (which crashes on socks5h://).
    """
    tunnel: Optional[socket.socket] = None
    conn: Optional[http.client.HTTPConnection] = None
    try:
        if proxy is not None:
            tunnel = proxy.connect(host, port, timeout)
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            if tunnel is not None:
                conn.sock = ctx.wrap_socket(tunnel, server_hostname=host)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            if tunnel is not None:
                conn.sock = tunnel

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
            conn.request("POST", path, body=body, headers=headers)
        else:
            conn.request("GET", path, headers=headers)

        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        if resp.status >= 400:
            raise OSError(f"HTTP {resp.status}")
        return json.loads(raw)
    finally:
        if conn is not None:
            conn.close()
        elif tunnel is not None:
            tunnel.close()


class GeoRiskService:
    """IP geolocation + VPN likelihood + IP purity risk scoring service with caching."""

    def __init__(self) -> None:
        self.cache: Dict[str, IpRiskReport] = {}
        self.lock = threading.Lock()

    def fetch_exit_ip_report(self, proxy: Optional[ProxyClient] = None) -> IpRiskReport:
        """
        Query the current exit public IP (directly or through the given ProxyClient)
        and return its evaluated IpRiskReport.
        """
        # 1. ip-api.com (rich proxy/hosting/mobile/reverse fields)
        try:
            data = _http_json_raw(
                "http",
                "ip-api.com",
                80,
                "/json/?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,isp,org,as,reverse,mobile,proxy,hosting,query",
                timeout=8.0,
                proxy=proxy,
            )
            if isinstance(data, dict) and data.get("status") == "success" and data.get("query"):
                report = evaluate_ip_risk({
                    "ip": data.get("query", ""),
                    "country": data.get("country", "未知"),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "reverse": data.get("reverse", ""),
                    "is_mobile": bool(data.get("mobile", False)),
                    "is_proxy": bool(data.get("proxy", False)),
                    "is_hosting": bool(data.get("hosting", False)),
                    "source": "ip-api",
                })
                with self.lock:
                    self.cache[report.ip] = report
                return report
        except Exception:
            pass

        # 2. ipwho.is (HTTPS fallback)
        try:
            data = _http_json_raw("https", "ipwho.is", 443, "/", timeout=8.0, proxy=proxy)
            if isinstance(data, dict) and data.get("success", True) and data.get("ip"):
                conn_info = data.get("connection") or {}
                cc = str(data.get("country_code") or "")
                report = evaluate_ip_risk({
                    "ip": data.get("ip", ""),
                    "country": country_zh(cc, str(data.get("country") or "")),
                    "country_code": cc,
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                    "isp": conn_info.get("isp", ""),
                    "org": conn_info.get("org", ""),
                    "asn": f"AS{conn_info.get('asn')}" if conn_info.get("asn") else "",
                    "source": "ipwho.is",
                })
                with self.lock:
                    self.cache[report.ip] = report
                return report
        except Exception:
            pass

        # 3. api.ipify.org + ip-api/ipapi.co fallback
        try:
            ip_data = _http_json_raw("https", "api.ipify.org", 443, "/?format=json", timeout=8.0, proxy=proxy)
            ip = str((ip_data or {}).get("ip") or "").strip()
            if ip:
                reports = self.query_ips([ip], proxy=proxy)
                if ip in reports:
                    reports[ip].source = reports[ip].source or "ipify"
                    return reports[ip]
        except Exception as exc:
            raise RuntimeError(f"所有公网 IP 查询源均失败：{exc}") from exc

        raise RuntimeError("所有公网 IP 查询源均失败")

    def query_ips(self, ips: List[str], proxy: Optional[ProxyClient] = None) -> Dict[str, IpRiskReport]:
        result: Dict[str, IpRiskReport] = {}
        pending: List[str] = []
        with self.lock:
            for ip in ips:
                clean = (ip or "").strip()
                if not clean:
                    continue
                if not is_public_ip(clean):
                    result[clean] = evaluate_ip_risk({"ip": clean})
                elif clean in self.cache:
                    result[clean] = self.cache[clean]
                elif clean not in pending:
                    pending.append(clean)

        if not pending:
            return result

        fetched = self._batch_ipapi(pending, proxy=proxy)
        rem = [ip for ip in pending if ip not in fetched]
        if rem:
            fetched.update(self._single_ipwhois(rem, proxy=proxy))
        rem = [ip for ip in pending if ip not in fetched]
        if rem:
            fetched.update(self._single_ipapi(rem, proxy=proxy))

        with self.lock:
            self.cache.update(fetched)
        result.update(fetched)
        return result

    def _batch_ipapi(self, ips: List[str], proxy: Optional[ProxyClient] = None) -> Dict[str, IpRiskReport]:
        out: Dict[str, IpRiskReport] = {}
        try:
            data = _http_json_raw(
                "http",
                "ip-api.com",
                80,
                "/batch?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,isp,org,as,reverse,mobile,proxy,hosting,query",
                timeout=10.0,
                payload=[{"query": ip} for ip in ips[:100]],
                proxy=proxy,
            )
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("status") == "success" and item.get("query"):
                        q = str(item["query"])
                        out[q] = evaluate_ip_risk({
                            "ip": q,
                            "country": item.get("country", "未知"),
                            "country_code": item.get("countryCode", ""),
                            "region": item.get("regionName", ""),
                            "city": item.get("city", ""),
                            "isp": item.get("isp", ""),
                            "org": item.get("org", ""),
                            "asn": item.get("as", ""),
                            "reverse": item.get("reverse", ""),
                            "is_mobile": bool(item.get("mobile", False)),
                            "is_proxy": bool(item.get("proxy", False)),
                            "is_hosting": bool(item.get("hosting", False)),
                            "source": "ip-api",
                        })
        except Exception:
            pass
        return out

    def _single_ipapi(self, ips: List[str], proxy: Optional[ProxyClient] = None) -> Dict[str, IpRiskReport]:
        out: Dict[str, IpRiskReport] = {}
        for ip in ips:
            try:
                item = _http_json_raw(
                    "http",
                    "ip-api.com",
                    80,
                    f"/json/{ip}?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,isp,org,as,reverse,mobile,proxy,hosting,query",
                    timeout=8.0,
                    proxy=proxy,
                )
                if isinstance(item, dict) and item.get("status") == "success":
                    out[ip] = evaluate_ip_risk({
                        "ip": ip,
                        "country": item.get("country", "未知"),
                        "country_code": item.get("countryCode", ""),
                        "region": item.get("regionName", ""),
                        "city": item.get("city", ""),
                        "isp": item.get("isp", ""),
                        "org": item.get("org", ""),
                        "asn": item.get("as", ""),
                        "reverse": item.get("reverse", ""),
                        "is_mobile": bool(item.get("mobile", False)),
                        "is_proxy": bool(item.get("proxy", False)),
                        "is_hosting": bool(item.get("hosting", False)),
                        "source": "ip-api",
                    })
            except Exception:
                continue
        return out

    def _single_ipwhois(self, ips: List[str], proxy: Optional[ProxyClient] = None) -> Dict[str, IpRiskReport]:
        out: Dict[str, IpRiskReport] = {}
        for ip in ips:
            try:
                item = _http_json_raw("https", "ipwho.is", 443, f"/{ip}", timeout=8.0, proxy=proxy)
                if isinstance(item, dict) and item.get("success", True) and item.get("ip"):
                    conn_info = item.get("connection") or {}
                    cc = str(item.get("country_code") or "")
                    out[ip] = evaluate_ip_risk({
                        "ip": ip,
                        "country": country_zh(cc, str(item.get("country") or "")),
                        "country_code": cc,
                        "region": item.get("region", ""),
                        "city": item.get("city", ""),
                        "isp": conn_info.get("isp", ""),
                        "org": conn_info.get("org", ""),
                        "asn": f"AS{conn_info.get('asn')}" if conn_info.get("asn") else "",
                        "source": "ipwho.is",
                    })
            except Exception:
                continue
        return out


class NetworkSpeedEngine:
    """Multi-protocol network latency & availability probe engine."""

    @staticmethod
    def build_dns_packet(hostname: str) -> bytes:
        header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for part in hostname.split("."):
            qname += bytes([len(part)]) + part.encode("ascii")
        return header + qname + b"\x00\x00\x01\x00\x01"

    @staticmethod
    def resolve(host: str, port: int) -> str:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return infos[0][4][0]

    @staticmethod
    def tcp_measure(host: str, port: int, timeout: float, proxy: Optional[ProxyClient]) -> float:
        start = time.perf_counter()
        if proxy is None:
            sock = socket.create_connection((host, port), timeout=timeout)
        else:
            sock = proxy.connect(host, port, timeout)
        ms = (time.perf_counter() - start) * 1000.0
        sock.close()
        return ms

    @staticmethod
    def icmp_ping(host: str, count: int = 4, timeout_ms: int = 2000) -> List[Optional[float]]:
        proc = subprocess.run(
            ["ping", "-n", str(count), "-w", str(int(timeout_ms)), host],
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
            encoding="gbk",
            errors="replace",
            timeout=timeout_ms * count / 1000 + 10,
        )
        samples: List[Optional[float]] = []
        for line in proc.stdout.splitlines():
            low = line.lower()
            hit = re.search(r"(?:时间|time)[=<]\s*([\d.]+)\s*ms", line, re.IGNORECASE)
            if hit:
                samples.append(float(hit.group(1)))
            elif (
                "请求超时" in line
                or "timed out" in low
                or "无法访问" in line
                or "unreachable" in low
                or "could not find" in low
                or "找不到主机" in line
            ):
                samples.append(None)
        return samples

    @staticmethod
    def http_probe(
        scheme: str,
        host: str,
        port: int,
        path: str,
        timeout: float,
        proxy: Optional[ProxyClient],
    ) -> Tuple[float, int]:
        start = time.perf_counter()
        tunnel: Optional[socket.socket] = None
        conn: Optional[http.client.HTTPConnection] = None
        try:
            if proxy is not None:
                tunnel = proxy.connect(host, port, timeout)
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                if tunnel is not None:
                    conn.sock = ctx.wrap_socket(tunnel, server_hostname=host)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                if tunnel is not None:
                    conn.sock = tunnel
            conn.request("HEAD", path or "/", headers={"User-Agent": USER_AGENT})
            resp = conn.getresponse()
            resp.read()
            code = resp.status
            if code in (405, 501):
                conn.close()
                conn = None
                tunnel = None
                return NetworkSpeedEngine.http_get_fallback(scheme, host, port, path, timeout, proxy)
            return (time.perf_counter() - start) * 1000.0, code
        finally:
            if conn is not None:
                conn.close()
            elif tunnel is not None:
                tunnel.close()

    @staticmethod
    def http_get_fallback(
        scheme: str,
        host: str,
        port: int,
        path: str,
        timeout: float,
        proxy: Optional[ProxyClient],
    ) -> Tuple[float, int]:
        start = time.perf_counter()
        tunnel: Optional[socket.socket] = None
        conn: Optional[http.client.HTTPConnection] = None
        try:
            if proxy is not None:
                tunnel = proxy.connect(host, port, timeout)
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                if tunnel is not None:
                    conn.sock = ctx.wrap_socket(tunnel, server_hostname=host)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                if tunnel is not None:
                    conn.sock = tunnel
            conn.request("GET", path or "/", headers={"User-Agent": USER_AGENT})
            resp = conn.getresponse()
            resp.read()
            return (time.perf_counter() - start) * 1000.0, resp.status
        finally:
            if conn is not None:
                conn.close()
            elif tunnel is not None:
                tunnel.close()

    @staticmethod
    def dns_measure(
        server: str,
        hostname: str,
        timeout: float,
        proxy: Optional[ProxyClient],
    ) -> Tuple[float, int, int]:
        packet = NetworkSpeedEngine.build_dns_packet(hostname)
        if proxy is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                start = time.perf_counter()
                sock.sendto(packet, (server, 53))
                reply, _ = sock.recvfrom(1024)
                ms = (time.perf_counter() - start) * 1000.0
            finally:
                sock.close()
        else:
            start = time.perf_counter()
            sock = proxy.connect(server, 53, timeout)
            try:
                sock.sendall(len(packet).to_bytes(2, "big") + packet)
                length = int.from_bytes(_recv_exact(sock, 2), "big")
                reply = _recv_exact(sock, length)
                ms = (time.perf_counter() - start) * 1000.0
            finally:
                sock.close()
        answer_count = int.from_bytes(reply[6:8], "big")
        rcode = reply[3] & 0x0F
        return ms, answer_count, rcode


@dataclass
class NetworkConfig:
    targets: List[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    protocol: str = "tcp"
    proxy_mode: str = "系统代理（自动）"
    manual_proxy: str = DEFAULT_MANUAL_PROXY
    dns_server: str = DEFAULT_DNS_SERVER
    samples: int = 4
    timeout: float = 3.0
    interval: int = 30
    auto_loop: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": list(self.targets),
            "protocol": self.protocol,
            "proxy_mode": self.proxy_mode,
            "manual_proxy": self.manual_proxy,
            "dns_server": self.dns_server,
            "samples": self.samples,
            "timeout": self.timeout,
            "interval": self.interval,
            "auto_loop": self.auto_loop,
        }

    @classmethod
    def load(cls, config_path: Path) -> "NetworkConfig":
        if not config_path.exists():
            return cls()
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return cls()
            targets = [str(t).strip() for t in data.get("targets", DEFAULT_TARGETS) if str(t).strip()]
            return cls(
                targets=targets or list(DEFAULT_TARGETS),
                protocol=str(data.get("protocol", "tcp")),
                proxy_mode=str(data.get("proxy_mode", "系统代理（自动）")),
                manual_proxy=str(data.get("manual_proxy", DEFAULT_MANUAL_PROXY)),
                dns_server=str(data.get("dns_server", DEFAULT_DNS_SERVER)),
                samples=max(1, min(20, int(data.get("samples", 4)))),
                timeout=max(0.5, min(30.0, float(data.get("timeout", 3.0)))),
                interval=max(5, min(600, int(data.get("interval", 30)))),
                auto_loop=bool(data.get("auto_loop", False)),
            )
        except Exception:
            return cls()

    def save(self, config_path: Path) -> None:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
