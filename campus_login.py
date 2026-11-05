#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校园网（锐捷 ePortal）自动登录守护脚本。仅依赖 Python 3 标准库，无需 pip 安装任何东西。

用法：
  python3 campus_login.py              常驻运行，每 check_interval 秒检测一次，掉线即登录
  python3 campus_login.py --once       检测一次，掉线则登录，然后退出
  python3 campus_login.py --check      只报告当前状态，不做登录（0=在线 1=掉线 2=未知）
  python3 campus_login.py --dry-run    掉线时打印将要提交的字段（密码打码），不登录
  python3 campus_login.py --dump       把门户页和它引用的 JS 存到 portal_dump/ 便于排查
  python3 campus_login.py -c 配置文件   指定配置文件（默认同目录 config.json）

开机自启：见同目录的 campus-login.service（systemd），装好后自动常驻并断线重登。

密码加密模式（config.json 里的 password_mode）：
  auto    默认。能自动找到门户页里的 RSA 公钥就用 RSA 加密，找不到就退回明文
  rsa     强制用门户页里的 RSA 公钥加密密码（passwordEncrypt=true）
  static  直接使用抓包得到的密文 password_static（passwordEncrypt=true）
  plain   明文提交（passwordEncrypt=false）

判定逻辑：请求一个探测地址，由校园网关"表态"。
  - 探测点正常返回 204        -> 判定在线，什么都不做
  - 被 302 重定向到 index.jsp -> 判定掉线，从重定向地址里取本次的 queryString 再登录
  - 探测点连不上但门户可达    -> 按掉线处理
  - 探测点和门户都连不上      -> 真实断网/不在校园网，本轮跳过，不乱发登录请求
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.cookiejar
import json
import logging
import logging.handlers
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG = logging.getLogger("campus")

ONLINE, OFFLINE, UNKNOWN = "online", "offline", "unknown"

DEFAULTS = {
    # ---- 必填 ----
    "portal_ip": "210.38.161.189",   # 认证网关地址，不带 http://
    "user_id": "",                   # 学号 / 账号
    "password": "",                  # 明文密码（password_mode 为 static 时可不填）

    # ---- 联网检测 ----
    # 任意可以正常访问的 http 地址即可；掉线时会被网关重定向到认证页。
    "probe_url": "http://connect.rom.miui.com/generate_204",

    # ---- 登录参数 ----
    "service": "default",            # 门户上选的接入方式，如「实验室」「校园网」「中国移动」
    "password_mode": "auto",         # auto / rsa / static / plain
    "password_reverse": True,        # 门户"新实现"是 RSAUtils.encryptedString(key, password.reverse())
    "password_append_mac": True,     # 门户加密的明文是「密码 + '>' + mac」
    "rsa_padding": "raw",            # 门户用 RSAUtils.encryptedString（无填充）；老式门户才用 pkcs1
    "mac": "",                       # 留空则自动从 queryString 里取
    "password_static": "",           # 抓包得到的密码密文（password_mode=static 时用）
    "login_token": "",               # 留空则自动从门户页里取
    "rsa_public_key": "",            # 留空则自动从门户页/JS 里找；也可直接贴 PEM 或 base64
    "extra_fields": {},              # 额外表单字段，原样并入登录请求

    # ---- 运行时段 ----
    # 只在这段时间内检测和登录；留空表示全天。过了结束时间这里会彻底静默，
    # 适合"晚上断网"的宿舍网络，避免整夜刷失败日志、也避免把账号刷到风控。
    "active_start": "",              # 如 "07:00"
    "active_end": "",                # 如 "22:30"

    # ---- 运行参数 ----
    "check_interval": 30,            # 轮询间隔（秒），最小 10
    "max_backoff": 600,              # 连续登录失败后的最大退避（秒）
    "timeout": 8,                    # 单次请求超时（秒）
    "verify_after_login": True,      # 登录后复检一次，确认真的通了
    "lock_port": 47823,              # 单实例锁占用的本地端口，只在本机回环上
    "log_file": "campus_login.log",
    "log_max_bytes": 1048576,
    "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
}


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------- 基础工具

def out(msg):
    """pythonw 无控制台时 sys.stdout 为 None，安全输出。"""
    if sys.stdout is not None:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()


def _safe_console():
    """个别 Windows 控制台编码装不下中文，避免直接崩在打印上。"""
    for stream in (sys.stdout, sys.stderr):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            "在线".encode(getattr(stream, "encoding", None) or "utf-8")
        except (UnicodeEncodeError, LookupError):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass


def resolve_path(p):
    return p if os.path.isabs(p) else os.path.join(BASE_DIR, p)


def load_config(path):
    if not os.path.exists(path):
        raise SystemExit(f"找不到配置文件：{path}\n请把 config.json 放在脚本同目录，或加 -c 指定路径。")
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            user_cfg = json.load(f)
    except UnicodeDecodeError:
        raise SystemExit(f"配置文件编码不是 UTF-8（{path}）。用记事本打开，另存为时把编码选成 UTF-8。")
    except json.JSONDecodeError as e:
        raise SystemExit(f"配置文件不是合法 JSON：{e}")

    cfg = dict(DEFAULTS)
    cfg.update({k: v for k, v in user_cfg.items() if not k.startswith("_")})

    missing = [k for k in ("user_id", "password") if not str(cfg.get(k) or "").strip()]
    if str(cfg.get("password_mode")) == "static" and cfg.get("password_static"):
        missing = [k for k in missing if k != "password"]
    if missing:
        raise SystemExit("配置文件里还没填：" + "、".join(missing) + "（打开 config.json 填写后再运行）")
    if any(str(cfg.get(k) or "").startswith(("请填写", "CHANGE_ME")) for k in ("user_id", "password")):
        raise SystemExit("配置文件里的账号或密码还是占位内容，请改成真实值。")

    cfg["check_interval"] = max(10, int(cfg["check_interval"]))
    cfg["timeout"] = max(2, float(cfg["timeout"]))
    cfg["password_mode"] = str(cfg.get("password_mode") or "auto").lower()
    if cfg["password_mode"] not in ("auto", "rsa", "static", "plain"):
        raise SystemExit("password_mode 只能是 auto / rsa / static / plain")
    return cfg


def setup_logging(cfg, verbose):
    LOG.setLevel(logging.DEBUG)
    LOG.handlers.clear()
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.handlers.RotatingFileHandler(
        resolve_path(cfg["log_file"]), maxBytes=int(cfg["log_max_bytes"]),
        backupCount=2, encoding="utf-8", delay=True)
    fh.setLevel(level)
    fh.setFormatter(fmt)
    LOG.addHandler(fh)

    if sys.stderr is not None:          # pythonw 下没有控制台
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(level)
        sh.setFormatter(fmt)
        LOG.addHandler(sh)


def acquire_single_instance(port):
    """占用一个回环端口当锁；已有实例在跑时返回 None。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", int(port)))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def parse_hhmm(value):
    """"07:00" -> 420（分钟）。格式不对返回 None。"""
    try:
        h, m = str(value).split(":")
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h * 60 + m
        return None
    except (ValueError, AttributeError):
        return None


def in_active_window(cfg, now=None):
    """当前是否在允许认证的时段内。未配置时段则永远为 True。"""
    start, end = parse_hhmm(cfg.get("active_start")), parse_hhmm(cfg.get("active_end"))
    if start is None or end is None or start == end:
        return True
    t = now or time.localtime()
    cur = t.tm_hour * 60 + t.tm_min
    if start < end:                  # 普通时段，如 07:00-22:30
        return start <= cur < end
    return cur >= start or cur < end  # 跨午夜，如 22:00-06:00


def window_text(cfg):
    if parse_hhmm(cfg.get("active_start")) is None or parse_hhmm(cfg.get("active_end")) is None:
        return "全天"
    return f"{cfg['active_start']}-{cfg['active_end']}"


# --------------------------------------------------------------------------- RSA（纯标准库）

def _der_read(data, pos, expect=None):
    if pos + 2 > len(data):
        raise ValueError("DER 数据不完整")
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if expect is not None and tag != expect:
        raise ValueError(f"DER tag {tag:#04x} 与期望 {expect:#04x} 不符")
    end = pos + ln
    if end > len(data):
        raise ValueError("DER 长度越界")
    return tag, data[pos:end], end


def parse_rsa_public_key(der):
    """解析 SubjectPublicKeyInfo（或裸 PKCS#1 RSAPublicKey），返回 (n, e)。"""
    _, outer, _ = _der_read(der, 0, 0x30)
    pos = 0
    tag, first, pos = _der_read(outer, pos)
    if tag == 0x30:                                  # SPKI：SEQUENCE{算法, BIT STRING}
        _, bits, _ = _der_read(outer, pos, 0x03)
        if not bits or bits[0] != 0:
            raise ValueError("BIT STRING 前导字节异常")
        _, rsa, _ = _der_read(bits[1:], 0, 0x30)
    else:                                            # 裸 PKCS#1：两个 INTEGER 直接跟在外层里
        rsa = outer
        pos = 0
    p = 0
    _, n_b, p = _der_read(rsa, p, 0x02)
    _, e_b, p = _der_read(rsa, p, 0x02)
    n = int.from_bytes(n_b, "big")
    e = int.from_bytes(e_b, "big")
    if n <= 0 or e <= 0:
        raise ValueError("RSA 公钥数值异常")
    return n, e


def pem_to_der(text):
    body = "".join(l.strip() for l in text.strip().splitlines() if "-----" not in l)
    return base64.b64decode(body)


def rsautils_encrypt(plaintext, n, e):
    """复刻门户 security.js 里的 RSAUtils.encryptedString。

    它不做 PKCS#1 填充：把明文字符按每字符一字节取出，补零到 chunkSize 的整数倍，
    每块当作**小端**整数做 RSA，输出十六进制、每 4 位补齐。所以结果是确定性的。
    （chunkSize = 2*biHighIndex(n)，即 2*((n.bit_length()-1)//16)）
    """
    if not n or not e:
        raise ValueError("RSA 公钥不完整（模数或指数为空）")
    chunk = 2 * ((n.bit_length() - 1) // 16)
    if chunk <= 0:
        raise ValueError("RSA 模数长度异常")
    data = bytes(ord(ch) & 0xFF for ch in plaintext)
    data += b"\x00" * ((-len(data)) % chunk)
    parts = []
    for i in range(0, len(data), chunk):
        m = int.from_bytes(data[i:i + chunk], "little")
        c = pow(m, e, n)
        h = format(c, "x")
        parts.append(h.zfill((len(h) + 3) // 4 * 4))
    return " ".join(parts)


def rsa_encrypt_pkcs1v15(plaintext: bytes, n: int, e: int) -> str:
    """RSA PKCS#1 v1.5 加密，返回十六进制串（长度 = 2 * 模长字节数）。"""
    if not n or not e:
        raise ValueError("RSA 公钥不完整（模数或指数为空）")
    k = (n.bit_length() + 7) // 8
    if len(plaintext) > k - 11:
        raise ValueError(f"明文太长（{len(plaintext)} 字节），RSA-{k * 8} 最多 {k - 11} 字节")
    ps_len = k - 3 - len(plaintext)
    ps = bytearray()
    while len(ps) < ps_len:
        for b in os.urandom(ps_len - len(ps) + 8):
            if b and len(ps) < ps_len:
                ps.append(b)
            if len(ps) >= ps_len:
                break
    em = b"\x00\x02" + bytes(ps) + b"\x00" + plaintext
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big").hex()


_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA )?PUBLIC KEY-----[\s\S]{20,}?-----END (?:RSA )?PUBLIC KEY-----")
_B64KEY_RE = re.compile(r"""["'](MII[A-Za-z0-9+/=]{120,})["']""")
_TOKEN_RE = re.compile(r"""loginToken["']?\s*[:=]\s*["']?([0-9a-fA-F]{16,64})""")
# 门户 JS 里写死的公钥：new RSAKeyPair("10001", "", "<模数>")
_RSAKEYPAIR_RE = re.compile(
    r"""new\s+RSAKeyPair\(\s*["']([0-9a-fA-F]+)["']\s*,\s*["'][0-9a-fA-F]*["']\s*,\s*["']([0-9a-fA-F]{32,})["']""",
    re.I)
# pageInfo 接口下发的字段（值可能是十六进制、十进制或 base64，先宽泛地抓出来再解析）
_MODULUS_RE = re.compile(r"""publicKeyModulus["']?\s*[:=]\s*["']?([A-Za-z0-9+/=]{16,})""", re.I)
_EXPONENT_RE = re.compile(r"""publicKeyExponent["']?\s*[:=]\s*["']?([A-Za-z0-9+/=]{1,16})""", re.I)
_ENC_FLAG_RE = re.compile(r"""passwordEncrypt["']?\s*[:=]\s*["']?(true|false)""", re.I)


def encode_query_string(qs):
    """页面里是 encodeURIComponent(getQueryString())，所以要整体 URL 编码一次。

    如果拿到的已经是编码过的（含 %3D 且没有裸的 =），就不再重复编码。
    """
    if not qs:
        return qs
    if "%3d" in qs.lower() and "wlanuserip=" not in qs:
        return qs
    return urllib.parse.quote(qs, safe="")


def _parse_key_int(val, is_exponent=False):
    """pageInfo 下发的公钥字段可能是十六进制、十进制，也可能是 base64。

    指数尤其容易猜错：'10001' 是十六进制的 65537，'65537' 才是十进制。
    所以不按长相猜，而是把两种读法都算出来，优先取 RSA 里常见的指数值。
    模数：常见的长十六进制串，也可能是十进制或 base64。
    """
    s = (val or "").strip().strip('"')
    if not s:
        raise ValueError("字段为空")
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", s))

    if is_exponent:
        candidates = []
        if is_hex:
            candidates.append(int(s, 16))
        if s.isdigit():
            candidates.append(int(s, 10))
        for v in candidates:                      # 3 / 17 / 65537 是绝对主流
            if v in (3, 17, 65537):
                return v
        for v in candidates:                      # 退而求其次：合理的奇数
            if 1 < v < 2 ** 32 and v % 2 == 1:
                return v
        if candidates:
            return candidates[0]
        return int.from_bytes(base64.b64decode(s + "=" * (-len(s) % 4)), "big")

    if is_hex and len(s) % 2 == 0 and len(s) >= 32:
        return int(s, 16)
    if s.isdigit() and len(s) > 32:
        return int(s, 10)
    return int.from_bytes(base64.b64decode(s + "=" * (-len(s) % 4)), "big")


def fetch_page_info(client, cfg, qs_encoded):
    """调门户的 pageInfo 接口，拿 RSA 公钥（模数/指数）、是否加密、loginToken。

    返回 dict：{"n": int|None, "e": int|None, "password_encrypt": bool|None, "token": str}
    """
    info = {"n": None, "e": None, "password_encrypt": None, "token": ""}
    url = f"{base_url(cfg)}/eportal/InterFace.do?method=pageInfo"
    try:
        r = client.post_form(url, {"queryString": qs_encoded}, timeout=min(6, client.timeout))
    except NetworkError as e:
        LOG.debug("pageInfo 接口不可用：%s", e)
        return info

    # 响应里的 pageInfo 常常是一段转义的 JSON 字符串，先把 \" 还原再提字段
    text = r.text.replace('\\"', '"').replace("\\/", "/")
    m_mod = _MODULUS_RE.search(text)
    m_exp = _EXPONENT_RE.search(text)
    if m_mod and m_exp:
        try:
            n = _parse_key_int(m_mod.group(1))
            e = _parse_key_int(m_exp.group(1), is_exponent=True)
            if n > 1 and e > 1:
                info["n"], info["e"] = n, e
                LOG.debug("pageInfo 里带了 RSA 公钥（%d 位，指数 %d / 0x%x）",
                          n.bit_length(), e, e)
        except Exception as ex:
            LOG.warning("pageInfo 公钥字段解析失败（模数=%r，指数=%r）：%s",
                        m_mod.group(1)[:24], m_exp.group(1)[:16], ex)
    m_enc = _ENC_FLAG_RE.search(text)
    if m_enc:
        info["password_encrypt"] = m_enc.group(1).lower() == "true"
    m_tok = _TOKEN_RE.search(text)
    if m_tok:
        info["token"] = m_tok.group(1)
    if not m_mod:
        LOG.debug("pageInfo 响应里没有 publicKeyModulus（前 200 字：%s）", text[:200])
    return info


def find_public_key(texts):
    """在页面/JS 文本里找 RSA 公钥，返回 (n, e) 或 None。"""
    for text in texts:
        for m in _PEM_RE.finditer(text or ""):
            try:
                return parse_rsa_public_key(pem_to_der(m.group(0)))
            except Exception as e:
                LOG.debug("PEM 公钥解析失败：%s", e)
        for m in _B64KEY_RE.finditer(text or ""):
            try:
                return parse_rsa_public_key(base64.b64decode(m.group(1)))
            except Exception as e:
                LOG.debug("base64 公钥解析失败：%s", e)
    return None


def find_js_key(texts):
    """在门户 JS 里找写死的 RSAKeyPair（门户实际加密用的就是这把）。返回 (n, e) 或 None。"""
    for text in texts:
        for m in _RSAKEYPAIR_RE.finditer(text or ""):
            try:
                e = int(m.group(1), 16)
                n = int(m.group(2), 16)
                if n > 1 and e > 1:
                    return n, e
            except ValueError:
                continue
    return None


def find_login_token(texts):
    for text in texts:
        m = _TOKEN_RE.search(text or "")
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------- HTTP

class NetworkError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随跳转，把 3xx 当普通响应交回来，便于从 Location 里取参数。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class Response:
    __slots__ = ("status", "headers", "body", "url")

    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def header(self, name):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ""


class HttpClient:
    def __init__(self, cfg):
        self.timeout = float(cfg["timeout"])
        self.ua = cfg["user_agent"]
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect())

    def request(self, url, data=None, headers=None, timeout=None):
        h = {"User-Agent": self.ua, "Accept": "*/*"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=data, headers=h)
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as r:
                return Response(r.status, dict(r.headers.items()), r.read(), r.geturl())
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read() or b""
            except Exception:
                pass
            return Response(e.code, dict(e.headers.items()), body, getattr(e, "url", url) or url)
        except (urllib.error.URLError, OSError) as e:
            raise NetworkError(f"{type(e).__name__}: {getattr(e, 'reason', e)}") from e

    def get(self, url, **kw):
        return self.request(url, **kw)

    def post_form(self, url, fields, **kw):
        data = urllib.parse.urlencode(fields).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        headers.update(kw.pop("headers", {}))
        return self.request(url, data=data, headers=headers, **kw)


# --------------------------------------------------------------------------- 门户交互

def base_url(cfg):
    return f"http://{cfg['portal_ip']}"


def login_url(cfg):
    return f"{base_url(cfg)}/eportal/InterFace.do?method=login"


def index_url(cfg):
    return f"{base_url(cfg)}/eportal/index.jsp"


def _looks_like_portal(text, ip):
    """判断一段文本/地址是否属于认证门户。"""
    low = (text or "").lower()
    return ip in (text or "") or "eportal" in low or "index.jsp" in low or "wlanuserip" in low


def probe(client, cfg):
    """返回 (status, portal_url, detail)。"""
    ip = cfg["portal_ip"]
    try:
        r = client.get(cfg["probe_url"])
    except NetworkError as e:
        return UNKNOWN, None, f"探测点不可达（{e}）"

    if 300 <= r.status < 400:
        loc = r.header("Location")
        if not loc:
            return UNKNOWN, None, f"HTTP {r.status} 但没有 Location"
        full = urllib.parse.urljoin(cfg["probe_url"], loc)
        if _looks_like_portal(full, ip):
            return OFFLINE, full, f"网关重定向到认证页（HTTP {r.status}）"
        return ONLINE, None, f"重定向到 {full}（不是认证页，判定在线）"

    if r.status == 204:
        return ONLINE, None, "探测点返回 204"
    if r.status == 200:
        text = r.text
        target = find_redirect_url(text)
        if target and _looks_like_portal(target, ip):
            return OFFLINE, target, "HTTP 200 + JS 跳转到认证页"
        if "wlanuserip" in text or _looks_like_portal(text, ip):
            return OFFLINE, None, "HTTP 200 但内容是门户页"
        return ONLINE, None, "探测点返回 200"
    return UNKNOWN, None, f"探测点返回 HTTP {r.status}"


def portal_alive(client, cfg):
    """探测点挂了的时候，用来判断到底是真断网还是只是没认证。"""
    try:
        return True, client.get(index_url(cfg), timeout=min(4, client.timeout))
    except NetworkError:
        return False, None


_INDEX_RE = re.compile(r"index\.jsp\?([^\"'\s<>]+)")
_WLANUSERIP_RE = re.compile(r"wlanuserip=[^\"'\s<>]+")
# 网关常用「HTTP 200 + JS 跳转」代替 302，参数藏在脚本里
_JS_REDIRECT_RE = re.compile(
    r"""(?:top\.self\.|top\.|self\.|window\.|document\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""",
    re.I)


def find_redirect_url(text):
    """从一段脚本里抠出跳转地址，如 top.self.location.href='http://.../index.jsp?...'。"""
    m = _JS_REDIRECT_RE.search(text or "")
    return m.group(1) if m else None


def extract_query_string(text):
    m = _INDEX_RE.search(text)
    if m:
        return m.group(1)
    m = _WLANUSERIP_RE.search(text)
    if m:
        return m.group(0)
    # 参数可能是 URL 编码过的（wlanuserip%3D...）
    decoded = urllib.parse.unquote(text or "")
    m = _WLANUSERIP_RE.search(decoded)
    return m.group(0) if m else None


def _qs_from_page(text):
    """从页面内容里取 queryString：先看 JS 跳转地址，再看直接出现的参数串。"""
    target = find_redirect_url(text or "")
    if target:
        qs = urllib.parse.urlparse(target).query
        if qs:
            return qs
    return extract_query_string(text or "")


def get_query_string(client, cfg, portal_url=None, page=None):
    """取本次会话的 queryString：优先用网关重定向地址里的，其次从页面里抓。"""
    if portal_url:
        qs = urllib.parse.urlparse(portal_url).query
        if qs:
            LOG.debug("从重定向地址取到 queryString（%d 字符）", len(qs))
            return qs

    if page is not None:
        qs = _qs_from_page(page.text)
        if qs:
            return qs

    try:
        r = client.get(index_url(cfg))
    except NetworkError as e:
        LOG.debug("访问门户首页失败：%s", e)
        return None
    qs = urllib.parse.urlparse(r.url).query
    if qs:
        return qs
    return _qs_from_page(r.text) or None


def collect_sources(client, cfg, page, page_hint=None):
    """返回门户页正文 + 它引用的所有脚本正文，用来找公钥和 loginToken。

    page 为 None 时会主动抓一次页面：优先抓 page_hint（网关给的那个带参数的
    index.jsp 地址），因为公钥和 loginToken 都在那个会话的页面上。
    """
    if page is None:
        url = page_hint or index_url(cfg)
        try:
            page = client.get(url, timeout=min(6, client.timeout))
            LOG.debug("抓取页面用于查找公钥：%s", url)
        except NetworkError as e:
            LOG.debug("页面取不到（%s）：%s", url, e)

    texts = [page.text if page is not None else ""]
    page_url = page.url if page is not None and page.url else index_url(cfg)
    srcs = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", texts[0] or "", re.I)
    for src in srcs[:25]:
        full = urllib.parse.urljoin(page_url, src)
        try:
            texts.append(client.get(full, timeout=min(6, client.timeout)).text)
        except NetworkError as e:
            LOG.debug("脚本 %s 取不到：%s", full, e)
    LOG.debug("收集到 %d 段页面/脚本文本（%d 个 script 标签）", len(texts), len(srcs))
    return texts, srcs


def discover_key_and_token(client, cfg, page, portal_url=None, qs=None):
    """拿 RSA 公钥和 loginToken。一次登录只调一次 pageInfo，公钥和 token 必须同源。

    门户的公钥是按会话下发的：调一次 pageInfo 就建一个会话并配一把钥匙。
    如果拿 A 会话的钥匙去登 B 会话，服务端解出来的就是乱码，只会回"密码错误"。
    """
    info = {"n": None, "e": None, "token": cfg.get("login_token") or "", "password_encrypt": None}

    # 1) 配置文件里手工指定的公钥最优先（排查时用）
    if cfg.get("rsa_public_key"):
        raw = cfg["rsa_public_key"].strip()
        try:
            der = pem_to_der(raw) if "-----" in raw else base64.b64decode(raw)
            info["n"], info["e"] = parse_rsa_public_key(der)
            LOG.info("使用配置文件里指定的 RSA 公钥（%d 位）", info["n"].bit_length())
        except Exception as ex:
            raise ConfigError(f"rsa_public_key 解析失败：{ex}")

    # 2) 调一次 pageInfo：公钥、passwordEncrypt、loginToken 都取这一次的
    if qs:
        pi = fetch_page_info(client, cfg, qs)
        if info["n"] is None and pi["n"] is not None:
            info["n"], info["e"] = pi["n"], pi["e"]
            LOG.info("使用 pageInfo 下发的 RSA 公钥（%d 位，指数 %d / 0x%x）",
                     pi["n"].bit_length(), pi["e"], pi["e"])
        if not info["token"] and pi["token"]:
            info["token"] = pi["token"]
        if info["password_encrypt"] is None:
            info["password_encrypt"] = pi["password_encrypt"]

    # 3) 兜底：pageInfo 没给公钥时，找 JS 里写死的那把
    if info["n"] is None:
        texts, _ = collect_sources(client, cfg, page, portal_url)
        found = find_js_key(texts) or find_public_key(texts)
        if found:
            info["n"], info["e"] = found
            LOG.info("改用页面里找到的 RSA 公钥（%d 位，指数 %d / 0x%x）",
                     found[0].bit_length(), found[1], found[1])
        if not info["token"]:
            info["token"] = find_login_token(texts) or ""

    if info["n"] is not None and info["e"] is None:
        LOG.warning("公钥只有模数没有指数，按没有公钥处理")
        info["n"] = info["e"] = None

    return info


def query_param(qs, name):
    """从 queryString 里取一个参数（兼容它可能被 URL 编码过一次或两次）。"""
    pat = re.compile(r"(?:^|&)" + re.escape(name) + r"=([^&]*)")
    for _ in range(3):
        m = pat.search(qs or "")
        if m:
            return urllib.parse.unquote(m.group(1))
        qs = urllib.parse.unquote(qs or "")
    return ""


def build_password_plaintext(cfg, qs_raw):
    """门户是把 `密码 + ">" + mac` 拿去加密的（见 doauthen 里的 passwordMac）。"""
    plain = cfg["password"]
    if not cfg.get("password_append_mac", True):
        return plain
    mac = query_param(qs_raw, "mac") or cfg.get("mac") or "111111111"
    return f"{plain}>{mac}"


def resolve_credentials(client, cfg, page, portal_url=None, qs=None, qs_raw=None):
    """按 password_mode 决定本次提交的 password / passwordEncrypt / loginToken。"""
    mode = cfg["password_mode"]

    if mode == "static":
        if not cfg.get("password_static"):
            raise ConfigError("password_mode=static 但 password_static 是空的")
        token = cfg.get("login_token") or ""
        if not token and qs:
            token = fetch_page_info(client, cfg, qs).get("token") or ""
        if not token:
            texts, _ = collect_sources(client, cfg, page, portal_url)
            token = find_login_token(texts) or ""
        LOG.debug("static 模式取到 loginToken：%s", token or "(没有)")
        return {"password": cfg["password_static"], "passwordEncrypt": "true", "loginToken": token}

    if mode == "plain":
        return {"password": cfg["password"], "passwordEncrypt": "false", "loginToken": ""}

    info = discover_key_and_token(client, cfg, page, portal_url, qs)
    token = info["token"]
    if info["n"] is None:
        if mode == "rsa":
            raise ConfigError(
                "没拿到 RSA 公钥（pageInfo 接口和页面脚本里都没有）。请把浏览器抓到的 "
                "publicKeyModulus / publicKeyExponent 填到 config.json 的 rsa_public_key，"
                "或运行 --dump 查看响应。")
        if cfg.get("password_static"):
            LOG.warning("没拿到 RSA 公钥，改用抓包密文（password_static）")
            return {"password": cfg["password_static"], "passwordEncrypt": "true", "loginToken": token}
        LOG.warning("没拿到 RSA 公钥，先按明文提交试试（若失败见 --dump 说明）")
        return {"password": cfg["password"], "passwordEncrypt": "false", "loginToken": token}

    if info["password_encrypt"] is False:
        LOG.info("门户声明不需要加密密码（passwordEncrypt=false），按明文提交")
        return {"password": cfg["password"], "passwordEncrypt": "false", "loginToken": token}

    plain = build_password_plaintext(cfg, qs_raw or "")
    LOG.debug("待加密明文共 %d 个字符（密码 + '>' + mac）", len(plain))
    if cfg.get("password_reverse", True):
        # 门户的 encryptedPassword 里是 encryptedString(key, xxx.split("").reverse().join(""))
        plain = plain[::-1]
        LOG.debug("按门户 JS 的做法，先把明文反转再加密")

    try:
        if cfg.get("rsa_padding", "raw") == "pkcs1":
            cipher = rsa_encrypt_pkcs1v15(plain.encode("utf-8"), info["n"], info["e"])
        else:
            cipher = rsautils_encrypt(plain, info["n"], info["e"])
    except ValueError as ex:
        raise ConfigError(f"密码加密失败：{ex}")
    LOG.debug("密码已用 RSA 加密（%d 字符）", len(cipher))
    return {"password": cipher, "passwordEncrypt": "true", "loginToken": token}


def build_login_fields(cfg, query_string, creds):
    fields = {
        "userId": cfg["user_id"],
        "password": creds["password"],
        "service": cfg["service"],
        "queryString": query_string,
        "operatorPwd": "",
        "operatorUserId": "",
        "validcode": "",
        "passwordEncrypt": creds["passwordEncrypt"],
    }
    if creds.get("loginToken"):
        fields["loginToken"] = creds["loginToken"]
    extra = cfg.get("extra_fields") or {}
    if isinstance(extra, dict):
        fields.update({str(k): str(v) for k, v in extra.items()})
    return fields


def masked(fields):
    shown = dict(fields)
    if shown.get("password"):
        p = str(shown["password"])
        shown["password"] = (p[:8] + "…" + p[-4:]) if len(p) > 16 else "*" * len(p)
    if shown.get("queryString"):
        q = str(shown["queryString"])
        shown["queryString"] = q if len(q) <= 120 else q[:117] + "…"
    return ", ".join(f"{k}={v!r}" for k, v in shown.items())


def do_login(client, cfg, query_string, creds):
    """返回 (成功与否, 说明)。"""
    fields = build_login_fields(cfg, query_string, creds)
    headers = {"Referer": index_url(cfg)}
    try:
        r = client.post_form(login_url(cfg), fields, headers=headers)
    except NetworkError as e:
        return False, f"登录请求发不出去（{e}）"

    body = r.text.strip()
    try:
        payload = json.loads(body)
    except ValueError:
        return False, f"登录接口返回的不是 JSON（HTTP {r.status}）：{body[:200]}"

    result = str(payload.get("result", "")).lower()
    message = payload.get("message") or payload.get("msg") or ""
    if result == "success":
        return True, f"接口返回成功：{message}"
    return False, f"接口返回 result={result or '?'} message={message or '(空)'}"


# --------------------------------------------------------------------------- 主流程

def cycle(client, cfg, mode, force=False):
    """执行一轮检测与（按需）登录。mode: check / dry / login。

    force=True 时即使探测显示在线也照样登录一次（用来验证登录参数）。
    返回 (本轮结束时的联网状态, 说明, 本轮是否成功登录过)。
    """
    status, portal_url, detail = probe(client, cfg)
    LOG.debug("探测：%s（%s）", status, detail)

    if mode == "check":
        return status, detail, False
    if status == ONLINE and not force:
        return status, detail, False
    if status == ONLINE and force:
        LOG.info("无视在线状态，强制尝试登录一次（%s）", detail)
        portal_url, page = None, None
        status = OFFLINE

    page = None
    if status == UNKNOWN:
        reachable, page = portal_alive(client, cfg)
        if not reachable:
            LOG.warning("%s；门户也不可达，判定为真实断网或不在校园网，本轮跳过", detail)
            return UNKNOWN, detail, False
        LOG.info("%s；但门户可达，按掉线处理", detail)
        portal_url = page.url

    ok, msg = False, ""
    for attempt in (1, 2):
        qs_raw = get_query_string(client, cfg, portal_url, page)
        if not qs_raw:
            LOG.error("拿不到门户要求的 queryString，无法登录（可先用 --check 观察网关应答）")
            return UNKNOWN, "取不到 queryString", False
        qs = encode_query_string(qs_raw)
        LOG.debug("queryString 长度 %d（编码后 %d）", len(qs_raw), len(qs))

        creds = resolve_credentials(client, cfg, page, portal_url, qs, qs_raw)
        LOG.debug("提交方式：passwordEncrypt=%s，loginToken=%s",
                  creds["passwordEncrypt"], "有" if creds.get("loginToken") else "无")

        if mode == "dry":
            LOG.info("【dry-run】将 POST %s", login_url(cfg))
            LOG.info("【dry-run】字段：%s", masked(build_login_fields(cfg, qs, creds)))
            return OFFLINE, "dry-run：参数已取到，未提交", False

        ok, msg = do_login(client, cfg, qs, creds)
        if ok:
            break

        # 会话过期说明参数已经不是这一轮的了，重新探测拿一份新的再试一次
        if attempt == 1 and "expired" in msg.lower():
            LOG.info("门户提示会话过期，重新探测取新参数后再试一次")
            time.sleep(1)
            st2, portal_url2, _ = probe(client, cfg)
            if st2 == ONLINE:
                return ONLINE, "重试前检测已在线", False
            portal_url, page = portal_url2, None
            continue

        LOG.warning("登录失败：%s", msg)
        return OFFLINE, msg, False

    LOG.info("登录成功：%s", msg)
    if cfg["verify_after_login"]:
        time.sleep(2)
        st2, _, detail2 = probe(client, cfg)
        if st2 != ONLINE:
            LOG.warning("接口说成功了，但复检仍为 %s（%s）", st2, detail2)
            return OFFLINE, msg + "，但复检未通过", True
        LOG.info("复检通过，已恢复联网（%s）", detail2)
    return ONLINE, msg, True


def dump_portal(client, cfg):
    """把门户页和引用的脚本存盘，便于排查公钥/参数问题。"""
    folder = resolve_path("portal_dump")
    os.makedirs(folder, exist_ok=True)

    try:
        page = client.get(index_url(cfg))
    except NetworkError as e:
        out(f"打不开门户页 {index_url(cfg)}：{e}")
        return 1

    def save(name, text):
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return path

    saved = [save("index.html", page.text)]
    texts, srcs = collect_sources(client, cfg, page)
    for i, text in enumerate(texts[1:], 1):
        saved.append(save(f"script_{i}.js", text))

    key = find_public_key(texts)
    token = find_login_token(texts)
    summary = [
        f"门户页：{page.url}（HTTP {page.status}）",
        f"script 标签：{len(srcs)} 个，已下载 {len(texts) - 1} 个",
        f"queryString：{'找到' if extract_query_string(page.text) else '页面里没找到'}",
        f"RSA 公钥：{'找到（%d 位）' % key[0].bit_length() if key else '没找到'}",
        f"loginToken：{token or '没找到'}",
        "",
        "存到：" + folder,
    ]
    for p in saved:
        summary.append("  " + p)
    text = "\n".join(summary)
    save("_summary.txt", text)
    out(text)
    LOG.info("门户页已转存到 %s", folder)
    return 0


def write_config(args):
    """给安装脚本用：按命令行参数生成 config.json（密码从 stdin 读，不出现在进程列表里）。"""
    password = ""
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    elif args.password:
        password = args.password
    if not args.user or not password:
        out("生成配置失败：账号或密码为空")
        return 2

    cfg = dict(DEFAULTS)
    cfg.update({
        "user_id": args.user,
        "password": password,
        "service": args.service or "实验室",
        "password_mode": "auto",
        "password_reverse": True,
        "active_start": args.active_start,
        "active_end": args.active_end,
        "_说明": "以 _ 开头的键是备注，脚本忽略。本文件含明文密码，权限应保持 600。",
        "_password_mode说明": "auto=自动从门户找公钥加密（推荐）；static=用抓包密文；plain=明文。",
        "_active说明": "只在 active_start~active_end 之间检测登录；留空表示全天。",
        "_service说明": "门户上选的接入方式，脚本会自动做 URL 编码。",
    })
    path = args.out or os.path.join(BASE_DIR, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    out(f"配置已写入：{path}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="校园网 ePortal 自动登录")
    ap.add_argument("-c", "--config", default=os.path.join(BASE_DIR, "config.json"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="检测并（必要时）登录一次后退出")
    g.add_argument("--check", action="store_true", help="只报告状态，不登录")
    g.add_argument("--dry-run", action="store_true", dest="dry_run", help="掉线时只打印参数，不登录")
    g.add_argument("--dump", action="store_true", help="转存门户页与脚本，排查用")
    g.add_argument("--write-config", action="store_true", dest="write_config",
                   help="（安装脚本用）生成 config.json")
    ap.add_argument("--force-login", action="store_true", dest="force_login",
                   help="即使当前在线也强制登录一次（验证登录参数用）")
    ap.add_argument("--out", default="")
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--password-stdin", action="store_true", dest="password_stdin")
    ap.add_argument("--service", default="")
    ap.add_argument("--active-start", default="", dest="active_start")
    ap.add_argument("--active-end", default="", dest="active_end")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    _safe_console()
    if args.write_config:
        return write_config(args)

    cfg = load_config(args.config)
    setup_logging(cfg, args.verbose)
    client = HttpClient(cfg)

    try:
        if args.dump:
            return dump_portal(client, cfg)

        if args.check:
            status, detail, _ = cycle(client, cfg, "check")
            out({"online": "在线", "offline": "掉线（未认证）", "unknown": "状态未知"}[status] + f" —— {detail}")
            return {"online": 0, "offline": 1, "unknown": 2}[status]

        if args.once or args.dry_run or args.force_login:
            if not in_active_window(cfg):
                LOG.warning("当前不在认证时段（%s），手动运行照常执行", window_text(cfg))
            label = "dry-run" if args.dry_run else ("force-login" if args.force_login else "once")
            LOG.info("=== 单次运行（%s） ===", label)
            status, detail, _ = cycle(client, cfg, "dry" if args.dry_run else "login",
                                      force=args.force_login)
            out({"online": "在线", "offline": "仍然掉线", "unknown": "状态未知"}[status] + f" —— {detail}")
            return 0 if status == ONLINE else 1

        lock = acquire_single_instance(cfg["lock_port"])
        if lock is None:
            LOG.error("已有实例在运行（本地端口 %s 被占用），退出", cfg["lock_port"])
            return 3

        LOG.info("=== 守护启动：每 %s 秒检测一次，探针 %s，密码模式 %s，运行时段 %s ===",
                 cfg["check_interval"], cfg["probe_url"], cfg["password_mode"], window_text(cfg))
        if in_active_window(cfg):
            reachable, _ = portal_alive(client, cfg)
            if not reachable:
                LOG.warning("门户 %s 现在不可达，可能不在校园网内。等接上校园网后会自动开始工作。",
                            base_url(cfg))
        fails = 0
        paused = None
        try:
            while True:
                active = in_active_window(cfg)
                if active != paused:
                    if active:
                        LOG.info("当前在认证时段（%s），开始检测", window_text(cfg))
                    else:
                        LOG.info("已过 %s，进入静默：不再探测也不重试，等到 %s 自动恢复",
                                 cfg.get("active_end"), cfg.get("active_start"))
                    paused = active
                if not active:
                    time.sleep(60)          # 时段外每分钟醒一次，只看时间
                    continue

                try:
                    status, detail, _ = cycle(client, cfg, "login")
                except ConfigError as e:
                    LOG.error("配置问题，无法继续：%s", e)
                    return 4
                except Exception:                  # 任何意外都不该让守护进程死掉
                    LOG.exception("本轮出现未预期错误")
                    status, detail = UNKNOWN, "异常"

                if status == ONLINE:
                    fails = 0
                    wait = cfg["check_interval"]
                    LOG.debug("在线，%s 秒后再检测", wait)
                else:
                    fails += 1
                    wait = min(cfg["check_interval"] * (2 ** min(fails, 6)), cfg["max_backoff"])
                    if fails >= 5:
                        # 防止把账号刷到锁定/触发验证码
                        wait = max(wait, 1800)
                        LOG.warning("已连续失败 %d 次，为避免触发验证码或锁号，改为每 %d 秒才试一次",
                                    fails, wait)
                    LOG.info("第 %d 次未恢复（%s），%s 秒后重试", fails, detail, wait)
                time.sleep(wait)
        except KeyboardInterrupt:
            LOG.info("收到中断，退出")
        finally:
            lock.close()
        return 0
    except ConfigError as e:
        LOG.error("配置问题：%s", e)
        out(f"配置问题：{e}")
        return 4


if __name__ == "__main__":
    sys.exit(main())
