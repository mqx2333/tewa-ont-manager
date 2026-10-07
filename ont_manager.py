# -*- coding: utf-8 -*-
# ont_manager.py — TEWA / 天邑 光猫（ONT）管理 GUI
# Copyright (C) 2026 mqx2333
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
"""
TEWA-708G 光猫 · 超管密码获取 + IPv6 放行规则管理（GUI）

功能
  ① 超管密码：一键 开启Telnet -> 读取设备MAC -> 离线算SU -> 提权 -> 取 telecomadmin 密码
  ② 放行规则：连接光猫 root，查看 / 添加 / 删除 ip6tables (INPUT/FORWARD) 的端口放行规则
  ③ Telnet 开关：一键开关 Telnet（网络层 iptables 拦截新连接；可选定时自动恢复防锁死）
  ④ IPv6 路由修复：光猫下发的委派前缀若落成 on-link，一键补回指向二级路由的下一跳
     （修复因前缀变更导致的全屋 IPv6 双向不通；运行时改动，重启/换前缀后重跑）

依赖：仅 Python 3 标准库（tkinter）。无需第三方包。
用法：python ont_manager.py        （或双击 run.bat）

声明：仅用于自有设备的网络调试。请在法律允许的范围内使用，后果自负。
      放行规则为运行时规则，光猫重启后失效。
"""
import re
import socket
import time
import threading
import subprocess
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# ---------------------------------------------------------------------------
# SU 密码算法（由设备 MAC 派生 root 密码，社区逆向）
# ---------------------------------------------------------------------------
SU_CT1 = "QbNUTaMecPWVSKdCgXIJRrsfYXwyqpvnDHWzQuPmAGtAxRTphBcwBnNkjbFmvVMqaFkEutSrDCxsCKjBzEyDEUJTZfHZghMHYFdeASGNaUgFtdbYRkshJHkFNXMcKdfw"
SU_CT2 = "NXMcKdfwRkshJHkFaUgFtdbYYFdeASGNZfHZghMHzEyDEUJTDCxsCKjBaFkEutSrjbFmvVMqhBcwBnNkAGtAxRTpDHWzQuPmYXwyqpvngXIJRrsfcPWVSKdCQbNUTaMe"
SU_CT3 = "eMaTUNbQCdKSVWPcfsrRJIXgnvpqywXYmPuQzWHDpTRxAtGAkNnBwcBhqMVvmFbjrStuEkFaBjKCsxCDTJUEDyEzHMhgZHfZNGSAedFYYbdtFgUaFkHJhskRwfdKcMXN"


def generate_su(mac_or_hex):
    """返回 (su1, su2, su3) 三个候选；无效 MAC 返回 ()。"""
    hex_clean = "".join(c for c in mac_or_hex.upper() if c in "0123456789ABCDEF")
    if len(hex_clean) < 12:
        return ()
    v19 = [ord(c) for c in reversed(hex_clean[-8:])]
    v10 = next(((v - 48) | j for j, v in enumerate(v19) if 49 <= v <= 57), 5)
    a1, a2, a3 = [], [], []
    for k in range(len(v19)):
        v15 = (v19[k] & v19[7 - k]) if k < 4 else (v19[k] | v19[k - 4])
        v16 = v15 + v10
        if v16 > 127:
            v10 = k
            v16 = k
        a1.append(SU_CT1[v16])
        a2.append(SU_CT2[v16])
        a3.append(SU_CT3[v16])
        v10 += max(k, 1)
    return ("".join(a1), "".join(a2), "".join(a3))


# ---------------------------------------------------------------------------
# Telnet 会话
# ---------------------------------------------------------------------------
class OntTelnet:
    def __init__(self, host, port=23, user="telnetadmin", password="telnetadmin"):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.sock = None

    def _read(self, wait_ms):
        time.sleep(wait_ms / 1000.0)
        data = b""
        self.sock.settimeout(0.4)
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        return data.decode("latin-1", "replace")

    def _write(self, line):
        self.sock.sendall((line + "\r\n").encode("latin-1"))

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        self._read(1000)
        self._write(self.user)
        self._read(800)
        self._write(self.password)
        self._read(1000)

    def cmd(self, command, wait_ms=900):
        self._write(command)
        return self._read(wait_ms)

    def read_mac(self):
        out = self.cmd("cat /sys/class/net/eth0/address", 900)
        m = re.search(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
        return m.group(0) if m else ""

    def login_root(self, su_candidates):
        """依次试 SU，成功返回命中的密码，否则 None。成功后停留在 root(#)。"""
        for su in su_candidates:
            self._write("su")
            self._read(700)
            self._write(su)
            out = self._read(1200)
            if "#" in out:
                return su
        return None

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def enable_telnet_http(host):
    """请求免登录接口开启 Telnet，返回是否收到成功响应。"""
    try:
        with urllib.request.urlopen("http://%s:8080/entelnet.cgi" % host, timeout=6) as r:
            body = r.read().decode("latin-1", "replace")
        return "SUCCESS" in body.upper()
    except Exception:
        return False


def parse_ip6tables(text):
    """把 ip6tables -S 输出解析成规则列表。"""
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("-A "):
            continue
        toks = line.split()
        chain = toks[1] if len(toks) > 1 else ""
        dest = proto = dport = target = ""
        i = 2
        while i < len(toks):
            t = toks[i]
            if t == "-d" and i + 1 < len(toks):
                dest = toks[i + 1]; i += 2; continue
            if t == "-p" and i + 1 < len(toks):
                proto = toks[i + 1]; i += 2; continue
            if t == "--dport" and i + 1 < len(toks):
                dport = toks[i + 1]; i += 2; continue
            if t == "-j" and i + 1 < len(toks):
                target = toks[i + 1]; i += 2; continue
            i += 1
        rules.append({"line": line, "chain": chain, "dest": dest,
                      "proto": proto, "dport": dport, "target": target})
    return rules


def local_ipv6_prefix():
    """返回本机 RA 下发的 /64 前缀，如 2001:db8:1:2::/64；取不到返回 ''。"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetIPAddress -AddressFamily IPv6 | "
             "Where-Object {$_.PrefixOrigin -eq 'RouterAdvertisement' -and "
             "$_.IPAddress -notlike 'fe80*' -and $_.PrefixLength -eq 64} | "
             "Select-Object -First 1 -ExpandProperty IPAddress)"],
            capture_output=True, text=True, timeout=15)
        ip = out.stdout.strip().splitlines()
        ip = ip[0].strip() if ip else ""
        if ip and ":" in ip:
            return ":".join(ip.split(":")[:4]) + "::/64"
    except Exception:
        pass
    return ""


def parse_ip6_routes(text):
    """解析 `ip -6 route` 输出。"""
    routes = []
    for line in text.replace("\r", "").splitlines():
        line = line.strip()
        m = re.match(r"^([0-9A-Fa-f:]+/\d+)\s+(.*)$", line)
        if not m:
            continue
        dest, rest = m.group(1), m.group(2)
        vm = re.search(r"\bvia\s+([0-9A-Fa-f:]+)", rest)
        dm = re.search(r"\bdev\s+(\S+)", rest)
        routes.append({"dest": dest,
                       "via": vm.group(1) if vm else "",
                       "dev": dm.group(1) if dm else ""})
    return routes


def find_delegated_prefix(routes):
    """挑出 br0 上、无下一跳的全局网段（=被委派但没指向二级路由的前缀）。"""
    cands = [r for r in routes
             if r["dev"] == "br0" and not r["via"]
             and re.match(r"^[0-9A-Fa-f:]+/\d+$", r["dest"])
             and not r["dest"].lower().startswith("fe80")]
    if not cands:
        return None
    cands.sort(key=lambda r: int(r["dest"].split("/")[1]))
    return cands[0]["dest"]


def parse_ip6_neigh(text):
    out = []
    for line in text.replace("\r", "").splitlines():
        m = re.match(r"^([0-9A-Fa-f:]+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]+)\s*(.*)$",
                     line.strip())
        if m:
            out.append({"addr": m.group(1), "dev": m.group(2),
                        "mac": m.group(3), "flags": m.group(4)})
    return out


def _eui64_linklocal(mac):
    try:
        b = [int(x, 16) for x in mac.split(":")]
    except Exception:
        return ""
    if len(b) != 6:
        return ""
    b[0] ^= 0x02
    return "fe80::%02x%02x:%02xff:fe%02x:%02x%02x" % (b[0], b[1], b[2], b[3], b[4], b[5])


def _eui64_to_mac(addr):
    """从 EUI-64 形式的 IPv6 地址里还原 MAC（IID 含 ff:fe）。"""
    try:
        b = []
        for h in addr.split(":")[-4:]:
            b += [int(h[:2], 16), int(h[2:], 16)]
        if b[3] != 0xff or b[4] != 0xfe:
            return ""
        mac = [b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]]
        return ":".join("%02x" % x for x in mac)
    except Exception:
        return ""


def find_router_next_hop(neighs, prefix, routes=None):
    """探测二级路由在 br0 上的下一跳，返回可用于 `via` 的 IPv6 地址（找不到返回 ''）。"""
    net = None
    try:
        import ipaddress
        net = ipaddress.ip_network(prefix, strict=False)
    except Exception:
        pass
    # 1) 邻居表：带 router 标志、落在 prefix 内的全局地址
    for n in neighs:
        if n["dev"] != "br0" or "router" not in n["flags"]:
            continue
        if n["addr"].lower().startswith("fe80"):
            continue
        if net is not None:
            try:
                import ipaddress
                if ipaddress.ip_address(n["addr"]) not in net:
                    continue
            except Exception:
                continue
        return n["addr"]
    # 2) 邻居表：带 router 标志的链路本地地址
    for n in neighs:
        if n["dev"] == "br0" and "router" in n["flags"] \
                and n["addr"].lower().startswith("fe80"):
            return n["addr"]
    # 3) 邻居表：带 router 标志的 MAC -> 链路本地
    for n in neighs:
        if n["dev"] == "br0" and "router" in n["flags"]:
            ll = _eui64_linklocal(n["mac"])
            if ll:
                return ll
    # 4) 从已有 via 路由（旧前缀残留）的 EUI-64 下一跳推链路本地
    if routes:
        for r in routes:
            if r["via"] and "ff:fe" in r["via"].lower():
                ll = _eui64_linklocal(_eui64_to_mac(r["via"])) if _eui64_to_mac(r["via"]) else ""
                if ll:
                    return ll
    return ""


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("TEWA-708G 光猫 · 超管密码 / 放行规则管理")
        self.root.geometry("860x660")
        self.root.minsize(760, 560)

        self.su_found = tk.StringVar(value="")
        self.mac_var = tk.StringVar(value="")
        self.ip_var = tk.StringVar(value="192.168.1.1")
        self.port_var = tk.StringVar(value="23")
        self.user_var = tk.StringVar(value="telnetadmin")
        self.pw_var = tk.StringVar(value="telnetadmin")
        self.status_var = tk.StringVar(value="未连接")
        self.rule_show_all = tk.BooleanVar(value=False)
        self.scope_mode = tk.StringVar(value="all")
        self.scope_var = tk.StringVar(value="")
        self.rule_map = {}   # treeview iid -> 规则原始行

        # Telnet 开关状态
        self.tel_state = tk.StringVar(value="未知（点『刷新状态』）")
        self.auto_recover = tk.StringVar(value="300")
        self.tel_client = None          # 常驻 root 会话，供“开启”撤销封禁
        self.tel_lock = threading.Lock()

        # IPv6 路由修复
        self.nexthop_var = tk.StringVar(value="")

        self._build_top()
        self._build_notebook()

    # 《Telnet 关闭》用的封禁规则（只拦新连接，不断开当前会话）
    TEL_RULE = "-p tcp --dport 23 -m conntrack --ctstate NEW -j DROP"

    def _tel_rule_add(self):
        return "iptables -I INPUT 1 " + self.TEL_RULE

    def _tel_rule_del(self):
        return "iptables -D INPUT " + self.TEL_RULE

    # -- 顶部：连接参数 ----------------------------------------------------
    def _build_top(self):
        f = ttk.LabelFrame(self.root, text="连接参数（光猫）")
        f.pack(fill="x", padx=10, pady=(10, 4))
        rows = [
            ("光猫 IP", self.ip_var, 12),
            ("Telnet 端口", self.port_var, 6),
            ("用户", self.user_var, 12),
            ("密码", self.pw_var, 12),
        ]
        for idx, (label, var, width) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=0, column=idx * 2, padx=(8, 2), pady=8, sticky="e")
            e = ttk.Entry(f, textvariable=var, width=width)
            e.grid(row=0, column=idx * 2 + 1, padx=(0, 8), pady=8, sticky="w")
        ttk.Label(self.root, textvariable=self.status_var, foreground="#0a7").pack(anchor="w", padx=14)

    # -- Notebook -----------------------------------------------------------
    def _build_notebook(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=8)
        self.tab_su = ttk.Frame(nb)
        self.tab_rules = ttk.Frame(nb)
        self.tab_telnet = ttk.Frame(nb)
        self.tab_route = ttk.Frame(nb)
        nb.add(self.tab_su, text="  ① 超管密码  ")
        nb.add(self.tab_rules, text="  ② 放行规则  ")
        nb.add(self.tab_telnet, text="  ③ Telnet 开关  ")
        nb.add(self.tab_route, text="  ④ IPv6 路由修复  ")
        self._build_tab_su()
        self._build_tab_rules()
        self._build_tab_telnet()
        self._build_tab_route()

    # -- Tab 1: 超管密码 ---------------------------------------------------
    def _build_tab_su(self):
        t = self.tab_su
        box = ttk.LabelFrame(t, text="设备 MAC（留空则自动从光猫读取）")
        box.pack(fill="x", padx=8, pady=8)
        ttk.Entry(box, textvariable=self.mac_var, width=26).pack(side="left", padx=8, pady=8)
        ttk.Button(box, text="从光猫读取", command=self.on_read_mac).pack(side="left", padx=4)

        ttk.Button(t, text="⚡ 一键获取超管密码（开Telnet → 提权 → 取密码）",
                   command=self.on_oneclick).pack(fill="x", padx=8, pady=10)

        res = ttk.LabelFrame(t, text="超管密码")
        res.pack(fill="x", padx=8, pady=4)
        row = ttk.Frame(res); row.pack(fill="x", padx=8, pady=8)
        self.pw_show = tk.StringVar(value="—")
        lbl = ttk.Label(row, textvariable=self.pw_show, font=("Consolas", 18, "bold"),
                        foreground="#c00")
        lbl.pack(side="left")
        ttk.Button(row, text="复制", command=self.copy_pw).pack(side="left", padx=12)

        ttk.Label(t, text="日志").pack(anchor="w", padx=10)
        self.log_su = scrolledtext.ScrolledText(t, height=12, font=("Consolas", 9))
        self.log_su.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # -- Tab 2: 放行规则 ---------------------------------------------------
    def _build_tab_rules(self):
        t = self.tab_rules

        bar = ttk.Frame(t); bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="连接并提权", command=self.on_connect).pack(side="left")
        ttk.Button(bar, text="刷新规则", command=self.on_refresh).pack(side="left", padx=6)
        ttk.Checkbutton(bar, text="显示全部规则(含固件默认)", variable=self.rule_show_all,
                        command=self.render_rules_last).pack(side="left", padx=10)
        ttk.Button(bar, text="导出为 .sh", command=self.on_export).pack(side="right")

        cols = ("chain", "proto", "dport", "dest", "target")
        self.tree = ttk.Treeview(t, columns=cols, show="headings", height=9)
        for c, w in zip(cols, (80, 70, 90, 340, 90)):
            self.tree.heading(c, text={"chain": "链", "proto": "协议", "dport": "端口",
                                       "dest": "目的地址(-d)", "target": "动作"}[c])
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)
        self.last_rules = []

        ttk.Button(t, text="删除选中规则", command=self.on_delete).pack(anchor="w", padx=8, pady=(0, 6))

        add = ttk.LabelFrame(t, text="添加放行")
        add.pack(fill="x", padx=8, pady=4)
        r1 = ttk.Frame(add); r1.pack(fill="x", padx=8, pady=6)
        ttk.Label(r1, text="链:").pack(side="left")
        self.cmb_chain = ttk.Combobox(r1, values=["INPUT", "FORWARD", "两者"], width=8, state="readonly")
        self.cmb_chain.current(2); self.cmb_chain.pack(side="left", padx=4)
        ttk.Label(r1, text="协议:").pack(side="left", padx=(10, 0))
        self.cmb_proto = ttk.Combobox(r1, values=["tcp", "udp", "tcp+udp"], width=9, state="readonly")
        self.cmb_proto.current(2); self.cmb_proto.pack(side="left", padx=4)
        ttk.Label(r1, text="端口(可逗号多填):").pack(side="left", padx=(10, 0))
        self.ent_port = ttk.Entry(r1, width=22); self.ent_port.pack(side="left", padx=4)
        self.ent_port.insert(0, "10000,10001")

        r2 = ttk.Frame(add); r2.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Radiobutton(r2, text="所有地址", variable=self.scope_mode, value="all",
                        command=self._scope_state).pack(side="left")
        ttk.Radiobutton(r2, text="指定地址/前缀:", variable=self.scope_mode, value="spec",
                        command=self._scope_state).pack(side="left", padx=(10, 0))
        self.ent_scope = ttk.Entry(r2, textvariable=self.scope_var, width=34)
        self.ent_scope.pack(side="left", padx=4)
        self.btn_scope64 = ttk.Button(r2, text="本机 /64", command=self.fill_local_64)
        self.btn_scope64.pack(side="left", padx=4)
        ttk.Button(r2, text="添加放行", command=self.on_add).pack(side="right")
        self._scope_state()

        ttk.Label(t, text="日志").pack(anchor="w", padx=10)
        self.log_rules = scrolledtext.ScrolledText(t, height=7, font=("Consolas", 9))
        self.log_rules.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # -- Tab 3: Telnet 开关 ------------------------------------------------
    def _build_tab_telnet(self):
        t = self.tab_telnet

        st = ttk.LabelFrame(t, text="当前状态（端口 23）")
        st.pack(fill="x", padx=8, pady=8)
        ttk.Label(st, textvariable=self.tel_state, font=("Microsoft YaHei", 12, "bold")) \
            .pack(side="left", padx=10, pady=10)
        ttk.Button(st, text="刷新状态", command=self.on_tel_status).pack(side="right", padx=8)

        ops = ttk.Frame(t); ops.pack(fill="x", padx=8, pady=4)
        ttk.Button(ops, text="✔ 开启 Telnet", command=self.on_tel_open) \
            .pack(side="left", ipadx=20, ipady=6)
        ttk.Button(ops, text="✘ 关闭 Telnet", command=self.on_tel_close) \
            .pack(side="left", padx=12, ipadx=20, ipady=6)

        rec = ttk.LabelFrame(t, text="防锁死：关闭后自动恢复")
        rec.pack(fill="x", padx=8, pady=6)
        ttk.Label(rec, text="自动恢复延时(秒)，0 = 不自动恢复:").pack(side="left", padx=8, pady=8)
        ttk.Spinbox(rec, from_=0, to=86400, width=8, textvariable=self.auto_recover) \
            .pack(side="left", padx=4)

        note = ("说明：光猫根文件系统只读，无法持久禁用 telnetd；本开关用 iptables 只拦截"
                "【新的】TCP:23 连接（当前管理会话与放行规则操作不受影响）。\n"
                "· 关闭后，本工具仍能通过已建立的常驻会话再次『开启』；若会话丢失，靠上面的"
                "自动恢复或重启光猫（运行规则会清空、Telnet 也会回到关闭）恢复。")
        ttk.Label(t, text=note, foreground="#666", justify="left") \
            .pack(anchor="w", padx=12, pady=(6, 2))

        ttk.Label(t, text="日志").pack(anchor="w", padx=10)
        self.log_tel = scrolledtext.ScrolledText(t, height=8, font=("Consolas", 9))
        self.log_tel.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _port23_open(self):
        try:
            s = socket.create_connection((self.ip_var.get().strip(), 23), timeout=3)
            s.close()
            return True
        except Exception:
            return False

    def _ensure_tel_root(self):
        """返回常驻 root 会话（须在 tel_lock 内调用）。"""
        if self.tel_client and self.tel_client.sock:
            try:
                if "__alive__" in self.tel_client.cmd("echo __alive__", 600):
                    return self.tel_client
            except Exception:
                pass
            try:
                self.tel_client.close()
            except Exception:
                pass
            self.tel_client = None
        c = self._new_client()
        c.connect()
        mac = self.mac_var.get().strip() or c.read_mac()
        used = c.login_root(generate_su(mac))
        if not used:
            c.close()
            raise RuntimeError("SU 提权失败（MAC=%s）" % (mac or "空"))
        self.tel_client = c
        return c

    def on_tel_status(self):
        self.tel_state.set("检测中…")
        def work():
            return self._port23_open()
        def done(open_, err):
            if err:
                self.tel_state.set("检测失败"); return
            self.tel_state.set("端口 23：开放（Telnet 可用）" if open_ else "端口 23：已关闭/被拦")
        self._run_async(work, done)

    def on_tel_open(self):
        self.log_tel.delete("1.0", "end")
        def work():
            msgs = []
            ok = enable_telnet_http(self.ip_var.get().strip())
            msgs.append("[开] entelnet.cgi -> " + ("SUCCESS" if ok else "无响应（可能已开/端口不同）"))
            try:
                with self.tel_lock:
                    c = self._ensure_tel_root()
                    c.cmd(self._tel_rule_del(), 700)
                    msgs.append("[开] 已尝试移除 23 端口封禁规则")
            except Exception as e:
                msgs.append("[开] 未能撤销封禁(无 root 会话时正常): %s" % e)
            return msgs
        def done(res, err):
            if err:
                self._log(self.log_tel, "[-] " + str(err)); return
            for m in res:
                self._log(self.log_tel, m)
            self.on_tel_status()
        self._run_async(work, done)

    def on_tel_close(self):
        self.log_tel.delete("1.0", "end")
        def work():
            msgs = []
            with self.tel_lock:
                c = self._ensure_tel_root()
                c.cmd(self._tel_rule_add(), 800)
                msgs.append("[关] 已拦截新的 TCP:23 连接（iptables DROP NEW）")
                try:
                    n = int(self.auto_recover.get())
                except Exception:
                    n = 0
                if n > 0:
                    c.cmd("setsid sh -c 'sleep %d; iptables -D INPUT %s' </dev/null "
                          ">/dev/null 2>&1 &" % (n, self.TEL_RULE), 600)
                    msgs.append("[关] 已设置 %d 秒后自动恢复（防锁死）" % n)
            return msgs
        def done(res, err):
            if err:
                self._log(self.log_tel, "[-] " + str(err))
                messagebox.showerror("关闭失败", str(err)); return
            for m in res:
                self._log(self.log_tel, m)
            self.on_tel_status()
        self._run_async(work, done)

    # -- Tab 4: IPv6 路由修复 ---------------------------------------------
    def _build_tab_route(self):
        t = self.tab_route
        tip = ("光猫下发给二级路由的委派前缀，有时会落成 on-link（没有下一跳），"
               "导致光猫把包直接往局域网里 NDP（实际主机在路由器后面），"
               "全屋 IPv6 出站/入站一起失效。\n"
               "此按钮给光猫补一条指向二级路由的下一跳路由（运行时生效，光猫重启后需重跑）。")
        ttk.Label(t, text=tip, wraplength=800, justify="left",
                  foreground="#444").pack(anchor="w", padx=10, pady=8)

        row = ttk.Frame(t); row.pack(fill="x", padx=8, pady=4)
        ttk.Button(row, text="⚡ 一键修复 IPv6 路由", command=self.on_fix_route) \
            .pack(side="left", ipadx=16, ipady=6)
        ttk.Button(row, text="查看当前 IPv6 路由", command=self.on_show_routes) \
            .pack(side="left", padx=10)
        ttk.Label(row, text="下一跳(留空自动探测):").pack(side="left", padx=(20, 4))
        ttk.Entry(row, textvariable=self.nexthop_var, width=34).pack(side="left")

        ttk.Label(t, text="日志").pack(anchor="w", padx=10, pady=(8, 0))
        self.log_route = scrolledtext.ScrolledText(t, height=15, font=("Consolas", 9))
        self.log_route.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _ipv6_outbound_ok(self):
        try:
            rc = subprocess.run(
                ["ping", "-6", "-n", "1", "-w", "2500", "2001:4860:4860::8888"],
                capture_output=True, timeout=8).returncode
            return rc == 0
        except Exception:
            return None

    def on_show_routes(self):
        self.log_route.delete("1.0", "end")
        def work():
            return self._root_session(lambda c: c.cmd("ip -6 route", 2000))
        def done(res, err):
            if err:
                self._log(self.log_route, "[-] " + str(err)); return
            out, used = res
            for l in out.replace("\r", "").splitlines():
                if "/" in l:
                    self._log(self.log_route, l)
        self._run_async(work, done)

    def on_fix_route(self):
        self.log_route.delete("1.0", "end")
        def work():
            def fn(c):
                routes = parse_ip6_routes(c.cmd("ip -6 route", 2000))
                prefix = find_delegated_prefix(routes)
                if not prefix:
                    raise RuntimeError("未找到需要在 br0 上补下一跳的委派前缀（可能已正常）")
                for r in routes:
                    if r["dest"] == prefix and r["via"]:
                        return {"prefix": prefix, "nexthop": r["via"], "changed": False}
                neighs = parse_ip6_neigh(c.cmd("ip -6 neigh show dev br0", 2000))
                nh = self.nexthop_var.get().strip() or \
                    find_router_next_hop(neighs, prefix, routes)
                if not nh:
                    raise RuntimeError("未探测到二级路由下一跳，请在上方输入框手动填写其 IPv6 地址")
                # 先清掉该前缀的 on-link/重复路由，再加带下一跳的路由
                for _ in range(6):
                    d = c.cmd("ip -6 route del %s" % prefix, 600).lower()
                    if ("rtnetlink" in d or "no such" in d
                            or "not found" in d or "cannot" in d):
                        break
                cmd = "ip -6 route replace %s via %s dev br0" % (prefix, nh)
                c.cmd(cmd, 1200)
                after = c.cmd("ip -6 route", 2000)
                return {"prefix": prefix, "nexthop": nh, "changed": True,
                        "cmd": cmd, "after": after}
            info, used = self._root_session(fn)
            info["outbound"] = self._ipv6_outbound_ok()
            return info
        def done(res, err):
            if err:
                self._log(self.log_route, "[-] " + str(err))
                messagebox.showerror("修复失败", str(err)); return
            info = res
            if not info["changed"]:
                self._log(self.log_route, "[=] %s 已指向 %s，无需修复" %
                          (info["prefix"], info["nexthop"]))
            else:
                self._log(self.log_route, "[+] " + info["cmd"])
                for l in info["after"].replace("\r", "").splitlines():
                    if "/" in l and not l.strip().startswith(("fe80", "ff00", "#")):
                        self._log(self.log_route, "    " + l)
                self._log(self.log_route, "[i] 修复完成；运行时改动，光猫重启/换前缀后需重跑。")
            ob = info.get("outbound")
            self._log(self.log_route, "[自检] 本机 IPv6 出站: " +
                      ("正常" if ob else "仍异常" if ob is False else "未测"))
        self._run_async(work, done)

    def _scope_state(self):
        state = "normal" if self.scope_mode.get() == "spec" else "disabled"
        self.ent_scope.configure(state=state)
        self.btn_scope64.configure(state=state)

    # -- 通用日志/线程 -----------------------------------------------------
    def _log(self, widget, msg):
        widget.insert("end", msg.rstrip() + "\n")
        widget.see("end")

    def _run_async(self, work, done):
        def _t():
            try:
                res = work()
                err = None
            except Exception as e:            # noqa
                res, err = None, e
            self.root.after(0, lambda: done(res, err))
        threading.Thread(target=_t, daemon=True).start()

    def _new_client(self):
        return OntTelnet(self.ip_var.get().strip(), self.port_var.get().strip(),
                         self.user_var.get().strip(), self.pw_var.get().strip())

    def _root_session(self, fn):
        """在后台线程内：连接 -> 算SU -> 提权 -> 执行 fn(client) -> 关闭。"""
        c = self._new_client()
        c.connect()
        mac = self.mac_var.get().strip() or c.read_mac()
        sus = generate_su(mac)
        used = c.login_root(sus)
        if not used:
            c.close()
            raise RuntimeError("SU 提权失败，请检查 MAC（%s）" % (mac or "空"))
        try:
            return fn(c), used
        finally:
            c.close()

    # -- 超管密码 ----------------------------------------------------------
    def on_read_mac(self):
        self.log_su.delete("1.0", "end")
        self.status_var.set("连接中…")
        def work():
            c = self._new_client(); c.connect(); mac = c.read_mac(); c.close()
            return mac
        def done(mac, err):
            if err:
                self.status_var.set("失败"); messagebox.showerror("错误", str(err)); return
            if mac:
                self.mac_var.set(mac)
                self.status_var.set("已读取 MAC: " + mac)
                self._log(self.log_su, "[+] MAC = " + mac)
            else:
                self.status_var.set("未取到 MAC")
        self._run_async(work, done)

    def on_oneclick(self):
        self.pw_show.set("…"); self.log_su.delete("1.0", "end")
        host = self.ip_var.get().strip()
        self.status_var.set("执行中…")
        def work():
            lines = []
            lines.append("[*] 目标 %s" % host)
            ok = enable_telnet_http(host)
            lines.append("[*] entelnet.cgi: " + ("SUCCESS，Telnet 已开启" if ok else "未确认(可能已开/端口不同)"))
            c = self._new_client(); c.connect()
            mac = self.mac_var.get().strip() or c.read_mac()
            lines.append("[*] 设备 MAC = " + (mac or "(未取到)"))
            sus = generate_su(mac)
            lines.append("[*] SU 候选 = " + ", ".join(sus))
            used = c.login_root(sus)
            if not used:
                c.close()
                raise RuntimeError("SU 提权失败（MAC=%s）" % mac)
            lines.append("[+] 提权成功，SU = " + used)
            c.cmd("exit", 700)
            out = c.cmd("telecomadmin get", 2600)
            c.close()
            m = re.search(r"passwd\s*=\s*(\S+)", out)
            if not m:
                raise RuntimeError("未从输出解析到 passwd=…：\n" + out)
            return m.group(1), mac, used, lines
        def done(res, err):
            if err:
                self.pw_show.set("失败"); self.status_var.set("失败")
                self._log(self.log_su, "[-] " + str(err))
                messagebox.showerror("失败", str(err)); return
            pw, mac, used, lines = res
            self.mac_var.set(mac)
            for l in lines:
                self._log(self.log_su, l)
            self._log(self.log_su, "[+] 超管密码 = " + pw)
            self.pw_show.set(pw)
            self.status_var.set("完成")
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self._log(self.log_su, "[i] 密码已复制到剪贴板")
        self._run_async(work, done)

    def copy_pw(self):
        pw = self.pw_show.get()
        if pw and pw not in ("—", "…"):
            self.root.clipboard_clear(); self.root.clipboard_append(pw)

    # -- 放行规则 ----------------------------------------------------------
    def on_connect(self):
        self.status_var.set("连接并提权中…")
        def work():
            return self._root_session(lambda c: None)
        def done(res, err):
            if err:
                self.status_var.set("失败"); messagebox.showerror("错误", str(err)); return
            used = res[1]
            self.status_var.set("已连接 root（SU=%s）" % used)
            self._log(self.log_rules, "[+] root 就绪，SU = " + used)
            self.on_refresh()
        self._run_async(work, done)

    def on_refresh(self):
        self.status_var.set("读取规则中…")
        def work():
            def fn(c):
                out = c.cmd("ip6tables -S INPUT", 1500)
                out += "\n" + c.cmd("ip6tables -S FORWARD", 1500)
                return parse_ip6tables(out)
            return self._root_session(fn)
        def done(res, err):
            if err:
                self.status_var.set("失败"); messagebox.showerror("错误", str(err)); return
            rules, used = res
            self.last_rules = rules
            self.status_var.set("已连接 root（SU=%s），共 %d 条 -A 规则" % (used, len(rules)))
            self.render_rules_last()
        self._run_async(work, done)

    def render_rules_last(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.rule_map.clear()
        shown = 0
        for r in self.last_rules:
            if not self.rule_show_all.get() and not r["dport"]:
                continue
            iid = self.tree.insert("", "end", values=(r["chain"], r["proto"] or "-",
                                                      r["dport"] or "-", r["dest"] or "-",
                                                      r["target"] or "-"))
            self.rule_map[iid] = r["line"]
            shown += 1

    def _collect_add_cmds(self):
        chain = self.cmb_chain.get()
        proto = self.cmb_proto.get()
        portstr = self.ent_port.get().strip()
        chains = ["INPUT", "FORWARD"] if chain == "两者" else [chain]
        protos = ["tcp", "udp"] if proto == "tcp+udp" else [proto]
        ports = [p.strip() for p in re.split(r"[,\s]+", portstr) if p.strip()]
        if not ports:
            raise ValueError("请填写端口")
        for p in ports:
            if not p.isdigit() or not (0 < int(p) < 65536):
                raise ValueError("端口不合法: " + p)
        scope = self.scope_var.get().strip() if self.scope_mode.get() == "spec" else ""
        cmds = []
        for ch in chains:
            for pr in protos:
                for pt in ports:
                    cmd = "ip6tables -I %s 1" % ch
                    if scope:
                        cmd += " -d %s" % scope
                    cmd += " -p %s --dport %s -j ACCEPT" % (pr, pt)
                    cmds.append(cmd)
        return cmds

    def on_add(self):
        try:
            cmds = self._collect_add_cmds()
        except Exception as e:
            messagebox.showerror("参数错误", str(e)); return
        self.status_var.set("添加中…")
        def work():
            def fn(c):
                outs = []
                for cmd in cmds:
                    outs.append(cmd + "\n" + c.cmd(cmd, 700))
                return outs
            return self._root_session(fn)
        def done(res, err):
            if err:
                self.status_var.set("失败"); messagebox.showerror("错误", str(err)); return
            outs, used = res
            for o in outs:
                self._log(self.log_rules, "[+] " + o.strip())
            self.status_var.set("已添加 %d 条" % len(outs))
            self.on_refresh()
        self._run_async(work, done)

    def on_delete(self):
        sel = list(self.tree.selection())
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择要删除的规则"); return
        lines = [self.rule_map[i] for i in sel]
        if not messagebox.askyesno("确认", "删除选中的 %d 条规则？\n\n%s" %
                                   (len(lines), "\n".join(lines[:12]))):
            return
        self.status_var.set("删除中…")
        def work():
            def fn(c):
                outs = []
                for line in lines:
                    cmd = "ip6tables -D " + line[3:]   # 把 "-A " 换成 "-D "
                    outs.append(cmd + "\n" + c.cmd(cmd, 700))
                return outs
            return self._root_session(fn)
        def done(res, err):
            if err:
                self.status_var.set("失败"); messagebox.showerror("错误", str(err)); return
            outs, used = res
            for o in outs:
                self._log(self.log_rules, "[-] " + o.strip())
            self.status_var.set("已删除 %d 条" % len(outs))
            self.on_refresh()
        self._run_async(work, done)

    def fill_local_64(self):
        p = local_ipv6_prefix()
        if p:
            self.scope_var.set(p)
        else:
            messagebox.showinfo("提示", "未检测到本机 /64 前缀，请手动填写。")

    def on_export(self):
        rules = [r for r in self.last_rules if r["dport"] and r["target"] == "ACCEPT"]
        if not rules:
            messagebox.showinfo("提示", "当前没有可导出的 ACCEPT 规则（请先刷新）"); return
        path = filedialog.asksaveasfilename(defaultextension=".sh",
                                            initialfile="ip6_allow.sh",
                                            filetypes=[("Shell", "*.sh")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\n# 光猫 IPv6 放行（重启后需重放）\n")
            for r in rules:
                line = r["line"]           # -A CHAIN ... -j ACCEPT
                f.write("ip6tables -I " + line[3:] + "\n")
        self._log(self.log_rules, "[i] 已导出: " + path)
        messagebox.showinfo("完成", "已导出到:\n" + path)


def main():
    root = tk.Tk()
    try:
        root.call("tk", "scaling", 1.2)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
