#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nimbus —— Nimbus 管理面板：vlmcsd KMS 服务的可视化管理界面（单文件，Python 3 标准库，零第三方依赖）

设计要点
--------
* vlmcsd 本体是一个静态 C 守护进程，不带任何 HTTP 服务。所以管理界面是**独立进程**：
  它读写 /etc/vlmcsd.ini、给 vlmcsd 发 SIGHUP 触发重载（不断开现有客户端）、
  调 systemctl 做启停，读 journald/日志文件做统计。vlmcsd 崩了或管理界面崩了互不影响。
* 激活统计**不从 vlmcsd 内存里拿数据**（MaintainClients 默认 FALSE，也不去改编译开关），
  而是把 vlmcsd 的日志行解析后写进本地 SQLite：
    - 内存占用恒定（SQLite 页缓存封顶 2 MB，写入走单线程队列，聚合全部用 SQL）
    - 磁盘有配额（默认 6 GB，超出后滚动删除最旧记录 + incremental_vacuum）
    - 一行记录约 120 字节 → 6 GB ≈ 5000 万条记录，小办公室够用几十年
* 两种模式：
    --mode demo   本机演示：假配置 + 假服务 + 合成激活流量（你正在看的这个）
    --mode real   Linux 真机：真的读写 ini、SIGHUP、systemctl、journalctl
* 被管理的 vlmcsd 用什么单元名/配置文件路径由 --unit / --ini 决定（默认 vlmcsd 与
  /etc/vlmcsd.ini）；面板找不到这个 unit 时不会崩，只会如实显示"未检测到 KMS 服务"。

用法
----
    python nimbus.py --mode demo --port 8099
    python nimbus.py --mode real --port 8099 --bind 127.0.0.1
    python nimbus.py --mode real --data-dir /var/lib/nimbus --token-file /etc/nimbus.token \
                     --unit vlmcsd --ini /etc/vlmcsd.ini

安全
----
* 安装时生成随机 token（文件 600 权限），所有 /api/* 请求必须带 token。
* 默认只绑 127.0.0.1；对外暴露请走 Caddy 反向代理 + HTTPS（界面里有现成配置）。
* 真机模式下服务需要能改 /etc/vlmcsd.ini 并重启 vlmcsd —— 等于半个 root 面板，
  别裸奔在公网。
"""

import argparse
import base64
import collections
import hashlib
import http.client
import json
import os
import queue
import random
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xmlrpc.client
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

VERSION = "0.2.0"
HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# 可选参数（就是界面上那份表单的字段定义，前端直接按这份 schema 渲染）
# --------------------------------------------------------------------------
FIELD_SCHEMA = [
    {"key": "Port", "label": "服务端口", "type": "int", "min": 1, "max": 65535,
     "default": 1688, "flag": "-P", "help": "KMS 客户端连接端口，默认 1688"},
    {"key": "Listen", "label": "监听地址", "type": "str", "default": "0.0.0.0:1688",
     "flag": "-L", "help": "格式 IP:端口，可留空只按端口监听"},
    {"key": "MaxWorkers", "label": "最大并发任务", "type": "int", "min": 1, "max": 4096,
     "default": 256, "flag": "-m", "help": "同时处理的客户端上限；1 核小机器 64 也够"},
    # ini 里的键名偶尔和命令行上的不一样（vlmcsd 自己的叫法是 ConnectionTimeout /
    # WhiteListingLevel / LogVerbose），所以 ini 名单独给一个字段，写 ini 时用它。
    {"key": "MaxIdleTime", "ini": "ConnectionTimeout", "label": "空闲断开（秒）", "type": "int",
     "min": 1, "max": 3600, "default": 30, "flag": "-t",
     "help": "客户端空闲多久后被断开；vlmcsd 的 ini 里这个键叫 ConnectionTimeout"},
    {"key": "WhitelistingLevel", "ini": "WhiteListingLevel", "label": "白名单/严格模式", "type": "choice",
     "default": "0", "flag": "-K",
     "choices": [["0", "0 - 应答未知产品（推荐）"], ["1", "1 - 只应答已知 KMSID"], ["2", "2 - 更严格"]],
     "help": "收紧后客户端报未知产品会被拒绝"},
    {"key": "CheckClientTime", "label": "校验客户端时钟", "type": "bool", "default": False,
     "flag": "-c", "help": "开启后客户端时间偏差过大将被拒绝"},
    {"key": "LogFile", "label": "日志目标", "type": "str", "default": "syslog",
     "flag": "-l", "help": "syslog 或文件路径"},
    {"key": "LogVerbose", "label": "详细日志", "type": "bool", "default": True, "flag": "-v",
     "help": "vlmcsd 的 -v 开关：激活统计靠它打出的逐条明细，关掉统计就只剩空壳"},
]
DEMO_CONFIG = {f["key"]: f["default"] for f in FIELD_SCHEMA}
FIELD_BY_KEY = {f["key"]: f for f in FIELD_SCHEMA}
INI_NAME = {f["key"]: f.get("ini", f["key"]) for f in FIELD_SCHEMA}
KEY_BY_INI = {v.lower(): k for k, v in INI_NAME.items()}
# 历史遗留：早期版本往 ini 里写过这两个键名，vlmcsd 并不认识它们（启动时打
# "Unknown keyword" 警告，设置其实完全没生效）。重写 ini 时直接丢掉。
LEGACY_INI_KEYS = {"maxidletime", "loglevel"}


def truthy(v):
    """把界面上 / ini 里的各种真假写法归一。"""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def ini_value(field, value):
    """把界面上的值写成 vlmcsd.ini 认的写法（布尔统一写 1/0）。"""
    if field["type"] == "bool":
        return "1" if truthy(value) else "0"
    return str(value)

PRODUCTS = [
    ("Windows 10 Pro", "03612-00206-496-93381-03-1033-7601.0000-2322023"),
    ("Windows 10 Enterprise", "03612-00206-497-93381-03-1033-7601.0000-2322023"),
    ("Windows 11 Pro", "03612-00206-500-93381-03-1033-7601.0000-2322023"),
    ("Windows 11 Enterprise", "03612-00206-501-93381-03-1033-7601.0000-2322023"),
    ("Windows Server 2019 Datacenter", "00477-00100-000-001-9600.0000-2322023"),
    ("Windows Server 2022 Standard", "00477-00100-001-001-9600.0000-2322023"),
    ("Microsoft Office 2021 Pro Plus", "00477-00100-002-001-9600.0000-2322023"),
    ("Microsoft Office 2019 Pro Plus", "00477-00100-003-001-9600.0000-2322023"),
]
FAIL_REASONS = [
    "KMSID not found (unknown product)",
    "client clock skew too large",
    "client not in whitelist",
    "requested ePID not available",
]
CLIENT_VERSIONS = ["6.3.9600.19958", "10.0.19041.1", "10.0.22621.1", "10.0.17763.1", "16.0.14332.1"]


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def _dur_text(sec):
    """秒数 → 「几天几小时」，给启动时间那栏用。"""
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    if d:
        return "%d 天 %d 小时" % (d, h)
    if h:
        return "%d 小时 %d 分" % (h, m)
    return "%d 分" % m


# Windows 11 复用 Windows 10 的 GVLK 与 Activation ID（例如专业版都是
# 2de67392-b7a7-462a-b1ca-108dd189f588），而 KMS 请求里**不含系统版本号**，所以
# 服务器端根本无法区分 Win10 / Win11；vlmcsd 内置的数据表又比 Windows 11 旧，
# 于是一律叫 "Windows 10 xxx"。基础版标成 10/11 更贴近事实；带年份、LTSB/LTSC、
# Server、ARM64 的名字一律不动（那些确实没有 Win11 对应版本）。
_DISPLAY_ALIAS = [
    (re.compile(r"^Windows 10 (Home|Home N|Home Single Language|Professional|Professional N|"
                r"Enterprise|Enterprise N|Education|Education N)$"),
     r"Windows 10/11 \1"),
]


def _alias_product(name):
    for pat, repl in _DISPLAY_ALIAS:
        if pat.match(name):
            return pat.sub(repl, name)
    return name


# --------------------------------------------------------------------------
# 统计存储：单表 SQLite，内存恒定，磁盘有配额
# --------------------------------------------------------------------------
class StatsStore:
    """一行 = 一次激活尝试。所有聚合都交给 SQLite，绝不把行读进 Python 列表。"""

    def __init__(self, db_path: Path, quota_bytes: int, retention_days: int = 0):
        self.db_path = db_path
        self.quota_bytes = quota_bytes
        self.retention_days = retention_days
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        # 内存封顶：页缓存 2 MB，关掉 mmap，WAL 保证写入不阻塞读取
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=-2048",
            "PRAGMA mmap_size=0",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA auto_vacuum=INCREMENTAL",
        ):
            self.db.execute(pragma)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                   ts      INTEGER NOT NULL,
                   ip      TEXT    NOT NULL,
                   product TEXT    NOT NULL,
                   version TEXT    NOT NULL,
                   ok      INTEGER NOT NULL,
                   reason  TEXT    NOT NULL DEFAULT '',
                   elapsed REAL    NOT NULL DEFAULT 0
               )"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_product ON events(product)")
        # 机器码（CMID）是后加的列：老库要能平滑升上来，不能要求用户删库
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(events)")}
        if "cmid" not in cols:
            self.db.execute("ALTER TABLE events ADD COLUMN cmid TEXT NOT NULL DEFAULT ''")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_events_cmid ON events(cmid)")
        # 执法流水：谁在什么时候因为什么被封/解封，以及 Steward 那边的结果
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS enforce (
                   ts      INTEGER NOT NULL,
                   ip      TEXT    NOT NULL,
                   action  TEXT    NOT NULL,   -- ban / unban
                   reason  TEXT    NOT NULL,
                   detail  TEXT    NOT NULL DEFAULT '',
                   ok      INTEGER NOT NULL,
                   response TEXT   NOT NULL DEFAULT ''
               )"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_enforce_ts ON enforce(ts)")
        # 账户事件：登录、失败、增删改，都留个痕（统计库现成，不必再搞一套日志）
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS auth (
                   ts      INTEGER NOT NULL,
                   name    TEXT    NOT NULL,
                   ip      TEXT    NOT NULL,
                   action  TEXT    NOT NULL,
                   ok      INTEGER NOT NULL,
                   detail  TEXT    NOT NULL DEFAULT ''
               )"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth(ts)")
        self.db.commit()

    def record_auth(self, name, ip, action, ok, detail=""):
        with self.lock:
            self.db.execute("INSERT INTO auth (ts, name, ip, action, ok, detail) VALUES (?,?,?,?,?,?)",
                            (int(time.time()), name or "?", ip or "", action, 1 if ok else 0,
                             (detail or "")[:200]))
            self.db.commit()

    def auth_log(self, limit=60):
        with self.lock:
            rows = self.db.execute("SELECT * FROM auth ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r["ts"], "name": r["name"], "ip": r["ip"], "action": r["action"],
                 "ok": bool(r["ok"]), "detail": r["detail"]} for r in rows]

    def add(self, ts: int, ip, product, version, ok, reason="", elapsed=0.0, cmid=""):
        with self.lock:
            self.db.execute(
                "INSERT INTO events (ts, ip, product, version, ok, reason, elapsed, cmid) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ts, ip, product, version, 1 if ok else 0, reason, elapsed, cmid or ""),
            )
            self.db.commit()

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.db_path) + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    def prune(self):
        """配额/保留期到了就滚动删最旧的，再增量回收空间。内存占用不随数据量变化。"""
        removed = 0
        if self.retention_days:
            cutoff = int((datetime.now() - timedelta(days=self.retention_days)).timestamp())
            with self.lock:
                cur = self.db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                removed += cur.rowcount
                self.db.commit()
        if self.quota_bytes and self.size_bytes() > self.quota_bytes:
            with self.lock:
                total = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if total:
                    # 一次砍掉 5%，避免每来一行就 VACUUM
                    cut = self.db.execute(
                        "SELECT ts FROM events ORDER BY ts LIMIT 1 OFFSET ?", (max(1, int(total * 0.05)),)
                    ).fetchone()
                    if cut:
                        cur = self.db.execute("DELETE FROM events WHERE ts < ?", (cut["ts"],))
                        removed += cur.rowcount
                        self.db.commit()
                self.db.execute("PRAGMA incremental_vacuum")
        return removed

    def clear(self):
        """清空全部激活记录（表结构与配额设置保留），顺手把磁盘空间还回去。"""
        with self.lock:
            removed = self.db.execute("DELETE FROM events").rowcount
            self.db.commit()
            self.db.execute("PRAGMA incremental_vacuum")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed

    # --- 限流：按 IP / 机器码统计窗口内的激活次数 --------------------------
    def counts(self, since_ts, by="ip", limit=20):
        col = "cmid" if by == "cmid" else "ip"
        with self.lock:
            rows = self.db.execute(
                "SELECT %s AS k, COUNT(*) AS n, SUM(ok) AS ok, MAX(ts) AS last FROM events "
                "WHERE ts >= ? AND %s <> '' GROUP BY %s ORDER BY n DESC, last DESC LIMIT ?"
                % (col, col, col), (since_ts, limit)).fetchall()
        return [{"key": r["k"], "n": r["n"], "ok": r["ok"] or 0, "last": r["last"]} for r in rows]

    def ips_of_cmid(self, cmid, since_ts):
        with self.lock:
            rows = self.db.execute(
                "SELECT ip, COUNT(*) AS n FROM events WHERE cmid = ? AND ts >= ? "
                "GROUP BY ip ORDER BY n DESC", (cmid, since_ts)).fetchall()
        return [{"ip": r["ip"], "n": r["n"]} for r in rows]

    def total_since(self, since_ts):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?",
                                   (since_ts,)).fetchone()[0]

    # --- 执法流水 ---------------------------------------------------------
    def record_enforce(self, ip, action, reason, ok, detail="", response=""):
        with self.lock:
            self.db.execute(
                "INSERT INTO enforce (ts, ip, action, reason, detail, ok, response) "
                "VALUES (?,?,?,?,?,?,?)",
                (int(time.time()), ip, action, reason, detail[:200], 1 if ok else 0,
                 (response or "")[:400]),
            )
            self.db.commit()

    def enforce_state(self):
        """每个 IP 当前的执法状态：取该 IP 最后一条记录。ban=在封，unban=已解封。"""
        with self.lock:
            rows = self.db.execute(
                "SELECT e.* FROM enforce e JOIN (SELECT ip, MAX(ts) mts FROM enforce GROUP BY ip) m "
                "ON e.ip = m.ip AND e.ts = m.mts ORDER BY e.ts DESC").fetchall()
        return [{"ts": r["ts"], "ip": r["ip"], "action": r["action"], "reason": r["reason"],
                 "detail": r["detail"], "ok": bool(r["ok"]), "response": r["response"]}
                for r in rows]

    def enforce_log(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT * FROM enforce ORDER BY ts DESC LIMIT ?",
                                   (limit,)).fetchall()
        return [{"ts": r["ts"], "ip": r["ip"], "action": r["action"], "reason": r["reason"],
                 "detail": r["detail"], "ok": bool(r["ok"]), "response": r["response"]}
                for r in rows]

    def summary(self):
        day_start = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        with self.lock:
            total, = self.db.execute("SELECT COUNT(*) FROM events").fetchone()
            today, = self.db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (day_start,)).fetchone()
            today_ok, = self.db.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ? AND ok = 1", (day_start,)
            ).fetchone()
            clients, = self.db.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts >= ?",
                                       (day_start - 30 * 86400,)).fetchone()
            first, last = self.db.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return {
            "total": total, "today": today, "today_ok": today_ok,
            "clients_30d": clients,
            "first": datetime.fromtimestamp(first).strftime("%Y-%m-%d") if first else None,
            "last": datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M:%S") if last else None,
            "storage_bytes": self.size_bytes(),
            "quota_bytes": self.quota_bytes,
        }

    def series(self, days=30):
        start = int((datetime.now() - timedelta(days=days - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0).timestamp())
        rows = self.db.execute(
            """SELECT date(ts, 'unixepoch', 'localtime') d,
                      SUM(ok) ok, COUNT(*) total
                 FROM events WHERE ts >= ? GROUP BY d ORDER BY d""", (start,)
        ).fetchall()
        return [{"day": r["d"], "ok": r["ok"], "fail": r["total"] - r["ok"]} for r in rows]

    def top(self, by="product", days=30, limit=8):
        start = int((datetime.now() - timedelta(days=days)).timestamp())
        col = {"product": "product", "ip": "ip", "version": "version", "reason": "reason"}[by]
        where = f"WHERE ts >= ? AND {col} <> ''"
        rows = self.db.execute(
            f"SELECT {col} k, COUNT(*) n, SUM(ok) ok FROM events {where} GROUP BY k ORDER BY n DESC LIMIT ?",
            (start, limit),
        ).fetchall()
        return [{"key": r["k"], "n": r["n"], "ok": r["ok"]} for r in rows]

    def page(self, page=1, per=50, days=30, q="", result="", product=""):
        start = int((datetime.now() - timedelta(days=days)).timestamp())
        where, args = ["ts >= ?"], [start]
        if q:
            where.append("(ip LIKE ? OR product LIKE ? OR version LIKE ?)")
            args += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if result == "ok":
            where.append("ok = 1")
        elif result == "fail":
            where.append("ok = 0")
        if product:
            where.append("product = ?")
            args.append(product)
        sql_where = " AND ".join(where)
        total = self.db.execute(f"SELECT COUNT(*) FROM events WHERE {sql_where}", args).fetchone()[0]
        rows = self.db.execute(
            f"""SELECT ts, ip, product, version, ok, reason, elapsed FROM events
                 WHERE {sql_where} ORDER BY ts DESC LIMIT ? OFFSET ?""",
            args + [per, (page - 1) * per],
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "time": datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
                "ip": r["ip"], "product": r["product"], "version": r["version"],
                "ok": bool(r["ok"]), "reason": r["reason"], "elapsed": round(r["elapsed"], 3),
            })
        return {"total": total, "page": page, "per": per, "rows": out}


# --------------------------------------------------------------------------
# 演示后端：假服务 + 合成流量（demo 模式下跑这个）
# --------------------------------------------------------------------------
class DemoBackend:
    real = False
    # 演示模式下只是把真机模式的字段补齐，好让前端两条路径长得一样
    UNIT = "vlmcsd"
    INI = Path("/etc/vlmcsd.ini")

    def __init__(self, store: StatsStore):
        self.store = store
        self.config = dict(DEMO_CONFIG)
        self.previous = None
        self.running = True
        self.started_at = time.time() - 3 * 86400 - 4 * 3600
        self.log_lines = []
        self.pending_reload = False
        subnets = ["192.168.1.", "192.168.1.", "10.0.0.", "172.16.5."]
        self.ips = [f"{random.choice(subnets)}{random.randint(2, 250)}" for _ in range(46)]
        self._log("vlmcsd 1113 (demo), built with: THREADS=1 NO_DNS=1", "info")
        self._log("Listening on 0.0.0.0:1688, [::]:1688", "info")
        threading.Thread(target=self._traffic, daemon=True).start()

    # --- helpers ---------------------------------------------------------
    def _log(self, msg, level="info"):
        self.log_lines.append({"t": now_iso(), "level": level, "msg": msg})
        del self.log_lines[:-400]

    def _traffic(self):
        """合成激活流量：启动时补一批历史数据，之后每隔几秒来一条。"""
        self._seed_history()
        while True:
            time.sleep(random.uniform(5, 14))
            self._one_event()

    def _seed_history(self):
        if self.store.summary()["total"] > 0:
            return
        self._log("seeding 30 days of synthetic activation history", "info")
        end = time.time()
        for day in range(30, -1, -1):
            count = random.randint(6, 34)
            if datetime.fromtimestamp(end - day * 86400).weekday() >= 5:
                count = int(count * 0.4)
            for _ in range(count):
                ts = int(end - day * 86400 + random.uniform(7 * 3600, 20 * 3600))
                if ts > time.time():
                    ts = int(time.time()) - random.randint(60, 3600)
                self._insert(ts, quiet=True)

    def _insert(self, ts, quiet=False):
        product, epid = random.choice(PRODUCTS)
        ip = random.choice(self.ips)
        ok = random.random() > 0.08
        reason = "" if ok else random.choice(FAIL_REASONS)
        version = random.choice(CLIENT_VERSIONS)
        elapsed = round(random.uniform(0.004, 0.09), 3)
        self.store.add(ts, ip, product, version, ok, reason, elapsed)
        if not quiet:
            if ok:
                self._log(f"Connection from {ip}: RPC bind ok, ePID {epid[:12]}..., {product}: success "
                          f"({elapsed * 1000:.0f} ms)", "ok")
            else:
                self._log(f"Connection from {ip}: {product}: rejected - {reason}", "warn")

    def _one_event(self):
        if not self.running:
            return
        self._insert(int(time.time()))

    # --- API surface -----------------------------------------------------
    def status(self):
        return {
            "available": True,
            "unit": self.UNIT,
            "ini": str(self.INI),
            "running": self.running,
            "since": datetime.fromtimestamp(self.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": int(time.time() - self.started_at),
            "pid": 4242 if self.running else None,
            "version": "vlmcsd 1113 (demo)",
            "build": "clang 15.0 · x86_64 Linux musl PIE (演示数据)",
            "binary": "/usr/local/bin/vlmcsd",
            "sha256": "3f9c1d0e7a5b46c2e8f1a9d3b7c5e2f4a6b8d0c2e4f6a8b0c2d4e6f8a0b2c4d6",
            "reload_pending": self.pending_reload,
        }

    def read_config(self):
        return dict(self.config)

    def validate(self, patch):
        clean, errors = {}, []
        for f in FIELD_SCHEMA:
            if f["key"] not in patch:
                continue
            v = patch[f["key"]]
            if f["type"] == "int":
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    errors.append(f"{f['label']}: 必须是整数")
                    continue
                if not (f["min"] <= v <= f["max"]):
                    errors.append(f"{f['label']}: 需在 {f['min']}~{f['max']} 之间")
                    continue
            elif f["type"] == "bool":
                v = bool(v)
            elif f["type"] == "choice":
                v = str(v)
                if v not in [c[0] for c in f["choices"]]:
                    errors.append(f"{f['label']}: 取值不合法")
                    continue
            else:
                v = str(v).strip()
            clean[f["key"]] = v
        if "Listen" in clean and clean["Listen"]:
            if not re.match(r"^[0-9a-fA-F:.\[\]]+:\d{1,5}$", clean["Listen"]):
                errors.append("监听地址: 需要 IP:端口 形式，例如 0.0.0.0:1688")
        return clean, errors

    def save_config(self, patch):
        clean, errors = self.validate(patch)
        if errors:
            return {"ok": False, "errors": errors}
        self.previous = dict(self.config)
        self.config.update(clean)
        changed = ", ".join(f"{k}={v}" for k, v in clean.items())
        self._log(f"config written to /etc/vlmcsd.ini: {changed}", "info")
        self.pending_reload = True
        time.sleep(0.15)
        self._log("SIGHUP sent, vlmcsd reloaded configuration (现有客户端未断开)", "ok")
        self.pending_reload = False
        return {"ok": True, "applied": clean, "reloaded": True, "restart_required": False}

    def rollback(self):
        if not self.previous:
            return {"ok": False, "errors": ["还没有可回滚的上一份配置"]}
        self.config, self.previous = self.previous, dict(self.config)
        self._log("rolled back to the previous configuration and sent SIGHUP", "warn")
        return {"ok": True, "config": dict(self.config)}

    def service(self, action):
        if action == "start":
            self.running, self.started_at = True, time.time()
            self._log("Started vlmcsd (demo).", "ok")
        elif action == "stop":
            self.running = False
            self._log("Stopped vlmcsd (demo).", "warn")
        elif action == "restart":
            self.running, self.started_at = True, time.time()
            self._log("Restarted vlmcsd (demo).", "ok")
        else:
            return {"ok": False, "errors": [f"未知动作 {action}"]}
        return {"ok": True, "status": self.status()}

    def logs(self, lines=200):
        return self.log_lines[-lines:][::-1]

    def execstart(self):
        c = self.config
        # -v 是无参开关，不能写成 "-v 3"（那样 vlmcsd 会当成多余的参数直接报用法退出）
        cmd = [f"/usr/local/bin/vlmcsd -D -e -T0 -P {c['Port']}",
               f"-L {c['Listen']}",
               f"-m {c['MaxWorkers']}",
               f"-t {c['MaxIdleTime']}",
               f"-K{c['WhitelistingLevel']}",
               f"-c{1 if truthy(c['CheckClientTime']) else 0}",
               f"-l {c['LogFile']}"]
        if truthy(c.get("LogVerbose", True)):
            cmd.append("-v")
        return " ".join(cmd)


# --------------------------------------------------------------------------
# 真机后端：真的读写 ini / SIGHUP / systemctl / journalctl
# 说明：以下路径未在真机验证过（本机是 Windows），进仓库后会有一轮真机验收。
# --------------------------------------------------------------------------
class LinuxBackend:
    real = True
    manager = "systemd"          # 面板上显示用的进程管理器名
    # 被管理程序的默认身份；可用 --unit / --ini 覆盖，改的只是"去哪里找 vlmcsd"
    UNIT = "vlmcsd"
    INI = Path("/etc/vlmcsd.ini")

    def __init__(self, store: StatsStore, unit: str = "", ini: str = ""):
        self.store = store
        self.UNIT = unit or self.UNIT
        self.INI = Path(ini) if ini else self.INI
        self.log_lines = []
        self.previous = None
        self._ini_extra = []
        self._bin_cache = {}
        self._block = []          # 正在累计的那次连接日志块
        self._tail_thread = None
        self.available = self._detect_service()
        threading.Thread(target=self._tail, daemon=True).start()

    # --- 与 systemd 打交道的小工具（任何失败都不抛异常，只如实报告） -------
    def _detect_service(self) -> bool:
        """能 systemctl cat 到这个单元就算"服务在"；没有 systemctl 也只是返回 False。"""
        try:
            r = subprocess.run(["systemctl", "cat", self.UNIT],
                               capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0

    def _systemctl(self, *argv, timeout=20):
        """统一的 systemctl 调用：返回 (CompletedProcess|None, stderr 文本)，从不抛异常。"""
        try:
            r = subprocess.run(["systemctl", *argv], capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return None, f"systemctl 调用失败：{e}"
        return r, (r.stderr or "").strip()

    def _missing_hint(self) -> str:
        return (f"未检测到 KMS 服务：systemd 单元 {self.UNIT} 不存在（没装 vlmcsd，或单元名不对）。"
                f"面板其余功能照常可用。")

    # --- 被管理二进制：路径 / 版本 / 构建信息 / sha256 ---------------------
    def _binary_info(self):
        """问二进制自己的版本，别在面板里写死。

        vlmcsd -V 会打印 "vlmcsd <git 描述> 64-bit" 加编译器与目标平台。面板每 5
        秒轮询一次状态，所以按 (路径, mtime) 缓存，不用每次都开进程 + 读整份文件。
        """
        path = ""
        for cand in (shutil.which("vlmcsd"), "/usr/local/bin/vlmcsd",
                     "/usr/bin/vlmcsd", "/usr/sbin/vlmcsd"):
            if cand and Path(cand).exists():
                path = cand
                break
        if not path:
            return {"path": "", "version": "", "build": "", "sha256": None}
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            mtime = 0
        cached = self._bin_cache
        if cached.get("path") == path and cached.get("mtime") == mtime:
            return cached
        version = build = ""
        try:
            r = subprocess.run([path, "-V"], capture_output=True, text=True, timeout=10)
            lines = [l.strip() for l in ((r.stdout or "") + "\n" + (r.stderr or "")).splitlines()
                     if l.strip()]
            if lines:
                version = lines[0]
            parts = []
            for line in lines:
                if line.startswith("Compiler:"):
                    parts.append(line.split(":", 1)[1].strip())
                elif line.startswith("Intended platform:"):
                    parts.append(line.split(":", 1)[1].strip())
            build = " · ".join(parts)
        except (OSError, subprocess.SubprocessError):
            pass
        info = {"path": path, "version": version, "build": build,
                "sha256": _sha256(Path(path)), "mtime": mtime}
        self._bin_cache = info
        return info

    # --- ini -------------------------------------------------------------
    def read_config(self):
        cfg = dict(DEMO_CONFIG)
        self._ini_extra = []
        if self.INI.exists():
            for line in self.INI.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";")) or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip().lower() in LEGACY_INI_KEYS:
                    continue
                key = KEY_BY_INI.get(k.strip().lower())
                if not key:
                    self._ini_extra.append((k.strip(), v.strip()))
                    continue
                v = v.strip()
                cfg[key] = truthy(v) if FIELD_BY_KEY[key]["type"] == "bool" else v
        return cfg

    def _write_ini(self, cfg):
        body = ["; managed by nimbus", f"; updated {now_iso()}", ""]
        for f in FIELD_SCHEMA:
            body.append(f"; {f['help']}")
            body.append(f"{INI_NAME[f['key']]} = {ini_value(f, cfg.get(f['key'], f['default']))}")
            body.append("")
        # 面板没暴露的键（RandomizationLevel / ActivationInterval / KmsData ...）
        # 原样写回：保存一次参数就把手写的高级配置抹掉，是绝对不能接受的。
        extra = getattr(self, "_ini_extra", [])
        if extra:
            body.append("; 以下键由手工维护，面板只读不写")
            for k, v in extra:
                body.append(f"{k} = {v}")
            body.append("")
        tmp = Path(str(self.INI) + ".tmp")
        tmp.write_text("\n".join(body), encoding="utf-8")
        shutil.copy2(self.INI, str(self.INI) + ".bak") if self.INI.exists() else None
        os.replace(tmp, self.INI)

    def validate(self, patch):
        return DemoBackend.validate(self, patch)

    def save_config(self, patch):
        clean, errors = self.validate(patch)
        if errors:
            return {"ok": False, "errors": errors}
        if not self.available and not self._detect_service():
            return {"ok": False, "errors": [self._missing_hint()]}
        self.previous = self.read_config()
        cfg = dict(self.previous)
        cfg.update(clean)
        self._write_ini(cfg)
        needs_restart = "Port" in clean or "Listen" in clean
        if needs_restart:
            self._systemctl("restart", self.UNIT, timeout=20)
        else:
            self._systemctl("kill", "-s", "HUP", self.UNIT, timeout=10)
        return {"ok": True, "applied": clean, "reloaded": not needs_restart, "restart_required": needs_restart}

    def rollback(self):
        if not self.previous:
            return {"ok": False, "errors": ["还没有可回滚的上一份配置"]}
        self._write_ini(self.previous)
        self._systemctl("restart", self.UNIT, timeout=20)
        self.previous = None
        return {"ok": True, "config": self.read_config()}

    def status(self):
        # 单元可能是刚装上的：没检测到就每次重新探一次，装好 vlmcsd 后不用重启面板
        if not self.available:
            self.available = self._detect_service()
        if not self.available:
            return {
                "available": False, "unit": self.UNIT, "ini": str(self.INI),
                "manager": self.manager,
                "running": False, "pid": None, "since": None, "uptime": None,
                "version": None, "build": "", "binary": None, "sha256": None,
                "reload_pending": False, "hint": self._missing_hint(),
            }
        r_active, _ = self._systemctl("is-active", self.UNIT, timeout=10)
        r_show, _ = self._systemctl("show", self.UNIT, "-p", "MainPID",
                                    "-p", "ActiveEnterTimestamp", timeout=10)
        active = r_active.stdout.strip() if r_active else ""
        info = r_show.stdout if r_show else ""
        pid = re.search(r"MainPID=(\d+)", info)
        since = re.search(r"ActiveEnterTimestamp=(.+)", info)
        binfo = self._binary_info()
        return {
            "available": True, "unit": self.UNIT, "ini": str(self.INI),
            "manager": self.manager,
            "running": active == "active",
            "pid": int(pid.group(1)) if pid and pid.group(1) != "0" else None,
            "since": since.group(1).strip() if since else None,
            "uptime": None,
            "version": binfo["version"],          # 真的去问二进制，别写死
            "build": binfo["build"],
            "binary": binfo["path"],
            "sha256": binfo["sha256"],
            "reload_pending": False,
        }

    def service(self, action):
        if action not in ("start", "stop", "restart"):
            return {"ok": False, "errors": [f"未知动作 {action}"]}
        if not self.available and not self._detect_service():
            return {"ok": False, "errors": [self._missing_hint()], "status": self.status()}
        r, err = self._systemctl(action, self.UNIT, timeout=30)
        if r is None:
            return {"ok": False, "errors": [err], "status": self.status()}
        return {"ok": r.returncode == 0, "errors": [err] if r.returncode and err else [],
                "status": self.status()}

    def logs(self, lines=200):
        if not self.available and not self._detect_service():
            return [{"t": "", "level": "warn", "msg": self._missing_hint()}]
        try:
            r = subprocess.run(["journalctl", "-u", self.UNIT, "-n", str(lines), "--no-pager", "-o", "cat"],
                               capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:
            return [{"t": "", "level": "warn", "msg": f"journalctl 不可用：{e}"}]
        out = []
        for line in r.stdout.splitlines()[::-1]:
            level = "warn" if re.search(r"error|fail|reject", line, re.I) else "ok" if "success" in line.lower() else "info"
            out.append({"t": "", "level": level, "msg": line})
        return out

    def execstart(self):
        r, err = self._systemctl("show", self.UNIT, "-p", "ExecStart", timeout=10)
        if r is None:
            return err
        return r.stdout.strip()

    # --- 日志 → 统计 ------------------------------------------------------
    # vlmcsd 的一次激活在日志里是一个块，形如：
    #   IPv4 connection accepted: 10.0.0.5:52211.
    #   <<< Incoming KMS request
    #   Protocol version                : 6.0
    #   Application ID                  : <guid> (Windows)
    #   SKU ID (aka Activation ID)      : <guid> (Windows Server 2019 ARM64)
    #   KMS ID (aka KMS counted ID)     : <guid> (Windows Server 2019)
    #   Client machine ID               : <guid>
    #   >>> Sending response, ePID source = randomized at program start
    #   IPv4 connection closed: 10.0.0.5:52211.
    # 所以按块累计、看到 closed 才落库。systemd（journalctl）与容器（日志文件）
    # 两条链路共用这套解析，别再各写一份。
    ACCEPT_RE = re.compile(r"IPv4 connection accepted: (?P<ip>[\d.]+):(?P<port>\d+)")
    CLOSE_RE = re.compile(r"IPv4 connection closed: (?P<ip>[\d.]+):\d+")
    # 三行产品信息，越往下越具体。界面要的是「哪个 Windows」，所以优先取 SKU：
    #   Application ID : <guid> (Windows)                      ← 产品族
    #   SKU ID         : <guid> (Windows Server 2019 ARM64)    ← 具体版本
    #   KMS ID         : <guid> (Windows Server 2019)
    PRODUCT_RE = re.compile(r"Application ID\s*:\s*\S+\s*\((?P<product>[^)]+)\)")
    SKU_RE = re.compile(r"SKU ID[^:]*:\s*\S+\s*\((?P<sku>[^)]+)\)")
    KMSID_RE = re.compile(r"KMS ID[^:]*:\s*\S+\s*\((?P<kms>[^)]+)\)")
    PROTO_RE = re.compile(r"Protocol version\s*:\s*(?P<ver>[\d.]+)")
    CMID_RE = re.compile(r"Client machine ID\s*:\s*(?P<cmid>[0-9a-fA-F][0-9a-fA-F-]{10,40})")
    SENT_RE = re.compile(r">>>\s*Sending response")
    REJECT_RE = re.compile(r"(reject|not licensed|error|fail)", re.I)
    # 只有 "accepted" + "closed"、中间没有任何请求体的连接，是端口探活（监控健康检查、
    # 扫描器）。它不该被记成一次"失败的激活"，否则面板上的失败数全是噪声。
    PAYLOAD_RE = re.compile(r"<<<|Application ID|Client machine ID|Sending response|"
                            r"reject|not licensed|error|fail", re.I)

    def _level_of(self, line: str) -> str:
        if re.search(r"error|fail|reject", line, re.I):
            return "warn"
        if "success" in line.lower():
            return "ok"
        return "info"

    @staticmethod
    def _named(match):
        """取括号里的名字；vlmcsd 认不出来时会写 (Unknown)，那种不算数。"""
        if not match:
            return ""
        name = (match.group(1) or "").strip()
        return "" if name.lower() == "unknown" else name

    def _event_from_block(self, block):
        """把一个连接块变成一条统计记录；不是一个完整块就返回 None。"""
        m = self.ACCEPT_RE.search(block)
        if not m:
            return None
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if not self.PAYLOAD_RE.search(block):
            # 只有 accepted + closed、中间什么都没有 = 端口探活（监控、扫描器），不入库。
            # 但中间只要还有别的行，就说明确实发生过什么：哪怕没解析出请求体也要记下来，
            # 否则"客户端连上了但失败"会变成面板上完全看不见的空白。
            if len(lines) <= 2:
                return None
            note = lines[1][:100] if len(lines) > 1 else ""
            reason = "连接里没有 KMS 请求内容" + ("：" + note if note else "")
            return m.group("ip"), "", "", False, reason
        ip = m.group("ip")
        ok = bool(self.SENT_RE.search(block))
        product = (self._named(self.SKU_RE.search(block))
                   or self._named(self.KMSID_RE.search(block))
                   or self._named(self.PRODUCT_RE.search(block)))
        product = _alias_product(product)
        pv = self.PROTO_RE.search(block)
        version = ("v%s" % pv.group("ver")) if pv else ""
        cm = self.CMID_RE.search(block)
        cmid = cm.group("cmid").lower() if cm else ""
        reason = ""
        if not ok:
            bad = [ln for ln in block.splitlines() if self.REJECT_RE.search(ln)]
            reason = (bad[0] if bad else block.strip().splitlines()[-1] if block.strip() else "")[:120]
        return ip, cmid, product, version, ok, reason

    def _feed(self, line):
        """喂一行日志进来：accepted 开块，closed 收块入库。"""
        if not line:
            return
        self.log_lines.append({"t": now_iso(), "level": self._level_of(line), "msg": line})
        del self.log_lines[:-400]
        if self.ACCEPT_RE.search(line):
            self._block = [line]
            return
        if self._block:
            self._block.append(line)
            if self.CLOSE_RE.search(line):
                ev = self._event_from_block("\n".join(self._block))
                if ev:
                    ip, cmid, product, version, ok, reason = ev
                    self.store.add(int(time.time()), ip, product, version, ok, reason, cmid=cmid)
                self._block = []

    def _tail(self):
        """journalctl -f 跟着 systemd 单元读日志。"""
        while True:
            if not self.available and not self._detect_service():
                time.sleep(10)  # 还没装 vlmcsd：安静等待，别刷屏
                continue
            try:
                proc = subprocess.Popen(["journalctl", "-u", self.UNIT, "-f", "-n", "0", "-o", "cat"],
                                        stdout=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    self._feed(line.rstrip())
            except Exception:  # noqa: BLE001
                pass
            time.sleep(5)


class _UnixRPCTransport(xmlrpc.client.Transport):
    """让 xmlrpc.client 走 unix socket。

    supervisord 的 RPC 只监听 /run/supervisor.sock。以前每次都 fork 一个
    supervisorctl 去问状态，实测一次 0.22 秒（要起一个 Python 解释器），而面板
    每 5 秒就要问两三次 —— 上 RPC 之后是毫秒级。
    """

    def __init__(self, path):
        super().__init__()
        self.path = path

    def make_connection(self, host):
        path = self.path

        class _Conn(http.client.HTTPConnection):
            def __init__(self):
                super().__init__("localhost")

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(5)
                self.sock.connect(path)

        return _Conn()


# --------------------------------------------------------------------------
# 容器后端：容器里没有 systemd / journald，改用 supervisord
# --------------------------------------------------------------------------
class ContainerBackend(LinuxBackend):
    """supervisord 版真机后端（Docker 部署用）。

    容器里既没有 systemd 也没有 journald，所以：
      * 进程控制走 supervisorctl —— 这里把父类使用的 systemctl 语义就地翻译
        过去，因此父类的 save_config / rollback / service / status / execstart
        一行都不用改；
      * 日志改成读文件（vlmcsd 用 "-l /var/log/vlmcsd.log" 写文件），统计线程
        用 python 按行轮询文件增量，效果等同 journalctl -f。
    """

    manager = "supervisord"
    PROGRAM = "vlmcsd"
    # supervisorctl 是独立进程，只认 -c 指定的那份配置。alpine 里主配置不在
    # supervisorctl 的默认查找路径上，不显式传它就会去找 /run/supervisord.sock
    # （不存在），于是所有状态查询都失败。
    SUPERVISOR_CONF = "/etc/supervisor/supervisord.conf"

    def __init__(self, store, unit="", ini="", log_file=""):
        self.log_file = Path(log_file) if log_file else Path("/var/log/vlmcsd.log")
        self._info_cache = None          # (时间戳, getProcessInfo 结果)
        super().__init__(store, unit, ini)

    # --- supervisord 的 XML-RPC（热路径，比 fork supervisorctl 快两个数量级）--
    def _supervisor_sock(self):
        """从主配置里读 unix_http_server 的 socket 路径。"""
        try:
            txt = self.SUPERVISOR_CONF and Path(self.SUPERVISOR_CONF).read_text(
                encoding="utf-8", errors="replace") or ""
        except OSError:
            txt = ""
        m = re.search(r"(?ms)^\s*\[unix_http_server\]\s*$(.*?)(?=^\s*\[|\Z)", txt)
        if m:
            f = re.search(r"(?m)^\s*file\s*=\s*(\S+)", m.group(1))
            if f:
                return f.group(1)
        return "/run/supervisor.sock"

    def _sup_rpc(self):
        """连不上就返回 None，调用方自动退回 supervisorctl。"""
        sock = self._supervisor_sock()
        try:
            if not Path(sock).exists():
                return None
            return xmlrpc.client.ServerProxy("http://localhost/RPC2",
                                             transport=_UnixRPCTransport(sock))
        except Exception:  # noqa: BLE001
            return None

    def _process_info(self):
        """getProcessInfo 的结果，缓存 1.5 秒（一次页面刷新会问好几次状态）。"""
        now = time.time()
        if self._info_cache and now - self._info_cache[0] < 1.5:
            return self._info_cache[1]
        info = None
        proxy = self._sup_rpc()
        if proxy is not None:
            try:
                info = dict(proxy.supervisor.getProcessInfo(self.PROGRAM))
            except Exception:  # noqa: BLE001
                info = None
        if info is None:
            r, _ = self._sup("status", self.PROGRAM, timeout=10)
            if r is None or r.returncode != 0:
                self._info_cache = (now, None)
                return None
            out = r.stdout or ""
            state = re.search(r"\b(RUNNING|STOPPED|STARTING|BACKOFF|STOPPING|EXITED|FATAL)\b", out)
            pid = re.search(r"pid (\d+)", out)
            up = re.search(r"uptime (\d+):(\d+):(\d+)", out)
            secs = (int(up.group(1)) * 3600 + int(up.group(2)) * 60 + int(up.group(3))) if up else 0
            info = {"statename": state.group(1) if state else "UNKNOWN",
                    "pid": int(pid.group(1)) if pid else 0,
                    "start": int(now - secs) if secs else 0}
        self._info_cache = (now, info)
        return info

    # --- supervisorctl 基础调用 ------------------------------------------
    def _sup(self, *argv, timeout=20):
        cmd = ["supervisorctl"]
        conf = Path(self.SUPERVISOR_CONF)
        if conf.exists():
            cmd += ["-c", str(conf)]
        try:
            r = subprocess.run(cmd + list(argv), capture_output=True,
                               text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return None, f"supervisorctl 调用失败：{e}"
        return r, (r.stderr or "").strip()

    @staticmethod
    def _done(argv, returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def _detect_service(self) -> bool:
        if self._process_info() is not None:
            return True
        if not shutil.which("supervisorctl"):
            return False
        r, _ = self._sup("status", self.PROGRAM, timeout=10)
        return r is not None and r.returncode == 0

    def _missing_hint(self) -> str:
        return (f"未检测到 KMS 服务：supervisord 里没有名为 {self.PROGRAM} 的程序。"
                f"面板其余功能照常可用。")

    def _command_line(self) -> str:
        for conf in ("/etc/supervisor/conf.d/vlmcsd.conf",
                     "/etc/supervisord.d/vlmcsd.conf"):
            p = Path(conf)
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip().startswith("command="):
                        return line.split("=", 1)[1].strip()
        return f"/usr/local/bin/{self.PROGRAM} (managed by supervisord)"

    # --- 把 systemctl 的调用翻译成 supervisorctl -------------------------
    def _systemctl(self, *argv, timeout=20):
        if not argv:
            return None, "空调用"
        action, rest = argv[0], list(argv[1:])

        if action == "cat":
            return self._sup("status", self.PROGRAM, timeout=timeout)

        if action == "is-active":
            info = self._process_info()
            if info is None:
                return None, "supervisord 里没有名为 %s 的程序" % self.PROGRAM
            active = info.get("statename") == "RUNNING"
            return self._done(argv, 0 if active else 3,
                              "active\n" if active else "inactive\n"), ""

        if action == "show":
            props = [a for a in rest if not a.startswith("-")]
            info = self._process_info() or {}
            lines = []
            if any("MainPID" in p for p in props):
                lines.append("MainPID=%s" % (info.get("pid") or 0))
            if any("ActiveEnterTimestamp" in p for p in props):
                start = info.get("start") or 0
                since = ""
                if start:
                    since = "%s (up %s)" % (
                        datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S"),
                        _dur_text(int(time.time() - start)))
                lines.append("ActiveEnterTimestamp=%s" % since)
            if any("ExecStart" in p for p in props):
                lines.append("ExecStart=%s" % self._command_line())
            return self._done(argv, 0, "\n".join(lines) + "\n"), ""

        if action in ("start", "stop", "restart"):
            return self._sup(action, self.PROGRAM, timeout=timeout)

        if action == "kill":
            sig = "HUP"
            if "-s" in rest and rest.index("-s") + 1 < len(rest):
                sig = rest[rest.index("-s") + 1]
            r, err = self._sup("signal", sig, self.PROGRAM, timeout=timeout)
            if r is not None and r.returncode == 0:
                return r, err
            # supervisorctl signal 不被支持时退回直接给进程发信号
            try:
                pr = subprocess.run(["pkill", f"-{sig}", "-x", self.PROGRAM],
                                    capture_output=True, text=True, timeout=10)
                return pr, (pr.stderr or "").strip()
            except (OSError, subprocess.SubprocessError) as e:
                return None, f"发送 {sig} 失败：{e}"

        return None, f"supervisor 后端不支持的操作：{action}"

    # --- 日志：读文件而不是 journalctl -----------------------------------
    def logs(self, lines=200):
        if not self.log_file.exists():
            return [{"t": "", "level": "warn", "msg": f"日志文件还不存在：{self.log_file}"}]
        try:
            with self.log_file.open("r", encoding="utf-8", errors="replace") as fh:
                tail = fh.readlines()[-lines:]
        except OSError as e:
            return [{"t": "", "level": "warn", "msg": f"读日志失败：{e}"}]
        out = []
        for line in reversed(tail):
            line = line.rstrip()
            if line:
                out.append({"t": "", "level": self._level_of(line), "msg": line})
        return out

    def _tail(self):
        """tail -F 日志文件（vlmcsd 的 stdout 由 supervisord 落进这个文件）。"""
        while True:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                self.log_file.touch(exist_ok=True)
                with self.log_file.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(0, os.SEEK_END)
                    buf = ""
                    while True:
                        chunk = fh.read()
                        if not chunk:
                            time.sleep(1)
                            # 日志被轮转掉了就重新打开
                            try:
                                if fh.tell() > self.log_file.stat().st_size:
                                    break
                            except OSError:
                                break
                            continue
                        buf += chunk
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            self._feed(line.rstrip())
            except Exception:  # noqa: BLE001
                pass
            time.sleep(5)


# --------------------------------------------------------------------------
# 限流：Nimbus 算账（谁超了），宿主机上的 Steward 执法（ufw 封禁）
# --------------------------------------------------------------------------
# 这几段永远不封：回环与内网。KMS 客户端都是公网 IP，跳过它们不会漏掉真正的滥用，
# 但能防止「把 127.0.0.1 封了」这种自残（容器内的自测、宿主自己连自己都会中招）。
SKIP_DEFAULT = "127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
UNBAN_GRACE = 3600          # 解封之后一小时内不再自动封同一个 IP，免得封-解死循环


def parse_networks(text):
    import ipaddress
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


def is_skipped(ip, nets):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True            # 认不出来的地址一律不碰
    return any(addr in n for n in nets)


class Limiter:
    """按 IP 与机器码统计窗口内的激活次数，算出该封谁、该解封谁。

    只做判断，不动手：防火墙的权柄留在宿主机上（Steward），Nimbus 在容器里也不该有。
    判断是幂等的 —— 已封的 IP 不会重复出现在待封列表里。
    """

    def __init__(self, store, limit=10, window="day", ban_hours=24, skip=SKIP_DEFAULT):
        self.store = store
        self.limit = max(0, int(limit))
        self.window = window if window in ("hour", "day", "total") else "day"
        self.ban_hours = max(0, int(ban_hours))
        self.skip_nets = parse_networks(skip)
        self.enabled = self.limit > 0

    def window_start(self):
        now = datetime.now()
        if self.window == "hour":
            return int((now - timedelta(hours=1)).timestamp())
        if self.window == "total":
            return 0
        return int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

    def window_text(self):
        return {"hour": "最近 1 小时", "total": "累计"}.get(self.window, "今天")

    def decide(self):
        """返回 (待封, 待解封, 快照)。"""
        since = self.window_start()
        now = int(time.time())
        state = {e["ip"]: e for e in self.store.enforce_state()}
        banned = {ip for ip, e in state.items() if e["action"] == "ban" and e["ok"]}
        keep = self.ban_hours * 3600

        pending_unban = []
        for ip, e in state.items():
            if e["action"] == "unban" and not e["ok"]:
                pending_unban.append({"ip": ip, "reason": e["reason"] or "manual",
                                      "detail": e["detail"] or "面板上手动解封"})
            elif e["action"] == "ban" and e["ok"] and keep and now - e["ts"] >= keep:
                pending_unban.append({"ip": ip, "reason": "ttl",
                                      "detail": "已封禁满 %d 小时" % self.ban_hours})
        unbanning = {u["ip"] for u in pending_unban}

        targets = {}
        if self.enabled:
            for row in self.store.counts(since, "ip", 500):
                if row["n"] > self.limit and not is_skipped(row["key"], self.skip_nets):
                    targets[row["key"]] = {"reason": "ip", "count": row["n"],
                                           "detail": "该 IP %s内激活 %d 次"
                                                     % (self.window_text(), row["n"])}
            for row in self.store.counts(since, "cmid", 500):
                if row["n"] <= self.limit or len(row["key"]) < 12:
                    continue
                for used in self.store.ips_of_cmid(row["key"], since):
                    ip = used["ip"]
                    if is_skipped(ip, self.skip_nets) or ip in targets:
                        continue
                    targets[ip] = {"reason": "cmid", "count": used["n"],
                                   "detail": "机器码 %s… 在%s内被激活 %d 次"
                                             % (row["key"][:8], self.window_text(), row["n"])}

        def in_grace(ip):
            e = state.get(ip)
            return bool(e and e["action"] == "unban" and e["ok"]
                        and now - e["ts"] < UNBAN_GRACE)

        pending_ban = [dict(v, ip=ip) for ip, v in targets.items()
                       if ip not in banned and ip not in unbanning and not in_grace(ip)]

        return pending_ban, pending_unban, {
            "enabled": self.enabled, "limit": self.limit, "window": self.window,
            "window_text": self.window_text(), "ban_hours": self.ban_hours,
            "skip": [str(n) for n in self.skip_nets], "banned": sorted(banned),
            "pending_ban": pending_ban, "pending_unban": pending_unban,
        }

    def status(self, top=10):
        pending_ban, pending_unban, snap = self.decide()
        since = self.window_start()
        snap.update({
            "since": since, "now": int(time.time()),
            "total": self.store.total_since(since),
            "top_ips": [dict(r, over=self.enabled and r["n"] > self.limit,
                             skipped=is_skipped(r["key"], self.skip_nets))
                        for r in self.store.counts(since, "ip", top)],
            "top_cmids": [dict(r, over=self.enabled and r["n"] > self.limit)
                          for r in self.store.counts(since, "cmid", top)],
            "log": self.store.enforce_log(100),
            "state": self.store.enforce_state(),
        })
        return snap

    def request_unban(self, ip):
        """面板上手动解封：写一条待执行的 unban 记录，等 Steward 来取。"""
        if not ip:
            return {"ok": False, "error": "没给 IP"}
        self.store.record_enforce(ip, "unban", "manual", False, "面板手动解封", "")
        return {"ok": True, "ip": ip}


def _sha256(path: Path):
    import hashlib
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# 账户：第一次进来先设一个，之后用户名 + 密码登录
# --------------------------------------------------------------------------
PASSWORD_MIN = 8
SESSION_TTL = 7 * 86400
LOGIN_WINDOW = 300
LOGIN_MAX_FAIL = 8
LOGIN_BLOCK = 300
USER_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")
# 反向代理（比如 Caddy 容器）发来的请求，直连方是内网地址；只有这种来源才采信
# X-Forwarded-For，否则登录限流会把所有人当成同一个 IP。
TRUSTED_PROXY = ("127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password, salt=None):
    """把密码存成可校验的字符串。

    优先 scrypt（标准库自带、内存硬）；没编进 scrypt 就退回 pbkdf2。算法与参数都写在
    字符串里，将来调参不会认不出老密码。
    """
    salt = salt or os.urandom(16)
    raw = password.encode("utf-8")
    if hasattr(hashlib, "scrypt"):
        n, r, p = 1 << 14, 8, 1
        dk = hashlib.scrypt(raw, salt=salt, n=n, r=r, p=p, dklen=32)
        return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(dk))
    iters = 200000
    dk = hashlib.pbkdf2_hmac("sha256", raw, salt, iters, dklen=32)
    return "pbkdf2$%d$%s$%s" % (iters, _b64(salt), _b64(dk))


def verify_password(password, stored):
    try:
        parts = (stored or "").split("$")
        raw = password.encode("utf-8")
        if parts[0] == "scrypt" and len(parts) == 6:
            _, n, r, p, salt_b64, want_b64 = parts
            salt, want = base64.b64decode(salt_b64), base64.b64decode(want_b64)
            got = hashlib.scrypt(raw, salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(want))
        elif parts[0] == "pbkdf2" and len(parts) == 4:
            _, iters, salt_b64, want_b64 = parts
            salt, want = base64.b64decode(salt_b64), base64.b64decode(want_b64)
            got = hashlib.pbkdf2_hmac("sha256", raw, salt, int(iters), dklen=len(want))
        else:
            return False
        return _same(got.hex(), want.hex())
    except (ValueError, TypeError, IndexError):
        return False


def _same(a, b):
    """定时安全比较；compare_digest 只吃 ASCII 的 str，非 ASCII 会抛 TypeError。"""
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def _trusted_proxy_peer(ip):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in TRUSTED_PROXY)


class LoginGuard:
    """给登录失败上摩擦：同一来源在窗口内错太多次就短暂拒绝。"""

    def __init__(self, window=LOGIN_WINDOW, limit=LOGIN_MAX_FAIL, block=LOGIN_BLOCK):
        self.window, self.limit, self.block = window, limit, block
        self.fails = {}
        self.blocked_until = {}
        self.lock = threading.Lock()

    def wait_seconds(self, ip):
        now = time.time()
        with self.lock:
            until = self.blocked_until.get(ip, 0)
            if until > now:
                return int(until - now) + 1
            self.blocked_until.pop(ip, None)
            self.fails[ip] = [t for t in self.fails.get(ip, []) if now - t < self.window]
            return 0

    def fail(self, ip):
        now = time.time()
        with self.lock:
            hits = [t for t in self.fails.get(ip, []) if now - t < self.window]
            hits.append(now)
            self.fails[ip] = hits
            if len(hits) >= self.limit:
                self.blocked_until[ip] = now + self.block
                self.fails[ip] = []
                return True
        return False

    def ok(self, ip):
        with self.lock:
            self.fails.pop(ip, None)
            self.blocked_until.pop(ip, None)


class Accounts:
    """账户与会话，存一个 0600 的 JSON 文件（和服务 token 放在同一个数据目录）。"""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data = {"users": {}, "sessions": {}}
        self._load()

    def _load(self):
        try:
            if self.path.exists():
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
                self.data.setdefault("users", {})
                self.data.setdefault("sessions", {})
        except (OSError, ValueError):
            self.data = {"users": {}, "sessions": {}}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(str(self.path) + ".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.chmod(str(tmp), 0o600)
            os.replace(str(tmp), str(self.path))
        except OSError:
            pass

    def need_setup(self):
        with self.lock:
            return not self.data["users"]

    def names(self):
        with self.lock:
            return sorted(self.data["users"])

    def create(self, name, password):
        name = (name or "").strip()
        if not USER_RE.match(name):
            return False, "用户名只能 2~32 位字母、数字、下划线、点或横线"
        if len(password or "") < PASSWORD_MIN:
            return False, "密码至少 %d 位" % PASSWORD_MIN
        with self.lock:
            if name in self.data["users"]:
                return False, "这个用户名已经有了"
            self.data["users"][name] = {"hash": hash_password(password),
                                        "created": int(time.time()), "last_login": 0}
            self._save()
        return True, ""

    def set_password(self, name, password):
        if len(password or "") < PASSWORD_MIN:
            return False, "密码至少 %d 位" % PASSWORD_MIN
        with self.lock:
            u = self.data["users"].get(name)
            if not u:
                return False, "没有这个账户"
            u["hash"] = hash_password(password)
            self._save()
        return True, ""

    def delete(self, name):
        with self.lock:
            if name not in self.data["users"]:
                return False, "没有这个账户"
            if len(self.data["users"]) <= 1:
                return False, "这是最后一个账户，删了就没人能登录了"
            self.data["users"].pop(name)
            for tok in [t for t, s in self.data["sessions"].items() if s.get("user") == name]:
                self.data["sessions"].pop(tok, None)
            self._save()
        return True, ""

    def check(self, name, password):
        with self.lock:
            u = self.data["users"].get((name or "").strip())
        if not u:
            verify_password(password or "", hash_password("dummy-password"))   # 别用耗时泄露用户名是否存在
            return False
        return verify_password(password or "", u["hash"])

    def touch_login(self, name):
        with self.lock:
            if name in self.data["users"]:
                self.data["users"][name]["last_login"] = int(time.time())
                self._save()

    def listing(self):
        with self.lock:
            sessions = collections.Counter(s.get("user") for s in self.data["sessions"].values())
            return [{"name": n, "created": u.get("created", 0), "last_login": u.get("last_login", 0),
                     "sessions": sessions.get(n, 0)}
                    for n, u in sorted(self.data["users"].items())]

    def new_session(self, name, ttl=SESSION_TTL):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self._prune_locked()
            self.data["sessions"][tok] = {"user": name, "created": int(time.time()),
                                          "expires": int(time.time()) + ttl}
            self._save()
        return tok

    def session_user(self, token):
        if not token:
            return ""
        with self.lock:
            s = self.data["sessions"].get(token)
            if not s:
                return ""
            if s.get("expires", 0) < time.time():
                self.data["sessions"].pop(token, None)
                self._save()
                return ""
            return s.get("user", "")

    def drop_session(self, token):
        with self.lock:
            if self.data["sessions"].pop(token, None):
                self._save()

    def drop_user_sessions(self, name):
        with self.lock:
            victims = [t for t, s in self.data["sessions"].items() if s.get("user") == name]
            for t in victims:
                self.data["sessions"].pop(t, None)
            if victims:
                self._save()
        return len(victims)

    def _prune_locked(self):
        now = time.time()
        for t in [t for t, s in self.data["sessions"].items() if s.get("expires", 0) < now]:
            self.data["sessions"].pop(t, None)


# --------------------------------------------------------------------------
# DNS 自检：A 记录用 getaddrinfo，SRV 记录自己组包查（标准库没有 SRV 解析）
# --------------------------------------------------------------------------
def check_a(domain):
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos})
        return {"ok": True, "values": ips}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "values": []}


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii", "ignore")
    return out + b"\x00"


def check_srv(name, servers=("8.8.8.8", "1.1.1.1", "223.5.5.5"), timeout=2.0):
    """手搓一条 SRV 查询，解析回答里的 SRV 记录。网络不通就如实报错。"""
    tid = secrets.randbelow(65535)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", 33, 1)
    for srv in servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (srv, 53))
                data, _ = s.recvfrom(4096)
            return {"ok": True, "server": srv, "values": _parse_srv(data)}
        except Exception:  # noqa: BLE001
            continue
    return {"ok": False, "error": "所有 DNS 服务器都不可达（本机网络受限时正常）", "values": []}


def _parse_srv(data):
    try:
        (_tid, _flags, qd, an, _ns, _ar) = struct.unpack(">HHHHHH", data[:12])
        pos = 12
        for _ in range(qd):  # 跳过问题段
            while data[pos]:
                pos += data[pos] + 1
            pos += 5
        out = []
        for _ in range(an):
            while True:  # 名字（可能被压缩指针截断）
                ln = data[pos]
                if ln & 0xC0 == 0xC0:
                    pos += 2
                    break
                if ln == 0:
                    pos += 1
                    break
                pos += ln + 1
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 33 and rdlen >= 7:
                pri, weight, port = struct.unpack(">HHH", rdata[:6])
                target, p = [], 6
                while p < len(rdata) and rdata[p]:
                    ln = rdata[p]
                    target.append(rdata[p + 1:p + 1 + ln].decode("ascii", "replace"))
                    p += ln + 1
                out.append({"priority": pri, "weight": weight, "port": port, "target": ".".join(target) or "?"})
        return out
    except Exception:  # noqa: BLE001
        return []


# --------------------------------------------------------------------------
# Caddy：把线上真实的配置读出来、按修改写回去、让它立刻生效
# --------------------------------------------------------------------------
def _flat_name(field):
    return ", ".join("%s=%s" % (k, v) for part in (field or ()) for k, v in part)


def _parse_cert_time(s):
    """证书时间是 "Oct  8 17:31:46 2026 GMT" 这种格式。"""
    s = " ".join((s or "").split())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _cert_fields(decoded):
    out = {
        "subject": _flat_name(decoded.get("subject")),
        "issuer": _flat_name(decoded.get("issuer")),
        "not_before": decoded.get("notBefore") or "",
        "not_after": decoded.get("notAfter") or "",
        "sans": [v for k, v in decoded.get("subjectAltName", ()) if k == "DNS"],
    }
    t = _parse_cert_time(out["not_after"])
    out["days_left"] = int((t - datetime.now(timezone.utc)).total_seconds() // 86400) if t else None
    return out


class CaddyManager:
    """面板上的「域名与 HTTPS」。

    只做三件事：把线上真实的 Caddyfile 读出来给你看、按你的改动定向写回去、让
    Caddy 立刻生效。容器部署里 Caddy 是另一个容器，所以重载走它的 admin API
    （只开在 compose 内网，没有发布到宿主机）；裸机部署退到 caddy reload /
    systemctl reload caddy。
    """

    def __init__(self, caddyfile="", admin="", cert_dir="", upstream="", kms_host=""):
        self.caddyfile = Path(caddyfile) if caddyfile else None
        self.admin = (admin or "").rstrip("/")
        self.cert_dir = Path(cert_dir) if cert_dir else None
        self.upstream = upstream or "127.0.0.1:8099"
        self.kms_host = kms_host

    # --- 文件 -------------------------------------------------------------
    def configured(self):
        return self.caddyfile is not None

    def readable(self):
        try:
            return bool(self.caddyfile and self.caddyfile.is_file())
        except OSError:
            return False

    def writable(self):
        if not self.caddyfile:
            return False
        node = self.caddyfile if self.caddyfile.exists() else self.caddyfile.parent
        try:
            return os.access(node, os.W_OK)
        except OSError:
            return False

    def read(self):
        if not self.readable():
            return ""
        return self.caddyfile.read_text(encoding="utf-8", errors="replace")

    # --- 解析（轻量实现：只认顶层站点块的地址 / reverse_proxy / tls）------
    @staticmethod
    def _strip_comment(line):
        i = line.find("#")
        return line[:i] if i >= 0 else line

    def parse(self, text):
        info = {"domains": [], "email": "", "upstream": "", "blocks": [], "has_global": False}
        kind, header, body, depth, head_i = None, "", [], 0, 0
        for i, raw in enumerate(text.splitlines()):
            line = self._strip_comment(raw).strip()
            if kind is None:
                if line == "{":
                    kind, header, body, depth, head_i = "global", "", [], 1, i
                    info["has_global"] = True
                elif line.endswith("{"):
                    kind, header, body, depth, head_i = "site", line[:-1].strip(), [], 1, i
                continue
            if line == "}":
                depth -= 1
                if depth > 0:
                    body.append(line)
                    continue
                if kind == "site":
                    blk = {"addr": header, "head": head_i, "close": i, "upstream": "", "tls": ""}
                    for b in body:
                        s = b.strip()
                        if s.startswith("reverse_proxy") and not blk["upstream"]:
                            blk["upstream"] = s[len("reverse_proxy"):].strip()
                        elif s.startswith("tls") and not blk["tls"]:
                            blk["tls"] = s[3:].strip()
                    info["blocks"].append(blk)
                    info["domains"] += [a.strip() for a in header.split(",") if a.strip()]
                else:
                    for b in body:
                        s = b.strip()
                        if s.startswith("email"):
                            info["email"] = s[5:].strip()
                            break
                kind, header, body, depth = None, "", [], 0
                continue
            if line.endswith("{"):
                depth += 1
            body.append(line)
        if info["blocks"]:
            info["upstream"] = info["blocks"][0]["upstream"]
        return info

    def block(self, domain, email="", upstream=""):
        """新站点块模板：只有整个 Caddyfile 里一个站点块都没有时才用它。"""
        return (f"{domain} {{\n"
                + (f"\ttls {email}\n" if email else "")
                + f"\treverse_proxy {upstream or self.upstream}\n"
                "\tencode zstd gzip\n"
                "\theader {\n"
                "\t\tStrict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
                "\t\tX-Content-Type-Options \"nosniff\"\n"
                "\t\tX-Frame-Options \"DENY\"\n"
                "\t\tReferrer-Policy \"no-referrer\"\n"
                "\t\t-Server\n"
                "\t}\n"
                "\tlog {\n"
                f"\t\toutput file /data/access.log\n"
                "\t\tformat console\n"
                "\t}\n"
                "}\n")

    def apply(self, domain, email):
        """定向改：只换站点地址和 tls 邮箱，块里其他指令（反代目标等）一律保留。

        返回 (新文本, 错误列表)。
        """
        domain = (domain or "").strip().lower()
        email = (email or "").strip()
        if not re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$", domain):
            return None, ["域名不合法：%s（要写成 panel.example.com 这种）" % (domain or "(空)")]
        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return None, ["邮箱不合法：%s" % email]

        old = self.read()
        info = self.parse(old)
        if len(info["blocks"]) > 1:
            return None, ["%s 里有 %d 个站点块，面板不替你猜该改哪一个，请直接编辑该文件"
                          % (self.caddyfile, len(info["blocks"]))]
        if not info["blocks"]:
            text = (old.rstrip() + "\n\n" if old.strip() else "") + self.block(domain, email)
            return text, []

        blk = info["blocks"][0]
        lines = old.splitlines()
        lines[blk["head"]] = "%s {" % domain

        # 缩进跟着原有风格走（别把 tab 风格的文件混成空格）
        indent = "\t"
        for j in range(blk["head"] + 1, blk["close"]):
            if lines[j].strip():
                indent = re.match(r"\s*", lines[j]).group(0) or "\t"
                break

        tls_i = None
        for j in range(blk["head"] + 1, blk["close"]):
            if self._strip_comment(lines[j]).strip().startswith("tls"):
                tls_i = j
                break

        if email and tls_i is not None:
            lines[tls_i] = "%stls %s" % (indent, email)
        elif email:
            k = blk["head"] + 1
            while k < blk["close"] and not lines[k].strip():
                k += 1
            lines.insert(k, "%stls %s" % (indent, email))
        elif tls_i is not None and "@" in blk["tls"]:
            # 原来写的是邮箱才删；tls internal 之类的自定义指令不动
            del lines[tls_i]

        return "\n".join(lines).rstrip() + "\n", []

    def write(self, text):
        """就地覆写，不做 rename。

        文件很可能是从宿主机 bind mount 进来的**单文件**挂载点，往挂载点上
        rename 会被内核拒掉（EBUSY），所以必须原地写。
        """
        try:
            self.caddyfile.parent.mkdir(parents=True, exist_ok=True)
            if self.caddyfile.exists():
                shutil.copy2(str(self.caddyfile), str(self.caddyfile) + ".bak")
            with open(self.caddyfile, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            return True, ""
        except OSError as e:
            return False, "写 %s 失败：%s" % (self.caddyfile, e)

    # --- 重载 -------------------------------------------------------------
    def reload_method(self):
        if self.admin:
            return "admin"
        if shutil.which("caddy"):
            return "caddy"
        try:
            r = subprocess.run(["systemctl", "cat", "caddy"], capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                return "systemctl"
        except (OSError, subprocess.SubprocessError):
            pass
        return "manual"

    def reload(self, text):
        """把新配置交给 Caddy。返回 (是否成功, 错误, 说明)。"""
        method = self.reload_method()
        if method == "admin":
            req = urllib.request.Request(
                self.admin + "/load", data=text.encode("utf-8"), method="POST",
                headers={"Content-Type": "text/caddyfile", "Cache-Control": "must-revalidate"})
            try:
                # admin 在容器内网，必须绕开环境里的 HTTP(S)_PROXY，否则会被代到别处去
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(req, timeout=20) as r:
                    return True, "", "已通过 Caddy admin API 热重载（HTTP %d）" % r.status
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace").strip()
                return False, "Caddy 拒绝了这份配置（HTTP %d）：%s" % (e.code, detail[:400]), ""
            except Exception as e:  # noqa: BLE001
                return False, "连不上 Caddy admin（%s）：%s" % (self.admin, e), ""
        if method == "caddy":
            try:
                r = subprocess.run(["caddy", "reload", "--config", str(self.caddyfile),
                                    "--adapter", "caddyfile"], capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as e:
                return False, "caddy reload 失败：%s" % e, ""
            return r.returncode == 0, (r.stderr or "").strip()[:400], "已用 caddy reload 重载"
        if method == "systemctl":
            try:
                r = subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as e:
                return False, "systemctl reload caddy 失败：%s" % e, ""
            return r.returncode == 0, (r.stderr or "").strip()[:400], "已用 systemctl reload caddy 重载"
        return False, "", ("配置已写入 %s，但这个环境没有可用的重载通道，"
                           "请手工执行：caddy reload --config %s" % (self.caddyfile, self.caddyfile))

    def save(self, domain, email):
        # 先校验输入，再谈环境：不然在 demo 模式下填错域名，看到的会是"没接 Caddy"
        text, errors = self.apply(domain, email)
        if errors:
            return {"ok": False, "errors": errors}
        if not self.configured():
            return {"ok": False, "errors": ["这个后端没有接 Caddy（真机模式请加 --caddyfile /etc/caddy/Caddyfile）"]}
        if not self.writable():
            return {"ok": False, "errors": [
                "%s 不可写：容器里要把它挂进来（compose 的 volumes），或者让面板以有写权限的用户运行"
                % self.caddyfile]}
        ok, err = self.write(text)
        if not ok:
            return {"ok": False, "errors": [err]}
        reloaded, rerr, rmsg = self.reload(text)
        out = {"ok": True, "reloaded": reloaded, "message": rmsg,
               "domain": domain, "email": email, "text": text}
        if rerr:
            out["warning"] = rerr
        return out

    # --- 证书 -------------------------------------------------------------
    @staticmethod
    def _decode_cert(path):
        try:
            return ssl._ssl._test_decode_cert(str(path))  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None

    def cert_info(self, host):
        info = {"domain": host, "source": "", "trusted": None, "error": "", "path": "",
                "subject": "", "issuer": "", "not_before": "", "not_after": "",
                "sans": [], "days_left": None}
        if host and self.cert_dir and self.cert_dir.exists():
            try:
                cands = sorted(self.cert_dir.glob("*/*/*.crt"),
                               key=lambda p: p.stat().st_mtime, reverse=True)
            except OSError:
                cands = []
            for p in cands:
                if p.parent.name != host:
                    continue
                d = self._decode_cert(p)
                if d:
                    info.update(_cert_fields(d))
                    info.update({"source": "caddy-storage", "path": str(p), "trusted": True})
                    return info
        if not host:
            return info
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    info.update(_cert_fields(ss.getpeercert() or {}))
                    info.update({"source": "live", "trusted": True})
                    return info
        except ssl.SSLCertVerificationError as e:
            info["trusted"] = False
            info["error"] = "证书校验没过：" + (getattr(e, "verify_message", "") or str(e))
        except Exception as e:  # noqa: BLE001
            info["error"] = "%s: %s" % (type(e).__name__, e)
        # 握手失败也尽量把证书细节取出来给用户看
        try:
            pem = ssl.get_server_certificate((host, 443), timeout=8)
            tmp = Path(tempfile.gettempdir()) / ("nimbus-%s.crt" % host)
            tmp.write_text(pem, encoding="ascii")
            d = self._decode_cert(tmp)
            if d:
                info.update(_cert_fields(d))
                info["source"] = "live-unverified"
        except Exception:  # noqa: BLE001
            pass
        return info

    # --- 汇总给界面 --------------------------------------------------------
    def site_host(self):
        """从 Caddyfile 的第一个站点块里取出地址，返回 (原文地址, 纯主机名)。"""
        text = self.read()
        info = self.parse(text)
        raw = info["domains"][0] if info["domains"] else ""
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", raw).split(":")[0].strip().lower()
        if not re.match(r"^[a-z0-9.\-]+$", host):
            host = ""
        return raw, host

    def public_url(self, token):
        """面板对外的入口（带 token，点开即登录）。没配域名就返回空串。"""
        raw, host = self.site_host()
        if not host or "." not in host:
            return ""
        scheme = "http" if raw.startswith("http://") else "https"
        return "%s://%s/?token=%s" % (scheme, host, token)

    def status(self):
        text = self.read()
        info = self.parse(text)
        raw_addr, host = self.site_host()
        method = self.reload_method() if self.configured() else "manual"
        a = check_a(host) if host else {"ok": False, "values": [], "error": "还没有配置域名"}
        # 没配域名时用占位符生成示例，别让 DNS 表里出现空名字
        shown_host = host or "panel.example.com"
        shown = text or ("# 当前后端没有接真实的 Caddyfile，下面是按默认值生成的示例\n"
                         + self.block(shown_host, info["email"]))
        return {
            "configured": self.configured(),
            "caddyfile": str(self.caddyfile or ""),
            "readable": self.readable(),
            "writable": self.writable(),
            "domain": raw_addr, "host": host,
            "email": info["email"],
            "upstream": info["upstream"] or self.upstream,
            "blocks": len(info["blocks"]),
            "has_global": info["has_global"],
            "text": shown,
            "reload": {"method": method, "target": self.admin,
                       "available": method in ("admin", "caddy", "systemctl")},
            "cert": self.cert_info(host),
            "a": a,
            "dns_records": caddy_dns_records(shown_host, a.get("values"), self.kms_host),
            "notes": caddy_notes(method),
        }


def caddy_dns_records(domain, ips=None, kms_host=""):
    value = "、".join(ips) if ips else "<这台服务器的公网 IP>"
    rows = [{"type": "A", "name": domain, "value": value,
             "why": "浏览器用这个域名访问面板，Caddy 也按它签发证书"}]
    if kms_host:
        rows.append({"type": "A", "name": kms_host.split(":")[0], "value": value,
                     "why": "KMS 客户端连的地址（裸 TCP 1688，不经过 Caddy）"})
    rows.append({"type": "SRV", "name": "_vlmcs._tcp." + domain,
                 "value": "0 0 1688 " + (kms_host.split(":")[0] if kms_host else domain),
                 "why": "可选的自动发现记录，vlmcs 诊断客户端用得上"})
    return rows


def caddy_notes(method):
    notes = ["80 和 443 必须能从公网访问，Caddy 才能签发 / 续期 Let's Encrypt 证书。",
             "改域名后要先让 DNS 解析到这台机器，证书签发通常几秒到几十秒。"]
    if method == "admin":
        notes.append("保存走 Caddy 的 admin API 热重载：正在处理的连接不会断。")
        notes.append("admin 端点只开在容器内网（compose 网络），没有发布到宿主机。")
    elif method == "caddy":
        notes.append("保存后自动执行 caddy reload --config <Caddyfile>。")
    elif method == "systemctl":
        notes.append("保存后自动执行 systemctl reload caddy。")
    else:
        notes.append("这个环境没有自动重载通道：保存只写文件，还要你手工让 Caddy 重新加载。")
    return notes


# --------------------------------------------------------------------------
# HTTP 服务
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "nimbus/" + VERSION
    app = None  # 由 main() 注入

    def log_message(self, fmt, *args):  # 静音默认访问日志
        pass

    # --- 基础 ------------------------------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else ""

    def _client_ip(self):
        """直连方是反代容器时，采信 X-Forwarded-For 的第一段 —— 否则登录限流会把
        所有人当成同一个 IP（反代的地址）。直连方不在内网就只看它自己。"""
        peer = self.client_address[0]
        if _trusted_proxy_peer(peer):
            xff = self.headers.get("X-Forwarded-For", "")
            first = xff.split(",")[0].strip() if xff else ""
            if first:
                return first
        return peer

    def _authed(self, q):
        """两种凭证：① 登录后发的会话令牌（浏览器）② 服务 token（机器）。

        服务 token 必须留着：Steward 每 60 秒要用它拉 /api/enforce/pending 取限流决策，
        那种调用没法让人登录。它存在 0600 的文件里，只给机器用。
        """
        if q.get("token", [None])[0] == self.app["token"]:
            return True
        cred = self._bearer()
        if not cred:
            return False
        if self.app["accounts"].session_user(cred):
            return True
        return _same(cred, self.app["token"])

    def _user(self):
        cred = self._bearer()
        if not cred:
            return ""
        u = self.app["accounts"].session_user(cred)
        if u:
            return u
        return "(服务 token)" if _same(cred, self.app["token"]) else ""

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            return self._send(200, (HERE / "ui.html").read_text(encoding="utf-8"),
                              "text/html; charset=utf-8")
        if u.path == "/api/meta":
            return self._send(200, {"version": VERSION, "mode": self.app["mode"],
                                    "schema": FIELD_SCHEMA, "real": self.app["backend"].real,
                                    "kms_host": self.app["caddy"].kms_host,
                                    "started": self.app["started"]})
        if u.path == "/api/auth":
            acc = self.app["accounts"]
            return self._send(200, {"need_setup": acc.need_setup(), "users": acc.names(),
                                    "password_min": PASSWORD_MIN, "session_ttl": SESSION_TTL,
                                    "service_token": True, "me": self._user()})
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized", "hint": "需要登录"})
        b = self.app["backend"]
        try:
            if u.path == "/api/summary":
                return self._send(200, {"service": b.status(), "stats": self.app["store"].summary(),
                                        "execstart": b.execstart(), "mode": self.app["mode"]})
            if u.path == "/api/config":
                return self._send(200, {"config": b.read_config(), "schema": FIELD_SCHEMA})
            if u.path == "/api/logs":
                return self._send(200, {"lines": b.logs(int(q.get("lines", ["200"])[0]))})
            if u.path == "/api/stats":
                st = self.app["store"]
                return self._send(200, {
                    "page": st.page(int(q.get("page", ["1"])[0]), int(q.get("per", ["50"])[0]),
                                    int(q.get("days", ["30"])[0]), q.get("q", [""])[0],
                                    q.get("result", [""])[0], q.get("product", [""])[0]),
                    "series": st.series(int(q.get("days", ["30"])[0])),
                    "top_products": st.top("product"), "top_ips": st.top("ip"),
                    "top_fails": st.top("reason"),
                    "summary": st.summary(),
                })
            if u.path == "/api/domain":
                return self._send(200, self.app["caddy"].status())
            if u.path == "/api/limits":
                return self._send(200, self.app["limiter"].status())
            if u.path == "/api/accounts":
                return self._send(200, {"users": self.app["accounts"].listing(),
                                        "me": self._user(),
                                        "log": self.app["store"].auth_log(60)})
            if u.path == "/api/enforce/pending":
                # 给宿主机上的 Steward 拉的：现在就该封谁、该解封谁
                lim = self.app["limiter"]
                ban, unban, snap = lim.decide()
                return self._send(200, {"ban": ban, "unban": unban, "limit": snap["limit"],
                                        "window": snap["window"],
                                        "window_text": snap["window_text"],
                                        "enabled": snap["enabled"], "now": int(time.time())})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        acc = self.app["accounts"]
        ip = self._client_ip()

        # --- 不需要登录的两个入口 -----------------------------------------
        if u.path == "/api/setup":
            if not acc.need_setup():
                return self._send(403, {"ok": False, "error": "已经有账户了，请直接登录"})
            body = self._json_body()
            name = (body.get("name") or "").strip()
            ok, err = acc.create(name, body.get("password") or "")
            if not ok:
                return self._send(400, {"ok": False, "error": err})
            acc.touch_login(name)
            self.app["store"].record_auth(name, ip, "setup", True, "首次设置账户")
            return self._send(200, {"ok": True, "session": acc.new_session(name), "name": name})
        if u.path == "/api/login":
            wait = self.app["guard"].wait_seconds(ip)
            if wait:
                return self._send(429, {"ok": False, "error": "登录失败次数太多，请 %d 秒后再试" % wait})
            body = self._json_body()
            name = (body.get("name") or "").strip()
            if acc.check(name, body.get("password") or ""):
                self.app["guard"].ok(ip)
                acc.touch_login(name)
                self.app["store"].record_auth(name, ip, "login", True, "")
                return self._send(200, {"ok": True, "session": acc.new_session(name), "name": name})
            blocked = self.app["guard"].fail(ip)
            self.app["store"].record_auth(name or "(空)", ip, "login", False,
                                          "密码错误" + ("，已临时拒绝该来源" if blocked else ""))
            return self._send(403, {"ok": False, "error": "用户名或密码不对"})

        # --- 以下都要已登录 -----------------------------------------------
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized"})
        b = self.app["backend"]
        body = self._json_body()
        me = self._user()
        if u.path == "/api/logout":
            acc.drop_session(self._bearer())
            return self._send(200, {"ok": True})
        if u.path == "/api/accounts/create":
            name = (body.get("name") or "").strip()
            ok, err = acc.create(name, body.get("password") or "")
            self.app["store"].record_auth(me, ip, "create:" + name, ok, err or "")
            return self._send(200 if ok else 400, {"ok": ok, "error": err, "users": acc.listing()})
        if u.path == "/api/accounts/password":
            # 改谁的都行，但要用"你自己当前的密码"确认一次
            if me == "(服务 token)" or not acc.check(me, body.get("actor_password") or ""):
                self.app["store"].record_auth(me or "?", ip, "password", False, "当前密码校验失败")
                return self._send(403, {"ok": False, "error": "请输入你自己当前的密码"})
            target = (body.get("name") or me).strip()
            ok, err = acc.set_password(target, body.get("password") or "")
            if ok:
                acc.drop_user_sessions(target)
            self.app["store"].record_auth(me, ip, "password:" + target, ok, err or "")
            return self._send(200 if ok else 400, {"ok": ok, "error": err})
        if u.path == "/api/accounts/delete":
            target = (body.get("name") or "").strip()
            ok, err = acc.delete(target)
            self.app["store"].record_auth(me, ip, "delete:" + target, ok, err or "")
            return self._send(200 if ok else 400, {"ok": ok, "error": err, "users": acc.listing()})
        if u.path == "/api/accounts/logout-all":
            n = acc.drop_user_sessions(me) if me and me != "(服务 token)" else 0
            self.app["store"].record_auth(me, ip, "logout_all", True, "退出 %d 个会话" % n)
            return self._send(200, {"ok": True, "dropped": n})
        try:
            if u.path == "/api/config":
                return self._send(200, b.save_config(body))
            if u.path == "/api/config/rollback":
                return self._send(200, b.rollback())
            if u.path == "/api/service":
                return self._send(200, b.service(body.get("action", "")))
            if u.path == "/api/domain":
                return self._send(200, self.app["caddy"].save(body.get("domain", ""),
                                                              body.get("email", "")))
            if u.path == "/api/domain/check":
                domain = (body.get("domain") or "").strip()
                if not domain:
                    return self._send(400, {"ok": False, "error": "请填域名"})
                return self._send(200, {"ok": True, "domain": domain,
                                        "a": check_a(domain),
                                        "srv": check_srv(f"_vlmcs._tcp.{domain}")})
            if u.path == "/api/enforce/report":
                # Steward 干完活回来汇报，把结果记进流水（否则下轮还会让它再封一次）
                ip = (body.get("ip") or "").strip()
                action = body.get("action") or "ban"
                if action not in ("ban", "unban") or not ip:
                    return self._send(400, {"ok": False, "error": "要 ip 与 action=ban|unban"})
                self.app["store"].record_enforce(
                    ip, action, body.get("reason") or "enforcer", bool(body.get("ok")),
                    body.get("detail") or "", body.get("response") or "")
                return self._send(200, {"ok": True, "ip": ip, "action": action})
            if u.path == "/api/limits/unban":
                return self._send(200, self.app["limiter"].request_unban(
                    (body.get("ip") or "").strip()))
            if u.path == "/api/stats/prune":
                return self._send(200, {"ok": True, "removed": self.app["store"].prune(),
                                        "summary": self.app["store"].summary()})
            if u.path == "/api/stats/clear":
                # 清空不可恢复，要求显式确认，避免前端误调
                if not body.get("confirm"):
                    return self._send(400, {"ok": False, "error": "清空记录需要 confirm=true"})
                before = self.app["store"].size_bytes()
                removed = self.app["store"].clear()
                after = self.app["store"].size_bytes()
                return self._send(200, {"ok": True, "removed": removed,
                                        "freed_bytes": max(0, before - after),
                                        "summary": self.app["store"].summary()})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="Nimbus 管理面板")
    ap.add_argument("--mode", choices=["demo", "real"], default="demo")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--token", default="")
    ap.add_argument("--data-dir", default="",
                    help="SQLite 库与默认 token 文件的存放目录（默认：脚本所在目录）")
    ap.add_argument("--token-file", default="",
                    help="显式指定 token 文件路径（默认 <data-dir>/nimbus.token）")
    ap.add_argument("--quota-gb", type=float, default=6.0, help="统计库磁盘配额（演示里按 MB 生效）")
    ap.add_argument("--retention-days", type=int, default=0)
    ap.add_argument("--unit", default="vlmcsd", help="真机模式：被管理的 systemd 单元名")
    ap.add_argument("--ini", default="/etc/vlmcsd.ini", help="真机模式：被管理的 vlmcsd 配置文件路径")
    ap.add_argument("--supervisor", action="store_true",
                    help="容器部署：用 supervisord 而不是 systemd 管理 vlmcsd")
    ap.add_argument("--log-file", default="",
                    help="配合 --supervisor：vlmcsd 的日志文件（默认 /var/log/vlmcsd.log）")
    ap.add_argument("--caddyfile", default="",
                    help="Caddy 的 Caddyfile 路径；给了它，界面上的「域名与 HTTPS」才能读改真实配置")
    ap.add_argument("--caddy-admin", default="",
                    help="Caddy admin API 地址，容器部署填 http://caddy:2019，用它做热重载")
    ap.add_argument("--caddy-cert-dir", default="",
                    help="Caddy 证书存储目录（只读挂进来，界面就能显示证书主体与到期时间）")
    ap.add_argument("--caddy-upstream", default="",
                    help="新建站点块时反代到哪里（默认 127.0.0.1:8099，容器里是 kms:8099）")
    ap.add_argument("--kms-host", default=os.environ.get("NIMBUS_KMS_HOST", ""),
                    help="KMS 客户端用的域名（只在界面里生成 DNS 记录时用，不参与反代）")
    ap.add_argument("--max-activations", type=int, default=10,
                    help="限流上限：窗口内每个 IP / 每个机器码最多激活几次（0 = 关闭限流）")
    ap.add_argument("--limit-window", choices=["hour", "day", "total"], default="day",
                    help="限流窗口，默认 day（当天）；total = 累计")
    ap.add_argument("--ban-hours", type=int, default=24,
                    help="封禁保留小时数，到点自动申请解封（0 = 不自动解封）")
    ap.add_argument("--enforce-skip", default=SKIP_DEFAULT,
                    help="永不封禁的网段（逗号分隔），默认回环与内网")
    args = ap.parse_args()

    data_dir = Path(args.data_dir).expanduser() if args.data_dir else HERE
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "nimbus.db"

    quota = int(args.quota_gb * (1 << 30))
    if args.mode == "demo":
        quota = 256 << 20  # 演示模式别真吃 6 GB
    store = StatsStore(db_path, quota, args.retention_days)
    if args.mode == "demo":
        backend = DemoBackend(store)
    elif args.supervisor:
        backend = ContainerBackend(store, args.unit, args.ini, args.log_file)
    else:
        backend = LinuxBackend(store, args.unit, args.ini)

    token = args.token or os.environ.get("NIMBUS_ADMIN_TOKEN") or ""
    token_file = Path(args.token_file).expanduser() if args.token_file else (data_dir / "nimbus.token")
    if not token:
        if token_file.exists():
            token = token_file.read_text(encoding="utf-8").strip()
        else:
            token = secrets.token_urlsafe(18)
            token_file.parent.mkdir(parents=True, exist_ok=True)
            token_file.write_text(token, encoding="utf-8")
            try:
                os.chmod(token_file, 0o600)
            except OSError:
                pass

    app = {"store": store, "backend": backend, "token": token, "mode": args.mode,
           "port": args.port, "started": now_iso(),
           "caddy": CaddyManager(args.caddyfile, args.caddy_admin, args.caddy_cert_dir,
                                 args.caddy_upstream, args.kms_host),
           "limiter": Limiter(store, args.max_activations, args.limit_window,
                              args.ban_hours, args.enforce_skip),
           "accounts": Accounts(data_dir / "accounts.json"), "guard": LoginGuard()}
    Handler.app = app

    # 后台配额巡检：10 分钟一次，内存不动
    def janitor():
        while True:
            time.sleep(600)
            try:
                store.prune()
            except Exception:  # noqa: BLE001
                pass
    threading.Thread(target=janitor, daemon=True).start()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    url = f"http://{args.bind}:{args.port}/?token={token}"
    print("=" * 72)
    print(f"  nimbus {VERSION}  [{args.mode} 模式]")
    print(f"  打开这个地址（已带 token）：{url}")
    public_url = app["caddy"].public_url(token)
    if public_url:
        print(f"  公网入口（直接点/收藏这个）：{public_url}")
    print(f"  纯 token：{token}（机器凭证，浏览器改用账户登录）")
    print(f"  忘了 token 就跑：cat {token_file}")
    if app["accounts"].need_setup():
        print("  注意：还没有账户，打开页面先设置账户名与密码")
    else:
        print(f"  账户：{'、'.join(app['accounts'].names())}（改密码在面板的「账户」页）")
    print(f"  统计库：{db_path}   配额 {human_bytes(store.quota_bytes)}")
    if args.mode == "real":
        print(f"  进程管理：{backend.manager}（单元/程序：{args.unit}）")
        print(f"  配置文件：{args.ini}")
        if args.supervisor:
            print(f"  日志文件：{args.log_file or '/var/log/vlmcsd.log'}")
    if app["caddy"].configured():
        print(f"  Caddyfile：{app['caddy'].caddyfile}"
              f"（{'可写' if app['caddy'].writable() else '只读'}）"
              f"  重载通道：{app['caddy'].reload_method()}")
    lim = app["limiter"]
    print(f"  限流：{'每 %s 每个 IP / 机器码 %d 次' % (lim.window_text(), lim.limit) if lim.enabled else '已关闭'}"
          f"　封禁保留 {lim.ban_hours} 小时　跳过 {'/'.join(str(n) for n in lim.skip_nets)}")
    print("=" * 72)
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
