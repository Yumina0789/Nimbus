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
import json
import os
import queue
import random
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

VERSION = "0.1.0"
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
        self.db.commit()

    def add(self, ts: int, ip, product, version, ok, reason="", elapsed=0.0):
        with self.lock:
            self.db.execute(
                "INSERT INTO events (ts, ip, product, version, ok, reason, elapsed) VALUES (?,?,?,?,?,?,?)",
                (ts, ip, product, version, 1 if ok else 0, reason, elapsed),
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
            where.append("(ip LIKE ? OR version LIKE ?)")
            args += [f"%{q}%", f"%{q}%"]
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
                "version": None, "binary": None, "sha256": None,
                "reload_pending": False, "hint": self._missing_hint(),
            }
        r_active, _ = self._systemctl("is-active", self.UNIT, timeout=10)
        r_show, _ = self._systemctl("show", self.UNIT, "-p", "MainPID",
                                    "-p", "ActiveEnterTimestamp", timeout=10)
        active = r_active.stdout.strip() if r_active else ""
        info = r_show.stdout if r_show else ""
        pid = re.search(r"MainPID=(\d+)", info)
        since = re.search(r"ActiveEnterTimestamp=(.+)", info)
        return {
            "available": True, "unit": self.UNIT, "ini": str(self.INI),
            "manager": self.manager,
            "running": active == "active",
            "pid": int(pid.group(1)) if pid and pid.group(1) != "0" else None,
            "since": since.group(1).strip() if since else None,
            "uptime": None, "version": "vlmcsd (real)",
            "binary": "/usr/local/bin/vlmcsd",
            "sha256": _sha256(Path("/usr/local/bin/vlmcsd")),
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
    # vlmcsd 的日志行形如：
    #   Connection from 10.0.0.5: ... <product>: success
    # 具体格式要在真机上用真实日志校准；解析不出来的行直接忽略，不影响服务。
    EVENT_RE = re.compile(r"Connection from (?P<ip>[\d.]+).*?(?P<product>[A-Za-z0-9 ().\-]{4,60}?):\s*(?P<verdict>success|rejected)", re.I)

    def _tail(self):
        while True:
            if not self.available and not self._detect_service():
                time.sleep(10)  # 还没装 vlmcsd：安静等待，别刷屏
                continue
            try:
                proc = subprocess.Popen(["journalctl", "-u", self.UNIT, "-f", "-n", "0", "-o", "cat"],
                                        stdout=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    line = line.rstrip()
                    m = self.EVENT_RE.search(line)
                    if m:
                        ok = m.group("verdict").lower() == "success"
                        self.store.add(int(time.time()), m.group("ip"), m.group("product"),
                                       "", ok, "" if ok else line[-80:])
                    self.log_lines.append({"t": now_iso(),
                                           "level": "warn" if re.search(r"reject|error", line, re.I) else "info",
                                           "msg": line})
                    del self.log_lines[:-400]
            except Exception:
                pass
            time.sleep(5)


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
        super().__init__(store, unit, ini)

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
            r, err = self._sup("status", self.PROGRAM, timeout=timeout)
            if r is None:
                return None, err
            active = bool(re.search(r"\bRUNNING\b", r.stdout or ""))
            return self._done(argv, 0 if active else 3,
                              "active\n" if active else "inactive\n", err), err

        if action == "show":
            props = [a for a in rest if not a.startswith("-")]
            r, err = self._sup("status", self.PROGRAM, timeout=timeout)
            out = r.stdout if r else ""
            pid = re.search(r"pid (\d+)", out)
            uptime = re.search(r"uptime (.+)", out)
            lines = []
            if any("MainPID" in p for p in props):
                lines.append("MainPID=%s" % (pid.group(1) if pid else "0"))
            if any("ActiveEnterTimestamp" in p for p in props):
                since = ""
                if uptime:
                    since = "%s (up %s)" % (now_iso(), uptime.group(1).strip())
                lines.append("ActiveEnterTimestamp=%s" % since)
            if any("ExecStart" in p for p in props):
                lines.append("ExecStart=%s" % self._command_line())
            return self._done(argv, 0, "\n".join(lines) + "\n", err), err

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
    def _level_of(self, line: str) -> str:
        if re.search(r"error|fail|reject", line, re.I):
            return "warn"
        if "success" in line.lower():
            return "ok"
        return "info"

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

    # vlmcsd 的一次激活在日志里是一个块，形如：
    #   IPv4 connection accepted: 10.0.0.5:52211.
    #   <<< Incoming KMS request
    #   Application ID                  : <guid> (Windows 10 Pro)
    #   Client machine ID               : <guid>
    #   >>> Sending response, ePID source = randomized at program start
    #   IPv4 connection closed: 10.0.0.5:52211.
    # 所以按块解析，而不是按单行正则。
    ACCEPT_RE = re.compile(r"IPv4 connection accepted: (?P<ip>[\d.]+):(?P<port>\d+)")
    CLOSE_RE = re.compile(r"IPv4 connection closed: (?P<ip>[\d.]+):\d+")
    PRODUCT_RE = re.compile(r"Application ID\s*:\s*\S+\s*\((?P<product>[^)]+)\)")
    SENT_RE = re.compile(r">>>\s*Sending response")
    REJECT_RE = re.compile(r"(reject|not licensed|error|fail)", re.I)
    # 只有 "accepted" + "closed"、中间没有任何请求体的连接，是端口探活（监控健康检查、
    # 扫描器）。它不该被记成一次"失败的激活"，否则面板上的失败数全是噪声。
    PAYLOAD_RE = re.compile(r"<<<|Application ID|Client machine ID|Sending response|"
                            r"reject|not licensed|error|fail", re.I)

    def _event_from_block(self, block):
        """把一个连接块变成一条统计记录；不是一个完整块就返回 None。"""
        m = self.ACCEPT_RE.search(block)
        if not m:
            return None
        if not self.PAYLOAD_RE.search(block):
            return None
        ip = m.group("ip")
        ok = bool(self.SENT_RE.search(block))
        p = self.PRODUCT_RE.search(block)
        product = p.group("product") if p else ""
        reason = ""
        if not ok:
            bad = [ln for ln in block.splitlines() if self.REJECT_RE.search(ln)]
            reason = (bad[0] if bad else block.strip().splitlines()[-1] if block.strip() else "")[:120]
        return ip, product, ok, reason

    def _tail(self):
        """tail -F 日志文件，按"连接块"累计并入库（代替 journalctl -f + 单行正则）。"""
        while True:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                self.log_file.touch(exist_ok=True)
                with self.log_file.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(0, os.SEEK_END)
                    buf = ""
                    block = []
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
                            line = line.rstrip()
                            if not line:
                                continue
                            self.log_lines.append({"t": now_iso(),
                                                   "level": self._level_of(line),
                                                   "msg": line})
                            del self.log_lines[:-400]
                            if self.ACCEPT_RE.search(line):
                                block = [line]
                                continue
                            if block:
                                block.append(line)
                                if self.CLOSE_RE.search(line):
                                    ev = self._event_from_block("\n".join(block))
                                    if ev:
                                        ip, product, ok, reason = ev
                                        self.store.add(int(time.time()), ip, product, "", ok, reason)
                                    block = []
            except Exception:
                pass
            time.sleep(5)


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


def caddy_config(domain, backend_host="127.0.0.1", backend_port=8099, email=""):
    return {
        "caddyfile": (
            f"# 保存到 /etc/caddy/Caddyfile\n"
            f"{domain} {{\n"
            + (f"    tls {email}\n" if email else "")
            + f"    reverse_proxy {backend_host}:{backend_port}\n"
            f"    encode zstd gzip\n"
            f"    header {{\n"
            f"        Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            f"        X-Content-Type-Options nosniff\n"
            f"        X-Frame-Options DENY\n"
            f"    }}\n"
            f"    log {{\n        output file /var/log/caddy/{domain}.log\n    }}\n"
            f"}}\n"
        ),
        "dns_records": [
            {"type": "A", "name": domain, "value": "<这台服务器的公网 IP>", "why": "让浏览器能解析到管理界面"},
            {"type": "A", "name": f"kms.{domain}", "value": "<这台服务器的公网 IP>", "why": "KMS 客户端要连的地址（可选，也可以直接用 IP）"},
            {"type": "SRV", "name": f"_vlmcs._tcp.{domain}", "value": "0 0 1688 kms." + domain,
             "why": "vlmcs 诊断客户端靠这条记录自动发现 KMS 主机"},
        ],
        "notes": [
            "80/443 必须能从公网访问，Caddy 才能签发 Let's Encrypt 证书。",
            "管理界面本机监听 127.0.0.1:8099 即可，公网只开 Caddy 的 443。",
            "装 Caddy 的两行：apt install -y caddy  然后  systemctl reload caddy",
            "DNS 改动生效需要时间（TTL），界面里的“检查”按钮可以反复点。",
        ],
    }


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

    def _authed(self, q):
        if q.get("token", [None])[0] == self.app["token"]:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], self.app["token"]):
            return True
        return False

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
                                    "started": self.app["started"]})
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized", "hint": "需要 token"})
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
            if u.path == "/api/domain/caddy":
                return self._send(200, caddy_config(q.get("domain", [""])[0] or "kms.example.com",
                                                    backend_port=self.app["port"],
                                                    email=q.get("email", [""])[0]))
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/login":
            tok = self._json_body().get("token", "")
            if tok and secrets.compare_digest(tok, self.app["token"]):
                return self._send(200, {"ok": True, "token": self.app["token"]})
            return self._send(403, {"ok": False, "error": "token 不正确"})
        if not self._authed(q):
            return self._send(401, {"error": "unauthorized"})
        b = self.app["backend"]
        body = self._json_body()
        try:
            if u.path == "/api/config":
                return self._send(200, b.save_config(body))
            if u.path == "/api/config/rollback":
                return self._send(200, b.rollback())
            if u.path == "/api/service":
                return self._send(200, b.service(body.get("action", "")))
            if u.path == "/api/domain/check":
                domain = (body.get("domain") or "").strip()
                if not domain:
                    return self._send(400, {"ok": False, "error": "请填域名"})
                return self._send(200, {"ok": True, "domain": domain,
                                        "a": check_a(domain),
                                        "srv": check_srv(f"_vlmcs._tcp.{domain}")})
            if u.path == "/api/stats/prune":
                return self._send(200, {"ok": True, "removed": self.app["store"].prune(),
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
           "port": args.port, "started": now_iso()}
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
    print(f"  纯 token：{token}")
    print(f"  统计库：{db_path}   配额 {human_bytes(store.quota_bytes)}")
    if args.mode == "real":
        print(f"  进程管理：{backend.manager}（单元/程序：{args.unit}）")
        print(f"  配置文件：{args.ini}")
        if args.supervisor:
            print(f"  日志文件：{args.log_file or '/var/log/vlmcsd.log'}")
    print("=" * 72)
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
