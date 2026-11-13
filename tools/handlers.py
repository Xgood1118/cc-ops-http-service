"""HTTP 接口处理逻辑。

安全设计：
- /file: 文件名白名单 + realpath 目录约束，禁止任何 data 目录之外的读取。
- /ping: 主机白名单（回环/内网）+ 参数列表调用（不经 shell），杜绝命令注入。
- /load: 载荷大小上限 + base64 + JSON 安全解析，不再反序列化 pickle。
- /diag: 仅在硬编码模式表内取值，不使用 eval。
"""
import base64
import binascii
import json
import os
import shutil
import subprocess

from .security import is_allowed_diag_host, resolve_inside

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# /load 允许的最大请求体（base64 前的原始字节数上限），防止内存型 DoS
MAX_LOAD_BODY = 1 * 1024 * 1024  # 1 MiB

# ping 单次诊断超时时间（秒）
PING_TIMEOUT = 10

# 诊断模式名 -> 固定结果。外部只能选择 key，结果内容不接受外部输入。
_DIAG_MODE = {
    "answer": 42,
    "double": 42,
}


def _send(handler, status, body, ctype="text/plain; charset=utf-8"):
    payload = body if isinstance(body, bytes) else str(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def handle_file(handler, query):
    """读取 data 目录下的报表文件。"""
    name = query.get("name", [""])[0]
    # 白名单 + realpath 双重校验，任何穿越/绝对路径/符号链接逃逸都被拒绝
    path = resolve_inside(DATA_DIR, name)
    if path is None:
        _send(handler, 400, "invalid name")
        return
    try:
        # 只允许读取普通文件，拒绝目录、设备等
        if not os.path.isfile(path):
            _send(handler, 404, "file not found")
            return
        with open(path, "rb") as fh:
            _send(handler, 200, fh.read())
    except OSError:
        _send(handler, 404, "file not found")


def handle_ping(handler, query):
    """对指定主机执行一次 ping 诊断。"""
    host = query.get("host", [""])[0]
    if not host:
        _send(handler, 400, "missing host")
        return
    if not is_allowed_diag_host(host):
        _send(handler, 400, "host not allowed")
        return
    ping_bin = shutil.which("ping")
    if ping_bin is None:
        _send(handler, 500, "ping unavailable")
        return
    # 参数以列表传递、shell=False：host 永远只是 argv 的一个元素，无法注入命令
    count_flag = "-n" if os.name == "nt" else "-c"
    try:
        result = subprocess.run(
            [ping_bin, count_flag, "1", host],
            shell=False,
            capture_output=True,
            timeout=PING_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        _send(handler, 504, "ping timeout")
        return
    except OSError:
        _send(handler, 500, "ping failed")
        return
    _send(handler, 200, result.stdout + result.stderr)


def handle_load(handler):
    """恢复运维侧缓存的会话数据（内部缓存迁移接口）。

    传输格式保持 base64；载荷内容使用 JSON 解析为基础数据类型，
    不再使用 pickle（pickle 反序列化等于远程代码执行）。
    """
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except ValueError:
        _send(handler, 400, "bad content-length")
        return
    if length < 0 or length > MAX_LOAD_BODY:
        _send(handler, 413, "payload too large")
        return
    raw = handler.rfile.read(length) if length else b""
    try:
        blob = base64.b64decode(raw, validate=True)
        obj = json.loads(blob.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _send(handler, 400, "bad cache payload")
        return
    _send(handler, 200, "restored: %r" % (obj,))


def handle_diag(handler, query):
    """执行固定的本地诊断模式。"""
    mode = query.get("mode", [""])[0]
    if mode not in _DIAG_MODE:
        _send(handler, 400, "unknown mode")
        return
    # 直接返回硬编码结果，不使用 eval
    _send(handler, 200, str(_DIAG_MODE[mode]))
