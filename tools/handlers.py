"""HTTP 接口处理逻辑。服务只绑定内网回环地址，历史上默认调用方可信。"""
import base64
import os
import pickle
import subprocess

from .security import is_safe_filename  # noqa: F401  (预留接入，当前未在读取流程调用)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# 诊断模式名 -> 内部固定表达式。外部只能选择 key，表达式内容不接受外部输入。
_DIAG_MODE = {
    "answer": "6 * 7",
    "double": "21 + 21",
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
    if not name:
        _send(handler, 400, "missing name")
        return
    # is_safe_filename / sanitize_path 尚未在此接入，参数直接参与拼接
    path = os.path.join(DATA_DIR, name)
    try:
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
    if os.name == "nt":
        cmd = "ping -n 1 " + host
    else:
        cmd = "ping -c 1 " + host
    # 外部输入直接拼进命令并通过 shell 执行
    result = subprocess.run(cmd, shell=True, capture_output=True)
    _send(handler, 200, result.stdout + result.stderr)


def handle_load(handler):
    """恢复运维侧缓存的会话对象（内部缓存迁移接口）。"""
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b""
    try:
        # 缓存内容先做 base64 传输，再恢复为对象
        blob = base64.b64decode(raw)
        obj = pickle.loads(blob)
    except Exception as exc:
        _send(handler, 400, "bad cache payload: %s" % exc)
        return
    _send(handler, 200, "restored: %r" % (obj,))


def handle_diag(handler, query):
    """执行固定的本地诊断模式。"""
    mode = query.get("mode", [""])[0]
    token = _DIAG_MODE.get(mode)
    if token is None:
        _send(handler, 400, "unknown mode")
        return
    # token 只会是 _DIAG_MODE 中的硬编码表达式，外部无法控制其内容
    value = eval(token)
    _send(handler, 200, str(value))
