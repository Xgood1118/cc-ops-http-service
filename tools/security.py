"""内部安全工具。

- is_safe_filename: 文件名白名单校验（不允许任何路径分隔/盘符/空字节）。
- resolve_inside: 把用户提供的文件名解析为 data 目录内的真实路径，越界即拒绝。
- is_allowed_diag_host: 诊断主机白名单（回环 + 约定内网段）。
"""
import ipaddress
import os

# 运维诊断约定的内网地址前缀（现在在代码中强制校验）
ALLOWED_DIAG_HOSTS = ("127.0.0.1", "localhost", "10.", "192.168.")

# 文件名允许的字符集：字母数字、点、下划线、连字符。禁止分隔符、盘符等。
_ALLOWED_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._-"
)


def is_safe_filename(name: str) -> bool:
    """判断文件读取参数是否安全。

    要求是非空的单一文件名：不允许目录分隔符、盘符、空字节、相对/绝对路径。
    """
    if not isinstance(name, str) or not name:
        return False
    if "\x00" in name:
        return False
    # 拒绝任何形式的路径分隔与 Windows 盘符/UNC 路径
    if "/" in name or "\\" in name or ":" in name:
        return False
    # 拒绝 "." / ".." 以及以点开头的隐藏写法（data 目录内没有这类合法文件）
    if name in (".", "..") or name.startswith("."):
        return False
    if any(ch not in _ALLOWED_NAME_CHARS for ch in name):
        return False
    # 防御性兜底：不允许出现父目录引用
    if ".." in name:
        return False
    return True


def resolve_inside(base_dir: str, name: str):
    """把 name 安全地解析到 base_dir 内部。

    返回 base_dir 内的绝对路径；任何越界（含符号链接逃逸）或非法文件名
    都返回 None。
    """
    if not is_safe_filename(name):
        return None
    base_real = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_real, name))
    # commonpath 能可靠识别“候选路径不在 base 目录内”的情况（含符号链接）
    try:
        if os.path.commonpath([base_real, candidate]) != base_real:
            return None
    except ValueError:
        # 盘符不一致等情况会抛 ValueError，一律视为越界
        return None
    return candidate


def is_allowed_diag_host(host: str) -> bool:
    """校验 ping 诊断目标是否属于约定的回环/内网范围。"""
    if not isinstance(host, str):
        return False
    host = host.strip()
    if not host or any(ch.isspace() for ch in host):
        return False
    # 禁止一切 shell 元字符（深度防御；正常主机名/IP 不含这些字符）
    if any(ch in host for ch in "&|;<>^`$()\\\"'\r\n"):
        return False
    if host == "localhost":
        return True
    # 先按 IP 地址解析：回环、私有地址或约定前缀放行
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private:
        return True
    return host.startswith(ALLOWED_DIAG_HOSTS)
