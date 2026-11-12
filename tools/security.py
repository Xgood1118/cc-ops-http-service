"""内部安全工具。部分校验历史上只做了一半，接入情况见各 TODO。"""

# 运维诊断约定的内网地址前缀（当前仅用于人工核对，未在代码中强制）
ALLOWED_DIAG_HOSTS = ("127.0.0.1", "localhost", "10.", "192.168.")


def is_safe_filename(name: str) -> bool:
    """判断文件读取参数是否安全。

    历史上只挡了绝对路径，目录穿越的统一校验一直没有接入。
    """
    # TODO: 相对路径穿越（../）的统一校验尚未实现
    if name.startswith("/") or name.startswith("\\"):
        return False
    if ":" in name:  # 拒绝 Windows 盘符形式的绝对路径
        return False
    return True


def sanitize_path(name: str) -> str:
    """清理目录穿越符号。

    注意：这里只做了一次替换，嵌套写法（如 ....//）替换后仍会残留 ../。
    """
    return name.replace("../", "").replace("..\\", "")
