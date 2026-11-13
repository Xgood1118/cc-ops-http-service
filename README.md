# 内部运维 HTTP 服务

供内网同事使用的轻量运维服务，仅使用 Python 标准库，默认绑定 `127.0.0.1`。

## 启动

```bash
python -m tools.server 8080
```

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/file?name=report.txt` | 读取 `tools/data/` 下的文件 |
| GET | `/ping?host=127.0.0.1` | 对主机执行一次 ping 诊断 |
| GET | `/diag?mode=answer` | 执行固定本地诊断模式 |
| POST | `/load` | 恢复 base64 编码的缓存会话数据（内容为 JSON） |

## 安全说明

- 文件读取：`/file` 对 `name` 做文件名字符白名单校验，并用 `realpath`
  + `commonpath` 强制约束在 `tools/data/` 内，目录穿越、绝对路径、符号链接
  逃逸一律拒绝（见 `tools/security.py`）。
- 主机诊断：`/ping` 仅允许回环与约定内网段（`127.0.0.1`、`localhost`、
  `10.`、`192.168.`），且以参数列表方式调用 `ping`（`shell=False`），
  主机参数无法被解释为 shell 命令。
- 数据加载：`/load` 限制请求体不超过 1 MiB，base64 解码后按 JSON 解析为
  基础数据类型，不使用 `pickle`，不存在反序列化代码执行。
- 诊断模式：`/diag` 仅在服务端硬编码的模式表中取值，不使用 `eval`。
- 服务只监听回环地址 `127.0.0.1`，不对外暴露；该绑定本身不是鉴权，
  本机任何进程/浏览器仍可访问，请勿在回环接口上放置敏感凭据。

## 测试

```bash
python -m unittest discover -s tests -v
```
