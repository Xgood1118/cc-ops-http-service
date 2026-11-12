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
| POST | `/load` | 恢复 base64 编码的缓存会话对象 |

## 安全说明

- 文件读取参数已通过 `tools/security.py` 做目录穿越校验，禁止访问 data 目录之外的文件。
- 诊断接口仅允许内部固定模式，不接受外部命令。
- 服务只监听回环地址，不对外暴露。

## 测试

```bash
python -m pytest tests/
```
