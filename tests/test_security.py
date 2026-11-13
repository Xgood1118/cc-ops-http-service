"""安全回归测试：覆盖路径穿越、命令注入、不安全反序列化三大漏洞。

每个漏洞同时包含：
- 攻击用例：修复后必须被拒绝（4xx）且不产生副作用；
- 正常业务用例：修复后必须保持原有功能（200 + 正确内容）。
"""
import base64
import http.client
import json
import os
import pickle
import tempfile
import threading
import unittest
import urllib.parse
from http.server import HTTPServer

from tools.server import OpsHandler


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), OpsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _request(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, body=body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def _get(port, path):
    return _request(port, "GET", path)


def _get_quoted(port, raw_query_value):
    """对查询参数值做完整 URL 编码后再发送。"""
    return _get(port, "/ping?host=" +
                urllib.parse.quote(raw_query_value, safe=""))


class FileTraversalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_normal_read_still_works(self):
        status, body = _get(self.port, "/file?name=report.txt")
        self.assertEqual(status, 200)
        self.assertIn("内部运维周报", body.decode("utf-8"))

    def test_second_normal_file(self):
        status, body = _get(self.port, "/file?name=notes.txt")
        self.assertEqual(status, 200)
        self.assertIn("回环", body.decode("utf-8"))

    def test_relative_traversal_blocked(self):
        for payload in ("../security.py", "..%2fsecurity.py",
                        "../../README.md", "..%5csecurity.py",
                        "....//security.py", "subdir/../../server.py"):
            status, _ = _get(self.port, "/file?name=" + payload)
            self.assertIn(status, (400, 404), payload)

    def test_absolute_path_blocked(self):
        for payload in ("C:/Windows/win.ini", "C:%5cWindows%5cwin.ini",
                        "/etc/passwd", "%2fetc%2fpasswd"):
            status, _ = _get(self.port, "/file?name=" + payload)
            self.assertEqual(status, 400, payload)

    def test_nul_byte_and_dotfile_blocked(self):
        for payload in ("report.txt%00.png", ".", "..", ".hidden"):
            status, _ = _get(self.port, "/file?name=" + payload)
            self.assertEqual(status, 400, payload)

    def test_missing_name(self):
        status, _ = _get(self.port, "/file")
        self.assertEqual(status, 400)


class PingInjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_injection_payloads_blocked(self):
        marker = os.path.join(tempfile.gettempdir(), "reg_ping_marker.txt")
        if os.path.exists(marker):
            os.remove(marker)
        payloads = [
            "127.0.0.1 & echo PWNED > " + marker,
            "127.0.0.1|ver",
            "127.0.0.1&&set",
            "127.0.0.1|whoami",
            "127.0.0.1; echo PWNED",
            "$(echo PWNED)",
            "`ver`",
        ]
        for payload in payloads:
            status, body = _get_quoted(self.port, payload)
            self.assertEqual(status, 400, payload)
            self.assertNotIn(b"PWNED", body)
        self.assertFalse(os.path.exists(marker),
                         "命令注入居然写出了文件，修复无效")

    def test_loopback_host_allowed(self):
        status, _ = _get(self.port, "/ping?host=127.0.0.1")
        # 200 表示进入了正常 ping 流程（即使机器上没有 ping 也不应是 400）
        self.assertIn(status, (200, 500, 504))

    def test_localhost_allowed(self):
        status, _ = _get(self.port, "/ping?host=localhost")
        self.assertIn(status, (200, 500, 504))

    def test_internal_ip_allowed(self):
        status, _ = _get(self.port, "/ping?host=10.0.0.1")
        self.assertIn(status, (200, 500, 504))
        status, _ = _get(self.port, "/ping?host=192.168.1.1")
        self.assertIn(status, (200, 500, 504))

    def test_public_host_rejected(self):
        status, _ = _get(self.port, "/ping?host=8.8.8.8")
        self.assertEqual(status, 400)

    def test_missing_host(self):
        status, _ = _get(self.port, "/ping")
        self.assertEqual(status, 400)


class PickleRceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_malicious_pickle_rejected(self):
        marker = os.path.join(tempfile.gettempdir(), "reg_pickle_marker.marker")
        if os.path.exists(marker):
            os.remove(marker)

        class RCE:
            def __reduce__(self):
                return (os.system,
                        ("echo PWNED_REG > " + marker,))

        payload = base64.b64encode(pickle.dumps(RCE())).decode("ascii")
        status, body = _request(self.port, "POST", "/load",
                                payload.encode("ascii"))
        self.assertEqual(status, 400)
        self.assertFalse(os.path.exists(marker),
                         "恶意 pickle 被执行了，修复无效")

    def test_legitimate_json_cache_restored(self):
        # 新的合法格式：base64(JSON)
        data = {"session": "ops", "ids": [1, 2, 3]}
        payload = base64.b64encode(
            json.dumps(data).encode("utf-8")).decode("ascii")
        status, body = _request(self.port, "POST", "/load",
                                payload.encode("ascii"))
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"restored: "))
        self.assertIn(b"'session': 'ops'", body)

    def test_garbage_payload_rejected(self):
        status, _ = _request(self.port, "POST", "/load", b"not-base64!!!")
        self.assertEqual(status, 400)

    def test_oversized_payload_rejected(self):
        big = base64.b64encode(b"x" * (2 * 1024 * 1024))
        # 服务端在读取请求体前就按 Content-Length 拒绝（413）并关闭连接；
        # 客户端仍在发送大请求体时可能收到 TCP RST，两种表现都算正确拒绝。
        try:
            status, _ = _request(self.port, "POST", "/load", big)
        except (http.client.HTTPException, ConnectionError, OSError):
            status = 413
        self.assertEqual(status, 413)

    def test_empty_body(self):
        status, _ = _request(self.port, "POST", "/load", b"")
        self.assertEqual(status, 400)


class DiagHardeningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_known_modes_unchanged(self):
        status, body = _get(self.port, "/diag?mode=answer")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode("utf-8"), "42")
        status, body = _get(self.port, "/diag?mode=double")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode("utf-8"), "42")

    def test_expression_injection_rejected(self):
        evil = "__import__('os').system('echo x')"
        status, _ = _get(self.port,
                         "/diag?mode=" + urllib.parse.quote(evil, safe=""))
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
