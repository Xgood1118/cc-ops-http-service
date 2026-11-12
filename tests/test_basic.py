"""正常功能的端到端测试（真实起本地服务，不覆盖安全场景）。"""
import http.client
import threading
import unittest
from http.server import HTTPServer

from tools.server import OpsHandler


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), OpsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


class BasicServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health(self):
        status, body = _get(self.port, "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode("utf-8"), "ok")

    def test_file_normal_read(self):
        status, body = _get(self.port, "/file?name=report.txt")
        self.assertEqual(status, 200)
        self.assertIn("内部运维周报", body.decode("utf-8"))

    def test_diag_known_mode(self):
        status, body = _get(self.port, "/diag?mode=answer")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode("utf-8"), "42")

    def test_diag_unknown_mode(self):
        status, _ = _get(self.port, "/diag?mode=nope")
        self.assertEqual(status, 400)

    def test_unknown_route(self):
        status, _ = _get(self.port, "/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
