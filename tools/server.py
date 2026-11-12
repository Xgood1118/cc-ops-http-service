"""内部运维 HTTP 服务入口（仅标准库）。

启动：python -m tools.server [port]
默认绑定 127.0.0.1:8080。
"""
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from . import handlers


class OpsHandler(BaseHTTPRequestHandler):
    def _route(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        return parsed.path, query

    def do_GET(self):
        path, query = self._route()
        if path == "/health":
            handlers._send(self, 200, "ok")
        elif path == "/file":
            handlers.handle_file(self, query)
        elif path == "/ping":
            handlers.handle_ping(self, query)
        elif path == "/diag":
            handlers.handle_diag(self, query)
        else:
            handlers._send(self, 404, "not found")

    def do_POST(self):
        path, _ = self._route()
        if path == "/load":
            handlers.handle_load(self)
        else:
            handlers._send(self, 404, "not found")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    port = int(argv[0]) if argv else 8080
    server = HTTPServer(("127.0.0.1", port), OpsHandler)
    print("serving on http://127.0.0.1:%d" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
