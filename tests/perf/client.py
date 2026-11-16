"""Load generator worker: keep-alive HTTP requests through a proxy for a fixed duration.

Usage: client.py <mode> <proxy_host> <proxy_port> <url> <seconds> <threads> [auth_b64|-] [signing_json|-]
mode: http (absolute-form GET through the proxy), direct (GET to the origin), connect (CONNECT + TLS per request)
Prints one JSON line: {"count": n, "errors": e, "latencies_ms": [...sampled...]}
"""

import base64
import http.client
import json
import random
import socket
import ssl
import sys
import threading
import time


def main() -> None:
    mode, host, port, url, seconds, threads = sys.argv[1:7]
    auth = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] != "-" else None
    signing = json.loads(sys.argv[8]) if len(sys.argv) > 8 and sys.argv[8] != "-" else None
    port, seconds, threads = int(port), float(seconds), int(threads)
    stop = time.monotonic() + seconds
    lock = threading.Lock()
    stats = {"count": 0, "errors": 0, "latencies": []}
    if signing and "master" in signing:
        sys.path.insert(0, signing["src"])
        from clearideas_egress.signing import Destination, SigningProfile, derive_run_key, sign_request
        profile = SigningProfile.parse()
        run_key = derive_run_key(base64.b64decode(signing["master"]), {"runId": "perf-run"})

    def record(latency, ok):
        with lock:
            stats["count"] += 1
            if not ok:
                stats["errors"] += 1
            if len(stats["latencies"]) < 20000 or random.random() < 0.05:
                stats["latencies"].append(latency * 1000)

    def worker():
        connection = None
        tls_context = ssl.create_default_context()  # once per thread: loading CA bundles is expensive
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        while time.monotonic() < stop:
            started = time.monotonic()
            ok = False
            try:
                if mode == "connect-direct":
                    sock = socket.create_connection((host, port), timeout=10)
                    tls = tls_context.wrap_socket(sock, server_hostname=url.split(":")[0])
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    ok = b"200" in tls.recv(1024)
                    tls.close()
                elif mode == "connect":
                    sock = socket.create_connection((host, port), timeout=10)
                    target = url
                    headers = f"Proxy-Authorization: Basic {auth}\r\n" if auth else ""
                    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{headers}\r\n".encode())
                    if b" 200 " in sock.recv(1024):
                        tls = tls_context.wrap_socket(sock, server_hostname=target.split(":")[0])
                        tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                        ok = b"200" in tls.recv(1024)
                        tls.close()
                    else:
                        sock.close()
                else:
                    if connection is None:
                        connection = http.client.HTTPConnection(host, port, timeout=10)
                    headers = {}
                    if auth:
                        headers["Proxy-Authorization"] = f"Basic {auth}"
                    path = url if mode == "http" else "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
                    if signing and "master" in signing:
                        scheme, rest = url.split("://", 1)
                        target_host, _, target_path = rest.partition("/")
                        destination = Destination.build("GET", scheme, target_host, 80, "/" + target_path)
                        headers.update(sign_request(run_key, "m1", profile, {"runId": "perf-run"}, destination))
                    connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    response.read()
                    ok = response.status == 200
                    if response.will_close:
                        connection.close()
                        connection = None
            except (OSError, http.client.HTTPException):
                if connection is not None:
                    connection.close()
                connection = None
            record(time.monotonic() - started, ok)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    print(json.dumps({"count": stats["count"], "errors": stats["errors"], "latencies_ms": stats["latencies"]}))


if __name__ == "__main__":
    main()
