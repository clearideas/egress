#!/usr/bin/env python3
"""Black-box smoke test of the production image, run the way it is deployed.

    python3 tests/docker/smoke.py [--image clearideas-egress:test] [--no-build]

Everything runs on a private Docker network with no route out (``--internal``), so the test is
hermetic and cannot reach the internet:

    origin  (93.184.215.14, DNS alias example.com)  python3 -m http.server 80
    proxy   the image under test: read-only root, tmpfs run directory, all capabilities dropped,
            no-new-privileges, demo user, a static policy allowing only http://example.com, and a
            throwaway error CA (made with the image's openssl)
    client  a throwaway container that drives the proxy and the monitor endpoints

Checks: the proxy runs as non-root; /livez, /readyz and /metrics answer; unauthenticated requests
get 407; an allowed origin is reachable; a non-allowed origin, a metadata IP literal and the cache
manager are refused, with the proxy's X-Egress-Error marker (for HTTPS: a readable 403 through the
error CA, which also exercises the image's certificate generator); access logs are JSON and never
contain the password; ``docker stop`` drains and exits cleanly. Exit status 0 when every check passes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCKER = os.environ.get("DOCKER", "docker")
SUBNET = "93.184.215.0/24"  # a "public" range: the proxy must treat the origin as an internet host
ORIGIN_IP = "93.184.215.14"
PASSWORD = "smoke-" + uuid.uuid4().hex  # must never appear in logs

CLIENT = r'''
import base64, json, socket, ssl, sys, time, urllib.request

proxy, password, origin_ip, cafile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
proxy_port, monitor_port = (int(sys.argv[5]), int(sys.argv[6])) if len(sys.argv) > 6 else (3128, 9090)
results = []

def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})

def monitor(path):
    try:
        with urllib.request.urlopen(f"http://{proxy}:{monitor_port}{path}", timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except OSError as e:
        return 0, repr(e)

def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError):
        status = 0
    return status, headers, body.decode(errors="replace")

def raw(request: bytes):
    try:
        with socket.create_connection((proxy, proxy_port), timeout=10) as s:
            s.sendall(request)
            return read_response(s)
    except OSError as e:
        return 0, {}, repr(e)

def get(url, auth=True, method="GET"):
    host = url.split("/")[2]
    lines = [f"{method} {url} HTTP/1.1", f"Host: {host}", "Connection: close"]
    if auth:
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(f"demo:{password}".encode()).decode())
    return raw(("\r\n".join(lines) + "\r\n\r\n").encode())

def code(body):
    return next((l.split(": ", 1)[1] for l in body.splitlines() if l.startswith("code: ")), None)

deadline = time.time() + 90
status = 0
while time.time() < deadline:
    status, body = monitor("/readyz")
    if status == 200:
        break
    time.sleep(1)
check("readyz 200", status == 200, body)
check("livez 200", monitor("/livez")[0] == 200)
status, metrics = monitor("/metrics")
check("metrics egress_squid_up 1", status == 200 and "\negress_squid_up 1" in "\n" + metrics, metrics[:300])
check("metrics error CA expiry", "egress_error_ca_not_after_timestamp_seconds" in metrics)

check("unauthenticated -> 407", get("http://example.com/", auth=False)[0] == 407)
status, headers, body = get("http://example.com/")
check("allowed origin -> 200, unmarked", status == 200 and "x-egress-error" not in headers, f"{status} {headers}")
check("wrong password -> 407", raw(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
      b"Proxy-Authorization: Basic " + base64.b64encode(b"demo:wrong") + b"\r\nConnection: close\r\n\r\n")[0] == 407)
status, headers, body = get("http://denied.example.net/")
check("other origin -> 403 from the proxy", (status, headers.get("x-egress-error"), code(body)) == (403, "denied", "denied"),
      f"{status} {headers.get('x-egress-error')} {body[:200]}")
check("metadata IP -> 403", get("http://169.254.169.254/latest/meta-data/")[0] == 403)
check("origin by IP literal -> 403", get(f"http://{origin_ip}/")[0] == 403)

def connect_outcome(target):
    # Refused CONNECTs get "200" and then the refusal inside TLS, from a certificate minted by the
    # proxy's error CA (docs/OPERATIONS.md, "Readable errors for sandboxes"). This client trusts only
    # that CA, so a successful handshake means the proxy itself answered.
    try:
        s = socket.create_connection((proxy, proxy_port), timeout=10)
    except OSError as e:
        return repr(e)
    with s:
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic ".encode()
                  + base64.b64encode(f"demo:{password}".encode()) + b"\r\n\r\n")
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                return "closed"
            head += chunk
        if not head.startswith(b"HTTP/1.1 200"):
            return head.split(b"\r\n")[0].decode()
        host = target.rsplit(":", 1)[0]
        try:
            with ssl.create_default_context(cafile=cafile).wrap_socket(s, server_hostname=host) as tls:
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                status, headers, body = read_response(tls)
                return f"refused {status} {headers.get('x-egress-error')} {code(body)}"
        except ssl.SSLCertVerificationError as e:
            return f"TUNNEL OPEN? certificate not from the error CA: {e}"
        except (ssl.SSLError, OSError) as e:
            return f"closed ({type(e).__name__})"

outcome = connect_outcome("example.com:22")
check("CONNECT to a non-TLS port refused readably", outcome == "refused 403 denied denied", outcome)
outcome = connect_outcome("denied.example.net:443")
check("CONNECT to another origin refused readably", outcome == "refused 403 denied denied", outcome)
status = get("cache_object://localhost/info")[0]
check("cache manager not reachable", status != 200, status)
print(json.dumps(results))
'''


def analyze_logs(logs: str) -> list[dict]:
    """Access-log checks: every record is JSON; denials are logged as such; the allowed request is."""
    results = []
    records = []
    for line in logs.splitlines():
        if line.startswith("{") and '"url"' in line:
            try:
                records.append(json.loads(line))
            except ValueError:
                results.append({"check": "access log line is JSON", "ok": False, "detail": line[:200]})
    results.append({"check": "JSON access log", "ok": len(records) > 0, "detail": f"{len(records)} records"})
    by_url = {}
    for record in records:
        by_url.setdefault(record.get("url"), set()).add(record.get("result"))
    denied = ["example.com:22", "denied.example.net:443", "http://denied.example.net/",
              "http://169.254.169.254/latest/meta-data/"]
    results.append({"check": "denied requests logged as TCP_DENIED",
                    "ok": all(by_url.get(url) == {"TCP_DENIED"} for url in denied),
                    "detail": {url: sorted(by_url.get(url, [])) for url in denied}})
    results.append({"check": "allowed request logged", "ok": "TCP_MISS" in by_url.get("http://example.com/", set()),
                    "detail": sorted(by_url.get("http://example.com/", []))})
    return results


def docker(*args: str, check: bool = True, capture: bool = True, timeout: float = 600) -> subprocess.CompletedProcess:
    result = subprocess.run([DOCKER, *args], capture_output=capture, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} ... failed:\n{result.stderr}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default=os.environ.get("EGRESS_IMAGE", "clearideas-egress:test"))
    parser.add_argument("--no-build", action="store_true", help="use an already built image")
    args = parser.parse_args()

    if not args.no_build:
        print(f"smoke: building {args.image}", file=sys.stderr)
        docker("build", "-q", "-t", args.image, str(REPO))

    read_only = os.environ.get("EGRESS_DOCKER_VOLUME_OPTS", "ro")
    writable_options = [option for option in read_only.split(",") if option != "ro"]  # e.g. SELinux "z"
    volume_suffix = ":" + ",".join(writable_options) if writable_options else ""
    tag = "egress-smoke-" + uuid.uuid4().hex[:8]
    network, origin, proxy, client = tag, tag + "-origin", tag + "-proxy", tag + "-client"
    results: list[dict] = []
    tmp = Path(tempfile.mkdtemp(prefix="egress-smoke."))
    try:
        tmp.chmod(0o755)
        policy = tmp / "policy.json"
        policy.write_text(json.dumps({"version": 1, "principals": {"demo": ["http://example.com"]}}))
        policy.chmod(0o644)

        # A throwaway error CA, made with the image's own openssl (the host may not have one).
        ca_dir = tmp / "ca"
        ca_dir.mkdir()
        ca_dir.chmod(0o777)
        docker("run", "--rm", "--user", "0", "--network", "none", "-v", f"{ca_dir}:/out{volume_suffix}",
               "--entrypoint", "sh", args.image, "-c",
               "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 "
               "-subj '/CN=egress smoke error CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' "
               "-addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout /out/error-ca.key -out /out/error-ca.pem "
               "2>/dev/null && chmod 0644 /out/error-ca.key /out/error-ca.pem")

        docker("network", "create", "--internal", "--subnet", SUBNET, network)
        docker("run", "-d", "--name", origin, "--network", network, "--ip", ORIGIN_IP,
               "--network-alias", "example.com", "--user", "0", "--entrypoint", "python3", args.image,
               "-m", "http.server", "80", "--bind", "0.0.0.0", "--directory", "/tmp")
        docker("run", "-d", "--name", proxy, "--network", network,
               "--read-only", "--tmpfs", "/run/egress:mode=1777,size=16m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "-e", "EGRESS_DEMO_USER=demo", "-e", f"EGRESS_DEMO_PASSWORD={PASSWORD}",
               "-e", "EGRESS_POLICY_FILE=/etc/egress/policy.json", "-e", "EGRESS_DRAIN_SECONDS=2",
               "-e", "EGRESS_ERROR_CA_CERT_FILE=/etc/egress-ca/error-ca.pem",
               "-e", "EGRESS_ERROR_CA_KEY_FILE=/etc/egress-ca/error-ca.key",
               "-v", f"{policy}:/etc/egress/policy.json:{read_only}",
               "-v", f"{ca_dir}:/etc/egress-ca:{read_only}", args.image)

        user = docker("image", "inspect", "-f", "{{.Config.User}}", args.image).stdout.strip()
        results.append({"check": "image USER is numeric (Kubernetes runAsNonRoot)",
                        "ok": bool(re.fullmatch(r"[1-9][0-9]*(:[0-9]+)?", user)), "detail": user})
        uid = docker("exec", proxy, "id", "-u").stdout.strip()
        results.append({"check": "proxy runs as non-root", "ok": uid not in ("", "0"), "detail": f"uid={uid}"})

        run = docker("run", "--name", client, "--network", network, "-v", f"{ca_dir}:/ca:{read_only}",
                     "--entrypoint", "python3", args.image,
                     "-c", CLIENT, proxy, PASSWORD, ORIGIN_IP, "/ca/error-ca.pem", check=False, timeout=180)
        try:
            results += json.loads(run.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            results.append({"check": "client ran", "ok": False, "detail": run.stdout[-500:] + run.stderr[-1500:]})

        logs = docker("logs", proxy).stdout + docker("logs", proxy).stderr
        results += analyze_logs(logs)
        results.append({"check": "password never logged", "ok": PASSWORD not in logs})

        started = time.monotonic()
        docker("stop", "-t", "30", proxy)
        state = json.loads(docker("inspect", proxy).stdout)[0]["State"]
        results.append({"check": "docker stop exits cleanly", "ok": state["ExitCode"] in (0, 143),
                        "detail": f"exit={state['ExitCode']} after {time.monotonic() - started:.1f}s "
                                  f"oom={state.get('OOMKilled')}"})
    except Exception as error:  # report, then clean up
        results.append({"check": "smoke harness", "ok": False, "detail": repr(error)})
    finally:
        failed = [r for r in results if not r["ok"]]
        if failed:
            tail = docker("logs", "--tail", "60", proxy, check=False)
            print("---- proxy logs (tail) ----\n" + tail.stdout + tail.stderr, file=sys.stderr)
        for name in (client, proxy, origin):
            docker("rm", "-f", name, check=False)
        docker("network", "rm", network, check=False)
        shutil.rmtree(tmp, ignore_errors=True)

    for r in results:
        print(f"{'ok  ' if r['ok'] else 'FAIL'}  {r['check']}" + (f"  ({r['detail']})" if r.get("detail") else ""))
    failed = [r for r in results if not r["ok"]]
    print(f"smoke: {len(results) - len(failed)}/{len(results)} checks passed", file=sys.stderr)
    return 1 if failed or not results else 0


if __name__ == "__main__":
    sys.exit(main())
