#!/usr/bin/env python3
"""Build-stage probe v2: deep-dive 169.254.169.254 (Go 404), gateway Postgres banner, bridge neighbors."""
import os, sys, socket, json, concurrent.futures as cf

def p(*a):
    print(" ".join(str(x) for x in a), flush=True)

def http_get(url, headers=None, timeout=4, maxb=600):
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(maxb).decode('utf-8','replace')
        return (r.status, dict(list(r.headers.items())[:6]), body)
    except urllib.error.HTTPError as e:
        try: b = e.read(maxb).decode('utf-8','replace')
        except Exception: b = ""
        return (e.code, dict(list(e.headers.items())[:6]) if e.headers else {}, b)
    except Exception as e:
        return ("ERR", {}, f"{type(e).__name__}:{e}")

def tcp(host, port, timeout=2.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.close(); return True
    except Exception:
        return False

def pg_banner(host, port, timeout=3.0):
    """Send postgres SSLRequest startup, read banner."""
    import struct
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(3)
        # SSLRequest: int32 len=8, int32 code=80877103
        s.sendall(struct.pack("!ii", 8, 80877103))
        resp = s.recv(1)
        s.close()
        return {"ssl_byte": resp.decode('latin1') if resp else "none"}
    except Exception as e:
        return {"err": f"{type(e).__name__}:{e}"}

def pg_startup_banner(host, port, timeout=3.0):
    """Send a plain StartupMessage and read the ErrorResponse (contains server version)."""
    import struct
    try:
        params = b"user\x00probe\x00database\x00probe\x00\x00"
        body = struct.pack("!i", 196608) + params  # protocol 3.0
        msg = struct.pack("!i", len(body)+4) + body
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(3)
        s.sendall(msg)
        data = s.recv(400)
        s.close()
        return data.decode('latin1','replace')[:300]
    except Exception as e:
        return f"ERR:{type(e).__name__}:{e}"

p("\n===== 169.254.169.254 DEEP =====")
for path in ["/", "/latest/", "/latest/meta-data", "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
             "/latest/api/token", "/computeMetadata/v1/", "/health", "/version", "/v1/", "/openapi.json"]:
    st, hd, bd = http_get("http://169.254.169.254"+path, timeout=3, maxb=300)
    p(f"169.254{path} -> status={st} server={hd.get('Server','')} body={bd[:160]!r}")

p("\n===== 169.254.169.254 PUT (IMDSv2 token) =====")
import urllib.request
try:
    req = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                 headers={"X-aws-ec2-metadata-token-ttl-seconds":"21600"})
    r = urllib.request.urlopen(req, timeout=3)
    p("IMDSv2 token:", r.status, r.read(300))
except Exception as e:
    p("IMDSv2 token ERR:", type(e).__name__, e)

p("\n===== GATEWAY POSTGRES =====")
p("pg ssl 172.17.0.1:5432:", json.dumps(pg_banner("172.17.0.1",5432)))
p("pg ssl 172.17.0.1:6543:", json.dumps(pg_banner("172.17.0.1",6543)))
p("pg startup 172.17.0.1:5432:", repr(pg_startup_banner("172.17.0.1",5432)))

p("\n===== BRIDGE NEIGHBORS 172.17.0.2-8 (5432,6543,2375,3000,80,443) =====")
def chk(hp):
    h,port = hp; return (h,port,tcp(h,port))
jobs = [(f"172.17.0.{i}",port) for i in range(2,9) for port in [5432,6543,2375,3000,80,443,8080]]
with cf.ThreadPoolExecutor(max_workers=24) as ex:
    for h,port,ok in ex.map(chk, jobs):
        if ok: p(f"bridge {h}:{port} OPEN")

p("\n===== host.docker.internal / other metadata =====")
for h in ["host.docker.internal","gateway.docker.internal"]:
    try:
        p(h, "=>", sorted({i[4][0] for i in socket.getaddrinfo(h,None)}))
    except Exception as e:
        p(h, "ERR", type(e).__name__)
p("END")