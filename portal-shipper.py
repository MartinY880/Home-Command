#!/usr/bin/env python3
"""Tail log files and push new lines to the Home Command portal. Config: /etc/portal-shipper.json
{"url": "http://PORTAL:3000", "token": "...", "host": "npm", "sources": [{"kind": "npm", "glob": "/data/logs/proxy-host-*_access.log", "backfill": 2000000}]}"""
import glob, json, os, socket, time, urllib.request
if os.path.exists("/etc/portal-shipper.json"): CFG = json.load(open("/etc/portal-shipper.json"))
else:   # container use: configured by environment variables
    CFG = {"url": os.environ["HC_URL"].rstrip("/"), "token": os.environ["HC_TOKEN"], "host": os.environ.get("HC_HOST", ""),
           "sources": [{"kind": os.environ.get("HC_KIND", "npm"), "glob": g.strip(), "backfill": int(os.environ.get("HC_BACKFILL", "3000000"))} for g in os.environ.get("HC_GLOB", "/logs/*.log").split(",") if g.strip()]}
STATE_F = os.environ.get("HC_STATE", "/var/lib/portal-shipper.json")
try: STATE = json.load(open(STATE_F))
except Exception: STATE = {}
HOST = CFG.get("host") or socket.gethostname()

def post(kind, lines):
    req = urllib.request.Request(CFG["url"] + "/ingest/" + kind, data=json.dumps({"host": HOST, "lines": lines}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Token": CFG["token"]})
    urllib.request.urlopen(req, timeout=30).read()

def scan():
    sent = 0
    for src in CFG["sources"]:
        for path in glob.glob(src["glob"]):
            try: st = os.stat(path)
            except FileNotFoundError: continue
            s = STATE.get(path)
            if s is None: s = {"ino": st.st_ino, "off": max(0, st.st_size - int(src.get("backfill", 0)))}
            elif s["ino"] != st.st_ino or st.st_size < s["off"]: s = {"ino": st.st_ino, "off": 0}   # rotated or truncated
            STATE[path] = s
            while st.st_size > s["off"]:
                with open(path, "rb") as f:
                    f.seek(s["off"]); data = f.read(1_000_000)
                end = data.rfind(b"\n") + 1
                if end == 0:
                    if len(data) >= 1_000_000: s["off"] += len(data)   # one absurdly long line: skip it
                    break
                lines = data[:end].decode("utf-8", "replace").splitlines()
                post(src["kind"], [l for l in lines if l.strip()])
                s["off"] += end; sent += len(lines)
    return sent

while True:
    try:
        before = json.dumps(STATE, sort_keys=True); scan()
        if json.dumps(STATE, sort_keys=True) != before: json.dump(STATE, open(STATE_F + ".tmp", "w")); os.replace(STATE_F + ".tmp", STATE_F)
    except Exception as e:
        print("shipper:", repr(e), flush=True); time.sleep(10)
    time.sleep(2)
