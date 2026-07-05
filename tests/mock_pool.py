#!/usr/bin/env python3
"""Mock standard-protocol stratum pool for end-to-end miner tests.

Speaks just enough stratum (subscribe / authorize / set_difficulty / notify /
submit) for the real miner binary to connect, build work, mine at a trivial
difficulty, and submit a share — which this server validates for shape and
accepts. Used by tests/run_tests.sh; not a general-purpose pool.

Modes:
  --port N     listen port (0 = ephemeral; the actual port is printed)
  --tls CERT   wrap the socket in TLS using CERT (a combined PEM with key,
               e.g. from `openssl req -x509 -newkey rsa:2048 -nodes`)
  --once       exit 0 after the first VALID submit has been accepted
  --diff D     stratum difficulty to assign (default 0.001 — a 2-thread
               sha256d run finds a share within a second or two)

Stdout markers (line-buffered, consumed by the runner):
  MOCK_READY <port>   listening
  MOCK_AUTHORIZED     a client completed subscribe+authorize
  SUBMIT_OK <json>    a well-formed share was received and accepted
  SUBMIT_BAD <why>    a submit arrived malformed (runner fails the test)
"""
import argparse
import json
import re
import socket
import ssl
import sys
import threading
import time

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

JOB_ID = "j1"
XNONCE1 = "08000002"       # 4 bytes
XNONCE2_SIZE = 4           # miner must submit 8 hex chars of extranonce2
NTIME = "%08x" % int(time.time())

NOTIFY_PARAMS = [
    JOB_ID,
    "00" * 32,             # prevhash
    "01" * 24,             # coinb1 (arbitrary, even-length hex)
    "02" * 24,             # coinb2
    [],                    # merkle branches
    "20000000",            # version
    "1d00ffff",            # nbits
    NTIME,
    True,                  # clean_jobs
]


def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def validate_submit(params):
    if not isinstance(params, list) or len(params) != 5:
        return "expected 5 params, got %r" % (params,)
    for i, p in enumerate(params):
        if not isinstance(p, str):
            return "param %d is not a string" % i
    user, job_id, xnonce2, ntime, nonce = params
    if job_id != JOB_ID:
        return "job_id %r != %r" % (job_id, JOB_ID)
    if len(xnonce2) != XNONCE2_SIZE * 2 or not HEX_RE.match(xnonce2):
        return "extranonce2 %r is not %d hex chars" % (xnonce2, XNONCE2_SIZE * 2)
    if len(ntime) != 8 or not HEX_RE.match(ntime):
        return "ntime %r is not 8 hex chars" % ntime
    if len(nonce) != 8 or not HEX_RE.match(nonce):
        return "nonce %r is not 8 hex chars" % nonce
    return None


def handle_client(conn, args, done_event):
    conn.settimeout(60)
    buf = b""
    authorized = False
    while not done_event.is_set():
        try:
            chunk = conn.recv(4096)
        except (OSError, ssl.SSLError):
            return
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                say("SUBMIT_BAD undecodable line %r" % line[:80])
                continue
            mid = msg.get("id")
            method = msg.get("method", "")
            if method == "mining.subscribe":
                send_json(conn, {"id": mid, "error": None, "result": [
                    [["mining.set_difficulty", "d1"], ["mining.notify", "n1"]],
                    XNONCE1, XNONCE2_SIZE]})
            elif method == "mining.authorize":
                send_json(conn, {"id": mid, "error": None, "result": True})
                if not authorized:
                    authorized = True
                    say("MOCK_AUTHORIZED")
                    send_json(conn, {"id": None, "method": "mining.set_difficulty",
                                     "params": [args.diff]})
                    send_json(conn, {"id": None, "method": "mining.notify",
                                     "params": NOTIFY_PARAMS})
            elif method == "mining.extranonce.subscribe":
                send_json(conn, {"id": mid, "error": None, "result": True})
            elif method == "mining.submit":
                why = validate_submit(msg.get("params"))
                if why:
                    say("SUBMIT_BAD " + why)
                    send_json(conn, {"id": mid, "error": [20, why, None],
                                     "result": None})
                    continue
                send_json(conn, {"id": mid, "error": None, "result": True})
                say("SUBMIT_OK " + json.dumps(msg.get("params")))
                if args.once:
                    # Give the reply time to flush through TLS before exiting.
                    time.sleep(0.3)
                    done_event.set()
                    return
            elif mid is not None:
                send_json(conn, {"id": mid, "error": None, "result": True})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--tls", metavar="PEM", default=None)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--diff", type=float, default=0.001)
    args = ap.parse_args()

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(4)
    srv.settimeout(1.0)
    say("MOCK_READY %d" % srv.getsockname()[1])

    done_event = threading.Event()
    while not done_event.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if ctx:
            try:
                conn = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError as e:
                say("SUBMIT_BAD tls handshake failed: %s" % e)
                conn.close()
                continue
        t = threading.Thread(target=handle_client, args=(conn, args, done_event),
                             daemon=True)
        t.start()
    sys.exit(0)


if __name__ == "__main__":
    main()
