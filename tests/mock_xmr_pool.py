#!/usr/bin/env python3
"""Mock Monero-dialect (RandomX) stratum pool for end-to-end miner tests.

Speaks just enough of the XMR dialect (login / job / submit / keepalived) for
the real miner binary to log in, mine at a trivial target, and submit a share.
Used by tests/run_tests.sh; not a general-purpose pool.

Its reason for existing is the NICEHASH nonce contract. Every job it sends
carries a private slice in the nonce's most-significant byte (blob byte 42),
exactly as NiceHash, xmrig-proxy and our own fee proxy hand out per-worker
slices. With --nicehash the login reply advertises the "nicehash" extension,
and every submitted nonce is then required to still carry that byte: a miner
that rewrites all four nonce bytes scans another worker's range and gets its
shares rejected as duplicates by the real pool, which is precisely the bug
this guards against. Without --nicehash the pool makes no such demand.

Modes:
  --port N     listen port (0 = ephemeral; the actual port is printed)
  --once       exit 0 after the first VALID submit has been accepted
  --nicehash   advertise the "nicehash" extension and enforce the slice
  --slice HH   the reserved nonce MSB, hex (default a7)

Stdout markers (line-buffered, consumed by the runner):
  MOCK_READY <port>   listening
  MOCK_LOGIN          a client completed login
  SUBMIT_OK <json>    a well-formed share was received and accepted
  SUBMIT_BAD <why>    a submit arrived malformed or off-slice (runner fails)
"""
import argparse
import json
import re
import socket
import sys
import threading

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

JOB_ID = "xj1"
SESSION_ID = "mock-session-1"
SEED_HASH = "00" * 31 + "01"
# 8 hex chars = the high 32 bits of the boundary. All-ones is the easiest
# possible target (difficulty 1), so the first hash a thread computes wins
# and the test does not depend on RandomX throughput.
TARGET = "ffffffff"

# Monero blob layout: the 4-byte nonce sits at byte offset 39. Everything
# else here is filler — the mock never validates the hash, only the shape
# and the slice, so the blob just has to be well-formed and >= 43 bytes.
NONCE_OFFSET = 39
BLOB_LEN = 76


def say(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def build_blob(slice_byte):
    blob = bytearray(range(BLOB_LEN))          # arbitrary but deterministic
    blob[NONCE_OFFSET:NONCE_OFFSET + 4] = bytes([0, 0, 0, slice_byte])
    return blob.hex()


def job_object(slice_byte):
    return {
        "job_id": JOB_ID,
        "blob": build_blob(slice_byte),
        "target": TARGET,
        "seed_hash": SEED_HASH,
        "height": 1,
    }


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def reply(conn, req_id, result):
    send_json(conn, {"id": req_id, "jsonrpc": "2.0", "error": None, "result": result})


class Pool:
    def __init__(self, args):
        self.args = args
        self.slice_byte = int(args.slice, 16)
        self.done = threading.Event()
        self.bad = False

    def check_submit(self, params):
        """Return None if the share is acceptable, else the reason string."""
        if not isinstance(params, dict):
            return "submit params not an object"
        if params.get("id") != SESSION_ID:
            return "wrong session id %r" % (params.get("id"),)
        if params.get("job_id") != JOB_ID:
            return "wrong job_id %r" % (params.get("job_id"),)

        nonce = params.get("nonce", "")
        result = params.get("result", "")
        if not isinstance(nonce, str) or len(nonce) != 8 or not HEX_RE.match(nonce):
            return "bad nonce %r" % (nonce,)
        if not isinstance(result, str) or len(result) != 64 or not HEX_RE.match(result):
            return "bad result hash %r" % (result,)

        # The nonce is submitted in blob byte order, so its most-significant
        # byte — the slice the pool reserved — is the LAST hex pair.
        if self.args.nicehash:
            msb = int(nonce[6:8], 16)
            if msb != self.slice_byte:
                return ("nonce %s left slice %02x (MSB %02x) — miner ignored "
                        "the nicehash extension" % (nonce, self.slice_byte, msb))
        return None

    def serve_client(self, conn):
        buf = b""
        with conn:
            while not self.done.is_set():
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self.handle(conn, line)

    def handle(self, conn, line):
        try:
            msg = json.loads(line.decode())
        except ValueError:
            say("SUBMIT_BAD unparseable line %r" % (line[:120],))
            self.bad = True
            self.done.set()
            return

        method = msg.get("method")
        req_id = msg.get("id")

        if method == "login":
            result = {
                "id": SESSION_ID,
                "status": "OK",
                "job": job_object(self.slice_byte),
            }
            if self.args.nicehash:
                result["extensions"] = ["algo", "nicehash", "keepalive"]
            reply(conn, req_id, result)
            say("MOCK_LOGIN")
        elif method == "submit":
            why = self.check_submit(msg.get("params"))
            if why:
                say("SUBMIT_BAD " + why)
                self.bad = True
                reply(conn, req_id, {"status": "OK"})
                self.done.set()
                return
            reply(conn, req_id, {"status": "OK"})
            say("SUBMIT_OK " + json.dumps(msg.get("params")))
            if self.args.once:
                self.done.set()
        elif method == "keepalived":
            reply(conn, req_id, {"status": "KEEPALIVED"})
        else:
            reply(conn, req_id, {"status": "OK"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--nicehash", action="store_true")
    ap.add_argument("--slice", default="a7")
    args = ap.parse_args()

    pool = Pool(args)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(4)
    srv.settimeout(0.5)
    say("MOCK_READY %d" % srv.getsockname()[1])

    while not pool.done.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=pool.serve_client, args=(conn,), daemon=True).start()

    srv.close()
    return 1 if pool.bad else 0


if __name__ == "__main__":
    sys.exit(main())
