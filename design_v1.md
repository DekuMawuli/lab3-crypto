# Design v1 – Crypto Client (AES-GCM + Custom HMAC)

Implements requirements_v2.md. Python 3, tkinter, `cryptography` package for AES-GCM and SHA-256 primitives only.

## 1. Approach in one paragraph
The client is a thin tkinter shell over two pure-Python modules that know nothing about Tk: `protocol.py` (framing + the three request/reply builders) and `crypto_ops.py` (AES-GCM file format, the custom HMAC). A `net.py` module opens one socket per request, sends, and reads the reply using `recv_exact`. The UI never blocks: every button click spawns a worker thread that calls into `net.py`/`crypto_ops.py` and posts results back to the UI through a `queue.Queue`, polled with `root.after`.

## 2. Module layout
```
crypto_client/
  main.py          # entry point
  ui.py            # tkinter window, thread dispatch, queue polling (only module that imports tkinter)
  config.py        # loads config.local.json (gitignored) / config.example.json, UI field overrides
  protocol.py       # header framing, recv_exact, build_request/parse_reply for get_key, decrypt, verify_hmac
  crypto_ops.py     # AES-GCM encrypt/decrypt-file-format, custom_hmac(key, data)
  net.py            # one-connection-per-request exchange(), wraps protocol.py over a socket
  fake_server.py    # local test server: framing + canned replies + the same custom_hmac check
  tests/
    test_protocol.py    # framing vector (section 9)
    test_crypto_ops.py  # AES-GCM vector, HMAC vectors (section 9)
    test_fake_server.py # error paths: bad username, oversized payload, malformed header
config.example.json
requirements.txt    # cryptography
```

## 3. Framing (protocol.py)
```python
import struct, json

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before n bytes received")
        buf += chunk
    return bytes(buf)

def send_message(sock, header: dict, payload: bytes = b""):
    header = dict(header, payload_len=len(payload))
    hb = json.dumps(header).encode("utf-8")
    assert len(hb) <= 1000, "header exceeds 1000-byte limit"
    sock.sendall(struct.pack(">I", len(hb)) + hb + payload)

def recv_message(sock):
    (hlen,) = struct.unpack(">I", recv_exact(sock, 4))
    header = json.loads(recv_exact(sock, hlen))
    payload = recv_exact(sock, header.get("payload_len", 0))
    return header, payload
```
Header length is big-endian per spec section 3; this is the first thing tested, against the section 9 vector, before anything else is built.

## 4. Requests (protocol.py, built on send_message/recv_message)
- `get_key(sock, username)` → sends `{"type":"get_key","username":...}`, expects `key_result`, returns the 32 raw key bytes (`base64.b64decode`).
- `decrypt(sock, username, key, enc_bytes)` → sends `{"type":"decrypt","username":...,"key":b64(key)}` with `enc_bytes` as payload, expects `decrypt_result`, returns the decrypted payload bytes.
- `verify_hmac(sock, username, key, mac, file_bytes)` → sends `{"type":"verify_hmac",...,"key":b64(key),"hmac":b64(mac)}` with `file_bytes` as payload, expects `verify_result`, returns `"VERIFIED"` or `"FAILED"`.
- Any `{"type":"error", "detail":...}` reply raises `ServerError(detail)`, caught separately from a `FAILED` verify result (requirement 8/17: these must not be conflated).

## 5. AES-GCM (crypto_ops.py)
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)   # cryptography returns ciphertext||tag already joined

def decrypt_local(key: bytes, blob: bytes) -> bytes:
    # used only to self-check the server's decrypt_result against what we expect; the server does the real decrypt
    nonce, body = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, body, None)
```
`encrypt_file` is checked against the section 9 vector (key, nonce fixed, `hello world` → the given 39-byte hex) before any networking — the nonce generator is swapped for a fixed one in that one test.

## 6. Custom HMAC (crypto_ops.py)
```python
from cryptography.hazmat.primitives import hashes

def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()

def custom_hmac(key: bytes, data: bytes) -> bytes:
    assert len(key) == 32
    ki = bytes(b ^ 0x36 for b in key)
    ko = bytes(b ^ 0x5C for b in key)
    return sha256(ko + sha256(ki + data))
```
This is Lecture 7's nested-MAC construction (`y = ψMD(ko || ψMD(ki || x))`) applied with `ψMD = SHA-256`. Checked against both section 9 vectors (`hello world` and the empty file) before it ever talks to the HMAC key derived from a real `get_key` call.

## 7. File naming (ui.py / a small `companions.py` helper)
Given a base file `report.txt`, derive:
- `report.txt.enc`, `report.txt.key` for the AES workflow
- `report.txt.hmac`, `report.txt.hmackey` for the HMAC workflow

A pure function `companion_path(base_path, suffix)` returns `f"{base_path}.{suffix}"`; used by both the UI (to prefill Save-as fields) and tests.

## 8. UI (ui.py)
```
+--------------------------------------------------------------+
| Server IP  [____________]        Port [8080]                 |
| Username   [____________]                                    |
| Message type [ Get AES key v ]                                |
| [Get Key]   <status: "No key fetched yet.">                  |
| Base file  [___________________________________] [Browse...] |
| [Encrypt]  [Decrypt]  [Compute HMAC]  [Verify HMAC]           |
| [=================== progress ===================]           |
| Ready.                                                        |
+--------------------------------------------------------------+
```
- Message type selects which `get_key` use the fetched key is for (next AES op vs next HMAC op) — the server endpoint is identical either way, only the client-side bookkeeping differs.
- **Threading:** each button spawns `threading.Thread(target=worker, args=(...))`; the worker never touches Tk widgets, it puts `(kind, data)` tuples on a `queue.Queue`; `root.after(50, poll_queue)` drains it and updates status/progress/enables buttons. Buttons are disabled for the duration of their own action.
- **Status line distinguishes:** idle / running / `VERIFIED` / `FAILED` (styled as a warning, not an error) / `error: <detail>` (styled as an error) / local validation message (missing field, file too large).

## 9. Fake server (fake_server.py)
A single-threaded `socketserver`-based TCP server bound to `127.0.0.1` that:
- Implements section 3 framing (shares `protocol.py`'s `recv_exact`/`recv_message`/`send_message`).
- `get_key` → returns a random 32-byte key (not remembered, matching the real server).
- `decrypt` → decrypts using `crypto_ops.decrypt_local` so a full client round trip can be tested offline.
- `verify_hmac` → recomputes `custom_hmac` over the received payload and compares.
- Deliberately returns `error` for a hardcoded bad username (`"__bad__"`) and for payloads over a small test limit, so the client's error-path handling (item 19) has something to exercise without touching the real server or its real limits.
This proves client/fake-server agreement, not correctness — correctness is the section 9 vectors and the real server.

## 10. Testing (tests/, pytest)
- `test_protocol.py`: the section 9 framing vector reproduces the exact given bytes; `recv_exact` correctly loops when `recv` is mocked to return data in small random chunks.
- `test_crypto_ops.py`: AES-GCM vector reproduces the exact 39-byte hex with the fixed key/nonce; HMAC vector reproduces both section 9 values (`hello world` and empty file); a one-byte change to the file changes the HMAC.
- `test_fake_server.py`: `get_key` → `decrypt` round trip returns the original bytes; `get_key` → `verify_hmac` returns VERIFIED, then FAILED after flipping a byte; bad username and oversized payload return `error` and are surfaced distinctly from `FAILED`.
- UI is checked manually: field validation, progress bar movement during a real network call, status line wording for all five states in item 8.

## 11. Build order (per spec section 11)
1. `protocol.py` framing + `recv_exact`, tested against the section 9 framing vector. No networking yet.
2. `crypto_ops.py` AES-GCM, tested against the section 9 AES vector. Still no networking.
3. `net.py` + real `get_key` against the actual server (needs `config.local.json` filled in with the instructor-provided IP/port/username).
4. Full encrypt → `decrypt` round trip against the real server; compare output to the original file byte-for-byte.
5. `crypto_ops.py` custom HMAC, tested against both section 9 HMAC vectors. No networking yet.
6. `verify_hmac` round trip against the real server: VERIFIED, then FAILED after changing one byte of the file.
7. `fake_server.py` + its tests, to cover error paths the real server won't reliably reproduce on demand.
8. `ui.py` + `main.py`, wiring everything above into the tkinter shell.

## 12. Risks and decisions
- **Why GCM is used as specified rather than CBC+HMAC:** the spec mandates AES-256-GCM with no AAD; GCM gives authenticated encryption in one pass, so a corrupted or tampered `.enc` file fails to decrypt rather than silently producing garbage plaintext.
- **Why the custom HMAC can't use the `cryptography` HMAC class:** that class implements RFC 2104 (key padded/compressed to the hash's block size, then hashed with ipad/opad). This course's construction uses the 32-byte key directly XORed with 0x36/0x5c with no block-size padding, so the two are numerically different — confirmed by the spec's own worked example, which says a standard-library HMAC gives the wrong answer.
- **Risk — nonce reuse:** GCM security depends on never reusing a (key, nonce) pair. Mitigated by always requesting a fresh key via `get_key` per file and generating a fresh random nonce per `encrypt_file` call (never reused across files, even with the same key).
- **Risk — thread safety of Tk:** mitigated entirely by the queue-based worker pattern in section 8 (same approach as lab1); no Tk call is ever made from a worker thread.
