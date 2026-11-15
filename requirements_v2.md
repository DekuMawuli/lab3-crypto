# Requirements v2

## Overview
The project is a TCP client for Applied Cryptography Lab 3 ("AES Encryption and Hashing"), implementing `crypto_message_spec_v2.md` against the course cloud server. It has two independent halves: an AES-256-GCM encrypt/decrypt round trip, and a course-specific HMAC compute/verify round trip (nested SHA-256, per Lecture 7's "Protocol Two (HMAC)" — not RFC 2104 HMAC). Encryption and HMAC computation always happen locally in the client; the server only hands out keys, decrypts, and checks HMACs.

## Project Requirements

### General
1. The code shall be written in Python 3, using only the standard library plus the `cryptography` package (for AES-GCM and SHA-256 primitives — not its HMAC module, see item 16).
2. The user interface shall use tkinter.
3. Networking and crypto logic shall be separate modules from the UI, so both are testable without a window.
4. Network requests shall run off the UI thread; the window shall remain responsive during a request.

### UI
5. The UI shall have fields for Server IP, Port (default 8080), and Username, and a Message type selector covering `get_key`, `decrypt`, and `verify_hmac`.
6. The UI shall let the user browse to a base file. From that base file's path, the client shall derive the companion file names (`<name>.enc`, `<name>.key`, `<name>.hmac`, `<name>.hmackey`) automatically per spec sections 5 and 6, rather than requiring the user to browse to each one individually.
7. The UI shall have a "Get Key" action (sends `get_key`, saves the returned key next to the chosen base file with the correct extension) and action buttons to run encryption, decryption, HMAC computation, and HMAC verification.
8. The UI shall show a progress indicator during network calls and a status line distinguishing: idle, in progress, success, `verify_result: FAILED` (a valid but negative outcome), and `error` (a malformed-request failure) — these two outcomes shall look visibly different, not both read as "failed."
9. Start of any action shall be blocked with an inline error, not a crash, if required fields are empty, the chosen file does not exist, or the file exceeds the spec's size limit (item 14).

### Transport and framing (spec section 3)
10. Every message in both directions shall use the exact framing: 4-byte big-endian unsigned length, then that many bytes of UTF-8 JSON header (≤1000 bytes), then the optional raw payload of `payload_len` bytes.
11. All socket reads shall loop until the requested byte count has been received; a single `recv()` call is never assumed to return the full amount.
12. One TCP connection is opened per request (connect, send, read reply, close), per the spec's recommended pattern.

### AES-GCM (spec section 5)
13. `get_key` returns a 32-byte AES key (base64 on the wire). Only server-issued keys are used for encryption; the client does not invent its own AES key.
14. Encryption: AES-256-GCM, no associated data. Output layout is exactly `nonce(12 random bytes, fresh per file) || ciphertext || tag(16 bytes)`. The largest plaintext accepted is 1,048,548 bytes (1 MiB − 28); larger files are rejected client-side before sending.
15. `decrypt` sends the key as standard base64 (with `=` padding) in the header and the encrypted file as the payload; the reply payload is written out as the decrypted file.

### Custom HMAC (spec section 6 / Lecture 7)
16. The HMAC is computed by hand as: `Ki = K XOR (0x36 * 32 bytes)`, `Ko = K XOR (0x5c * 32 bytes)`, `HMAC = SHA256(Ko || SHA256(Ki || x))`, where `x` is the raw file bytes and both SHA-256 calls operate on raw bytes (the inner result is never converted to hex before the outer hash). This is implemented directly with a SHA-256 primitive; the `cryptography` library's HMAC class is not used, since it implements RFC 2104 and would not match the server.
17. `verify_hmac` sends `key` and `hmac` as standard base64 in the header and the file as the payload. The reply's `result` field (`VERIFIED` or `FAILED`) is surfaced to the user as-is; a `FAILED` result is not treated as an exception or program error (item 8).

### Verification before using the real server
18. Before any network call is made, the framing implementation is checked against the spec's section 9 framing vector (the exact 61-byte `get_key` message), the AES-GCM implementation against its section 9 test vector (`hello world`, the given key and nonce, the expected 39-byte ciphertext), and the HMAC implementation against both section 9 vectors (the `hello world` case and the empty-file case).
19. A local fake server (implementing section 3 framing and canned replies on `127.0.0.1`) is used to exercise connection-level error paths — bad username, oversized payload, malformed header — without needing the real network or risking the real server's state.

### Security hygiene
20. The AES/HMAC keys are never printed to the console or written to any log; they exist only in memory and in their `.key` / `.hmackey` companion files.
21. The server IP, port, and username live in a local config file excluded from the shared git repository, not in source.

## Open decisions (defaults assumed, please check)
- **Config format:** a small JSON file (`config.local.json`, gitignored) with `server_ip`, `port`, `username`; a committed `config.example.json` shows the shape with placeholder values. The UI fields also let these be overridden/typed in per-session without editing the file.
- **File selection scope:** one base file is "active" at a time (matching the AES and HMAC workflows run independently in spec section 1); the client does not batch multiple files in one run.
- **Fake server scope:** the fake server only needs to prove framing/parsing correctness and exercise error paths; it is not expected to implement the real AES-GCM or HMAC semantics faithfully, so all crypto correctness checks are against the spec's section 9 vectors and the real server, not the fake one.
