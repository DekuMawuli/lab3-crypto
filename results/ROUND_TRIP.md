# Round-trip evidence — real server (18.225.10.8:8080, user mdeku)

Run 2026-11-17. `sample.txt` is the evidence file; its companion files
(`.enc`, `.key`, `.hmac`, `.hmackey`) are generated locally and are gitignored,
since the keys must never be committed (requirement 20/21).

## AES-256-GCM (encrypt → server decrypt)

- `get_key` → 32-byte key.
- Local `encrypt_file` → `sample.txt.enc` (103 bytes = 75-byte plaintext + 28-byte overhead).
- Server `decrypt` reply, written to `sample.txt.dec`.
- **Result: `sample.txt.dec` is byte-for-byte identical to `sample.txt`.**

## Custom HMAC (compute → server verify)

- `get_key` → 32-byte key.
- Local `custom_hmac` (spec section 6 / Lecture 7 construction) → `sample.txt.hmac`.
- Server `verify_hmac` on the unmodified file → **`VERIFIED`**.
- Same key and HMAC, file with its last byte flipped → **`FAILED`** (not an `error` —
  confirms the two outcomes are distinguished correctly, per spec section 4.3).

## Automated test suite

`.venv/bin/python -m pytest crypto_client/` → **22 passed**, covering the spec's
section 9 framing/AES-GCM/HMAC vectors and an offline round trip against
`fake_server.py`.
