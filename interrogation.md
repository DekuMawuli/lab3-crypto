# Lab 3 — Interrogation

Questions asked after reviewing the implementation (`crypto_client/protocol.py`,
`crypto_ops.py`, `net.py`, `fake_server.py`, `ui.py`), and the answers given,
demonstrating understanding of the design and implementation. See `Requirements_v1.md`,
`requirements_v2.md`, and `design_v1.md` for the full requirements/design record.

---

## Q: Why does the spec mandate AES-GCM here instead of, say, AES-CBC with a separate HMAC?

GCM is authenticated encryption in one pass: the 16-byte tag binds the ciphertext, so
tampering is detected at decrypt time rather than silently producing garbage plaintext
that a bug or attacker-controlled padding could otherwise exploit (the classic
CBC-padding-oracle class of problem). CBC+HMAC (the "MAC-then-Encrypt" pattern from
Lecture 7) achieves the same security goal but needs two separate primitives, two keys
or a key-derivation step, and gets the MAC-vs-encrypt ordering right to avoid the
documented MtE weaknesses — GCM folds all of that into one call with one key.
`crypto_ops.encrypt_file` relies on this: if the stored file is modified in transit or
on disk, `AESGCM.decrypt` raises on tag mismatch rather than returning corrupted bytes.

## Q: Why can't the HMAC half just use `cryptography`'s own HMAC class, since it's already imported for SHA-256?

The spec's test vectors (section 9) prove it would give the wrong answer, and the
lecture explains why: standard HMAC (RFC 2104) pads the key out to the hash's 64-byte
block size before deriving `ipad`/`opad` keys of that block size. This course's
"Protocol Two" construction (Lecture 7) XORs the 32-byte key directly with 32 bytes of
`0x36`/`0x5c` — no block-size padding step at all. The two constructions are
numerically different from the first XOR onward, so `custom_hmac` in `crypto_ops.py`
implements section 6 by hand with raw SHA-256 calls (`sha256(ko + sha256(ki + data))`)
rather than delegating to any HMAC primitive. `test_custom_hmac_matches_spec_section_9_hello_world_vector`
is the test that would fail immediately if a standard library were substituted in —
the spec even states the exact (wrong) digest a standard HMAC implementation would
produce for that vector, as a trap to check against.

## Q: What would change if Ki and Ko's XOR constants were swapped (0x5c for inner, 0x36 for outer)?

The inner and outer hashes would still each run, SHA-256 would still produce 32-byte
digests, and the code would not crash — but every HMAC value would differ from the
server's, because the server's reference implementation (and our test vectors) fix
`Ki = K ⊕ 0x36`, `Ko = K ⊕ 0x5c`, specifically. `verify_hmac` would come back `FAILED`
for every file, correct input or not, since the mismatch would be silent and
indistinguishable from a real tampering detection — which is exactly why
`test_custom_hmac_matches_spec_section_9_hello_world_vector` and the empty-file vector
test exist: they pin the constants against a known-correct digest before any network
call is made, so a swapped constant is caught locally in milliseconds rather than
showing up as a mysterious 100% `FAILED` rate against the real server.

## Q: Why open and close a new TCP connection for every single request instead of keeping one connection open for the whole session?

Spec section 2 recommends "one connection per request," and `net.connect` /
`decrypt`/`verify_hmac` honor that by taking a fresh socket each call rather than
holding a shared one in the client. This sidesteps needing any session or
sequencing logic — each exchange is a clean request/reply pair, there's no risk of a
stale key or stuck read from a previous exchange leaking into the next one, and
the server's own 60-second idle timeout (section 2) can never fire mid-session for a
client that never idles on an open socket. The cost is one extra TCP handshake per
action, which is irrelevant at this scale (a handful of manual button presses) but
would matter if the client needed to do many operations per second.

## Q: The spec says a `FAILED` verify result is "not an error." Why does the design go out of its way to keep that separate from a real `error` reply?

`net.py`'s `_check_reply` raises `ServerError` only for `{"type": "error"}` replies;
a `verify_result` with `result: "FAILED"` returns normally as the string `"FAILED"`.
`ui.py` mirrors this: `_on_verify_hmac`'s worker sets `self._pending_kind = "failed"`
(styled orange, a warning) only on a well-formed `FAILED` reply, while any
`ServerError` is caught separately and styled red as an `error:` message. Conflating
the two would be a real usability bug, not just a cosmetic one: the spec's own
compliance checklist calls this out explicitly ("`verify_result` FAILED is shown
differently from an `error` reply"), because a student debugging "why is everything
FAILED" needs to know immediately whether their HMAC math is wrong (a `FAILED`,
expected to be fixable by checking the vectors) or their request was malformed (an
`error`, which gives no detail and needs checking framing/username/field types
instead). `test_error_reply_raises_server_error_not_confused_with_failed_verify` and
`test_bad_username_raises_server_error_not_a_failed_result` are the tests that would
catch a regression here.

## Q: `fake_server.py` reimplements `decrypt` and `verify_hmac` using the same `crypto_ops` functions as the client. Doesn't that mean a bug in `crypto_ops.py` would just agree with itself?

Yes — that's explicitly called out in `design_v1.md` section 9 ("this proves
client/fake-server agreement, not correctness") and is why the fake server is only
one of two correctness layers, never the only one. If `custom_hmac` had the XOR
constants swapped, the fake-server round-trip tests
(`test_get_key_then_verify_hmac_round_trip_verifies_then_fails_on_tamper`) would still
pass, since both sides of that test call the same (equally wrong) function. What
actually catches that class of bug is `test_crypto_ops.py`'s hardcoded section 9
vectors, which were copied from the spec document, not derived from the code under
test — they don't move if the implementation changes. The fake server's real job is
narrower: proving the TCP/framing/threading plumbing in `net.py` and `protocol.py`
works end-to-end, and giving a safe place to test error paths (bad username,
oversized payload) that the real server might not reliably reproduce on demand
without risking its shared state.

## Q: Why does `encrypt_file` take an optional `nonce` parameter at all, if GCM's security depends on it being random and unpredictable?

Section 9's AES-GCM test vector is only checkable if the nonce is fixed to the exact
12 bytes the spec publishes (`000102...0b`) — otherwise the ciphertext would never
match the expected 39-byte hex, since GCM's output is a deterministic function of
(key, nonce, plaintext). `test_encrypt_file_matches_spec_section_9_vector_with_fixed_nonce`
passes `nonce=NONCE` explicitly for exactly this reason. In normal use (every call site
in `ui.py`), the parameter is left at its default of `None`, which triggers
`os.urandom(12)` inside the function — a fresh, unpredictable nonce per file, which is
what `test_encrypt_file_uses_a_fresh_random_nonce_by_default` checks for (two calls
with the same key must not produce the same leading 12 bytes). The parameter exists
only to make the function testable against a fixed vector; it is never a question of
the UI's own choice.
