# Applied Cryptography Lab 3 — AES Encryption and Hashing

A tkinter client implementing `crypto_message_spec_v2.md`: AES-256-GCM encrypt/decrypt and the
course's custom HMAC compute/verify, against the instructor's server.

Source repository: <https://github.com/DekuMawuli/lab3-crypto>

## Workflow (lineage visible in git history)

1. `Requirements_v1.md` — student-authored, committed before any AI involvement.
2. `requirements_v2.md`, `design_v1.md` — AI-assisted refinement.
3. `crypto_client/` — source and tests.
4. `interrogation.md` — design/implementation Q&A.

## Where to find the results

- `crypto_client/tests/` — automated tests, including the spec's section 9 vectors for framing,
  AES-GCM, and the custom HMAC, plus an offline round trip against `fake_server.py`.
- Run them: `.venv/bin/python -m pytest crypto_client/` (22 passing as of the last commit).
- `results/` — evidence of the two required round trips against the real server once
  `config.local.json` is filled in with the instructor-provided IP, port, and username.
