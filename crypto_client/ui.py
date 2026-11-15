"""tkinter shell. The only module in this package that imports tkinter.
Every network/crypto call runs in a worker thread; results come back through
a queue polled with root.after, so the window never blocks (requirement 4)."""
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from crypto_client import net
from crypto_client.companions import companion_path
from crypto_client.config import load_config
from crypto_client.crypto_ops import MAX_PLAINTEXT_LEN, custom_hmac, encrypt_file

CONFIG_DIR = Path(__file__).resolve().parent.parent


class CryptoClientApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Crypto Client")

        config = load_config(
            CONFIG_DIR / "config.local.json",
            fallback=CONFIG_DIR / "config.example.json",
        )

        self._queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._key: bytes | None = None
        self._base_file = tk.StringVar()

        self.server_ip = tk.StringVar(value=config.get("server_ip", ""))
        self.port = tk.StringVar(value=str(config.get("port", 8080)))
        self.username = tk.StringVar(value=config.get("username", ""))
        self.status = tk.StringVar(value="Ready.")
        self.key_status = tk.StringVar(value="No key fetched yet.")

        self._build_widgets()
        self.root.after(50, self._poll_queue)

    def _build_widgets(self):
        pad = {"padx": 6, "pady": 3}
        row = 0

        ttk.Label(self.root, text="Server IP").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(self.root, textvariable=self.server_ip, width=20).grid(row=row, column=1, **pad)
        ttk.Label(self.root, text="Port").grid(row=row, column=2, sticky="w", **pad)
        ttk.Entry(self.root, textvariable=self.port, width=8).grid(row=row, column=3, **pad)
        row += 1

        ttk.Label(self.root, text="Username").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(self.root, textvariable=self.username, width=20).grid(row=row, column=1, **pad)
        row += 1

        ttk.Button(self.root, text="Get Key", command=self._on_get_key).grid(row=row, column=0, **pad)
        ttk.Label(self.root, textvariable=self.key_status).grid(row=row, column=1, columnspan=3, sticky="w", **pad)
        row += 1

        ttk.Label(self.root, text="Base file").grid(row=row, column=0, sticky="w", **pad)
        ttk.Entry(self.root, textvariable=self._base_file, width=36).grid(row=row, column=1, columnspan=2, **pad)
        ttk.Button(self.root, text="Browse...", command=self._on_browse).grid(row=row, column=3, **pad)
        row += 1

        ttk.Button(self.root, text="Encrypt", command=self._on_encrypt).grid(row=row, column=0, **pad)
        ttk.Button(self.root, text="Decrypt", command=self._on_decrypt).grid(row=row, column=1, **pad)
        ttk.Button(self.root, text="Compute HMAC", command=self._on_compute_hmac).grid(row=row, column=2, **pad)
        ttk.Button(self.root, text="Verify HMAC", command=self._on_verify_hmac).grid(row=row, column=3, **pad)
        row += 1

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.grid(row=row, column=0, columnspan=4, sticky="ew", **pad)
        row += 1

        self.status_label = ttk.Label(self.root, textvariable=self.status)
        self.status_label.grid(row=row, column=0, columnspan=4, sticky="w", **pad)

    # -- helpers -----------------------------------------------------

    def _on_browse(self):
        path = filedialog.askopenfilename()
        if path:
            self._base_file.set(path)

    def _connection_fields(self):
        if not self.server_ip.get() or not self.username.get():
            self._set_status("error", "Server IP and username are required.")
            return None
        try:
            port = int(self.port.get())
        except ValueError:
            self._set_status("error", "Port must be a number.")
            return None
        return self.server_ip.get(), port, self.username.get()

    def _base_file_or_error(self):
        path = self._base_file.get()
        if not path or not os.path.exists(path):
            self._set_status("error", "Choose a file that exists first.")
            return None
        if os.path.getsize(path) > MAX_PLAINTEXT_LEN:
            self._set_status("error", f"File exceeds the {MAX_PLAINTEXT_LEN}-byte limit.")
            return None
        return path

    def _set_status(self, kind: str, text: str):
        self.status.set(text)
        color = {"error": "red", "failed": "orange", "ok": "black"}.get(kind, "black")
        self.status_label.configure(foreground=color)

    def _run_in_background(self, fn):
        self.progress.start(10)
        threading.Thread(target=self._worker, args=(fn,), daemon=True).start()

    def _worker(self, fn):
        self._pending_kind = "ok"
        try:
            fn()
            self._queue.put((self._pending_kind, self.status.get()))
        except net.ServerError as e:
            self._queue.put(("error", f"error: {e}"))
        except Exception as e:
            self._queue.put(("error", str(e)))

    def _poll_queue(self):
        try:
            while True:
                kind, text = self._queue.get_nowait()
                self.progress.stop()
                self._set_status(kind, text)
        except queue.Empty:
            pass
        self.root.after(50, self._poll_queue)

    # -- actions -------------------------------------------------------

    def _on_get_key(self):
        fields = self._connection_fields()
        if not fields:
            return
        host, port, username = fields

        def work():
            with net.connect(host, port) as sock:
                self._key = net.get_key(sock, username)
            self.key_status.set("Key fetched.")
            self.status.set("Key fetched.")

        self._run_in_background(work)

    def _on_encrypt(self):
        base = self._base_file_or_error()
        if base is None or self._key is None:
            if self._key is None:
                self._set_status("error", "Get a key first.")
            return

        def work():
            with open(base, "rb") as f:
                plaintext = f.read()
            encrypted = encrypt_file(self._key, plaintext)
            Path(companion_path(base, "enc")).write_bytes(encrypted)
            Path(companion_path(base, "key")).write_text(
                __import__("base64").b64encode(self._key).decode()
            )
            self.status.set(f"Encrypted -> {companion_path(base, 'enc')}")

        self._run_in_background(work)

    def _on_decrypt(self):
        fields = self._connection_fields()
        base = self._base_file_or_error()
        if not fields or base is None:
            return
        host, port, username = fields

        def work():
            import base64
            key = base64.b64decode(Path(companion_path(base, "key")).read_text())
            encrypted = Path(companion_path(base, "enc")).read_bytes()
            with net.connect(host, port) as sock:
                decrypted = net.decrypt(sock, username, key, encrypted)
            out_path = companion_path(base, "dec")
            Path(out_path).write_bytes(decrypted)
            self.status.set(f"Decrypted -> {out_path}")

        self._run_in_background(work)

    def _on_compute_hmac(self):
        base = self._base_file_or_error()
        if base is None or self._key is None:
            if self._key is None:
                self._set_status("error", "Get a key first.")
            return

        def work():
            import base64
            file_bytes = Path(base).read_bytes()
            mac = custom_hmac(self._key, file_bytes)
            Path(companion_path(base, "hmac")).write_text(base64.b64encode(mac).decode())
            Path(companion_path(base, "hmackey")).write_text(base64.b64encode(self._key).decode())
            self.status.set(f"HMAC written -> {companion_path(base, 'hmac')}")

        self._run_in_background(work)

    def _on_verify_hmac(self):
        fields = self._connection_fields()
        base = self._base_file_or_error()
        if not fields or base is None:
            return
        host, port, username = fields

        def work():
            import base64
            key = base64.b64decode(Path(companion_path(base, "hmackey")).read_text())
            mac = base64.b64decode(Path(companion_path(base, "hmac")).read_text())
            file_bytes = Path(base).read_bytes()
            with net.connect(host, port) as sock:
                result = net.verify_hmac(sock, username, key, mac, file_bytes)
            if result == "VERIFIED":
                self.status.set("VERIFIED")
            else:
                self._pending_kind = "failed"
                self.status.set("FAILED (HMAC did not match)")

        self._run_in_background(work)


def main():
    root = tk.Tk()
    CryptoClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
