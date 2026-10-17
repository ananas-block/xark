#!/usr/bin/env python3
"""Real-browser test of proveStreaming + the worker pool, both paths.

Serves crates/wasm (plus a fixtures dir: circuit.xbc, pk.bin, vk.bin for
sha256("abc") with a `--streamable` key) twice — once WITH the COOP/COEP headers
(cross-origin isolated → SharedArrayBuffer → worker pool) and once WITHOUT
(the common embedding: no SAB → single-threaded fallback) — opens each in headless
Chrome, and checks the reports the page POSTs back.

  wasm-pack build crates/wasm --target web --release --out-dir dist/web
  python3 crates/wasm/tests/browser/run.py <fixtures-dir> [browser]

`browser` is a Chrome binary (default: the macOS install), or `playwright:firefox`
/ `playwright:webkit` / `playwright:chromium` to drive a Playwright engine
(`PLAYWRIGHT_DIR` = a directory where `npm install playwright` ran; set
`PLAYWRIGHT_BROWSERS_PATH` if the browsers were installed elsewhere).
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

WASM_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIXTURES = os.path.abspath(sys.argv[1])
CHROME = sys.argv[2] if len(sys.argv) > 2 else "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def make_handler(isolated, results):
    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=WASM_DIR, **kw)

        def translate_path(self, path):
            if path.startswith("/fixtures/"):
                return os.path.join(FIXTURES, os.path.basename(path))
            return super().translate_path(path)

        def end_headers(self):
            if isolated:
                self.send_header("Cross-Origin-Opener-Policy", "same-origin")
                self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            results.append(json.loads(body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    return H


def run(isolated):
    results = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(isolated, results))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/tests/browser/index.html"
    profile = tempfile.mkdtemp()
    if CHROME.startswith("playwright:"):
        launcher = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pw_launch.mjs")
        cmd = ["node", launcher, CHROME.split(":", 1)[1], url]
    else:
        cmd = [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", f"--user-data-dir={profile}", url]
    chrome = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import time
        for _ in range(600):
            if results:
                break
            time.sleep(0.5)
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=10)
        except subprocess.TimeoutExpired:
            chrome.kill()
            chrome.wait()
        srv.shutdown()
        shutil.rmtree(profile, ignore_errors=True)
    if not results:
        raise SystemExit(f"no result from the page (isolated={isolated})")
    return results[0]


def main():
    iso = run(True)
    plain = run(False)
    brief = lambda r: {k: v for k, v in r.items() if not k.endswith("Proof")}
    print(json.dumps({"isolated": brief(iso), "not_isolated": brief(plain)}, indent=2))
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + msg)
        ok &= bool(cond)

    for name, r in (("isolated", iso), ("not isolated", plain)):
        check("error" not in r, f"{name}: no error")
        check(r.get("singleVerifies") is True, f"{name}: single-threaded proof verifies")
    check(iso.get("crossOriginIsolated") is True and iso.get("supported") is True, "COOP/COEP page: parallel supported")
    check(iso.get("poolVerifies") is True, "COOP/COEP page: pool proof verifies")
    check(iso.get("poolProof") == iso.get("singleProof"), "pool proof is byte-identical to single-threaded")
    check((iso.get("poolStats") or {}).get("fftCalls", 0) >= 4, "FFT sweeps ran on Web Workers")
    check(plain.get("supported") is False, "no-headers page: parallel unsupported (fallback)")
    check(str(plain.get("createPool", "")).startswith("refused"), "no-headers page: createPool refuses")
    check(plain.get("singleProof") == iso.get("singleProof"), "fallback proof identical across pages")
    for name, r in (("isolated", iso), ("not isolated", plain)):
        check(r.get("fetchStreamProof") == iso.get("singleProof"), f"{name}: proveFromStream(fetch(pk.bin)) gives the same proof")
    if os.path.exists(os.path.join(FIXTURES, "pk_smooth.bin")):
        want = iso.get("smoothSingleProof")
        for name, r in (("isolated", iso), ("not isolated", plain)):
            check(r.get("smoothSingleVerifies") is True, f"{name}: smooth-domain proof verifies")
            check(r.get("smoothSingleProof") == want, f"{name}: smooth-domain proof identical across pages")
            for k in ("smoothFetchHinted", "smoothFetchUnhinted"):
                check(r.get(k) == want, f"{name}: {k} gives the same smooth proof")
        check(iso.get("smoothPoolVerifies") is True, "COOP/COEP page: smooth pool proof verifies")
        check(iso.get("smoothPoolProof") == want, "smooth pool proof is byte-identical to single-threaded")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
