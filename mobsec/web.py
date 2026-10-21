"""Minimal local web UI (standard library only): upload an APK, IPA or source .zip, get the report.

Binds to 127.0.0.1 by default. Uploaded files are written to a private temp dir and deleted after scanning.
"""
from __future__ import annotations

import html
import shutil
import tempfile
import threading
import uuid
import webbrowser
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_UPLOAD = 1024 * 1024 * 1024  # 1 GB
JOBS: dict[str, dict] = {}

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>mobsec-rag</title><style>
:root{--bg:#f6f5f2;--fg:#1c1b19;--card:#fff;--line:#e4e2dc;--muted:#6d6b65;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--fg:#ebeae6;--card:#1c1c1a;--line:#31302d;--muted:#9e9c95;--accent:#7ea2ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:640px;margin:0 auto;padding:48px 16px}h1{margin:0 0 4px}p{color:var(--muted)}
form{background:var(--card);border:1px dashed var(--line);border-radius:14px;padding:28px;text-align:center;margin-top:24px}
input[type=file]{margin:12px 0;max-width:100%}button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 20px;font:inherit;cursor:pointer}
.s{margin-top:22px;padding:14px;border-radius:10px;background:var(--card);border:1px solid var(--line)}
</style></head><body><main><h1>mobsec-rag</h1>
<p>Upload an Android <b>.apk</b>, an iOS <b>.ipa</b>, or a <b>.zip</b> of Android / iOS / Flutter / React Native source code.
Analysis runs on this machine. Mode: <b>__MODE__</b></p>
<form method=post action=/scan enctype=multipart/form-data><input type=file name=file accept=".apk,.ipa,.zip,.xapk,.apks" required><br>
<button>Scan</button></form>__STATUS__</main></body></html>"""


def _status(job_id):
    j = JOBS.get(job_id)
    if not j:
        return "<div class=s>Unknown job.</div>"
    if j["state"] == "done":
        return f"<div class=s>Done. <a href='/report/{job_id}'>Open the report</a> · <a href='/report/{job_id}/json'>JSON</a> · <a href='/report/{job_id}/sarif'>SARIF</a></div>"
    if j["state"] == "error":
        return f"<div class=s>Scan failed: {html.escape(j['error'])}</div>"
    return f"<div class=s>Scanning <b>{html.escape(j['name'])}</b> ... this page refreshes automatically.</div><meta http-equiv=refresh content=3>"


def serve(host: str, port: int, llm, open_browser: bool = True):
    from .pipeline import run
    from .report import write_all
    mode = f"{llm.provider}:{llm.model}" if llm.enabled else "offline (no LLM)"
    work = Path(tempfile.mkdtemp(prefix="mobsec_web_"))

    def job(job_id, path: Path, outdir: Path):
        try:
            res = run(str(path), llm=llm, log=lambda *a: None)
            write_all(res, outdir)
            JOBS[job_id]["state"] = "done"
        except Exception as e:  # report any failure to the UI
            JOBS[job_id].update(state="error", error=str(e)[:500])
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype="text/html; charset=utf-8", code=200):
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("x-content-type-options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parts = self.path.strip("/").split("/")
            if parts[0] == "job" and len(parts) == 2:
                return self._send(PAGE.replace("__MODE__", mode).replace("__STATUS__", _status(parts[1])).encode())
            if parts[0] == "report" and len(parts) >= 2 and parts[1] in JOBS and JOBS[parts[1]]["state"] == "done":
                kind = parts[2] if len(parts) > 2 else "html"
                fname, ctype = {"html": ("report.html", "text/html; charset=utf-8"), "json": ("report.json", "application/json"),
                                "sarif": ("report.sarif", "application/json"), "md": ("report.md", "text/markdown")}.get(kind, (None, None))
                if fname:
                    return self._send((JOBS[parts[1]]["out"] / fname).read_bytes(), ctype)
            if self.path in ("/", ""):
                return self._send(PAGE.replace("__MODE__", mode).replace("__STATUS__", "").encode())
            self._send(b"not found", "text/plain", 404)

        def do_POST(self):
            if self.path != "/scan":
                return self._send(b"not found", "text/plain", 404)
            n = int(self.headers.get("content-length", 0))
            if n <= 0 or n > MAX_UPLOAD:
                return self._send(b"upload too large or empty", "text/plain", 413)
            body = self.rfile.read(n)
            msg = BytesParser(policy=email_policy).parsebytes(
                b"content-type: " + self.headers.get("content-type", "").encode() + b"\r\n\r\n" + body)
            part = next((p for p in msg.iter_parts() if p.get_param("name", header="content-disposition") == "file"), None)
            if part is None:
                return self._send(b"no file", "text/plain", 400)
            name = Path(part.get_filename() or "upload.bin").name
            if not name.lower().endswith((".apk", ".ipa", ".zip", ".xapk", ".apks")):
                return self._send(b"unsupported file type", "text/plain", 400)
            job_id = uuid.uuid4().hex[:12]
            d = work / job_id
            (d / "in").mkdir(parents=True)
            src = d / "in" / name
            src.write_bytes(part.get_payload(decode=True))
            JOBS[job_id] = {"state": "running", "name": name, "out": d / "out"}
            threading.Thread(target=job, args=(job_id, src, d / "out"), daemon=True).start()
            self.send_response(303)
            self.send_header("location", f"/job/{job_id}")
            self.end_headers()

    srv = ThreadingHTTPServer((host, port), H)
    url = f"http://{host}:{port}/"
    print(f"mobsec-rag web UI on {url} ({mode}). Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        shutil.rmtree(work, ignore_errors=True)
