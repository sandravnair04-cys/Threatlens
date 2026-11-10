"""ThreatLens - Advanced Phishing Detection & Threat Intelligence Platform."""
import hashlib
import os
import time
from collections import defaultdict, deque
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from flask_cors import CORS

import database as db
import scoring
import validators
import vt_client as vt

load_dotenv()  # reads VT_API_KEY and other settings from the .env file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 33 * 1024 * 1024   # reject bigger uploads early

# The browser extension runs on origin chrome-extension://<id>. Only /api/* is opened to it.
CORS(app, resources={r"/api/*": {"origins": [r"chrome-extension://.*"]}})

db.init_db()


# ------------------------------------------------------------------ security
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
    return resp


_hits = defaultdict(deque)


def rate_limited(view):
    """Very small in-memory limiter to protect the VirusTotal quota."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        limit = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))
        now = time.time()
        q = _hits[request.remote_addr]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return jsonify(error="Too many requests. Please wait a minute."), 429
        q.append(now)
        return view(*args, **kwargs)
    return wrapper


def json_error(message, status=400):
    return jsonify(error=message), status


# ------------------------------------------------------------------ core logic
def run_scan(scan_type, target, source, lookup, local_findings=None, extra=None):
    """Look the target up on VirusTotal, score it, save it, return the report."""
    vt_result, vt_error = None, None
    try:
        vt_result = lookup(target)
    except vt.VTNotFound:
        vt_result = {"found": False, "status": "not_found", "stats": {}, "reputation": None,
                     "flagged": [], "details": {}, "permalink": None,
                     "message": "VirusTotal has no report for this item."}
    except vt.VTError as exc:
        # URL scans can still show the local analysis; other types have nothing to show
        if scan_type != "url":
            raise
        vt_error = str(exc)

    stats = (vt_result or {}).get("stats")
    reputation = (vt_result or {}).get("reputation")
    assessment = scoring.build_assessment(local_findings, stats, reputation)

    report = {
        "scan_type": scan_type,
        "target": target,
        "assessment": assessment,
        "vt": vt_result,
        "vt_error": vt_error,
        "source": source,
    }
    if extra:
        report.update(extra)
    scan_id, created = db.save_scan(scan_type, target, assessment, stats, source, report)
    report.update(id=scan_id, created_at=created)
    return report


def get_source():
    return "extension" if request.headers.get("X-ThreatLens-Client") == "extension" else "web"


def handle(scan_type, validator, field, lookup, with_local=False):
    data = request.get_json(silent=True) or {}
    try:
        target = validator(data.get(field))
    except ValueError as exc:
        return json_error(str(exc), 400)
    local = None
    if with_local:
        _, local = scoring.analyse_url(target)
    try:
        return jsonify(run_scan(scan_type, target, get_source(), lookup, local))
    except vt.VTError as exc:
        return json_error(str(exc), exc.status)


# ------------------------------------------------------------------ API routes
@app.post("/api/scan/url")
@rate_limited
def api_scan_url():
    return handle("url", validators.normalise_url, "url", vt.lookup_url, with_local=True)


@app.post("/api/scan/domain")
@rate_limited
def api_scan_domain():
    return handle("domain", validators.normalise_domain, "domain", vt.lookup_domain)


@app.post("/api/scan/ip")
@rate_limited
def api_scan_ip():
    return handle("ip", validators.normalise_ip, "ip", vt.lookup_ip)


@app.post("/api/scan/hash")
@rate_limited
def api_scan_hash():
    return handle("hash", validators.normalise_hash, "hash", vt.lookup_file_hash)


@app.post("/api/scan/file")
@rate_limited
def api_scan_file():
    """Hash the file and look only the HASH up on VirusTotal. Nothing is uploaded here;
    uploading is a separate, consent-gated endpoint (/api/scan/file/upload)."""
    f = request.files.get("file")
    if not f or not f.filename:
        return json_error("Please choose a file.")
    sha = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: f.stream.read(1024 * 1024), b""):
        sha.update(chunk)
        size += len(chunk)
    file_hash = sha.hexdigest()
    extra = {"filename": os.path.basename(f.filename)[:200], "file_size": size}

    try:
        result = run_scan("file", file_hash, get_source(), vt.lookup_file_hash, extra=extra)
    except vt.VTError as exc:
        return json_error(str(exc), exc.status)
    return jsonify(result)


@app.post("/api/scan/file/upload")
@rate_limited
def api_upload_file():
    """Second step, only used after the user consents to uploading an unknown file."""
    f = request.files.get("file")
    if not f or request.form.get("consent") != "true":
        return json_error("Upload requires a file and explicit consent.")
    data = f.read()
    try:
        analysis_id = vt.upload_file(os.path.basename(f.filename or ""), data)
    except vt.VTError as exc:
        return json_error(str(exc), exc.status)
    return jsonify(message="File uploaded. VirusTotal is analysing it. "
                           "Scan the same file again in a few minutes to see the result.",
                   analysis_id=analysis_id, sha256=hashlib.sha256(data).hexdigest())


@app.get("/api/history")
def api_history():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    return jsonify(db.list_scans(limit=limit, scan_type=request.args.get("type")))


@app.get("/api/report/<int:scan_id>")
def api_report(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return json_error("Report not found.", 404)
    return jsonify(scan)


@app.get("/health")
def health():
    return jsonify(status="ok", virustotal_configured=bool(os.getenv("VT_API_KEY", "").strip()
                   and not os.getenv("VT_API_KEY", "").startswith("PASTE_")))


# ------------------------------------------------------------------ pages
@app.get("/")
def index():
    return render_template("index.html", prefill_url="")


@app.get("/check")
def check():
    """Opened by the browser extension's right-click menu. Pre-fills and auto-runs a URL scan."""
    url = (request.args.get("url") or "")[:2048]
    return render_template("index.html", prefill_url=url)


@app.get("/history")
def history():
    scan_type = request.args.get("type")
    if scan_type not in (None, "", "url", "domain", "ip", "hash", "file"):
        abort(400)
    return render_template("history.html", scans=db.list_scans(limit=200, scan_type=scan_type or None),
                           summary=db.summary(), active_type=scan_type or "")


@app.get("/report/<int:scan_id>")
def report(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("report.html", scan=scan, r=scan["result"])


@app.post("/report/<int:scan_id>/delete")
def delete_report(scan_id):
    db.delete_scan(scan_id)
    return redirect(url_for("history"))


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return json_error("Not found.", 404)
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def too_large(_):
    return json_error("File too large (maximum 32 MB).", 413)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
