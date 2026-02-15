import os
import argparse
from pathlib import Path

import socket
import struct
import fcntl
from datetime import datetime

from flask import (
    Flask,
    request,
    render_template_string,
    send_from_directory,
    redirect,
    url_for,
    abort,
    jsonify,
)
from werkzeug.utils import secure_filename

# Allowed file extensions (only used if --restrict-types is enabled)
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

HTML_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>File Upload Server</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .upload-area {
            width: 300px;
            height: 200px;
            border: 2px dashed #ccc;
            border-radius: 20px;
            text-align: center;
            padding: 30px;
            font-size: 16px;
            color: #999;
            margin-bottom: 20px;
        }
        .upload-area.dragover {
            background-color: #eef;
            border-color: #00f;
            color: #00f;
        }
        #fileInput { display: none; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 10px; border: 1px solid #ccc; }
        th { text-align: left; }
        td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
        td.time { white-space: nowrap; }
        td.size { white-space: nowrap; text-align: right; }
    </style>
</head>
<body>
<h1>Upload a File</h1>
<div class="upload-area" id="uploadArea">
    Drag and drop files here<br>or click to select a file
</div>
<form method="post" enctype="multipart/form-data">
    <input id="fileInput" type="file" name="file" onchange="this.form.submit()">
</form>

<h2>Uploaded Files</h2>
<table>
    <tr><th>Filename</th><th>Created</th><th>Size</th><th>View</th><th>Download</th></tr>
    {% for f in files %}
    <tr>
        <td class="mono">{{ f.name }}</td>
        <td class="time">{{ f.created }}</td>
        <td class="size">{{ f.size }}</td>
        <td><a href="{{ url_for('view_file', filename=f.name) }}" target="_blank">View</a></td>
        <td><a href="{{ url_for('download_file', filename=f.name) }}">Download</a></td>
    </tr>
    {% else %}
    <tr><td colspan="5">No files uploaded yet.</td></tr>
    {% endfor %}
</table>

<script>
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');

    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const dt = new DataTransfer();
        dt.items.add(e.dataTransfer.files[0]);
        fileInput.files = dt.files;
        fileInput.dispatchEvent(new Event('change'));
    });
</script>
</body>
</html>
'''

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_within_dir(base_dir: Path, target: Path) -> None:
    """Abort if target is not within base_dir (prevents path traversal)."""
    base_dir = base_dir.resolve()
    target = target.resolve()
    if base_dir not in target.parents and target != base_dir:
        abort(400, "Invalid filename")

def dedupe_path(path: Path) -> Path:
    """If path exists, create 'name (1).ext', 'name (2).ext', ..."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
        i += 1

def format_bytes(num: int) -> str:
    """Human-readable file sizes."""
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"

# ----------------------------
# Better CLI responses (JSON) vs GUI (redirect)
# ----------------------------

def _wants_json_response() -> bool:
    """
    Return JSON for CLI/API clients; keep redirect for browser form submits.
    - ?json=1 forces JSON.
    - Accept: application/json forces JSON.
    - If client doesn't advertise text/html, assume it's not a browser.
    """
    if request.args.get("json") in ("1", "true", "yes"):
        return True

    accept = request.headers.get("Accept", "")
    xrw = request.headers.get("X-Requested-With", "")

    if "application/json" in accept:
        return True
    if xrw.lower() == "xmlhttprequest":
        return True
    if "text/html" not in accept:
        return True

    return False

def _upload_success_response(original_name: str, saved_as: str, size_bytes: int):
    payload = {
        "ok": True,
        "original_filename": original_name,
        "saved_as": saved_as,
        "size_bytes": size_bytes,
        "view_url": url_for("view_file", filename=saved_as, _external=True),
        "download_url": url_for("download_file", filename=saved_as, _external=True),
    }
    if _wants_json_response():
        return jsonify(payload), 201
    return redirect(url_for("upload_file"))

# ----------------------------
# IP selection for banner
# ----------------------------

def _get_iface_ipv4_linux(ifname: str) -> str | None:
    """Return the IPv4 address for an interface name on Linux, or None if unavailable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
        res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    except Exception:
        return None

def _list_ipv4s_by_prefix(prefix: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        for ifname in os.listdir("/sys/class/net"):
            if ifname.startswith(prefix):
                ip = _get_iface_ipv4_linux(ifname)
                if ip and not ip.startswith("127."):
                    out.append((ifname, ip))
    except Exception:
        pass
    return out

def _guess_fallback_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets need to be sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _preferred_ip_for_examples(bound_host: str) -> tuple[str, str]:
    if bound_host not in ("0.0.0.0", "::"):
        return bound_host, "bound-host"

    tun = _list_ipv4s_by_prefix("tun")
    if tun:
        return tun[0][1], f"tun ({tun[0][0]})"

    eth = _list_ipv4s_by_prefix("eth")
    if eth:
        return eth[0][1], f"eth ({eth[0][0]})"

    return _guess_fallback_ip(), "fallback"

def print_transfer_examples(host: str, port: int, token: str | None) -> None:
    ip_for_examples, reason = _preferred_ip_for_examples(host)
    base = f"http://{ip_for_examples}:{port}"

    hdr = ""
    ps_hdr = ""
    if token:
        hdr = f' -H "X-Auth-Token: {token}"'
        ps_hdr = f" -Headers @{{'X-Auth-Token'='{token}'}}"

    print("\n=== Network info ===")
    if host in ("0.0.0.0", "::"):
        tun = _list_ipv4s_by_prefix("tun")
        eth = _list_ipv4s_by_prefix("eth")
        if tun:
            print("tun interfaces:", ", ".join([f"{n}={ip}" for n, ip in tun]))
        if eth:
            print("eth interfaces:", ", ".join([f"{n}={ip}" for n, ip in eth]))
    print(f"Using address for examples: {ip_for_examples} ({reason})\n")

    print("=== File transfer examples ===")
    print(f"Web UI:   {base}/")
    print(f"Upload:   {base}/ (multipart form)")
    print(f"View:     {base}/view/<filename>")
    print(f"Download: {base}/download/<filename>\n")

    print("curl (upload multipart; JSON response):")
    print(f'  curl{hdr} -F "file=@./path/to/file.zip" "{base}/?json=1"')

    print("\nPowerShell (upload multipart; JSON response):")
    print(f"  Invoke-RestMethod{ps_hdr} -Method Post -Form @{{file=Get-Item './path/to/file.zip'}} -Uri '{base}/?json=1'")

    print("\ncurl (upload raw bytes; JSON response):")
    print(f'  curl{hdr} --data-binary "@./path/to/file.zip" "{base}/?filename=file.zip&json=1"')

    print("\nPowerShell (upload raw bytes; JSON response):")
    print(f"  Invoke-RestMethod{ps_hdr} -Method Post -InFile './path/to/file.zip' -ContentType 'application/octet-stream' -Uri '{base}/?filename=file.zip&json=1'")

    print("\nDownload examples:")
    print(f'  curl{hdr} -L -o "./file.zip" "{base}/download/file.zip"')
    print(f"  Invoke-WebRequest{ps_hdr} -Uri '{base}/download/file.zip' -OutFile './file.zip'")
    print()

# ----------------------------
# Flask app
# ----------------------------

def create_app(upload_dir: Path, token: str | None, restrict_types: bool, overwrite: bool) -> Flask:
    app = Flask(__name__)
    app.config["UPLOAD_FOLDER"] = str(upload_dir)

    # Stops accidental large uploads
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 250  # 250 MiB

    upload_dir.mkdir(parents=True, exist_ok=True)

    def require_token_if_set() -> None:
        if not token:
            return
        got = request.headers.get("X-Auth-Token", "")
        if got != token:
            abort(401, "Missing/invalid token")

    @app.route("/", methods=["GET", "POST"])
    def upload_file():
        if request.method == "POST":
            require_token_if_set()

            # Support both multipart and raw-body uploads
            if request.files.get("file"):
                f = request.files["file"]
                if not f.filename:
                    return "No file selected", 400
                raw_name = f.filename
                data_stream = f.stream
            else:
                # Raw upload: client sends bytes, name via query string
                raw_name = request.args.get("filename", "")
                if not raw_name:
                    return "Missing filename (use ?filename=...)", 400
                data_stream = request.stream

            safe_name = secure_filename(raw_name)
            if not safe_name:
                return "Invalid filename", 400

            if restrict_types and not allowed_file(safe_name):
                return "Invalid file type", 400

            dest = upload_dir / safe_name
            ensure_within_dir(upload_dir, dest)

            if not overwrite:
                dest = dedupe_path(dest)

            # Write to .part first, then move into place
            tmp = dest.with_suffix(dest.suffix + ".part")
            with open(tmp, "wb") as out:
                for chunk in iter(lambda: data_stream.read(1024 * 1024), b""):
                    out.write(chunk)
            os.replace(tmp, dest)

            size_bytes = dest.stat().st_size if dest.exists() else 0
            return _upload_success_response(raw_name, dest.name, size_bytes)

        # Build file listing with created times (mtime) + human size
        entries = []
        for p in upload_dir.iterdir():
            if not p.is_file():
                continue
            if p.name.endswith(".part"):
                continue

            st = p.stat()
            ts = st.st_mtime  # "uploaded at" for this tool
            created = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            size_human = format_bytes(st.st_size)

            entries.append(
                {
                    "name": p.name,
                    "created": created,
                    "size": size_human,
                    "ts": ts,
                }
            )

        # Newest first
        entries.sort(key=lambda x: x["ts"], reverse=True)

        return render_template_string(HTML_TEMPLATE, files=entries)

    @app.route("/view/<filename>")
    def view_file(filename):
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name)

    @app.route("/download/<filename>")
    def download_file(filename):
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name, as_attachment=True)

    return app

# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start a Flask file upload server.")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (e.g. 127.0.0.1 or 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the server on")
    parser.add_argument("--upload-dir", default="uploads", help="Directory to store uploads")
    parser.add_argument("--token", default=None, help="Optional shared token (sent as X-Auth-Token header)")
    parser.add_argument("--restrict-types", action="store_true", help="Restrict uploads to a small list of extensions")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files (default is dedupe)")

    args = parser.parse_args()

    upload_dir = Path(args.upload_dir)

    app = create_app(
        upload_dir,
        token=args.token,
        restrict_types=args.restrict_types,
        overwrite=args.overwrite,
    )

    print_transfer_examples(args.host, args.port, args.token)
    app.run(debug=False, host=args.host, port=args.port)
