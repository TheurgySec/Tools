#!/usr/bin/env python3
import os
import argparse
import atexit
import shutil
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime

import socket
import struct
import fcntl

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

# ----------------------------
# Shared helpers
# ----------------------------

def format_bytes(num: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"

def _get_iface_ipv4_linux(ifname: str) -> str | None:
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
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def preferred_ips_for_printing(bound_host: str) -> list[str]:
    if bound_host not in ("0.0.0.0", "::"):
        return [bound_host]

    tun = [ip for _, ip in _list_ipv4s_by_prefix("tun")]
    eth = [ip for _, ip in _list_ipv4s_by_prefix("eth")]

    others: list[str] = []
    try:
        for ifname in os.listdir("/sys/class/net"):
            if ifname == "lo":
                continue
            if ifname.startswith("tun") or ifname.startswith("eth"):
                continue
            ip = _get_iface_ipv4_linux(ifname)
            if ip and not ip.startswith("127.") and ip not in tun and ip not in eth:
                others.append(ip)
    except Exception:
        pass

    ips = tun + eth + others
    if not ips:
        ips = [_guess_fallback_ip()]
    return ips

def ensure_within_dir(base_dir: Path, target: Path) -> None:
    base_dir = base_dir.resolve()
    target = target.resolve()
    if base_dir not in target.parents and target != base_dir:
        abort(400, "Invalid filename")

def dedupe_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
        i += 1

def wants_json_response() -> bool:
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

def list_files_with_meta(directory: Path) -> list[dict]:
    entries = []
    for p in directory.iterdir():
        if not p.is_file() or p.name.endswith(".part"):
            continue
        st = p.stat()
        ts = st.st_mtime
        entries.append(
            {
                "name": p.name,
                "created": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                "size": format_bytes(st.st_size),
                "ts": ts,
            }
        )
    entries.sort(key=lambda x: x["ts"], reverse=True)
    return entries

# ----------------------------
# Shared HTML template (receive + send)
# Adds context menu to copy curl/wget/PowerShell/URL + "Run on Windows" one-liners.
# ----------------------------

LISTING_HTML = r'''
<!doctype html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .upload-area {
            width: 340px;
            height: 210px;
            border: 2px dashed #ccc;
            border-radius: 18px;
            text-align: center;
            padding: 30px;
            font-size: 16px;
            color: #999;
            margin-bottom: 20px;
            user-select: none;
            display: {% if show_upload %}block{% else %}none{% endif %};
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
        td.actions { white-space: nowrap; }
        .hint { color: #666; font-size: 13px; margin-top: 12px; }

        /* Context menu */
        #ctxMenu {
            position: fixed;
            display: none;
            z-index: 9999;
            min-width: 260px;
            background: #fff;
            border: 1px solid #bbb;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            padding: 6px;
        }
        #ctxMenu .title {
            font-size: 12px;
            color: #666;
            padding: 6px 10px;
            border-bottom: 1px solid #eee;
            margin-bottom: 4px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        #ctxMenu button {
            width: 100%;
            text-align: left;
            background: transparent;
            border: 0;
            padding: 8px 10px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
        }
        #ctxMenu button:hover { background: #f2f2f2; }
        #ctxMenu button[disabled] {
            opacity: 0.45;
            cursor: not-allowed;
        }
        #ctxMenu .sep {
            height: 1px;
            background: #eee;
            margin: 6px 6px;
        }
        #toast {
            position: fixed;
            right: 20px;
            bottom: 20px;
            background: rgba(0,0,0,0.85);
            color: #fff;
            padding: 10px 12px;
            border-radius: 10px;
            display: none;
            max-width: 520px;
        }
        .copyLink { font-size: 13px; margin-right: 10px; }
    </style>
</head>
<body>
<h1>{{ header }}</h1>

<div class="upload-area" id="uploadArea">
    Drag and drop files here<br>or click to select a file
</div>
<form method="post" enctype="multipart/form-data" id="uploadForm">
    <input id="fileInput" type="file" name="file" onchange="this.form.submit()">
</form>

<h2>Files</h2>
<table id="filesTable">
    <tr><th>Filename</th><th>Created</th><th>Size</th><th>View</th><th>Download</th><th>Copy</th></tr>
    {% for f in files %}
    <tr class="fileRow" data-filename="{{ f.name }}">
        <td class="mono">{{ f.name }}</td>
        <td class="time">{{ f.created }}</td>
        <td class="size">{{ f.size }}</td>
        <td><a href="{{ url_for(view_endpoint, filename=f.name) }}" target="_blank">View</a></td>
        <td><a href="{{ url_for(download_endpoint, filename=f.name) }}">Download</a></td>
        <td class="actions">
            <a href="#" class="copyLink" data-copy="curl">curl</a>
            <a href="#" class="copyLink" data-copy="wget">wget</a>
            <a href="#" class="copyLink" data-copy="ps">PowerShell</a>
            <a href="#" class="copyLink" data-copy="run">Run</a>
        </td>
    </tr>
    {% else %}
    <tr><td colspan="6">No files available.</td></tr>
    {% endfor %}
</table>

<p class="hint">
    Tip: right-click a file row to copy download commands. “Run” gives Windows one-liners for .ps1/.bat/.cmd/.exe.
</p>

<div id="ctxMenu" role="menu" aria-hidden="true">
    <div class="title" id="ctxTitle"></div>
    <button type="button" data-action="curl">Copy curl</button>
    <button type="button" data-action="wget">Copy wget</button>
    <button type="button" data-action="ps">Copy PowerShell</button>
    <button type="button" data-action="url">Copy download URL</button>
    <div class="sep"></div>
    <button type="button" id="runBtn" data-action="run">Copy “Run on Windows” one-liner</button>
</div>

<div id="toast"></div>

<script>
    const SHOW_UPLOAD = {{ 'true' if show_upload else 'false' }};
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const uploadForm = document.getElementById('uploadForm');

    if (!SHOW_UPLOAD) {
        uploadArea.style.display = 'none';
        uploadForm.style.display = 'none';
    } else {
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
    }

    const ctxMenu = document.getElementById('ctxMenu');
    const ctxTitle = document.getElementById('ctxTitle');
    const toast = document.getElementById('toast');
    const runBtn = document.getElementById('runBtn');

    let ctxFilename = null;

    function extOf(filename) {
        const idx = filename.lastIndexOf('.');
        if (idx === -1) return '';
        return filename.slice(idx + 1).toLowerCase();
    }

    function downloadUrl(filename) {
        const prefix = "{{ download_path_prefix }}";
        return `${window.location.origin}${prefix}${encodeURIComponent(filename)}`;
    }

    function buildCommand(kind, filename) {
        const url = downloadUrl(filename);
        const out = filename;

        if (kind === 'curl') return `curl -L -o "${out}" "${url}"`;
        if (kind === 'wget') return `wget -O "${out}" "${url}"`;
        if (kind === 'ps')   return `Invoke-WebRequest -Uri "${url}" -OutFile "${out}"`;
        if (kind === 'url')  return url;
        if (kind === 'run')  return buildRunCommand(filename, url);

        return url;
    }

    function buildRunCommand(filename, url) {
        const ext = extOf(filename);
        const safeName = filename.replace(/"/g, '');

        if (ext === 'ps1') {
            return `powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object Net.WebClient).DownloadString('${url}'))"`;
        }

        if (ext === 'bat' || ext === 'cmd') {
            return `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest '${url}' -OutFile $env:TEMP\\${safeName}; cmd /c $env:TEMP\\${safeName}"`;
        }

        if (ext === 'exe') {
            return `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest '${url}' -OutFile $env:TEMP\\${safeName}; Start-Process $env:TEMP\\${safeName}"`;
        }

        return url;
    }

    function isRunnable(filename) {
        const ext = extOf(filename);
        return (ext === 'ps1' || ext === 'bat' || ext === 'cmd' || ext === 'exe');
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
            showToast('Copied to clipboard');
            return true;
        } catch (e) {
            window.prompt('Copy command:', text);
            return false;
        }
    }

    function showToast(msg) {
        toast.textContent = msg;
        toast.style.display = 'block';
        clearTimeout(toast._t);
        toast._t = setTimeout(() => toast.style.display = 'none', 1600);
    }

    function hideMenu() {
        ctxMenu.style.display = 'none';
        ctxMenu.setAttribute('aria-hidden', 'true');
        ctxFilename = null;
    }

    function showMenu(x, y, filename) {
        ctxFilename = filename;
        ctxTitle.textContent = filename;

        runBtn.disabled = !isRunnable(filename);
        runBtn.title = runBtn.disabled ? 'Only for .ps1/.bat/.cmd/.exe' : '';

        ctxMenu.style.display = 'block';
        ctxMenu.setAttribute('aria-hidden', 'false');

        const rect = ctxMenu.getBoundingClientRect();
        const px = Math.min(x, window.innerWidth - rect.width - 8);
        const py = Math.min(y, window.innerHeight - rect.height - 8);

        ctxMenu.style.left = px + 'px';
        ctxMenu.style.top = py + 'px';
    }

    document.addEventListener('contextmenu', (e) => {
        const row = e.target.closest('.fileRow');
        if (!row) return;
        e.preventDefault();
        hideMenu();
        showMenu(e.clientX, e.clientY, row.dataset.filename);
    });

    document.addEventListener('click', () => hideMenu());
    window.addEventListener('scroll', () => hideMenu(), { passive: true });
    window.addEventListener('resize', () => hideMenu(), { passive: true });

    ctxMenu.addEventListener('click', (e) => {
        const btn = e.target.closest('button');
        if (!btn || !ctxFilename) return;
        if (btn.disabled) return;
        const action = btn.dataset.action;
        copyText(buildCommand(action, ctxFilename));
        hideMenu();
    });

    document.getElementById('filesTable').addEventListener('click', (e) => {
        const link = e.target.closest('a.copyLink');
        if (!link) return;
        e.preventDefault();
        const row = e.target.closest('.fileRow');
        const filename = row?.dataset.filename;
        if (!filename) return;

        const kind = link.dataset.copy;
        if (kind === 'run' && !isRunnable(filename)) {
            showToast('Run is only for .ps1/.bat/.cmd/.exe');
            return;
        }

        copyText(buildCommand(kind, filename));
    });
</script>
</body>
</html>
'''

# ----------------------------
# RECEIVE mode (upload server)
# ----------------------------

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def create_receive_app(
    upload_dir: Path,
    token: str | None,
    restrict_types: bool,
    overwrite: bool,
    max_mb: int,
) -> Flask:
    app = Flask(__name__)
    app.config["UPLOAD_FOLDER"] = str(upload_dir)
    app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024
    upload_dir.mkdir(parents=True, exist_ok=True)

    def require_token_if_set() -> None:
        if not token:
            return
        got = request.headers.get("X-Auth-Token", "")
        if got != token:
            abort(401, "Missing/invalid token")

    def upload_success_response(original_name: str, saved_as: str, size_bytes: int):
        payload = {
            "ok": True,
            "original_filename": original_name,
            "saved_as": saved_as,
            "size_bytes": size_bytes,
            "view_url": url_for("recv_view_file", filename=saved_as, _external=True),
            "download_url": url_for("recv_download_file", filename=saved_as, _external=True),
        }
        if wants_json_response():
            return jsonify(payload), 201
        return redirect(url_for("recv_index"))

    @app.route("/", methods=["GET", "POST"], endpoint="recv_index")
    def recv_index():
        if request.method == "POST":
            require_token_if_set()

            if request.files.get("file"):
                f = request.files["file"]
                if not f.filename:
                    return "No file selected", 400
                raw_name = f.filename
                data_stream = f.stream
            else:
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

            tmp = dest.with_suffix(dest.suffix + ".part")
            with open(tmp, "wb") as out:
                for chunk in iter(lambda: data_stream.read(1024 * 1024), b""):
                    out.write(chunk)
            os.replace(tmp, dest)

            size_bytes = dest.stat().st_size if dest.exists() else 0
            return upload_success_response(raw_name, dest.name, size_bytes)

        entries = list_files_with_meta(upload_dir)
        return render_template_string(
            LISTING_HTML,
            title="Transfer - Receive",
            header="Receive files",
            files=entries,
            view_endpoint="recv_view_file",
            download_endpoint="recv_download_file",
            download_path_prefix="/download/",
            show_upload=True,
        )

    @app.route("/view/<filename>", endpoint="recv_view_file")
    def recv_view_file(filename):
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name)

    @app.route("/download/<filename>", endpoint="recv_download_file")
    def recv_download_file(filename):
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name, as_attachment=True)

    return app

def print_receive_examples(host: str, port: int, token: str | None) -> None:
    ips = preferred_ips_for_printing(host)
    ip = ips[0]
    base = f"http://{ip}:{port}"

    hdr = ""
    ps_hdr = ""
    if token:
        hdr = f' -H "X-Auth-Token: {token}"'
        ps_hdr = f" -Headers @{{'X-Auth-Token'='{token}'}}"

    print("\n=== Receive mode examples ===")
    print(f"Web UI:   {base}/")
    print("Upload (multipart; JSON response):")
    print(f'  curl{hdr} -F "file=@./path/to/file.zip" "{base}/?json=1"')
    print(f"  Invoke-RestMethod{ps_hdr} -Method Post -Form @{{file=Get-Item './path/to/file.zip'}} -Uri '{base}/?json=1'")
    print("\nUpload (raw bytes; JSON response):")
    print(f'  curl{hdr} --data-binary "@./path/to/file.zip" "{base}/?filename=file.zip&json=1"')
    print(f"  Invoke-RestMethod{ps_hdr} -Method Post -InFile './path/to/file.zip' -ContentType 'application/octet-stream' -Uri '{base}/?filename=file.zip&json=1'")
    print()

# ----------------------------
# SEND mode (serve directory / zip)
# ----------------------------

def create_zip_of_subdir(base_dir: Path, subdir: str) -> Path:
    subdir_path = (base_dir / subdir).resolve()
    if not subdir_path.exists() or not subdir_path.is_dir():
        raise FileNotFoundError(f"Subdirectory not found: {subdir}")

    tmpdir = Path(tempfile.mkdtemp(prefix="file_transfer_zip_"))
    atexit.register(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    zip_path = tmpdir / f"{Path(subdir).name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in subdir_path.rglob("*"):
            if p.is_file():
                arcname = p.relative_to(base_dir)
                zf.write(p, arcname.as_posix())
    return zip_path

def create_send_app(serve_dir: Path, token: str | None) -> Flask:
    app = Flask(__name__)
    app.config["SERVE_DIR"] = str(serve_dir)

    def require_token_if_set() -> None:
        if not token:
            return
        got = request.headers.get("X-Auth-Token", "")
        if got != token:
            abort(401, "Missing/invalid token")

    @app.route("/", methods=["GET"], endpoint="send_index")
    def send_index():
        entries = list_files_with_meta(serve_dir)
        return render_template_string(
            LISTING_HTML,
            title="Transfer - Send",
            header=f"Send files ({serve_dir})",
            files=entries,
            view_endpoint="send_view_file",
            download_endpoint="send_download_file",
            download_path_prefix="/download/",
            show_upload=False,
        )

    @app.route("/view/<filename>", methods=["GET"], endpoint="send_view_file")
    def send_view_file(filename):
        require_token_if_set()
        safe_name = secure_filename(Path(filename).name)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["SERVE_DIR"], safe_name, as_attachment=False)

    @app.route("/download/<filename>", methods=["GET"], endpoint="send_download_file")
    def send_download_file(filename):
        require_token_if_set()
        safe_name = secure_filename(Path(filename).name)
        if not safe_name:
            abort(404)
        return send_from_directory(app.config["SERVE_DIR"], safe_name, as_attachment=True)

    return app

def print_send_examples(host: str, port: int, token: str | None, hint_file: str | None = None) -> None:
    ips = preferred_ips_for_printing(host)
    ip = ips[0]
    base = f"http://{ip}:{port}"

    print("\n=== Send mode ===")
    print(f"Web UI: {base}/")
    print(f"Download pattern: {base}/download/<filename>")
    if token:
        print("Token is enabled; CLI downloads need header:  X-Auth-Token: <token>")

    if hint_file:
        url = f"{base}/download/{hint_file}"
        print("\nDownload commands for the selected file:")
        print(f"  URL: {url}\n")

        if token:
            print("  curl:")
            print(f'    curl -H "X-Auth-Token: {token}" -L -o "{hint_file}" "{url}"')
            print("  wget:")
            print(f'    wget --header="X-Auth-Token: {token}" -O "{hint_file}" "{url}"')
            print("  PowerShell:")
            print(f'    Invoke-WebRequest -Headers @{{"X-Auth-Token"="{token}"}} -Uri "{url}" -OutFile "{hint_file}"')
        else:
            print("  curl:")
            print(f'    curl -L -o "{hint_file}" "{url}"')
            print("  wget:")
            print(f'    wget -O "{hint_file}" "{url}"')
            print("  PowerShell:")
            print(f'    Invoke-WebRequest -Uri "{url}" -OutFile "{hint_file}"')

        ext = Path(hint_file).suffix.lower()
        if ext in (".ps1", ".bat", ".cmd", ".exe"):
            print("\nRun on Windows:")
            if ext == ".ps1":
                print(f'  powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object Net.WebClient).DownloadString(\'{url}\'))"')
            elif ext in (".bat", ".cmd"):
                print(f'  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest \'{url}\' -OutFile $env:TEMP\\{hint_file}; cmd /c $env:TEMP\\{hint_file}"')
            elif ext == ".exe":
                print(f'  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest \'{url}\' -OutFile $env:TEMP\\{hint_file}; Start-Process $env:TEMP\\{hint_file}"')

    print()

# ----------------------------
# Main CLI
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="File transfer tool (send + receive).")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_recv = sub.add_parser("receive", help="Run upload server (GUI + curl/PowerShell).")
    p_recv.add_argument("--host", default="0.0.0.0")
    p_recv.add_argument("--port", type=int, default=5000)
    p_recv.add_argument("--upload-dir", default="uploads")
    p_recv.add_argument("--token", default=None)
    p_recv.add_argument("--restrict-types", action="store_true", help="Restrict uploads to a small list of extensions")
    p_recv.add_argument("--overwrite", action="store_true", help="Overwrite existing files (default is dedupe)")
    p_recv.add_argument("--max-mb", type=int, default=250, help="Max upload size (MiB)")

    p_send = sub.add_parser("send", help="Serve files for others to download (with helpful HTML + copy commands).")
    p_send.add_argument("path", nargs="?", default=".", help="File or directory to serve (default: current directory)")
    p_send.add_argument("--host", default="0.0.0.0")
    p_send.add_argument("--port", type=int, default=8000)
    p_send.add_argument("--token", default=None)
    p_send.add_argument("--zip", dest="zip_dir", default=None, help="Subdirectory to zip and serve (zip only)")

    args = parser.parse_args()

    if args.mode == "receive":
        upload_dir = Path(args.upload_dir)
        app = create_receive_app(
            upload_dir=upload_dir,
            token=args.token,
            restrict_types=args.restrict_types,
            overwrite=args.overwrite,
            max_mb=args.max_mb,
        )
        print_receive_examples(args.host, args.port, args.token)
        app.run(debug=False, host=args.host, port=args.port)
        return

    if args.mode == "send":
        target = Path(args.path).expanduser().resolve()
        if not target.exists():
            raise SystemExit(f"Error: path does not exist: {target}")

        hint_file: str | None = None

        # If they pass a file, serve its parent directory but print hints for that file.
        if target.is_file():
            base_dir = target.parent
            hint_file = target.name
        else:
            base_dir = target

        if not base_dir.exists() or not base_dir.is_dir():
            raise SystemExit(f"Error: directory does not exist: {base_dir}")

        serve_dir = base_dir

        # If --zip, create zip into temp dir and serve only that temp directory
        if args.zip_dir:
            zip_path = create_zip_of_subdir(base_dir, args.zip_dir)
            serve_dir = zip_path.parent
            hint_file = zip_path.name  # make the printed hints point at the zip

        app = create_send_app(serve_dir=serve_dir, token=args.token)
        print_send_examples(args.host, args.port, args.token, hint_file=hint_file)
        app.run(debug=False, host=args.host, port=args.port)
        return

if __name__ == "__main__":
    main()

