# transfer.py

A small self-contained file transfer utility with two modes:

- `receive`: upload files to a machine (browser UI + curl/PowerShell friendly)
- `send`: serve files from a machine (browser UI + copy/paste download commands)

This is intended to be quick to run and easy to use on any network where HTTP access is available.

---

## Requirements

- Python 3
- Flask

Install Flask:

    python3 -m pip install flask

---

## Quick start

### Receive (upload server)

Start an upload server on port 5000:

    python3 transfer.py receive

Open in a browser:

    http://<server-ip>:5000/

Upload via curl:

    curl -F "file=@./example.zip" "http://<server-ip>:5000/?json=1"

Upload raw bytes (no multipart):

    curl --data-binary "@./example.zip" "http://<server-ip>:5000/?filename=example.zip&json=1"

---

### Send (download server)

Serve the current directory on port 8000:

    python3 transfer.py send

Open in a browser:

    http://<server-ip>:8000/

Download a file with curl:

    curl -L -o "file.bin" "http://<server-ip>:8000/download/file.bin"

Download a file with PowerShell:

    Invoke-WebRequest -Uri "http://<server-ip>:8000/download/file.bin" -OutFile "file.bin"

---

## Modes

### receive

The receive server stores uploaded files into an upload directory and provides:

- browser upload UI (drag and drop)
- file listing (created time and size)
- view and download links
- right-click context menu to copy download commands (curl/wget/PowerShell)
- API-friendly upload responses (JSON when requested)

Command:

    python3 transfer.py receive [options]

Options:

- `--host` (default: `0.0.0.0`)
- `--port` (default: `5000`)
- `--upload-dir` (default: `uploads`)
- `--max-mb` (default: `250`)
- `--overwrite` (overwrite files instead of deduping)
- `--restrict-types` (restrict to a small built-in extension list)
- `--token` (require `X-Auth-Token` header)

Example:

    python3 transfer.py receive --port 5000 --upload-dir ./uploads

---

### send

The send server serves a directory of files and provides:

- file listing (created time and size)
- view and download links
- right-click context menu to copy download commands (curl/wget/PowerShell)
- a “Run” copy option for `.ps1`, `.bat`, `.cmd`, and `.exe` (Windows one-liners)

Command:

    python3 transfer.py send [path] [options]

Where `path` can be either:
- a directory (serve that directory), or
- a file (serve the file’s parent directory, and print download hints for that file)

Examples:

Serve the current directory:

    python3 transfer.py send

Serve a specific directory:

    python3 transfer.py send /opt/tools

Serve a single file (prints download hints for that file):

    python3 transfer.py send PowerView.ps1

Options:

- `--host` (default: `0.0.0.0`)
- `--port` (default: `8000`)
- `--zip <subdir>` (zip a subdirectory and serve only the zip)
- `--token` (require `X-Auth-Token` header)

---

## Zip mode (send)

To share a directory as a single zip:

    python3 transfer.py send . --zip reports

This creates a zip in a temporary directory and serves only that zip.

---

## Token authentication

Both `receive` and `send` can require a token.

Start with a token:

    python3 transfer.py receive --token mysecret

Uploads must include the header:

    curl -H "X-Auth-Token: mysecret" -F "file=@./example.zip" "http://<server-ip>:5000/?json=1"

For downloads:

    curl -H "X-Auth-Token: mysecret" -L -o "file.bin" "http://<server-ip>:8000/download/file.bin"

PowerShell:

    Invoke-WebRequest -Headers @{ "X-Auth-Token"="mysecret" } -Uri "http://<server-ip>:8000/download/file.bin" -OutFile "file.bin"

---

## Endpoints

### receive mode

- `GET /`
  HTML upload UI + file listing

- `POST /`
  Upload endpoint (multipart form upload)

- `POST /?filename=<name>`
  Raw body upload endpoint

- `GET /view/<filename>`
  View file inline

- `GET /download/<filename>`
  Download file as attachment

---

### send mode

- `GET /`
  HTML file listing

- `GET /view/<filename>`
  View file inline

- `GET /download/<filename>`
  Download file as attachment

---

## Notes

- Filenames are normalised using `secure_filename()` to avoid invalid paths.
- Uploads are written to a temporary `.part` file and then renamed into place.
- By default, uploads do not overwrite existing files; they are deduped as `file (1).ext`, `file (2).ext`, etc.
- The server prints example URLs using preferred interfaces in this order: `tun*`, then `eth*`, then any others.
