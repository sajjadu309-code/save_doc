import json
import os
import secrets
import uuid
from email.parser import BytesParser
from email.policy import default
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse


ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", ROOT / "uploads")).resolve()
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".ppt", ".pptx"}
SESSIONS = set()


class PapertrailHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/files":
            self.list_files()
            return
        if route.startswith("/api/files/"):
            self.open_file(route.removeprefix("/api/files/"))
            return
        if route not in {"/", "/index.html"}:
            self.send_json(404, {"error": "Not found."})
            return

        page = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def list_files(self):
        if not self.is_authenticated():
            self.send_json(401, {"error": "Sign in to view your files."})
            return

        files = []
        for path in sorted(UPLOAD_DIR.iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
            if not path.is_file() or path.suffix.lower() not in ALLOWED_EXTENSIONS:
                continue
            _, separator, original_name = path.name.partition("_")
            files.append({
                "id": path.name,
                "name": original_name if separator else path.name,
                "size": path.stat().st_size,
                "extension": path.suffix.lower().lstrip("."),
            })
        self.send_json(200, {"files": files})

    def open_file(self, encoded_id):
        if not self.is_authenticated():
            self.send_json(401, {"error": "Sign in to open files."})
            return

        file_id = unquote(encoded_id)
        if not file_id or "/" in file_id or "\\" in file_id:
            self.send_json(404, {"error": "File not found."})
            return

        path = UPLOAD_DIR / file_id
        if not path.is_file() or path.suffix.lower() not in ALLOWED_EXTENSIONS:
            self.send_json(404, {"error": "File not found."})
            return

        _, separator, original_name = path.name.partition("_")
        display_name = original_name if separator else path.name
        content_types = {
            ".pdf": "application/pdf",
            ".ppt": "application/vnd.ms-powerpoint",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        }
        disposition = "inline" if path.suffix.lower() == ".pdf" else "attachment"
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_types[path.suffix.lower()])
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(display_name)}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        route = urlparse(self.path).path
        if route == "/api/login":
            self.login()
        elif route == "/api/logout":
            self.logout()
        elif route == "/api/upload":
            self.upload()
        else:
            self.send_json(404, {"error": "Not found."})

    def login(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            credentials = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Enter a valid email and password."})
            return

        if not isinstance(credentials, dict):
            self.send_json(400, {"error": "Enter a name and password."})
            return

        email = str(credentials.get("email", "")).strip()
        password = str(credentials.get("password", ""))
        if not email or not password:
            self.send_json(400, {"error": "Enter a name and password."})
            return

        session_id = secrets.token_urlsafe(32)
        SESSIONS.add(session_id)
        self.send_json(
            200,
            {"email": email},
            extra_headers={"Set-Cookie": f"papertrail_session={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"},
        )

    def logout(self):
        session_id = self.session_id()
        if session_id:
            SESSIONS.discard(session_id)
        self.send_json(
            200,
            {"ok": True},
            extra_headers={"Set-Cookie": "papertrail_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
        )

    def upload(self):
        if not self.is_authenticated():
            self.send_json(401, {"error": "Sign in again before uploading."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid upload size."})
            return
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            self.send_json(413, {"error": "Uploads must total less than 25 MB."})
            return

        content_type = self.headers.get("Content-Type", "")
        message_bytes = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
            + self.rfile.read(length)
        )
        message = BytesParser(policy=default).parsebytes(message_bytes)
        if not message.is_multipart():
            self.send_json(400, {"error": "Choose PDF or PowerPoint files."})
            return

        files = []
        for part in message.iter_parts():
            filename = part.get_filename()
            if not filename:
                continue
            safe_name = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
            extension = Path(safe_name).suffix.lower()
            if not safe_name or extension not in ALLOWED_EXTENSIONS:
                self.send_json(400, {"error": "Only PDF, PPT, and PPTX files are accepted."})
                return
            files.append((safe_name, part.get_payload(decode=True) or b""))

        if not files:
            self.send_json(400, {"error": "Choose at least one supported file."})
            return

        saved = []
        for filename, content in files:
            stored_name = f"{uuid.uuid4().hex[:8]}_{filename}"
            (UPLOAD_DIR / stored_name).write_bytes(content)
            saved.append({"id": stored_name, "name": filename, "size": len(content)})

        self.send_json(200, {"files": saved})

    def session_id(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("papertrail_session")
        return morsel.value if morsel else None

    def is_authenticated(self):
        return self.session_id() in SESSIONS

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    host = os.environ.get("PAPERTRAIL_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", os.environ.get("PAPERTRAIL_PORT", "10000")))
    server_address = (host, port)
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(server_address, PapertrailHandler)
    print(f"Papertrail is running at http://{host}:{port}")
    print("Serving Papertrail...")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()