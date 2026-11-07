"""Local HTTP bridge and event polling.
Run http.server in its own thread; mutate ClientApp only on its event loop.
Uses the standard library, without Flask, Django, or WebSocket."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import shutil
import tempfile
import time
from collections import deque
from collections.abc import Callable, Coroutine
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from typing import Any, BinaryIO
from urllib.parse import parse_qs, urlsplit

from client import BrowserClient, ClientApp, UICommand, UIEvent
from config import Settings
from files import resolve_receive_path
from protocol import validate_filename

LOGGER = logging.getLogger(__name__)

UI_DIR = Path(__file__).resolve().parent / "ui"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
UPLOAD_BLOCK_BYTES = 64 * 1024
MAX_JSON_BYTES = 64 * 1024
# Allow both default authentication and binding deadlines, plus cleanup time.
COMMAND_TIMEOUT_SECONDS = 25.0
REQUEST_TIMEOUT_SECONDS = 30.0
# Small refused bodies are drained after replying to avoid TCP resets on Windows.
REJECTION_DRAIN_BYTES = 8 * 1024
REJECTION_DRAIN_SECONDS = 0.1


class _HttpError(Exception):
    """Request error with an explicit HTTP status and a browser-safe message."""

    def __init__(self, status: int, message: str) -> None:
        """Lưu mã HTTP và lời giải thích an toàn để trả cho browser."""
        super().__init__(message)
        self.status = status
        self.message = message


def _cursor(query: str) -> int:
    """Đọc đúng một tham số after có giá trị là số nguyên không âm."""
    values = parse_qs(query).get("after", [])
    if len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
        raise ValueError("after must be a non-negative integer")
    return int(values[0])


def _safe_upload_name(filename: str) -> str:
    """Kiểm tên file upload theo cùng quy tắc dùng cho OFFER và file nhận."""
    return validate_filename(filename)


def _copy_exact(source: BinaryIO, target: Path, length: int) -> None:
    """Sao chép đúng length byte theo từng khối; từ chối body bị thiếu dữ liệu."""
    remaining = length
    with target.open("xb") as output:
        while remaining:
            block = source.read(min(UPLOAD_BLOCK_BYTES, remaining))
            if not block:
                raise ValueError("upload body shorter than Content-Length")
            output.write(block)
            remaining -= len(block)


class BridgeServer(ThreadingHTTPServer):
    """Loopback server with bounded event history, upload registry, and CSRF token."""

    client: ClientApp | BrowserClient
    event_loop: asyncio.AbstractEventLoop
    settings: Settings
    events: deque[tuple[int, UIEvent]]
    uploads: dict[str, Path]
    state_lock: Lock
    csrf_token: str
    _last_cursor: int
    _staging: tempfile.TemporaryDirectory[str]
    # Wait for request handlers before deleting their upload staging directories.
    daemon_threads = False

    def __init__(
        self, settings: Settings, client: ClientApp | BrowserClient, loop: asyncio.AbstractEventLoop
    ) -> None:
        """Bind 127.0.0.1 và khởi tạo handler cùng trạng thái dùng chung giữa các HTTP thread."""
        # Ignore bind_host: the UI is accessible only on the local client machine.
        super().__init__(("127.0.0.1", settings.bridge_port), BridgeHandler)
        self.settings = settings
        self.client = client
        self.event_loop = loop
        self.events = deque(maxlen=settings.bridge_event_history)
        self.uploads = {}
        self.state_lock = Lock()
        self.csrf_token = secrets.token_urlsafe(32)
        self._last_cursor = 0
        self._staging = tempfile.TemporaryDirectory(prefix="streamcollab-upload-")

    def server_close(self) -> None:
        """Đóng server và xóa các file upload tạm do bridge quản lý."""
        super().server_close()
        with self.state_lock:
            self.uploads.clear()
        self._staging.cleanup()

    def submit_command(self, command: UICommand) -> dict[str, object]:
        """Chuyển lệnh HTTP sang event loop của client và chờ trong thời hạn cho phép."""
        return self._run_on_loop(self.client.execute(command))

    def read_state(self) -> dict[str, object]:
        """Trả snapshot của client, CSRF token và cursor dùng cho polling."""
        return self._run_on_loop(self._state_on_loop())

    async def _state_on_loop(self) -> dict[str, object]:
        # Read cursor and snapshot on the same event loop as pump_events without yielding:
        # events after this cursor remain available through polling.
        """Đọc snapshot và cursor cùng lúc trên event loop của ứng dụng."""
        with self.state_lock:
            cursor = self._last_cursor
        return {"snapshot": self.client.snapshot(), "csrf_token": self.csrf_token, "cursor": cursor}

    def _run_on_loop(self, coroutine: Coroutine[Any, Any, dict[str, object]]) -> dict[str, object]:
        """Chạy coroutine client từ HTTP thread với thời hạn chờ phản hồi."""
        future = asyncio.run_coroutine_threadsafe(coroutine, self.event_loop)
        try:
            return future.result(timeout=COMMAND_TIMEOUT_SECONDS)
        except TimeoutError:
            future.cancel()
            raise

    def upload_path(self, upload_id: object) -> Path:
        """Tra upload_id do bridge cấp để lấy đường dẫn file tạm thuộc bridge."""
        with self.state_lock:
            path = self.uploads.get(upload_id) if isinstance(upload_id, str) else None
        if path is None:
            raise ValueError("unknown upload_id")
        return path

    def append_event(self, event: UIEvent) -> None:
        """Gán cursor tăng dần và lưu sự kiện vào lịch sử polling hữu hạn."""
        with self.state_lock:
            self._last_cursor += 1
            self.events.append((self._last_cursor, UIEvent(event.name, deepcopy(event.data))))

    def poll_events(self, after: int) -> dict[str, object]:
        """Trả sự kiện sau cursor, cursor tiếp theo và cờ yêu cầu tải lại lịch sử."""
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise ValueError("cursor must be a non-negative integer")
        with self.state_lock:
            history = list(self.events)
            last = self._last_cursor
        oldest = history[0][0] if history else last + 1
        # Reset when history has expired or the bridge restarted with a lower cursor.
        # Return retained history so the UI can recover after loading a fresh snapshot.
        reset = after < oldest - 1 or after > last
        start = 0 if reset else after
        events = [
            {"id": cursor, "name": event.name, "data": deepcopy(event.data)}
            for cursor, event in history
            if cursor > start
        ]
        return {"events": events, "next_cursor": last, "reset": reset}

    def store_upload(self, filename: str, source: BinaryIO, length: int) -> str:
        """Lưu upload theo từng khối và trả mã upload_id để tham chiếu file tạm."""
        name = _safe_upload_name(filename)
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("Content-Length must be a non-negative integer")
        if length > self.settings.max_file_bytes:
            raise ValueError("upload exceeds max_file_bytes")
        upload_id = secrets.token_urlsafe(16)
        # Use a separate folder per upload to preserve its original filename without collisions.
        folder = Path(self._staging.name) / upload_id
        folder.mkdir()
        try:
            target = resolve_receive_path(folder, name)
            _copy_exact(source, target, length)
        except BaseException:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        with self.state_lock:
            self.uploads[upload_id] = target
        return upload_id


class BridgeHandler(BaseHTTPRequestHandler):
    """Thin HTTP adapter forwarding JSON commands to ClientApp.execute."""

    server: BridgeServer
    timeout = REQUEST_TIMEOUT_SECONDS
    # Python 3.12 trả lỗi cho dòng request sai không kèm dòng trạng thái (kiểu HTTP/0.9).
    default_request_version = "HTTP/1.0"

    def do_GET(self) -> None:
        """Phục vụ asset được cho phép, /api/state và /api/events?after=N."""
        self._handle(self._route_get)

    def do_POST(self) -> None:
        """Nhận lệnh hoặc upload và trả kết quả JSON."""
        self._handle(self._route_post)

    def _handle(self, route: Callable[[], None]) -> None:
        """Đổi lỗi yêu cầu dự kiến thành mã HTTP; ghi log và trả HTTP 500 cho lỗi bất ngờ."""
        try:
            route()
            return
        except _HttpError as error:
            status, message = error.status, error.message
        except ValueError as error:
            status, message = 400, str(error)
        # Invalid credentials map to PermissionError; duplicate login/capacity map to
        # ConnectionError. Return these expected errors to the browser.
        except PermissionError as error:
            status, message = 403, str(error)
        except ConnectionError as error:
            status, message = 409, str(error)
        except TimeoutError:
            status, message = 504, "client core did not answer in time"
        except Exception:
            LOGGER.exception("bridge %s %s failed", self.command, urlsplit(self.path).path)
            status, message = 500, "internal error"
        # An unread request body may remain; do not reuse this connection after an error.
        self.close_connection = True
        self.write_json(status, {"error": message})
        self._drain_rejected_body()

    def _drain_rejected_body(self) -> None:
        """Đọc bỏ một phần body sau khi trả lỗi, có giới hạn byte và thời gian.

        Tránh đóng kết nối khi browser còn gửi POST nhỏ làm mất phản hồi JSON.
        Không chờ đọc hết một upload lớn đã bị từ chối."""
        if getattr(self, "_body_consumed", False):
            return
        raw = self.headers.get("Content-Length", "")
        if not raw.isascii() or not raw.isdigit():
            return
        try:
            remaining = min(int(raw), REJECTION_DRAIN_BYTES)
            deadline = time.monotonic() + REJECTION_DRAIN_SECONDS
            while remaining:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    return
                self.connection.settimeout(timeout)
                block = self.rfile.read1(remaining)
                if not block:
                    return
                remaining -= len(block)
        except (OSError, ValueError):
            pass  # Peer closed, stalled, or supplied an invalid length; response was sent.

    def _route_get(self) -> None:
        """Kiểm tra Host rồi trả snapshot, trang sự kiện hoặc asset UI được cho phép."""
        self._check_host()
        url = urlsplit(self.path)
        if url.path == "/api/state":
            self.write_json(200, self.server.read_state())
        elif url.path == "/api/events":
            self.write_json(200, self.server.poll_events(_cursor(url.query)))
        elif url.path in ASSETS:
            filename, content_type = ASSETS[url.path]
            self._send_bytes(200, (UI_DIR / filename).read_bytes(), content_type)
        else:
            raise _HttpError(404, "not found")

    def _route_post(self) -> None:
        """Kiểm tra Host, Origin và CSRF trước khi xử lý lệnh hoặc upload."""
        self._check_host()
        self._check_origin_and_token()
        url = urlsplit(self.path)
        if url.path == "/api/commands":
            self.write_json(200, self.server.submit_command(self._read_command()))
        elif url.path == "/api/uploads":
            self.write_json(201, {"upload_id": self._receive_upload(url.query)})
        else:
            raise _HttpError(404, "not found")

    def _local_hosts(self) -> set[str]:
        """Trả các giá trị Host loopback được phép cho cổng bridge hiện tại."""
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _check_host(self) -> None:
        # Reject DNS rebinding requests whose Host is not the local bridge address.
        """Từ chối yêu cầu có Host không trỏ tới HTTP bridge cục bộ."""
        if self.headers.get("Host") not in self._local_hosts():
            raise _HttpError(403, "forbidden host")

    def _check_origin_and_token(self) -> None:
        """Yêu cầu CSRF token hợp lệ và Origin cục bộ nếu header này được gửi."""
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://{h}" for h in self._local_hosts()}:
            raise _HttpError(403, "forbidden origin")
        token = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token.encode(), self.server.csrf_token.encode()):
            raise _HttpError(403, "invalid CSRF token")

    def _content_length(self) -> int:
        """Đọc Content-Length bắt buộc, không âm; báo lỗi HTTP nếu không hợp lệ."""
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise _HttpError(411, "Content-Length required")
        if not raw.isascii() or not raw.isdigit():
            raise ValueError("invalid Content-Length")
        return int(raw)

    def _read_command(self) -> UICommand:
        """Kiểm lệnh JSON và tra upload_id, không tin đường dẫn do browser cung cấp."""
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise _HttpError(415, "commands must be application/json")
        body = self.read_json()
        name, args = body.get("name"), body.get("args", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            raise ValueError("command needs a string name and an object args")
        if name == "send_file":
            # Browsers supply only upload_id; discard any caller-supplied filesystem path.
            args = {
                "recipient": args.get("recipient"),
                "path": self.server.upload_path(args.get("upload_id")),
            }
        return UICommand(name, dict(args))

    def _receive_upload(self, query: str) -> str:
        """Kiểm tên và kích thước upload rồi trả upload_id do bridge quản lý."""
        names = parse_qs(query).get("name", [])
        if len(names) != 1:
            raise ValueError("upload needs exactly one name parameter")
        length = self._content_length()
        if length > self.server.settings.max_file_bytes:
            raise _HttpError(413, "file is larger than the upload limit")
        return self.server.store_upload(names[0], self.rfile, length)

    def read_json(self) -> dict[str, object]:
        """Đọc đối tượng JSON có giới hạn kích thước và header Content-Length bắt buộc."""
        length = self._content_length()
        if length > MAX_JSON_BYTES:
            raise _HttpError(413, "command body is too large")
        raw = self.rfile.read(length)
        self._body_consumed = True
        if len(raw) != length:
            raise ValueError("body shorter than Content-Length")
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError as error:
            raise ValueError("body is not valid JSON") from error
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        return body

    def write_json(self, status: int, body: dict[str, object]) -> None:
        """Trả JSON UTF-8 cùng mã HTTP và header, không lộ traceback hoặc bí mật."""
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, data, "application/json; charset=utf-8")

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        """Gửi phản hồi có header bảo mật và xử lý trường hợp browser ngắt kết nối."""
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            LOGGER.debug("browser closed the connection before the response was sent")
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        """Ghi log HTTP qua logging sau khi loại dữ liệu query nhạy cảm."""
        message = format % args
        requestline = getattr(self, "requestline", "")
        if requestline:
            # Query strings may contain filenames; log only the method and URL path.
            command = getattr(self, "command", None) or "-"
            path = urlsplit(getattr(self, "path", "")).path
            message = message.replace(requestline, f"{command} {path}")
        LOGGER.debug("bridge %s %s", self.address_string(), message)


async def pump_events(client: ClientApp | BrowserClient, bridge: BridgeServer) -> None:
    """Dùng một tác vụ tiêu thụ để chuyển sự kiện client vào lịch sử bridge."""
    # The owner cancels this task on shutdown; let CancelledError propagate.
    while True:
        bridge.append_event(await client.events.get())
