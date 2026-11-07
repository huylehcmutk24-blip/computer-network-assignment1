"""S15: the local HTTP bridge enforces its request contract (Table 12 of the report).

Run on machine B while the server runs on machine A:
    python evidence/http_bridge_check.py --server <IP of A>
A browser client for client04 runs in this process and logs in to the server through
the bridge on 127.0.0.1; every request below is written byte by byte on a TCP socket.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading

from _common import Lab, Report, parse_args, quiet_logs

import web
from client import BrowserClient


def exchange(port: int, request: bytes) -> tuple[int, dict | bytes]:
    """Gửi một request thô và trả (mã trạng thái, body JSON hoặc bytes)."""
    with socket.create_connection(("127.0.0.1", port), timeout=40) as sock:
        sock.sendall(request)
        data = b""
        try:
            while chunk := sock.recv(65536):
                data += chunk
        except ConnectionResetError:
            pass
    if not data.startswith(b"HTTP/"):
        return 0, data  # Không có dòng trạng thái: ghi FAIL thay vì dừng script.
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def request(method: str, port: int, path: str, *, token: str = "", body: bytes = b"", **headers):
    """Dựng request HTTP/1.1 với Host loopback, CSRF token và Content-Length khi có body."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}", "Connection: close"]
    if token:
        lines.append(f"X-CSRF-Token: {token}")
    for name, value in headers.items():
        lines.append(f"{name.replace('_', '-')}: {value}")
    if body or method == "POST":
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/http_bridge_check.*."""
    args = parse_args(__doc__)
    async with Lab(args) as lab:
        report = Report("http_bridge_check", lab.mode)
        settings = lab.settings(4, bridge_port=0)
        browser = BrowserClient(settings)
        bridge = web.BridgeServer(settings, browser, asyncio.get_running_loop())
        thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        thread.start()
        pump = asyncio.create_task(web.pump_events(browser, bridge))
        port = bridge.server_address[1]

        async def call(raw: bytes):
            """Gửi request trong thread để event loop vẫn phục vụ bridge."""
            return await asyncio.to_thread(exchange, port, raw)

        status, state = await call(request("GET", port, "/api/state"))
        token = state["csrf_token"]

        def login(password: str) -> bytes:
            """Request đăng nhập JSON."""
            payload = json.dumps(
                {"name": "login", "args": {"username": "client04", "password": password}}
            ).encode()
            return request(
                "POST",
                port,
                "/api/commands",
                token=token,
                body=payload,
                Content_Type="application/json",
            )

        big = json.dumps({"name": "public", "args": {"text": "x" * 70000}}).encode()
        cases = [
            ("GET /api/state", request("GET", port, "/api/state"), 200),
            ("wrong password", login("wrong-password"), 403),
            ("correct password", login(lab.password), 200),
            ("foreign Host", b"GET /api/state HTTP/1.1\r\nHost: evil.example\r\n\r\n", 403),
            (
                "foreign Origin",
                request("POST", port, "/api/commands", token=token, Origin="http://evil.example"),
                403,
            ),
            ("missing CSRF token", request("POST", port, "/api/commands", body=b"{}"), 403),
            ("path outside the allowlist", request("GET", port, "/../config.py"), 404),
            (
                "no Content-Length",
                f"POST /api/commands HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-CSRF-Token: {token}"
                "\r\nContent-Type: application/json\r\n\r\n".encode(),
                411,
            ),
            ("not JSON", request("POST", port, "/api/commands", token=token, body=b"{}"), 415),
            (
                "command over 64 KiB",
                request(
                    "POST",
                    port,
                    "/api/commands",
                    token=token,
                    body=big,
                    Content_Type="application/json",
                ),
                413,
            ),
            (
                "upload over 100 MiB",
                request("POST", port, "/api/uploads?name=big.bin", token=token).replace(
                    b"Content-Length: 0", f"Content-Length: {settings.max_file_bytes + 1}".encode()
                ),
                413,
            ),
            ("malformed request line", b"HELLO\r\n\r\n", 400),
        ]
        results = {}
        for label, raw, expected in cases:
            status, _ = await call(raw)
            results[label] = status
            report.check(status == expected, f"{label}: HTTP {status} (expected {expected})")
        status, body = await call(request("GET", port, "/api/events?after=0"))
        report.check(status == 200 and body["events"], f"event poll: {len(body['events'])} events")
        report.data.update(statuses=results, expected={label: code for label, _, code in cases})

        await browser.close()
        pump.cancel()
        await asyncio.gather(pump, return_exceptions=True)
        await asyncio.to_thread(bridge.shutdown)
        await asyncio.to_thread(bridge.server_close)
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
