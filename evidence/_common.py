"""Shared helpers for the evidence scripts.

Two modes:
- two-machine (the mode used for the report): the server runs on machine A
  (python main.py server); the script runs on machine B and connects to it with
  --server <IP of A> (or --server auto). Accounts: the key files of clientNN in
  --keys (default config/secrets) and the shared password (asked, or taken from
  the STREAMCOLLAB_PASSWORD environment variable).
- local (no --server): a server is started inside the script on this machine, with
  temporary accounts. Useful to try a script; its numbers are not used in the report.

Each script writes evidence/out/<name>.txt (readable) and <name>.json (numbers).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import platform
import socket
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = Path(__file__).resolve().parent
OUT = EVIDENCE / "out"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import ClientApp, UICommand  # noqa: E402
from config import Settings  # noqa: E402
from demo import create_accounts  # noqa: E402
from server import ServerApp  # noqa: E402

LOCAL_PASSWORD = "evidence-password-1"


def environment() -> dict[str, str]:
    """Mô tả máy đang chạy script."""
    import cryptography

    return {
        "host": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
    }


def parse_args(description: str, extra: Callable[[argparse.ArgumentParser], None] | None = None):
    """Tham số chung: địa chỉ server trên máy A, thư mục khóa và các cổng."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--server", help="IP of machine A, or auto (UDP broadcast)")
    parser.add_argument("--keys", type=Path, default=ROOT / "config" / "secrets")
    parser.add_argument("--tcp-port", type=int, default=9000)
    parser.add_argument("--udp-port", type=int, default=9001)
    parser.add_argument("--discovery-port", type=int, default=9002)
    if extra is not None:
        extra(parser)
    return parser.parse_args()


class Report:
    """Gom dòng kết quả và số liệu, ghi evidence/out/<name>.txt và <name>.json."""

    def __init__(self, name: str, mode: str) -> None:
        """Bắt đầu một báo cáo cho chế độ two-machine hoặc local."""
        self.name = name
        self.mode = mode
        self.data: dict[str, object] = {
            "mode": mode,
            "date": time.strftime("%Y-%m-%d"),
            "environment": environment(),
        }
        self.lines = [
            f"# {name} - {time.strftime('%Y-%m-%d %H:%M:%S %z')} - mode {mode}",
            f"# {json.dumps(self.data['environment'])}",
        ]
        self.failures = 0

    def line(self, text: str) -> None:
        """Thêm một dòng thông tin."""
        print(text, flush=True)
        self.lines.append(text)

    def check(self, ok: bool, text: str) -> None:
        """Thêm một dòng PASS/FAIL."""
        self.line(f"{'PASS' if ok else 'FAIL'}: {text}")
        self.failures += 0 if ok else 1

    def save(self) -> int:
        """Ghi hai file kết quả và trả exit code 0 nếu không có FAIL."""
        verdict = "ALL PASS" if not self.failures else f"{self.failures} FAIL"
        self.line(f"RESULT: {verdict}")
        self.data["result"] = verdict
        OUT.mkdir(exist_ok=True)
        (OUT / f"{self.name}.txt").write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        (OUT / f"{self.name}.json").write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return 0 if not self.failures else 1


def quiet_logs() -> None:
    """Chỉ giữ cảnh báo trên màn hình để output của script dễ đọc."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")


class Session:
    """Một ClientApp đang chạy cùng tác vụ run() và bộ thu sự kiện có dấu thời gian."""

    def __init__(self, client: ClientApp) -> None:
        """Bắt đầu thu sự kiện của client."""
        self.client = client
        self.events: list[tuple[float, str, dict]] = []
        self.tasks: list[asyncio.Task] = []

    @property
    def name(self) -> str:
        """Username của client."""
        return self.client.settings.username

    async def _drain(self) -> None:
        """Lấy sự kiện khỏi hàng đợi UI để client không dừng vì hàng đợi đầy."""
        while True:
            event = await self.client.events.get()
            self.events.append((time.perf_counter(), event.name, event.data))

    def users(self) -> list[str]:
        """Danh sách online hiện tại của client."""
        return self.client.snapshot()["users"]

    def messages(self) -> list[tuple[float, dict]]:
        """Các sự kiện message đã nhận kèm thời điểm nhận."""
        return [(t, data) for t, name, data in self.events if name == "message"]

    async def close(self) -> None:
        """Đóng client và dừng các tác vụ phụ."""
        await self.client.close()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class Lab:
    """Nơi các script mở client: server thật trên máy A, hoặc server tạm trên máy này."""

    def __init__(self, args) -> None:
        """Đọc chế độ từ tham số; mật khẩu chỉ hỏi khi chạy với server trên máy A."""
        self.args = args
        self.remote = args.server is not None
        self.mode = "two-machine" if self.remote else "local"
        self.server: ServerApp | None = None
        self._temp: tempfile.TemporaryDirectory | None = None
        self.folder = Path(".")
        self.password = LOCAL_PASSWORD

    async def __aenter__(self) -> Lab:
        """Chuẩn bị tài khoản và server (chế độ local) hoặc hỏi mật khẩu (two-machine)."""
        self._temp = tempfile.TemporaryDirectory(prefix="streamcollab-evidence-")
        self.work = Path(self._temp.name)
        if self.remote:
            self.folder = self.args.keys
            self.password = os.environ.get("STREAMCOLLAB_PASSWORD") or getpass.getpass(
                "Password of the clientNN accounts: "
            )
        else:
            self.folder = self.work / "secrets"
            self.folder.mkdir()
            create_accounts(self.folder, LOCAL_PASSWORD)
            self.server = ServerApp(
                Settings(
                    tcp_port=0,
                    udp_port=0,
                    discovery_port=0,
                    users_path=self.folder / "users.json",
                    keyring_path=self.folder / "server.keys.json",
                )
            )
            await self.server.start()
        return self

    async def __aexit__(self, *exc) -> None:
        """Đóng server tạm và xóa thư mục làm việc."""
        if self.server is not None:
            await self.server.close()
        if self._temp is not None:
            self._temp.cleanup()

    @property
    def server_host(self) -> str:
        """Địa chỉ server mà client dùng."""
        return self.args.server if self.remote else "127.0.0.1"

    @property
    def ports(self) -> tuple[int, int]:
        """Cổng TCP và UDP của server."""
        if self.remote:
            return self.args.tcp_port, self.args.udp_port
        return self.server.tcp_address[1], self.server.udp_address[1]

    def settings(self, number: int, **overrides) -> Settings:
        """Settings cho clientNN trỏ tới server của phép đo."""
        username = f"client{number:02}"
        tcp_port, udp_port = self.ports
        values = {
            "username": username,
            "key_id": number,
            "server_host": self.server_host,
            "bind_host": "0.0.0.0" if self.remote else "127.0.0.1",
            "tcp_port": tcp_port,
            "udp_port": udp_port,
            "discovery_port": self.args.discovery_port if self.remote else 0,
            "keyring_path": self.folder / f"{username}.keys.json",
            "receive_dir": self.work / username,
            **overrides,
        }
        return Settings(**values)

    async def open(
        self, number: int, *, cls: type[ClientApp] = ClientApp, login: bool = True, **overrides
    ) -> Session:
        """Tạo client, connect, chạy nền và đăng nhập."""
        client = cls(self.settings(number, **overrides))
        session = Session(client)
        session.tasks.append(asyncio.create_task(session._drain()))
        await client.connect()
        session.tasks.append(asyncio.create_task(client.run()))
        if login:
            name = client.settings.username
            try:
                await client.execute(
                    UICommand("login", {"username": name, "password": self.password})
                )
            except PermissionError as error:
                await session.close()
                raise SystemExit(
                    f"{name} could not log in ({error}): wrong password, or {name} is already "
                    "logged in (close the browser-session clients on machine B first)."
                ) from None
        return session


async def wait_until(predicate: Callable[[], bool], timeout: float, step: float = 0.002) -> float:
    """Chờ tới khi predicate đúng; trả số giây đã chờ hoặc báo TimeoutError."""
    start = time.perf_counter()
    while not predicate():
        if time.perf_counter() - start > timeout:
            raise TimeoutError("condition not reached in time")
        await asyncio.sleep(step)
    return time.perf_counter() - start
