"""Single entry point: python main.py server or client. No separate chat CLI."""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from threading import Thread

from client import BrowserClient
from config import PROJECT_ROOT, Settings, configure_logging, load_settings
from server import ServerApp
from web import BridgeServer, pump_events

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Đọc tham số Terminal cho server/client và trả về Namespace chứa chế độ, đường dẫn cấu hình cùng các tùy chọn ghi đè."""

    parser = argparse.ArgumentParser(description="StreamCollab: server and client")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    commands = {}

    for mode in ("server", "client"):
        command = subparsers.add_parser(
            mode,
            argument_default=argparse.SUPPRESS,
        )

        command.add_argument(
            "--config",
            type=Path,
            default=PROJECT_ROOT / "config" / f"{mode}.example.json",
        )
        command.add_argument("--host", dest="bind_host")
        command.add_argument("--tcp-port", type=int)
        command.add_argument("--udp-port", type=int)
        command.add_argument("--discovery-port", type=int)

        commands[mode] = command

    client_parser = commands["client"]
    # --server auto: tìm server bằng DISCOVER broadcast thay vì nhập IP.
    client_parser.add_argument("--server", dest="server_host")
    client_parser.add_argument("--discovery-address")
    client_parser.add_argument("--username")
    client_parser.add_argument("--key-id", type=int)
    client_parser.add_argument("--keyring", dest="keyring_path", type=Path)
    client_parser.add_argument("--http-port", dest="bridge_port", type=int)
    client_parser.add_argument("--receive-dir", type=Path)
    client_parser.add_argument("--log-path", type=Path)

    return parser.parse_args()


async def run_server(settings: Settings) -> None:
    """Chạy ServerApp cho đến khi bị ngắt; luôn đóng app này, kể cả trong trường hợp khởi động thất bại."""
    app = ServerApp(settings)

    try:
        await app.start()

        try:
            discovery = app.discovery_address
        except ConnectionError:
            discovery = "disabled"
        logger.info(
            "Server started: TCP=%s, UDP=%s, discovery=%s",
            app.tcp_address,
            app.udp_address,
            discovery,
        )

        # Đợi cho đến khi người dùng ngắt chương trình bằng tổ hợp phím Ctrl+C.
        await asyncio.Event().wait()

    finally:
        await app.close()
        logger.info("SERVER STOPPED")


async def run_client(settings: Settings) -> None:
    """Giữ HTTP hoạt động; mỗi lần đăng nhập tạo một phiên mạng mới."""
    app = BrowserClient(settings)

    bridge: BridgeServer | None = None
    http_thread: Thread | None = None
    tasks: list[asyncio.Task[None]] = []

    try:
        tasks.append(asyncio.create_task(app.run()))

        bridge = BridgeServer(
            settings,
            app,
            asyncio.get_running_loop(),
        )

        # Run HTTP in a separate thread to avoid blocking asyncio.
        http_thread = Thread(
            target=bridge.serve_forever,
            daemon=True,
        )
        http_thread.start()

        tasks.append(asyncio.create_task(pump_events(app, bridge)))

        logger.info("CLIENT DISCONNECTED user=%s | Ready for login", settings.username)
        print(f"Open the interface: http://127.0.0.1:{bridge.server_address[1]}", flush=True)

        # Begin cleanup when either the core or the event pump stops.
        done, _ = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in done:
            task.result()

    finally:
        try:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            try:
                # File readers phải dừng lại trước khi bridge xóa các tệp tải lên đang chờ xử lý.
                await app.close()
            finally:
                await _close_http_bridge(bridge, http_thread)


async def _close_http_bridge(bridge: BridgeServer | None, http_thread: Thread | None) -> None:
    """Dừng luồng HTTP và giải phóng máy chủ, bao gồm cả trường hợp đã khởi động một phần."""
    if bridge is None:
        return
    try:
        if http_thread is not None and http_thread.ident is not None:
            await asyncio.to_thread(bridge.shutdown)
            await asyncio.to_thread(http_thread.join)
    finally:
        await asyncio.to_thread(bridge.server_close)


async def main(arguments: argparse.Namespace) -> None:
    """Tải setting, cấu hình logging, đồng thời chọn vòng đời cho server và client."""
    args = vars(arguments).copy()

    mode = args.pop("mode")
    config_path = args.pop("config")

    # The remaining arguments contain only explicitly supplied overrides.
    settings = load_settings(config_path, args)
    configure_logging(settings)

    if mode == "server":
        await run_server(settings)

    else:
        # Remote ports cannot be zero; port zero is only valid when binding.
        if not (1 <= settings.tcp_port <= 65535 and 1 <= settings.udp_port <= 65535):
            raise ValueError("Server TCP/UDP ports must be in the range 1..65535")

        await run_client(settings)


if __name__ == "__main__":
    # Parse --help and invalid arguments without opening an asyncio event loop.
    asyncio.run(main(parse_args()))
