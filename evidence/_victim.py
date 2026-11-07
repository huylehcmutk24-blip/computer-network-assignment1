"""Helper process for resilience_check.py: one logged-in client that the parent kills.

Usage (started by resilience_check.py, not by hand):
    python evidence/_victim.py <host> <tcp_port> <udp_port> <number> <keys_dir> <receive_dir>
The password is read from the STREAMCOLLAB_PASSWORD environment variable. The process
prints READY once ONLINE and then runs until it is killed, so the operating system
closes its sockets exactly as when a user's client process dies.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client import ClientApp, UICommand  # noqa: E402
from config import Settings  # noqa: E402


async def main() -> None:
    """Đăng nhập, báo READY rồi chạy cho tới khi bị kill."""
    host, tcp_port, udp_port, number, keys, receive = sys.argv[1:7]
    username = f"client{int(number):02}"
    client = ClientApp(
        Settings(
            username=username,
            key_id=int(number),
            server_host=host,
            bind_host="0.0.0.0" if host not in ("127.0.0.1", "localhost") else "127.0.0.1",
            tcp_port=int(tcp_port),
            udp_port=int(udp_port),
            keyring_path=Path(keys) / f"{username}.keys.json",
            receive_dir=Path(receive),
        )
    )

    async def drain() -> None:
        """Lấy sự kiện UI để hàng đợi không đầy."""
        while True:
            await client.events.get()

    asyncio.create_task(drain())
    await client.connect()
    asyncio.create_task(client.run())
    password = os.environ["STREAMCOLLAB_PASSWORD"]
    await client.execute(UICommand("login", {"username": username, "password": password}))
    print("READY", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
