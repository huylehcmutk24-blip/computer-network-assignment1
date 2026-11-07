"""S14: the client finds the server on machine A with a UDP broadcast and logs in.

Run on machine B while the server runs on machine A:
    python evidence/discovery_check.py --server auto
The script broadcasts DISCOVER to 255.255.255.255:9002, records the raw ANNOUNCE (to show
that it carries no username), measures the discovery time over five rounds, then logs in
as client04 through the address the answer came from.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import statistics
import sys
import time

from _common import Lab, Report, parse_args, quiet_logs, wait_until

from client import discover_server
from protocol import MessageType, Packet, decode_public_control, encode_public_control


async def raw_announce(port: int, address: str) -> tuple[bytes, str]:
    """Gửi một DISCOVER thô và trả bytes của ANNOUNCE cùng IP nguồn."""
    loop = asyncio.get_running_loop()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    probe.bind(("0.0.0.0", 0))
    probe.setblocking(False)
    try:
        request = Packet(MessageType.DISCOVER, "", "*", "__server__", "discovery", 0, "probe-1")
        await loop.sock_sendto(probe, encode_public_control(request), (address, port))
        async with asyncio.timeout(3):
            raw, source = await loop.sock_recvfrom(probe, 2048)
    finally:
        probe.close()
    return raw, source[0]


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/discovery_check.*."""

    def extra(parser) -> None:
        parser.add_argument("--discovery-address", default="255.255.255.255")

    args = parse_args(__doc__, extra)
    if args.server not in (None, "auto"):
        args.server = "auto"  # Bài này luôn tìm server bằng broadcast.
    async with Lab(args) as lab:
        report = Report("discovery_check", lab.mode)
        port = args.discovery_port if lab.remote else lab.server.discovery_address[1]
        address = args.discovery_address if lab.remote else "127.0.0.1"
        raw, source = await raw_announce(port, address)
        announce = decode_public_control(raw, {MessageType.ANNOUNCE})
        report.line(f"ANNOUNCE from {source}: {announce.metadata} ({len(raw)} bytes)")
        report.check(b"client" not in raw, "ANNOUNCE carries ports and counts, no username")

        settings = lab.settings(
            4, server_host="auto", discovery_port=port, discovery_address=address
        )
        times = []
        for _ in range(5):
            start = time.perf_counter()
            host, tcp_port, udp_port = await discover_server(settings)
            times.append((time.perf_counter() - start) * 1000)
        report.line(f"discovered {host}:{tcp_port} (UDP {udp_port}); times {times}")
        if lab.remote:
            report.check(
                not ipaddress.ip_address(host).is_loopback, "server reached on its LAN address"
            )
        session = await lab.open(
            4, server_host="auto", discovery_port=port, discovery_address=address
        )
        await wait_until(lambda: session.client.snapshot()["state"] == "ONLINE", 10)
        snapshot = session.client.snapshot()
        report.check(snapshot["state"] == "ONLINE", f"client04 logged in via {snapshot['server']}")
        await session.close()
        report.data.update(
            server_ip=host,
            announce=announce.metadata,
            announce_bytes=len(raw),
            discovery_median_ms=round(statistics.median(times), 1),
            discovery_max_ms=round(max(times), 1),
        )
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
