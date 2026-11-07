"""S12: TCP faults and client exits do not stop the server or the other sessions.

Run on machine B while the server runs on machine A (client04 to client09 not logged in):
    python evidence/resilience_check.py --server <IP of A>
From machine B the script sends a zero-length TCP frame, opens 30 connections that send
HELLO and are then reset, leaves one connection silent and one with half a length prefix,
kills a client process (client08), logs another client out, and kills the process of a
file receiver (client09) in the middle of a transfer. The server's reasons for closing
each connection are read from the server log of machine A by tools/collect_metrics.py.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from _common import Lab, Report, parse_args, quiet_logs, wait_until

from client import ClientState, UICommand
from protocol import MessageType, Packet, encode_public_control


def abort(sock: socket.socket) -> None:
    """Đóng TCP bằng RST như khi tiến trình bị kill."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def hello_frame(username: str) -> bytes:
    """Frame HELLO hợp lệ để mở đầu bắt tay."""
    hello = Packet(MessageType.HELLO, "", username, "__server__", "control", 0, "probe-hello")
    body = encode_public_control(hello)
    return struct.pack("!I", len(body)) + body


async def chat_latency(sender, receiver, text: str) -> float:
    """Gửi tin riêng và trả độ trễ tới khi bên nhận có sự kiện message (ms)."""
    before = len(receiver.messages())
    start = time.perf_counter()
    await sender.client.send_chat(text, receiver.name)
    await wait_until(lambda: len(receiver.messages()) > before, 15)
    return (time.perf_counter() - start) * 1000


def start_victim(lab: Lab, number: int) -> subprocess.Popen:
    """Chạy một client trong tiến trình riêng (evidence/_victim.py) và chờ nó ONLINE."""
    tcp_port, udp_port = lab.ports
    receive = lab.work / f"victim{number:02}"
    environment = {**os.environ, "STREAMCOLLAB_PASSWORD": lab.password}
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("_victim.py")),
            lab.server_host,
            str(tcp_port),
            str(udp_port),
            str(number),
            str(lab.folder),
            str(receive),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=environment,
    )
    if process.stdout.readline().strip() != "READY":
        process.kill()
        raise RuntimeError(f"client{number:02} helper did not log in")
    return process


async def tcp_faults(lab: Lab, first, second, report: Report) -> dict:
    """Frame rỗng, 30 lần reset quanh HELLO, kết nối im lặng và nửa prefix độ dài."""
    host, port = lab.server_host, lab.ports[0]
    probes: dict[str, list[int]] = {"zero_frame": [], "reset": [], "silent": [], "half": []}

    def raw_connect(kind: str) -> socket.socket:
        """Mở kết nối TCP thô tới server và ghi lại cổng nguồn."""
        sock = socket.create_connection((host, port), timeout=15)
        probes[kind].append(sock.getsockname()[1])
        return sock

    sock = await asyncio.to_thread(raw_connect, "zero_frame")
    sock.sendall(b"\x00\x00\x00\x00")
    await asyncio.sleep(0.2)
    sock.close()
    for index in range(30):
        sock = await asyncio.to_thread(raw_connect, "reset")
        sock.sendall(hello_frame(f"probe{index:02}"))
        if index % 3 == 0:
            await asyncio.sleep(0.01)
        abort(sock)
    await asyncio.sleep(0.5)
    chat = await chat_latency(first, second, "after resets")
    start = time.perf_counter()
    third = await lab.open(6)
    login = (time.perf_counter() - start) * 1000
    await third.close()
    report.check(True, f"after the faults: chat in {chat:.1f} ms, a new login in {login:.0f} ms")

    def wait_closed(kind: str, data: bytes) -> float:
        """Trả số giây tới khi server đóng kết nối."""
        sock = raw_connect(kind)
        sock.settimeout(30)
        start = time.perf_counter()
        if data:
            sock.sendall(data)
        sock.recv(1)
        sock.close()
        return time.perf_counter() - start

    silent, half = await asyncio.gather(
        asyncio.to_thread(wait_closed, "silent", b""),
        asyncio.to_thread(wait_closed, "half", b"\x00\x00"),
    )
    report.check(
        9.5 < silent < 11.5 and 9.5 < half < 11.5,
        f"silent connection closed after {silent:.2f} s, half prefix after {half:.2f} s",
    )
    return {
        "chat_after_ms": round(chat, 1),
        "login_after_ms": round(login),
        "silent_close_s": round(silent, 2),
        "half_close_s": round(half, 2),
        "probe_ports": probes,
    }


async def client_exits(lab: Lab, first, report: Report) -> dict:
    """Tiến trình client bị kill và một client LOGOUT: những người khác thấy họ rời đi."""
    victim = await asyncio.to_thread(start_victim, lab, 8)
    await wait_until(lambda: "client08" in first.users(), 10)
    victim.kill()  # Hệ điều hành đóng socket của tiến trình bị kill.
    vanished = await wait_until(lambda: "client08" not in first.users(), 15)
    fourth = await lab.open(7)
    await wait_until(lambda: "client07" in first.users(), 10)
    await fourth.close()
    logged_out = await wait_until(lambda: "client07" not in first.users(), 10)
    report.check(
        True,
        f"vanished client seen by others after {vanished * 1000:.1f} ms, "
        f"LOGOUT after {logged_out * 1000:.1f} ms",
    )
    victim.wait(timeout=10)
    return {"vanished_ms": round(vanished * 1000, 1), "logout_ms": round(logged_out * 1000, 1)}


async def receiver_killed(lab: Lab, first, report: Report) -> dict:
    """Kill tiến trình bên nhận giữa lượt truyền 4 MiB: bên gửi được báo và vẫn online."""
    receiver = await asyncio.to_thread(start_victim, lab, 9)
    await wait_until(lambda: "client09" in first.users(), 10)
    source = lab.work / "mid.bin"
    source.write_bytes(os.urandom(4 * 1024 * 1024))
    result = await first.client.execute(
        UICommand("send_file", {"path": source, "recipient": "client09"})
    )

    def transfer() -> dict:
        """Bản ghi lượt truyền ở bên gửi."""
        for item in first.client.snapshot()["transfers"]:
            if item.get("transfer_id") == result["transfer_id"]:
                return item
        return {}

    await wait_until(lambda: transfer().get("bytes_transferred", 0) > 200_000, 60)
    receiver.kill()
    told = await wait_until(lambda: transfer().get("status") == "FAILED", 15)
    code = transfer().get("code")
    report.check(
        first.client.state == ClientState.ONLINE and code == "ENDPOINT_DISCONNECTED",
        f"receiver gone mid file: sender told in {told * 1000:.1f} ms ({code}), stays online",
    )
    receiver.wait(timeout=10)
    return {"mid_file_ms": round(told * 1000, 1), "mid_file_code": code}


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/resilience_check.*."""
    args = parse_args(__doc__)
    async with Lab(args) as lab:
        report = Report("resilience_check", lab.mode)
        first = await lab.open(4)
        second = await lab.open(5)
        report.data["client_ip"] = first.client._tcp_socket.getsockname()[0]
        report.data.update(await tcp_faults(lab, first, second, report))
        await second.close()
        report.data.update(await client_exits(lab, first, report))
        report.data.update(await receiver_killed(lab, first, report))
        await first.close()
        if lab.server is not None:
            report.check(all(not t.done() for t in lab.server._tasks), "server tasks still running")
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
