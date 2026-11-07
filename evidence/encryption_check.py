"""S10: no plaintext chat, file data or password on the wire; tampering is rejected.

Run on machine B while the server runs on machine A:
    python evidence/encryption_check.py --server <IP of A>
Every byte that client04 and client05 send and receive on their sockets is captured
while they log in, chat and send a small file through the server. The script searches
the captures for the marker strings and the password, checks the envelope format, and
flips every bit of one protected datagram.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import suppress

from _common import Lab, Report, parse_args, quiet_logs, wait_until
from cryptography.fernet import InvalidToken

from client import UICommand
from protocol import MAGIC, PROTOCOL_VERSION, MessageType, Packet, deserialize_packet
from security import SecurityContext, load_keyring

PUBLIC_MARKER = "MARKER-PUBLIC-7f3a"
PRIVATE_MARKER = "MARKER-PRIVATE-91c2"
FILE_MARKER = b"MARKER-FILE-5d0e"


def install_capture(loop, datagrams: list[bytes], sent: list[bytes], read: list[bytes]) -> dict:
    """Bọc các hàm socket của event loop để chép mọi byte gửi và nhận."""
    original = {
        "sock_sendto": loop.sock_sendto,
        "sock_sendall": loop.sock_sendall,
        "sock_recvfrom": loop.sock_recvfrom,
        "sock_recv": loop.sock_recv,
    }

    async def sendto(sock, data, address):
        datagrams.append(bytes(data))
        return await original["sock_sendto"](sock, data, address)

    async def sendall(sock, data):
        sent.append(bytes(data))
        return await original["sock_sendall"](sock, data)

    async def recvfrom(sock, size):
        data, peer = await original["sock_recvfrom"](sock, size)
        datagrams.append(bytes(data))
        return data, peer

    async def recv(sock, size):
        data = await original["sock_recv"](sock, size)
        read.append(bytes(data))
        return data

    loop.sock_sendto, loop.sock_sendall = sendto, sendall
    loop.sock_recvfrom, loop.sock_recv = recvfrom, recv
    return original


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/encryption_check.*."""
    args = parse_args(__doc__)
    loop = asyncio.get_running_loop()
    datagrams: list[bytes] = []
    sent: list[bytes] = []
    read: list[bytes] = []
    async with Lab(args) as lab:
        report = Report("encryption_check", lab.mode)
        original = install_capture(loop, datagrams, sent, read)
        try:
            first = await lab.open(4)
            second = await lab.open(5)
            await wait_until(lambda: "client05" in first.users(), 10)
            await first.client.send_chat(PUBLIC_MARKER)
            await first.client.send_chat(PRIVATE_MARKER, "client05")
            await wait_until(lambda: len(second.messages()) >= 2, 10)
            source = lab.work / "marker.txt"
            source.write_bytes(FILE_MARKER * 40)
            await first.client.execute(
                UICommand("send_file", {"path": source, "recipient": "client05"})
            )
            await wait_until(lambda: (lab.work / "client05" / "marker.txt").exists(), 20)
            await asyncio.sleep(0.3)
            for session in (first, second):
                await session.close()
        finally:
            for name, function in original.items():
                setattr(loop, name, function)
        keyring = load_keyring(lab.folder / "client04.keys.json")
        password = lab.password

    stream = sent + read
    everything = datagrams + stream
    report.line(f"captured {len(datagrams)} UDP datagrams and {len(stream)} TCP reads/writes")
    absent = True
    for secret in (PUBLIC_MARKER.encode(), PRIVATE_MARKER.encode(), FILE_MARKER, password.encode()):
        found = sum(secret in chunk for chunk in everything)
        absent &= found == 0
        label = "password" if secret == password.encode() else secret.decode()
        report.check(found == 0, f"{label!r} absent from every captured byte")
    enveloped = sum(d[:2] == MAGIC and d[2] == PROTOCOL_VERSION for d in datagrams)
    report.check(
        enveloped == len(datagrams), f"{enveloped} of {len(datagrams)} datagrams are SC v1"
    )

    # Mỗi lần ghi TCP là prefix 4 byte + body; mỗi lần đọc là prefix hoặc (một phần) body.
    bodies = [chunk[4:] for chunk in sent] + [chunk for chunk in read if len(chunk) > 4]
    plaintext = []
    for body in bodies:
        if body[:2] != MAGIC:
            with suppress(ValueError):
                plaintext.append(deserialize_packet(body).kind.value)
    report.line(f"plaintext TCP frames: {plaintext}")
    report.check(
        sorted(set(plaintext)) == ["HELLO", "HELLO_ACK"],
        "only HELLO and HELLO_ACK travel without encryption",
    )

    context = SecurityContext(keyring)
    key_id = next(iter(keyring))
    probe = Packet(MessageType.MSG_PUBLIC, "s" * 43, "client04", "*", "chat", 7, "m" * 32, b"hi")
    wire = context.protect(probe, key_id, 1200)
    accepted = 0
    for bit in range(len(wire) * 8):
        tampered = bytearray(wire)
        tampered[bit // 8] ^= 1 << (bit % 8)
        try:
            context.unprotect(bytes(tampered), 1200)
            accepted += 1
        except (InvalidToken, ValueError):
            pass
    report.check(accepted == 0, f"all {len(wire) * 8} single-bit changes rejected")
    report.data.update(
        datagrams=len(datagrams),
        tcp_chunks=len(stream),
        secrets_absent=absent,
        plaintext_frames=plaintext,
        bit_flips=len(wire) * 8,
        flips_accepted=accepted,
    )
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
