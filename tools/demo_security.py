"""Show packet protection on both UDP hops using temporary in-memory keys."""

import socket
from dataclasses import replace

from config import Settings
from protocol import MessageType, Packet, unpack_envelope
from security import SecurityContext, generate_key

LIMIT = Settings().max_datagram_bytes


def send_hop(label, packet, key_id, sender, receiver):
    wire = sender.protect(packet, key_id, LIMIT)
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx,
    ):
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(2)
        tx.sendto(wire, rx.getsockname())
        received, _ = rx.recvfrom(LIMIT + 1)
    received_id, decoded = receiver.unprotect(received, LIMIT)
    if received != wire or decoded != packet or received_id != key_id:
        raise RuntimeError("Packet round-trip mismatch")
    _, token = unpack_envelope(wire)
    print(f"{label} (key_id={key_id})")
    print(f"  Token preview: {token[:44].decode()}...")
    print(f"  Decrypted text: {decoded.payload.decode()}")
    return wire, decoded


def main():
    k1, k2 = generate_key(), generate_key()
    first, server, second = (
        SecurityContext({1: k1}),
        SecurityContext({1: k1, 2: k2}),
        SecurityContext({2: k2}),
    )
    packet = Packet(
        MessageType.MSG_PRIVATE,
        "session-one",
        "client01",
        "client02",
        "chat",
        0,
        "demo-security",
        b"Chao Khoa",
    )
    print("Original text:", packet.payload.decode())
    wire, decoded = send_hop("client01 -> server", packet, 1, first, server)
    relay = replace(
        decoded,
        session_id="session-two",
        sender="__server__",
        metadata={"origin_user": "client01", "target_user": "client02"},
    )
    send_hop("server -> client02", relay, 2, server, second)


if __name__ == "__main__":
    main()
