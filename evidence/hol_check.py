"""S5b: chat on the same path is not held back while a file chunk is missing.

Run on machine B while the server runs on machine A:
    python evidence/hol_check.py --server <IP of A>
client04 sends a 2 MiB file to client05 through the server, and a private message to
client05 every 100 ms on the same UDP association. client04 does not send chunk 300 the
first time (one deliberate gap), so the file stream waits for the retry while chat goes on.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import statistics
import sys
import time

from _common import Lab, Report, parse_args, quiet_logs, wait_until

from client import ClientApp, UICommand
from protocol import MessageType

FILE_BYTES = 2 * 1024 * 1024
SKIPPED_CHUNK = 300


class SkipOneChunk(ClientApp):
    """Không gửi lần đầu của chunk SKIPPED_CHUNK; ghi thời điểm bỏ và lúc gửi lại."""

    skipped_at: float | None = None
    resent_at: float | None = None
    file_sends = 0

    async def send_datagram(self, packet, peer):
        """Đếm lần gửi FILE_DATA và bỏ đúng một lần gửi đầu tiên của chunk đã chọn."""
        if packet.kind == MessageType.FILE_DATA:
            self.file_sends += 1
            if packet.metadata.get("chunk_index") == SKIPPED_CHUNK:
                if self.skipped_at is None:
                    self.skipped_at = time.perf_counter()
                    return
                if self.resent_at is None:
                    self.resent_at = time.perf_counter()
        await super().send_datagram(packet, peer)


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/hol_check.*."""
    args = parse_args(__doc__)
    async with Lab(args) as lab:
        report = Report("hol_check", lab.mode)
        sender = await lab.open(4, cls=SkipOneChunk)
        receiver = await lab.open(5)
        await wait_until(lambda: "client05" in sender.users(), 10)
        client = sender.client
        sent_at: dict[str, float] = {}

        async def send_private(text: str) -> None:
            """Gửi tin riêng và ghi thời điểm gửi theo message_id."""
            start = time.perf_counter()
            message_id = await client.send_chat(text, "client05")
            sent_at[message_id] = start

        for index in range(20):
            await send_private(f"idle {index}")
            await asyncio.sleep(0.05)
        await wait_until(lambda: len(receiver.messages()) >= 20, 10)

        source = lab.work / "hol.bin"
        payload = os.urandom(FILE_BYTES)
        source.write_bytes(payload)
        file_started = time.time()
        result = await client.execute(
            UICommand("send_file", {"path": source, "recipient": "client05"})
        )
        transfer_id = result["transfer_id"]

        def status() -> str:
            """Trạng thái lượt truyền ở bên gửi."""
            for item in client.snapshot()["transfers"]:
                if item.get("transfer_id") == transfer_id:
                    return item.get("status", "")
            return ""

        index = 0
        while status() not in {"COMPLETED", "FAILED", "CANCELLED"}:
            await send_private(f"during {index}")
            index += 1
            await asyncio.sleep(0.1)
        file_finished = time.time()
        await wait_until(lambda: len(receiver.messages()) >= 20 + index, 10)

        received = {data["message_id"]: at for at, data in receiver.messages()}
        latency = {mid: (received[mid] - sent_at[mid]) * 1000 for mid in sent_at}
        idle = [latency[mid] for mid in list(sent_at)[:20]]
        during = [latency[mid] for mid in list(sent_at)[20:]]
        gap_start, gap_end = client.skipped_at, client.resent_at
        in_gap = [latency[mid] for mid, at in sent_at.items() if gap_start <= at <= gap_end]
        saved = lab.work / "client05" / "hol.bin"
        same = saved.exists() and hashlib.sha256(saved.read_bytes()).hexdigest() == (
            hashlib.sha256(payload).hexdigest()
        )
        chunks = FILE_BYTES // client.settings.chunk_size
        gap_ms = (gap_end - gap_start) * 1000
        report.data.update(
            gap_ms=round(gap_ms),
            idle_median_ms=round(statistics.median(idle), 1),
            idle_max_ms=round(max(idle), 1),
            during_messages=len(during),
            during_median_ms=round(statistics.median(during), 1),
            during_max_ms=round(max(during), 1),
            gap_messages=len(in_gap),
            gap_min_ms=round(min(in_gap), 1) if in_gap else None,
            gap_max_ms=round(max(in_gap), 1) if in_gap else None,
            file_sends=client.file_sends,
            chunks=chunks,
            sha256_equal=same,
            file_started_epoch=round(file_started, 4),
            file_finished_epoch=round(file_finished, 4),
        )
        report.line(f"chunk {SKIPPED_CHUNK} missing for {gap_ms:.0f} ms")
        report.line(
            f"idle chat latency: median {statistics.median(idle):.1f} ms, max {max(idle):.1f} ms"
        )
        report.line(
            f"during the transfer: {len(during)} messages, median "
            f"{statistics.median(during):.1f} ms, max {max(during):.1f} ms"
        )
        if in_gap:
            report.line(
                f"while the chunk was missing: {len(in_gap)} messages, "
                f"{min(in_gap):.1f} to {max(in_gap):.1f} ms"
            )
        report.line(
            f"FILE_DATA datagrams sent by client04: {client.file_sends} for {chunks} chunks"
        )
        report.check(status() == "COMPLETED" and same, "transfer completed, SHA-256 equal")
        report.check(client.file_sends == chunks + 1, "only the skipped chunk was sent twice")
        report.check(bool(in_gap) and max(in_gap) < gap_ms, "chat not held back during the gap")
        for session in (sender, receiver):
            await session.close()
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
