"""File transfers, lifecycle cleanup, and SHA-256 verification.

The client supplies ordered, deduplicated packets and reliable-send/UI callbacks.
One file may be active per client, either sending or receiving. Transport owns
ACK/retry; a server ACK does not prove the recipient saved the file."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from config import Settings
from protocol import (
    TERMINAL_FILE_ERROR_CODES,
    MessageType,
    Packet,
    validate_file_metadata,
    validate_file_offer_identity,
    validate_filename,
)

# Receiver ghi đĩa theo khối 64 KiB (256 chunk mặc định) thay vì từng chunk.
WRITE_BLOCK_BYTES = 64 * 1024
logger = logging.getLogger(__name__)


class TransferStatus(StrEnum):
    """COMPLETED requires successful size and hash verification by the receiver."""

    OFFERED = "OFFERED"
    READY = "READY"
    TRANSFERRING = "TRANSFERRING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_STATUSES = {
    TransferStatus.COMPLETED,
    TransferStatus.FAILED,
    TransferStatus.CANCELLED,
}


class TransferPreparationError(ValueError):
    """A safe, machine-readable preparation failure without filesystem paths."""

    def __init__(self, code: str, reason: str) -> None:
        """Lưu mã lỗi ổn định và lời giải thích an toàn để hiển thị trên UI."""
        self.code = code
        super().__init__(f"{code}: {reason}")


@dataclass(frozen=True, slots=True)
class FileOffer:
    """Metadata shared with the peer; never includes the sender's absolute path."""

    transfer_id: str
    sender: str
    recipient: str
    filename: str
    size_bytes: int
    chunk_size: int
    total_chunks: int
    sha256: str

    def chunk_length(self, index: int) -> int:
        """Số byte của chunk hợp lệ; chunk cuối có thể ngắn hơn chunk_size."""
        return min(self.chunk_size, self.size_bytes - index * self.chunk_size)


@dataclass(slots=True)
class FileTransfer:
    """Per-file state; the lock serializes writes, verification, and cleanup."""

    offer: FileOffer
    path: Path
    incoming: bool = False
    status: TransferStatus = TransferStatus.OFFERED
    next_chunk: int = 0
    received_bytes: int = 0
    acknowledged_bytes: int = 0
    updated_at: float = 0.0
    final_result: str | None = None
    ready: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    finished: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    file: BinaryIO | None = field(default=None, repr=False)
    owns_partial: bool = False
    final_emitted: bool = False
    error_code: str | None = None
    pending_sends: int = 0
    drained: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    # Chunk đã nhận đúng thứ tự nhưng chưa ghi đĩa; ghi theo khối để giảm số lần đổi thread.
    write_buffer: bytearray = field(default_factory=bytearray, repr=False)
    # Mốc tạo lượt truyền (OFFER) để log thời gian tới kết quả cuối.
    started_at: float = field(default_factory=time.monotonic)

    @property
    def terminal(self) -> bool:
        """Lượt truyền đã thành công, thất bại hoặc bị hủy."""
        return self.status in TERMINAL_STATUSES


type SendMessage = Callable[[Packet], Awaitable[None]]
type EmitEvent = Callable[[str, dict[str, object]], Awaitable[None]]


def compute_sha256(path: Path) -> str:
    """Tính hash theo từng khối bằng thư viện chuẩn; cần gọi ngoài event loop."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def resolve_receive_path(receive_dir: Path, filename: str) -> Path:
    """Chỉ nhận tên file an toàn, chưa tồn tại và hợp lệ cả trên Windows."""

    validate_filename(filename)
    root = receive_dir.resolve()
    target = root / filename

    if target.is_symlink() or target.exists():
        raise FileExistsError(filename)

    if target.resolve().parent != root:
        raise ValueError("Path is outside the receive directory")

    return target


class FileTransferManager:
    """Một lượt đang gửi/nhận; bản ghi kết thúc được giữ trong lịch sử hữu hạn."""

    def __init__(
        self, settings: Settings, send_message: SendMessage, emit_event: EmitEvent
    ) -> None:
        """Chuẩn bị thư mục nhận, quản lý tác vụ và lịch sử lượt truyền/lỗi có giới hạn."""
        self._settings = settings
        self._send_message = send_message
        self._emit_event = emit_event
        self._root = settings.receive_dir.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._transfers: dict[str, FileTransfer] = {}
        self._active: FileTransfer | None = None
        self._send_task: asyncio.Task | None = None
        self._disk_tasks: set[asyncio.Task] = set()
        self._cleanup_tasks: dict[str, asyncio.Task] = {}
        self._failed_offers: dict[str, tuple[str, str, float]] = {}
        self._preparing = False
        self._closed = False
        self._close_lock = asyncio.Lock()

    def _ensure_open(self) -> None:
        """Kiểm tra trạng thái và báo lỗi nếu bộ quản lý truyền file đã đóng."""
        if self._closed:
            raise ConnectionError("File transfer manager is closed")

    def _reserve_slot(self) -> None:
        """Kiểm tra còn chỗ cho lượt truyền mới trong giới hạn cho phép."""
        self._ensure_open()

        self._prune_history()

        if self._preparing or (
            self._active is not None and (not self._active.terminal or self._busy(self._active))
        ):
            raise TransferPreparationError("capacity", "Another file is being sent or received")

    def _busy(self, transfer: FileTransfer) -> bool:
        """Cho biết lượt truyền còn gói đang gửi hoặc tác vụ cleanup hay không."""
        identifier = transfer.offer.transfer_id

        return bool(
            transfer.pending_sends
            or transfer.lock.locked()
            or (self._active is transfer and self._send_task is not None)
            or identifier in self._cleanup_tasks
        )

    def _prune_history(self) -> None:
        """Bỏ bản ghi kết thúc cũ nhất đã rảnh, giữ nguyên các lượt còn xử lý."""
        retained = sorted(
            [
                (transfer.updated_at, identifier, self._transfers)
                for identifier, transfer in self._transfers.items()
                if transfer.terminal and not self._busy(transfer)
            ]
            + [  # failure[0] - Mã lỗi; failure[1] - Lý do lỗi; failure[2]  - Thời điểm ghi nhận
                (failure[2], identifier, self._failed_offers)
                for identifier, failure in self._failed_offers.items()
            ],
            key=lambda item: item[0],
        )
        for _, identifier, table in retained[: -self._settings.max_transfer_history]:
            table.pop(identifier, None)

    @staticmethod
    def _validate_offer_identity(offer: FileOffer) -> None:
        """Kiểm tra định danh trước khi gửi phản hồi lỗi tới peer."""
        validate_file_offer_identity(offer.transfer_id, offer.sender, offer.recipient)

    def _validate_offer(self, offer: FileOffer) -> None:
        """Kiểm tra tính hợp lệ của thông tin đề nghị truyền file."""
        validate_file_metadata(asdict(offer))

        # Kích thước file phải không âm và không vượt giới hạn cấu hình
        if not 0 <= offer.size_bytes <= self._settings.max_file_bytes:
            raise ValueError("File size is outside the allowed range")

        # Kích thước mỗi chunk phải dương và nằm trong giới hạn đã thống nhất.
        if not 1 <= offer.chunk_size <= self._settings.chunk_size:
            raise ValueError("Chunk size is outside the agreed limits")

    async def _disk(self, operation: Callable, *args):
        """Chạy I/O trong thread; dù bị hủy, vẫn chờ I/O kết thúc trước khi dọn dẹp."""

        # Chạy thao tác đồng bộ trong thread để không chặn event loop.
        task = asyncio.create_task(asyncio.to_thread(operation, *args))

        # Lưu các task I/O.
        self._disk_tasks.add(task)

        try:
            # Ngăn yêu cầu hủy từ tác vụ gọi lan sang task I/O này.
            return await asyncio.shield(task)

        except asyncio.CancelledError:
            # Chờ luồng hoàn tất trước khi dọn dẹp, ngay cả sau nhiều lần hủy.
            while not task.done():
                try:
                    await asyncio.shield(task)

                except asyncio.CancelledError:
                    continue

                except Exception:
                    break

            if not task.cancelled():
                task.exception()
            raise

        finally:
            self._disk_tasks.discard(task)

    async def _send(
        self,
        transfer: FileTransfer,
        kind: MessageType,
        payload: bytes = b"",
        **metadata,
    ) -> None:
        """Gửi một gói file có thời hạn và theo dõi lúc mọi lần gửi đã kết thúc."""
        self._ensure_open()

        offer = transfer.offer

        packet = Packet(
            kind=kind,
            session_id="",  # The client fills the session; transport assigns the sequence.
            sender=offer.recipient if transfer.incoming else offer.sender,
            recipient=offer.sender if transfer.incoming else offer.recipient,
            stream_id="file-" + offer.transfer_id,
            sequence=0,
            message_id=secrets.token_hex(16),
            payload=payload,
            metadata={"transfer_id": offer.transfer_id, **metadata},
        )

        transfer.pending_sends += 1

        # Xóa tín hiệu hoàn tất của đợt trước
        transfer.drained.clear()

        try:
            async with asyncio.timeout(self._settings.transfer_idle_seconds):
                await self._send_message(packet)
        finally:
            transfer.pending_sends -= 1
            if not transfer.pending_sends:
                transfer.drained.set()  # Không còn thao tác gửi nào đang chạy

    async def _progress(self, transfer: FileTransfer) -> None:
        """Phát tiến độ theo số byte đã nhận hoặc số byte gửi đã được ACK."""
        transferred = transfer.received_bytes if transfer.incoming else transfer.acknowledged_bytes
        await self._emit_event(
            "file_progress",
            {
                "transfer_id": transfer.offer.transfer_id,
                "status": transfer.status.value,
                "bytes_transferred": transferred,
                "size_bytes": transfer.offer.size_bytes,
            },
        )

    async def _finished(self, transfer: FileTransfer) -> None:
        """Phát đúng một kết quả cuối cho lượt truyền rồi giới hạn lịch sử lưu lại."""
        if transfer.final_emitted:
            return
        transfer.final_emitted = True
        offer = transfer.offer
        seconds = max(time.monotonic() - transfer.started_at, 1e-9)
        # Dòng log có cấu trúc để tools/collect_metrics.py đọc số liệu đo.
        logger.info(
            "TRANSFER_%s role=%s id=%s file=%s bytes=%d seconds=%.3f mbps=%.3f sha256=%s code=%s "
            "ended=%.3f",
            "DONE" if transfer.status == TransferStatus.COMPLETED else transfer.status.value,
            "receiver" if transfer.incoming else "sender",
            offer.transfer_id,
            offer.filename,
            offer.size_bytes,
            seconds,
            offer.size_bytes / seconds / 1e6,
            offer.sha256.lower(),
            transfer.error_code or "-",
            time.time(),
        )
        await self._emit_event(
            "file_finished",
            {
                "transfer_id": transfer.offer.transfer_id,
                "filename": transfer.offer.filename,
                "status": transfer.status.value,
                "ok": transfer.status == TransferStatus.COMPLETED,
                "error": transfer.final_result or "",
                "code": transfer.error_code,
            },
        )
        self._prune_history()

    async def fail_transfer(self, transfer_id: str, code: str, reason: str) -> bool:
        """Báo lỗi server ngay và giao tác vụ cleanup chờ các gói đã cấp sequence."""
        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            return await self._remember_failed_offer(transfer_id, code, reason)
        if transfer.terminal:
            return False
        transfer.status = TransferStatus.FAILED
        transfer.final_result = reason
        transfer.error_code = code
        transfer.updated_at = time.monotonic()
        transfer.ready.set()
        transfer.finished.set()
        task = asyncio.create_task(self._drain_cleanup(transfer), name="file-failure-cleanup")
        self._cleanup_tasks[transfer_id] = task
        task.add_done_callback(lambda done: self._cleanup_done(transfer_id, done))
        await self._finished(transfer)
        return True

    async def _remember_failed_offer(self, identifier: str, code: str, reason: str) -> bool:
        """Nhớ lỗi tới trước OFFER và chỉ phát thông báo thất bại một lần."""
        if identifier in self._failed_offers:
            return False
        self._failed_offers[identifier] = (code, reason, time.monotonic())
        self._prune_history()
        await self._emit_event(
            "file_finished",
            {
                "transfer_id": identifier,
                "status": "FAILED",
                "ok": False,
                "code": code,
                "error": reason,
            },
        )
        return True

    def _cleanup_done(self, identifier: str, task: asyncio.Task) -> None:
        """Bỏ tác vụ cleanup đã xong và thu gọn các bản ghi lịch sử vừa rảnh."""
        self._cleanup_tasks.pop(identifier, None)
        if not task.cancelled():
            task.exception()
        self._prune_history()

    async def _drain_cleanup(self, transfer: FileTransfer) -> None:
        """Xóa file dở thuộc lượt truyền và chờ gửi xong, không hủy sequence đã cấp."""
        async with transfer.lock:
            await self._disk(self._discard_partial, transfer)
        if transfer.pending_sends:
            await transfer.drained.wait()
        sender = self._send_task if self._active is transfer else None
        if sender is not None and sender is not asyncio.current_task():
            await asyncio.gather(sender, return_exceptions=True)

    @staticmethod
    def _discard_partial(transfer: FileTransfer) -> None:
        """Đóng file và chỉ xóa file dở do chính lượt truyền này tạo."""
        if transfer.file is not None:
            transfer.file.close()
            transfer.file = None
        if transfer.owns_partial:
            transfer.owns_partial = False
            try:
                transfer.path.unlink(missing_ok=True)
            except OSError as error:
                # Lỗi khi dọn file dở không được chặn FILE_RESULT gửi về bên gửi.
                logger.warning(
                    "PARTIAL_NOT_REMOVED file=%s reason=%s",
                    transfer.path.name,
                    type(error).__name__,
                )

    async def _terminate(self, transfer: FileTransfer, status: TransferStatus, reason: str) -> bool:
        """Đặt trạng thái cuối, xóa dữ liệu dở, chờ bên gửi dừng và báo kết quả một lần."""
        async with transfer.lock:
            if transfer.terminal:
                return False
            transfer.status = status
            transfer.final_result = reason
            transfer.updated_at = time.monotonic()
            transfer.ready.set()
            transfer.finished.set()
            task = self._send_task if self._active is transfer else None
            # Let the bounded in-flight batch finish: cancelling a reliable send after
            # sequence allocation would leave a gap and invalidate the entire session.
            await self._disk(self._discard_partial, transfer)
        if task is not None and task is not asyncio.current_task():
            await asyncio.gather(task, return_exceptions=True)
        if not self._closed:
            await self._finished(transfer)
        return True

    async def offer_file(self, path: Path, sender: str, recipient: str) -> FileOffer:
        """Tính mã băm trước khi gửi OFFER; giữ chỗ trước để giới hạn số yêu cầu đồng thời."""

        self._reserve_slot()

        self._preparing = True  # Giữ lượt trước khi await tính hash.

        try:
            path = path.resolve(strict=True)
            if not path.is_file():
                raise ValueError("Source must be a regular file")

            size = path.stat().st_size

            if size > self._settings.max_file_bytes:
                raise ValueError("File exceeds the size limit")

            digest = await self._disk(compute_sha256, path)
            self._ensure_open()
            chunk_size = self._settings.chunk_size

            offer = FileOffer(
                secrets.token_hex(16),
                sender,
                recipient,
                path.name,
                size,
                chunk_size,
                (size + chunk_size - 1) // chunk_size,
                digest,
            )

            self._validate_offer(offer)

            # Tệp nguồn có thể nằm trong receive_dir; không kiểm tra trùng tên tệp đích tại đây.
            transfer = FileTransfer(offer, path, updated_at=time.monotonic())
            self._transfers[offer.transfer_id] = transfer
            self._active = transfer

        finally:
            self._preparing = False
        try:
            await self._send(transfer, MessageType.FILE_OFFER, **asdict(offer))

        except BaseException:
            self._transfers.pop(offer.transfer_id, None)
            if self._active is transfer:
                self._active = None
            raise

        return offer

    def _prepare_receive(self, transfer: FileTransfer) -> None:
        """Tạo .part độc quyền trước khi báo bên nhận đã sẵn sàng tự động."""
        resolve_receive_path(self._root, transfer.offer.filename)
        partial = resolve_receive_path(self._root, transfer.offer.filename + ".part")
        # Open exclusively and retain the handle instead of reopening for each chunk.
        transfer.file = partial.open("x+b")
        transfer.path = partial
        transfer.owns_partial = True
        transfer.status = TransferStatus.READY
        transfer.updated_at = time.monotonic()

    async def send_chunks(self, transfer_id: str) -> None:
        """Đợi bên nhận sẵn sàng, gửi dữ liệu rồi chờ kết quả kiểm tra file."""
        # 1. Chỉ cho phép một tác vụ gửi file đang hoạt động.
        self._ensure_open()
        transfer = self._transfers[transfer_id]

        if transfer.incoming:
            raise ValueError("Only an outgoing file can be sent")
        if transfer.terminal:
            return
        if self._send_task is not None:
            raise ValueError("Transfer is already running")

        self._send_task = asyncio.current_task()
        try:
            # 2. Chờ FILE_READY, có giới hạn thời gian.
            async with asyncio.timeout(self._settings.transfer_idle_seconds):
                await transfer.ready.wait()

            # Lượt truyền có thể bị hủy hoặc thất bại trong lúc chờ.
            if transfer.terminal:
                return
            if transfer.status != TransferStatus.READY:
                reason = transfer.final_result or "Receiver is not ready to receive the file"
                raise ConnectionError(reason)

            # 3. Gửi các chunk và cập nhật tiến độ sau mỗi nhóm.
            transfer.status = TransferStatus.TRANSFERRING
            await self._send_file_data(transfer)
            if transfer.terminal:
                return

            # 4. Báo đã gửi hết dữ liệu, rồi chờ FILE_RESULT từ bên nhận.
            transfer.status = TransferStatus.VERIFYING
            await self._progress(transfer)
            if transfer.terminal:
                return

            await self._send(transfer, MessageType.FILE_END)
            async with asyncio.timeout(self._settings.transfer_idle_seconds):
                await transfer.finished.wait()

        except asyncio.CancelledError:
            # Dọn lượt truyền rồi chuyển tiếp tín hiệu hủy cho hàm gọi.
            await self._terminate(transfer, TransferStatus.CANCELLED, "Send task was cancelled")
            raise
        except Exception:
            await self._terminate(
                transfer, TransferStatus.FAILED, "File transfer failed or timed out"
            )
            raise
        finally:
            # Luôn giải phóng tác vụ gửi và dọn bớt lịch sử đã kết thúc.
            self._send_task = None
            self._prune_history()

    async def _send_file_data(self, transfer: FileTransfer) -> None:
        """Gửi chunk theo cửa sổ trượt, chờ ACK và kiểm tra file nguồn vẫn khớp OFFER.

        Tối đa window_packets chunk chưa ACK cùng lúc. Mỗi ACK trả một chỗ trong cửa
        sổ để chunk kế tiếp đi ngay, không chờ cả nhóm như stop-and-wait theo lô.
        Transport vẫn neo cửa sổ của stream tại sequence nhỏ nhất chưa ACK."""
        offer = transfer.offer
        window = asyncio.Semaphore(self._settings.window_packets)
        progress_every = self._settings.window_packets
        file_hash = hashlib.sha256()
        acknowledged = [0, 0]  # [số chunk, số byte] đã được chặng hiện tại ACK.

        async def send_chunk(chunk_index: int, chunk_data: bytes) -> None:
            """Gửi một chunk; khi có ACK thì trả chỗ trong cửa sổ và cập nhật tiến độ."""
            try:
                await self._send(
                    transfer, MessageType.FILE_DATA, chunk_data, chunk_index=chunk_index
                )
            finally:
                window.release()
            acknowledged[0] += 1
            acknowledged[1] += len(chunk_data)
            transfer.acknowledged_bytes = acknowledged[1]
            transfer.updated_at = time.monotonic()
            last = acknowledged[0] == offer.total_chunks
            if not transfer.terminal and (acknowledged[0] % progress_every == 0 or last):
                await self._progress(transfer)

        # Đọc đĩa theo khối lớn trong thread rồi cắt chunk trong bộ nhớ: tránh một lần
        # chuyển thread cho mỗi chunk 256 byte.
        read_block = offer.chunk_size * 256
        buffer = memoryview(b"")
        with transfer.path.open("rb") as source:
            async with asyncio.TaskGroup() as group:
                for chunk_index in range(offer.total_chunks):
                    await window.acquire()
                    if transfer.terminal:
                        # Hủy: không cấp sequence mới; các chunk đã có sequence chạy nốt.
                        window.release()
                        break
                    if len(buffer) < offer.chunk_size:
                        block = await self._disk(source.read, read_block)
                        buffer = memoryview(bytes(buffer) + block)
                    expected_size = offer.chunk_length(chunk_index)
                    chunk_data = bytes(buffer[:expected_size])
                    buffer = buffer[expected_size:]
                    if len(chunk_data) != expected_size:
                        raise ValueError("Source file size changed")

                    file_hash.update(chunk_data)
                    # Task tạo theo thứ tự chunk và bước đầu của nó cấp sequence ngay,
                    # nên sequence của stream tăng đúng theo chunk_index.
                    group.create_task(send_chunk(chunk_index, chunk_data))

            # TaskGroup đã chờ mọi chunk đang bay nhận ACK (hoặc lỗi cả nhóm).
            if transfer.terminal:
                return

            # Còn byte chưa đọc nghĩa là file đã dài hơn kích thước trong OFFER.
            extra_byte = bytes(buffer[:1]) or await self._disk(source.read, 1)
            if extra_byte:
                raise ValueError("Source file changed after OFFER")

            # Kích thước đúng nhưng nội dung vẫn có thể đã thay đổi.
            if file_hash.hexdigest() != offer.sha256.lower():
                raise ValueError("Source file changed after OFFER")

    def _packet_transfer(self, packet: Packet) -> FileTransfer:
        """Tìm lượt truyền và kiểm tra gói thuộc đúng hai bên tham gia."""
        # 1. Lấy mã lượt truyền từ gói tin.
        transfer_id = packet.metadata.get("transfer_id")
        if not isinstance(transfer_id, str):
            raise ValueError("Missing transfer_id")

        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            raise ValueError("Transfer was not found")

        # 2. Xác định chiều của gói tin nhận được.
        offer = transfer.offer
        if transfer.incoming:
            # Mình nhận file: gói đi từ người gửi file tới người nhận file.
            expected_sender = offer.sender
            expected_recipient = offer.recipient
        else:
            # Mình gửi file: phản hồi đi từ người nhận file về người gửi file.
            expected_sender = offer.recipient
            expected_recipient = offer.sender

        # 3. Từ chối gói có người gửi hoặc người nhận không khớp.
        if packet.sender != expected_sender or packet.recipient != expected_recipient:
            raise PermissionError("Packet does not belong to the transfer participants")

        return transfer

    async def handle_packet(self, packet: Packet) -> None:
        """Xử lý gói file sau khi client đã xác thực và chuẩn hóa origin_user thành sender."""
        self._ensure_open()
        if packet.kind == MessageType.FILE_OFFER:
            await self._receive_offer(packet)
            return
        transfer = self._packet_transfer(packet)
        if (
            transfer.status == TransferStatus.FAILED
            and transfer.error_code in TERMINAL_FILE_ERROR_CODES
        ):
            return
        if packet.kind in {
            MessageType.FILE_READY,
            MessageType.FILE_RESULT,
        }:
            await self._receive_response(transfer, packet)
        elif packet.kind == MessageType.FILE_DATA:
            await self._receive_chunk(transfer, packet)
        elif packet.kind == MessageType.FILE_END:
            if not transfer.incoming:
                raise ValueError("END can only be sent to the receiver")
            await self._finish_receive(transfer)
        elif packet.kind == MessageType.CANCEL:
            reason = packet.metadata.get("reason")
            if not isinstance(reason, str) or not reason:
                reason = "Peer cancelled the file transfer"
            await self._terminate(transfer, TransferStatus.CANCELLED, reason)
        else:
            raise ValueError("Message is not part of the file protocol")

    async def _receive_offer(self, packet: Packet) -> None:
        """Đọc OFFER, kiểm tra lượt truyền, chuẩn bị file nhận và báo FILE_READY."""
        # 1. Đọc từng thông tin bắt buộc từ metadata của gói OFFER.
        try:
            metadata = packet.metadata
            offer = FileOffer(
                transfer_id=metadata["transfer_id"],
                sender=metadata["sender"],
                recipient=metadata["recipient"],
                filename=metadata["filename"],
                size_bytes=metadata["size_bytes"],
                chunk_size=metadata["chunk_size"],
                total_chunks=metadata["total_chunks"],
                sha256=metadata["sha256"],
            )
        except (KeyError, TypeError) as error:
            raise ValueError("FILE_OFFER is missing valid metadata") from error

        # 2. Kiểm tra người gửi và người nhận trước khi tạo file hoặc phản hồi.
        self._validate_offer_identity(offer)
        if packet.sender != offer.sender or packet.recipient != offer.recipient:
            raise PermissionError("OFFER identity does not match the header")

        # 3. OFFER lặp hợp lệ thì bỏ qua; cùng ID nhưng khác lượt thì báo lỗi.
        existing = self._transfers.get(offer.transfer_id)
        if existing is not None:
            if not existing.incoming:
                raise ValueError("transfer_id conflicts with an outgoing file")
            if existing.offer != offer:
                raise ValueError("Repeated OFFER has different metadata")
            return

        transfer = FileTransfer(
            offer=offer,
            path=self._root,
            incoming=True,
            updated_at=time.monotonic(),
        )

        # 4. Lỗi từ server có thể đến trước OFFER. Khi đó chỉ ghi nhận thất bại.
        previous_failure = self._failed_offers.pop(offer.transfer_id, None)
        if previous_failure is not None:
            error_code, reason, failed_at = previous_failure
            transfer.error_code = error_code
            transfer.final_result = reason
            transfer.updated_at = failed_at
            transfer.status = TransferStatus.FAILED
            transfer.final_emitted = True  # Lỗi đã được thông báo trước khi OFFER đến.
            self._transfers[offer.transfer_id] = transfer

            event_data = asdict(offer)
            event_data["status"] = "FAILED"
            event_data["error"] = reason
            event_data["code"] = error_code
            await self._emit_event("file_offer", event_data)
            return

        # 5. Kiểm tra thông tin file, chỗ nhận và tạo file .part trước khi báo READY.
        try:
            self._validate_offer(offer)
            self._reserve_slot()
            self._prepare_receive(transfer)
        except (OSError, ValueError) as error:
            # Chuẩn bị thất bại: báo UI và hủy, không gửi đường dẫn máy mình cho bên kia.
            transfer.status = TransferStatus.FAILED
            error_code, reason = self._preparation_error(error)
            transfer.error_code = error_code
            transfer.final_result = reason
            await self._finished(transfer)
            await self._send(transfer, MessageType.CANCEL, reason=transfer.final_result)
            return

        # 6. Ghi nhận lượt đang nhận, cập nhật UI rồi báo bên gửi có thể gửi DATA.
        self._transfers[offer.transfer_id] = transfer
        self._active = transfer
        try:
            await self._emit_event("file_offer", asdict(offer))
            await self._progress(transfer)
            await self._send(transfer, MessageType.FILE_READY)
        except asyncio.CancelledError:
            # Tác vụ bị hủy: dọn file dở rồi truyền tiếp tín hiệu hủy lên hàm gọi.
            await self._terminate(
                transfer, TransferStatus.CANCELLED, "Receive operation was cancelled"
            )
            raise
        except Exception:
            # Cập nhật UI hoặc gửi READY thất bại thì cũng phải dọn file dở.
            await self._terminate(
                transfer, TransferStatus.FAILED, "Could not signal receiver readiness"
            )
            raise

    @staticmethod
    def _preparation_error(failure: Exception) -> tuple[str, str]:
        """Đổi lỗi chuẩn bị nhận thành mã ổn định và lời giải thích an toàn cho người dùng."""
        if isinstance(failure, TransferPreparationError):
            return failure.code, str(failure)
        if isinstance(failure, FileExistsError):
            return "filename_exists", "filename_exists: The file or partial file already exists"
        if isinstance(failure, OSError):
            return "open_failed", "open_failed: Could not open the partial file for receiving"
        return (
            "invalid_offer",
            "invalid_offer: File metadata is invalid or exceeds configured limits",
        )

    async def _receive_response(self, transfer: FileTransfer, packet: Packet) -> None:
        """Bên gửi xử lý FILE_READY hoặc FILE_RESULT do bên nhận gửi về."""
        # Chỉ lượt gửi file mới được nhận hai loại phản hồi này.
        if transfer.incoming:
            raise ValueError("This response is only valid for the sender")

        # Lượt đã kết thúc thì không thay đổi trạng thái theo phản hồi đến muộn.
        if transfer.terminal:
            return

        if packet.kind == MessageType.FILE_READY:
            # Chỉ READY đầu tiên mới cho phép chuyển từ chờ sang gửi DATA.
            if transfer.status != TransferStatus.OFFERED:
                return

            transfer.status = TransferStatus.READY
            transfer.updated_at = time.monotonic()
            transfer.ready.set()  # Đánh thức send_chunks() đang chờ bên nhận sẵn sàng.
            return

        # handle_packet() chỉ đưa FILE_READY và FILE_RESULT vào hàm này.
        await self._receive_result(transfer, packet)

    async def _receive_result(self, transfer: FileTransfer, packet: Packet) -> None:
        """Kiểm tra kết quả từ bên nhận và thông báo kết quả cuối của lượt gửi."""
        # 1. Kết quả phải là True/False và chỉ được chấp nhận khi đang chờ xác minh.
        succeeded = packet.metadata.get("ok")
        if type(succeeded) is not bool:
            raise ValueError("FILE_RESULT.ok must be a boolean")
        if transfer.status != TransferStatus.VERIFYING:
            raise ValueError("RESULT arrived before the sender sent END")

        # 2. Thành công thì hash phải khớp OFFER; thất bại thì lưu lý do bên nhận báo.
        if succeeded:
            received_hash = str(packet.metadata.get("sha256")).lower()
            expected_hash = transfer.offer.sha256.lower()
            if received_hash != expected_hash:
                raise ValueError("RESULT hash does not match OFFER")

            transfer.status = TransferStatus.COMPLETED
            transfer.final_result = ""
        else:
            transfer.status = TransferStatus.FAILED
            transfer.final_result = packet.metadata.get(
                "error", "Receiver failed to verify the file"
            )

        # 3. Đánh thức tác vụ đang chờ kết quả và thông báo cho UI.
        transfer.updated_at = time.monotonic()
        transfer.finished.set()
        await self._finished(transfer)

    async def _receive_chunk(self, transfer: FileTransfer, packet: Packet) -> None:
        """Kiểm tra chunk rồi ghi tiếp vào file .part theo thứ tự transport đã giao."""
        if not transfer.incoming:
            raise ValueError("DATA can only be sent to the receiver")

        # Giữ khóa để việc ghi chunk không chạy cùng lúc với kiểm tra END hoặc dọn file.
        async with transfer.lock:
            if transfer.status not in {TransferStatus.READY, TransferStatus.TRANSFERRING}:
                raise ValueError("Transfer is not READY or has already ended")

            # 1-2. Chỉ số và độ dài chunk phải khớp OFFER và đúng chunk đang chờ.
            offer = transfer.offer
            chunk_index, chunk_data = self._checked_chunk(transfer, packet)

            # 3. Gom chunk trong bộ nhớ; ghi đĩa trong thread mỗi WRITE_BLOCK_BYTES và ở
            #    chunk cuối, để luồng nhận theo kịp cửa sổ gửi mà không chặn event loop.
            transfer.write_buffer += chunk_data
            last_chunk = chunk_index == offer.total_chunks - 1
            flushed = last_chunk or len(transfer.write_buffer) >= WRITE_BLOCK_BYTES
            if flushed:
                block = bytes(transfer.write_buffer)
                transfer.write_buffer.clear()
                await self._disk(self._write_chunk, transfer, block)

            # Lỗi từ server có thể kết thúc lượt trong lúc chờ ghi file.
            if transfer.terminal:
                return

            # 4. Chỉ cập nhật tiến độ khi ghi thành công và lượt vẫn đang hoạt động.
            transfer.next_chunk += 1
            transfer.received_bytes += len(chunk_data)
            transfer.status = TransferStatus.TRANSFERRING
            transfer.updated_at = time.monotonic()

        # Đã nhả khóa file trước khi chờ cập nhật UI; báo tiến độ theo khối đã ghi.
        if flushed:
            await self._progress(transfer)

    @staticmethod
    def _checked_chunk(transfer: FileTransfer, packet: Packet) -> tuple[int, bytes]:
        """Trả (chunk_index, dữ liệu) nếu đúng chunk kế tiếp và đúng độ dài trong OFFER."""
        offer = transfer.offer
        # 1. Chỉ số phải là số nguyên, nằm trong file và đúng chunk đang chờ.
        chunk_index = packet.metadata.get("chunk_index")
        if type(chunk_index) is not int:
            raise ValueError("Invalid chunk_index")
        if chunk_index < 0 or chunk_index >= offer.total_chunks:
            raise ValueError("Invalid chunk_index")
        if chunk_index != transfer.next_chunk:
            raise ValueError("Chunk is not the next ordered chunk")

        # 2. Payload phải là bytes và đủ độ dài; chunk cuối có thể ngắn hơn.
        chunk_data = packet.payload
        if not isinstance(chunk_data, bytes) or len(chunk_data) != offer.chunk_length(chunk_index):
            raise ValueError("Chunk length does not match OFFER")
        return chunk_index, chunk_data

    @staticmethod
    def _write_chunk(transfer: FileTransfer, data: bytes) -> None:
        """Ghi một khối chunk liên tiếp vào file .part đang mở rồi flush bộ đệm."""
        partial_file = transfer.file
        partial_file.write(data)
        partial_file.flush()

    def _verify_and_publish(self, transfer: FileTransfer) -> None:
        """Kiểm tra file .part rồi tạo tên file hoàn chỉnh bằng hard link, không ghi đè."""
        # 1. Flush dữ liệu đã ghi và quay về đầu file để đọc kiểm tra.
        partial_file = transfer.file
        partial_file.flush()
        partial_file.seek(0)

        # 2. File nhận được phải có đúng kích thước và SHA-256 trong OFFER.
        opened_file_info = os.fstat(partial_file.fileno())
        if opened_file_info.st_size != transfer.offer.size_bytes:
            raise ValueError("Received file size does not match")

        actual_hash = hashlib.file_digest(partial_file, "sha256").hexdigest()
        expected_hash = transfer.offer.sha256.lower()
        if actual_hash != expected_hash:
            raise ValueError("Received file SHA-256 does not match")

        # 3. Đường dẫn .part phải vẫn trỏ tới chính file đang mở, chưa bị thay thế.
        if transfer.path.is_symlink():
            raise ValueError("The .part path was replaced")
        path_file_info = transfer.path.stat()
        if not os.path.samestat(opened_file_info, path_file_info):
            raise ValueError("The .part path was replaced")

        # 4. Kiểm tra tên file đích và lượt truyền trước khi lưu kết quả cuối.
        final_path = resolve_receive_path(self._root, transfer.offer.filename)
        if transfer.terminal:
            raise ValueError("Receive transfer ended before the file was saved")

        partial_file.close()
        transfer.file = None

        # 5. Hard link tạo tên chính thức cho cùng dữ liệu, không sao chép nội dung.
        # Nếu tên đích đã tồn tại hoặc hệ thống không hỗ trợ hard link thì báo lỗi.
        os.link(transfer.path, final_path)
        partial_path, transfer.path = transfer.path, final_path
        transfer.owns_partial = False
        try:
            partial_path.unlink()
        except OSError as error:
            # File đích đã đủ và đúng SHA-256; tên .part còn sót chỉ được ghi cảnh báo.
            logger.warning(
                "PARTIAL_NOT_REMOVED file=%s reason=%s", partial_path.name, type(error).__name__
            )

    async def _finish_receive(self, transfer: FileTransfer) -> None:
        """Nhận END, kiểm tra file rồi gửi FILE_RESULT; END lặp nhận lại kết quả đã lưu."""
        verification_error = None

        # 1. Khóa file trong lúc kiểm tra và hoàn tất lượt nhận.
        async with transfer.lock:
            # Lượt đã kết thúc thì bỏ qua kiểm tra file, nhưng vẫn trả kết quả bên dưới.
            if not transfer.terminal:
                if transfer.status not in {TransferStatus.READY, TransferStatus.TRANSFERRING}:
                    raise ValueError("Receiver is not ready to receive the file")
                if transfer.next_chunk != transfer.offer.total_chunks:
                    raise ValueError("END arrived while chunks are still missing")

                # 2. Báo UI đang xác minh, sau đó kiểm tra và lưu file hoàn chỉnh.
                transfer.status = TransferStatus.VERIFYING
                try:
                    await self._progress(transfer)

                    # Trong lúc chờ UI, lượt có thể đã nhận thông báo lỗi từ server.
                    if not transfer.terminal:
                        await self._disk(self._verify_and_publish, transfer)
                except (OSError, ValueError) as failure:
                    # Ghi nhận lỗi và xóa file dở; vẫn gửi kết quả thất bại phía dưới.
                    verification_error = failure
                    self._record_verify_failure(transfer, failure)
                    await self._disk(self._discard_partial, transfer)
                else:
                    # Không ghi đè trạng thái lỗi/hủy xuất hiện trong lúc chờ kiểm tra.
                    if not transfer.terminal:
                        transfer.status = TransferStatus.COMPLETED
                        transfer.final_result = ""

                transfer.updated_at = time.monotonic()
                transfer.finished.set()

        # 3. Đã nhả khóa file: gửi hash nếu thành công, hoặc lý do nếu thất bại/hủy.
        if transfer.status == TransferStatus.COMPLETED:
            await self._send(
                transfer,
                MessageType.FILE_RESULT,
                ok=True,
                sha256=transfer.offer.sha256,
            )
        else:
            await self._send(
                transfer,
                MessageType.FILE_RESULT,
                ok=False,
                error=transfer.final_result,
            )

        # 4. Thông báo kết quả cuối cho UI trước khi chuyển lỗi lên hàm gọi.
        await self._finished(transfer)
        if verification_error is not None:
            raise verification_error

    def _record_verify_failure(self, transfer: FileTransfer, failure: Exception) -> None:
        """Lưu lỗi kiểm tra an toàn nhưng không ghi đè trạng thái cuối đã có."""
        if transfer.terminal:
            return
        transfer.status = TransferStatus.FAILED
        if isinstance(failure, FileExistsError):
            transfer.error_code, transfer.final_result = self._preparation_error(failure)
        else:
            transfer.error_code = "verification_failed"
            transfer.final_result = (
                "verification_failed: Size or hash mismatch, or file could not be saved"
            )

    async def cancel(self, transfer_id: str, reason: str) -> None:
        """Dừng gửi và chỉ xóa file dở thuộc lượt truyền; giữ file nguồn và file hoàn tất."""
        self._ensure_open()
        transfer = self._transfers.get(transfer_id)
        if transfer is not None and await self._terminate(
            transfer, TransferStatus.CANCELLED, reason
        ):
            await self._send(transfer, MessageType.CANCEL, reason=reason)

    async def expire_idle(self, now: float) -> None:
        """Dùng đồng hồ đơn điệu; gói trùng không kéo dài thời gian lưu kết quả cuối."""
        self._ensure_open()
        for identifier, failure in list(self._failed_offers.items()):
            if now - failure[2] >= self._settings.completed_retention_seconds:
                self._failed_offers.pop(identifier, None)
        for transfer_id, transfer in list(self._transfers.items()):
            age = now - transfer.updated_at
            if transfer.terminal:
                if age >= self._settings.completed_retention_seconds and not self._busy(transfer):
                    self._transfers.pop(transfer_id, None)
            elif age >= self._settings.transfer_idle_seconds:
                await self.cancel(transfer_id, "Transfer made no progress before the deadline")

    async def close(self) -> None:
        """Đóng không gửi mạng; chờ tác vụ và thao tác đĩa rồi dọn file dở."""
        async with self._close_lock:
            self._closed = True
            current = asyncio.current_task()
            sender = self._send_task
            if sender is not None and sender is not current:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
            await asyncio.gather(*self._cleanup_tasks.values(), return_exceptions=True)
            await asyncio.gather(*self._disk_tasks, return_exceptions=True)
            for transfer in self._transfers.values():
                async with transfer.lock:
                    await self._disk(self._discard_partial, transfer)
            self._transfers.clear()
            self._active = None
            self._send_task = None
            self._cleanup_tasks.clear()
            self._failed_offers.clear()
