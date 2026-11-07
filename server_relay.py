"""Quản lý chuyển tiếp file ở server, không ghép hoặc lưu nội dung file.

Luồng chính: reserve() giữ chỗ trước ACK -> relay() xếp gói gửi đi -> release()
trả chỗ đầu vào. Worker gửi giữ chỗ tới khi có ACK, gặp lỗi hoặc gói bị loại bỏ.
Các bước giữ chỗ và đổi trạng thái chạy đồng bộ trên event loop của server.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from config import Settings
from files import FileOffer
from protocol import Address, MessageType, Packet, protected_packet_size, serialize_packet
from security import SecurityContext
from transport import PacketKey, ReliableChannel

if TYPE_CHECKING:
    from server import Session, UserRegistry


def _offer_from_packet(packet: Packet) -> FileOffer:
    """Chỉ lấy các trường của OFFER, bỏ qua metadata bổ sung của gói relay."""
    return FileOffer(**{name: packet.metadata[name] for name in FileOffer.__dataclass_fields__})


def _packet_key(packet: Packet, peer: Address) -> PacketKey:
    """Dùng cùng một khóa khi giữ, chuyển tiếp và trả chỗ cho gói đầu vào."""
    return peer, packet.session_id, packet.stream_id, packet.sequence


@dataclass(slots=True)
class RelayTransfer:
    """Server chỉ giữ metadata và trạng thái, không ghép/ghi toàn bộ file."""

    offer: FileOffer
    owner_id: str
    recipient_id: str
    updated_at: float
    phase: str = "OFFERED"
    end_seen: bool = False
    highest_chunk: int = -1
    terminal_at: float | None = None
    cached_reply: Packet | None = None
    reservations: int = 0
    failure_code: str = ""
    failure_reason: str = ""
    notified: set[str] = field(default_factory=set)
    retired: bool = False

    @property
    def terminal(self) -> bool:
        """Cho biết lượt truyền đã đi đến trạng thái cuối hay chưa."""
        return self.terminal_at is not None


class FileCapacityFull(Exception):
    """No room to remember another stream safely; leave it unacknowledged."""


class FileBusinessError(Exception):
    def __init__(self, code: str, reason: str) -> None:
        """Gắn mã lỗi ổn định với lỗi kết thúc lượt truyền."""
        super().__init__(reason)
        self.code = code


class RelayPacketTooLarge(ValueError):
    """The validated forwarded packet cannot fit one downstream datagram."""

    code = "RELAY_TOO_LARGE"


@dataclass(slots=True)
class SendReservation:
    destination: Session
    transfer: RelayTransfer | None = None
    released: bool = False


@dataclass(slots=True)
class ForwardItem:
    packet: Packet
    reservation: SendReservation
    source_id: str | None = None


@dataclass(slots=True)
class FileIngress:
    transfer: RelayTransfer
    reservation: SendReservation | None


class OutboundQuota:
    """Giới hạn chung cho chat/file, gồm cả gói xếp hàng và gói đang chờ ACK.

    Mỗi chỗ thuộc đúng phiên đăng nhập của đích và chỉ được trả một lần.
    """

    def __init__(self, settings: Settings, users: UserRegistry, security: SecurityContext) -> None:
        """Dùng registry và bộ mã hóa chung để giới hạn gói đang gửi tới các phiên."""
        self._settings = settings
        self._users = users
        self._security = security

    def reserve(
        self,
        destination: Session,
        *,
        transfer: RelayTransfer | None = None,
        ahead: bool = False,
    ) -> SendReservation | None:
        """Tính quota cho cả hàng đợi và gói đang gửi; gói tới sớm phải chừa chỗ cho đầu luồng."""
        if not self._users.is_current(destination) or not destination.udp_ready.is_set():
            return None

        # Gói đến sớm phải chừa một chỗ cho gói đầu luồng còn thiếu.
        headroom = 1 if ahead else 0
        limit = self._settings.max_peer_pending
        if destination.outgoing_count >= limit - headroom:
            return None

        is_file = transfer is not None
        kind_limit = max(1, limit - 1)
        if is_file:
            used = destination.file_outgoing_count
        else:
            used = destination.outgoing_count - destination.file_outgoing_count
        if used >= kind_limit - headroom:
            return None

        destination.outgoing_count += 1

        if is_file:
            destination.file_outgoing_count += 1
            transfer.reservations += 1

        return SendReservation(destination, transfer)

    def release(self, reservation: SendReservation | None) -> None:
        """Trả chỗ đã giữ đúng một lần; các lần cleanup lặp không làm sai quota."""
        if reservation is None or reservation.released:
            return
        reservation.released = True
        reservation.destination.outgoing_count -= 1
        if reservation.transfer is not None:
            reservation.destination.file_outgoing_count -= 1
            reservation.transfer.reservations -= 1

    def check_size(self, packet: Packet, destination: Session) -> None:
        """Từ chối gói relay vượt giới hạn datagram mã hóa khi dùng sequence lớn nhất."""
        # Chừa độ dài sequence tương lai, không chỉ kiểm tra với placeholder seq=0.
        # serialize_packet vẫn validate schema; kích thước sau Fernet và envelope được
        # tính đúng bằng công thức, không cần mã hóa thử thêm một lần cho mỗi gói.
        plaintext = serialize_packet(replace(packet, sequence=2**63 - 1))
        if protected_packet_size(len(plaintext)) > self._settings.max_datagram_bytes:
            raise RelayPacketTooLarge("Forwarded file packet exceeds the datagram size limit")


class FileRelayManager:
    """Quản lý hai bên truyền file, trạng thái và các chỗ đã giữ cho từng gói.

    ReliableChannel lo thứ tự/ACK/retry; OutboundQuota lo dung lượng gửi đi.
    """

    def __init__(
        self,
        settings: Settings,
        users: UserRegistry,
        channel: ReliableChannel,
        outbound: OutboundQuota,
        send_control: Callable[[Session, MessageType, dict], bool],
    ) -> None:
        """Khởi tạo bộ quản lý relay, lịch sử lượt truyền và các dịch vụ mạng dùng chung."""
        self._settings = settings
        self._users = users
        self._channel = channel
        self._outbound = outbound
        self._send_control = send_control
        self._transfers: dict[str, RelayTransfer] = {}
        self._ingress: dict[PacketKey, FileIngress] = {}

    def inspect(self, packet: Packet, source: Session, peer: Address) -> RelayTransfer:
        """Kiểm nội dung, chủ sở hữu và trạng thái rồi trả lượt truyền hợp lệ."""
        transfer_id = packet.metadata["transfer_id"]

        if packet.stream_id != f"file-{transfer_id}":
            raise ValueError("Uplink file stream must be file-<transfer_id>")

        transfer = self._transfers.get(transfer_id)
        if transfer is None:
            transfer = self._new_transfer(packet, source)
        elif packet.kind == MessageType.FILE_OFFER and _offer_from_packet(packet) != transfer.offer:
            raise PermissionError("Transfer ID already belongs to a different offer")

        self._check_owner(packet, source, transfer)

        if packet.kind == MessageType.FILE_DATA:
            self._check_chunk(packet, transfer.offer)

        if not self._channel.has_received(packet, peer):
            self._check_phase(packet, transfer)

        return transfer

    @staticmethod
    def _check_chunk(packet: Packet, offer: FileOffer) -> None:
        """Kiểm chỉ số chunk và số byte payload đúng như OFFER đã khai báo."""
        index = packet.metadata["chunk_index"]
        if index >= offer.total_chunks:
            raise ValueError("Chunk index exceeds file")
        if len(packet.payload) != offer.chunk_length(index):
            raise ValueError("Chunk length does not match offer")

    def reserve(self, packet: Packet, source: Session, peer: Address) -> bool:
        """Giữ chỗ để chuyển tiếp hoặc xử lý gói thuộc lượt đã kết thúc trước khi ACK."""
        # 1. Kiểm tra chỗ đầu vào: chừa chỗ cho chat và cho gói đầu luồng còn thiếu.
        ahead = packet.sequence > self._channel.next_expected(packet, peer)
        file_limit = max(1, self._settings.max_receive_buffer - 1)
        if ahead:
            file_limit -= 1

        if len(self._ingress) >= file_limit:
            return False

        try:
            transfer = self.inspect(packet, source, peer)
        except FileCapacityFull:
            return False

        # 2. Nếu cần chuyển tiếp, giữ cả chỗ gửi ra trước khi chấp nhận gói.
        reservation = None
        try:
            outgoing, destination = self._forward_plan(packet, transfer)
            if destination is not None:
                self._outbound.check_size(outgoing, destination)
                reservation = self._outbound.reserve(destination, transfer=transfer, ahead=ahead)
                if reservation is None:
                    return False
        except (FileBusinessError, RelayPacketTooLarge) as error:
            self._fail(transfer, str(error), code=error.code)

        # 3. Ghi nhận gói đã nhận trách nhiệm xử lý, kể cả gói của lượt đã kết thúc.
        identifier = transfer.offer.transfer_id

        self._transfers[identifier] = transfer

        self._ingress[_packet_key(packet, peer)] = FileIngress(transfer, reservation)

        if transfer.failure_code:
            self._notify_failure(transfer, source)
        return True

    def relay(self, packet: Packet, source: Session) -> None:
        """Chuyển tiếp gói điều khiển/chunk file có giới hạn, không ghép hoặc lưu cả file ở server."""
        ingress = self._ingress[_packet_key(packet, source.udp_address)]
        transfer = ingress.transfer
        self._check_phase(packet, transfer)

        # Người nhận hoặc trạng thái có thể đã đổi trong lúc gói chờ worker.
        try:
            outgoing, destination = self._forward_plan(packet, transfer)
        except FileBusinessError as error:
            self._fail(transfer, str(error), code=error.code)
            return
        if destination is None:
            return  # DATA đã được cấp seq trước CANCEL vẫn được drain/ACK, không ghi lại file.

        reservation = ingress.reservation
        if (
            reservation is None
            or reservation.released
            or reservation.destination is not destination
        ):
            # Ví dụ: lượt đã kết thúc, giờ cần trả kết quả về bên gửi ban đầu.
            self._outbound.release(reservation)
            ingress.reservation = self._outbound.reserve(destination, transfer=transfer)
            reservation = ingress.reservation
            if reservation is None:
                raise ConnectionError("Terminal reply queue is full")

        # Bàn giao chỗ đã giữ cho hàng đợi gửi đi; release() không được trả lại chỗ này.
        destination.file_outbox.put_nowait(ForwardItem(outgoing, reservation))
        ingress.reservation = None
        self._commit_packet(packet, transfer, outgoing)

    def release(self, packet: Packet, peer: Address) -> None:
        """Trả chỗ nhận gói; chỗ đã giao cho tác vụ gửi không còn thuộc lượt giải phóng này."""
        ingress = self._ingress.pop(_packet_key(packet, peer), None)
        if ingress is not None:
            self._outbound.release(ingress.reservation)

    def fail_session(self, session_id: str, *, notify: bool = True) -> None:
        """Đặt lượt truyền về trạng thái cuối trước khi transport bỏ bộ đệm của phiên."""
        for transfer in self._transfers.values():
            if session_id in {transfer.owner_id, transfer.recipient_id}:
                self._fail(
                    transfer,
                    "Transfer endpoint disconnected",
                    code="ENDPOINT_DISCONNECTED",
                    notify=notify,
                )

    def release_destination(self, session: Session) -> None:
        """Trả chỗ đang giữ ở đích đã ngắt kết nối cho các gói đầu vào đang chờ.

        Worker vẫn sở hữu các gói đã ACK này; khi xử lý xong chỉ bỏ ingress,
        không trả quota thêm lần nữa."""
        for ingress in self._ingress.values():
            if ingress.reservation is not None and ingress.reservation.destination is session:
                self._outbound.release(ingress.reservation)

    def forget_session(self) -> None:
        """Bỏ bản ghi gói muộn khi cả hai phiên của lượt truyền đã rời đi."""
        receiving = {item.transfer.offer.transfer_id for item in self._ingress.values()}
        for identifier, transfer in tuple(self._transfers.items()):
            if not transfer.terminal or transfer.reservations or identifier in receiving:
                continue
            if not any(
                self._users.get_session(sid) for sid in {transfer.owner_id, transfer.recipient_id}
            ):
                self._transfers.pop(identifier)

    def expire(self, now: float, *, notify: bool = True) -> None:
        """Hết hạn phản hồi cuối nhưng giữ ID trong cùng bảng để gói muộn không mở lại file."""
        receiving = {item.transfer.offer.transfer_id for item in self._ingress.values()}
        for transfer_id, transfer in tuple(self._transfers.items()):
            if (
                not transfer.terminal
                and now - transfer.updated_at >= self._settings.transfer_idle_seconds
            ):
                self._fail(
                    transfer,
                    "File transfer idle timeout",
                    code="TRANSFER_TIMEOUT",
                    now=now,
                    notify=notify,
                )
            # Chỉ bỏ phản hồi khi cả phía nhận và phía gửi đã trả hết chỗ giữ.
            if not transfer.terminal or transfer.reservations or transfer_id in receiving:
                continue
            if now - transfer.terminal_at < self._settings.completed_retention_seconds:
                continue
            transfer.cached_reply = None
            transfer.retired = True
            transfer.failure_code = transfer.failure_code or "TRANSFER_RETIRED"
            transfer.failure_reason = transfer.failure_reason or "File transfer has already ended"
            if not any(
                self._users.get_session(sid) for sid in {transfer.owner_id, transfer.recipient_id}
            ):
                self._transfers.pop(transfer_id)

    def clear(self) -> None:
        """Xóa lịch sử sau khi transport và worker đã trả toàn bộ chỗ nhận gói."""
        self._transfers.clear()

    def _history_size(self, session_id: str) -> int:
        """Đếm lịch sử của phiên từ các lượt đang giữ, không lưu thêm một bảng đồng bộ."""
        count = 0

        for transfer in self._transfers.values():
            if session_id == transfer.owner_id or session_id == transfer.recipient_id:
                count += 1

        return count

    def _is_busy(self, session_id: str) -> bool:
        """Mỗi phiên chỉ gửi hoặc nhận một file tại một thời điểm."""
        for transfer in self._transfers.values():
            if not transfer.terminal and session_id in {transfer.owner_id, transfer.recipient_id}:
                return True
        return False

    def _new_transfer(self, packet: Packet, source: Session) -> RelayTransfer:
        """Kiểm OFFER đầu tiên và tạo bản ghi hoạt động hoặc thất bại, chưa lưu vào bảng."""
        if packet.kind != MessageType.FILE_OFFER or packet.sequence != 0:
            raise ValueError("Unknown transfer; send FILE_OFFER first")

        offer = _offer_from_packet(packet)
        if offer.sender != source.username or offer.recipient != packet.recipient:
            raise PermissionError("Offer identity does not match authenticated sender")
        if (
            offer.size_bytes > self._settings.max_file_bytes
            or offer.chunk_size > self._settings.chunk_size
        ):
            raise ValueError("File size or chunk_size exceeds configured limit")

        destination = self._users.find_user(offer.recipient)
        recipient_id = destination.session_id if destination is not None else ""
        parties = {source.session_id, recipient_id} - {""}
        for session_id in parties:
            if self._history_size(session_id) >= self._settings.max_transfer_history:
                raise FileCapacityFull("File stream history is full")

        if len(self._transfers) >= self._settings.max_clients * self._settings.max_transfer_history:
            raise FileCapacityFull("File relay history is full")

        transfer = RelayTransfer(offer, source.session_id, recipient_id, time.monotonic())

        if destination is None or not destination.udp_ready.is_set():
            self._fail(
                transfer,
                "File recipient is offline",
                code="RECIPIENT_OFFLINE",
                now=transfer.updated_at,
                notify=False,
            )
        elif any(self._is_busy(sid) for sid in parties):
            self._fail(
                transfer,
                "An endpoint is already sending or receiving a file",
                code="TRANSFER_LIMIT",
                now=transfer.updated_at,
                notify=False,
            )

        return transfer

    def _check_owner(self, packet: Packet, source: Session, transfer: RelayTransfer) -> None:
        """Yêu cầu đúng phiên gốc, vai trò bên gửi và người nhận không bị thay đổi."""
        owner_types = {MessageType.FILE_OFFER, MessageType.FILE_DATA, MessageType.FILE_END}

        recipient_types = {
            MessageType.FILE_READY,
            MessageType.FILE_RESULT,
        }

        if packet.kind in owner_types and source.session_id != transfer.owner_id:
            raise PermissionError("Only file owner may send this packet")

        if packet.kind in recipient_types and source.session_id != transfer.recipient_id:
            raise PermissionError("Only file recipient may send this packet")

        if source.session_id not in {transfer.owner_id, transfer.recipient_id}:
            raise PermissionError("Session does not belong to this transfer")

        if source.session_id == transfer.owner_id:
            expected = transfer.offer.recipient  # A gửi → đích phải là B
        else:
            expected = transfer.offer.sender  # B phản hồi → đích phải là A
        if packet.recipient != expected:
            raise PermissionError("Cannot redirect an existing transfer")

    def _check_phase(self, packet: Packet, transfer: RelayTransfer) -> None:
        """Kiểm trạng thái sẵn sàng, thứ tự END và hash trong kết quả báo thành công."""

        if transfer.terminal:
            return  # Terminal packet/retry không khởi động lại transfer.

        kind = packet.kind
        if (
            kind in {MessageType.FILE_DATA, MessageType.FILE_END, MessageType.FILE_RESULT}
            and transfer.phase != "READY"
        ):
            raise ValueError("File receiver is not ready")

        if kind == MessageType.FILE_DATA and transfer.end_seen:
            raise ValueError("File data follows FILE_END")

        # Nếu bên nhận báo thành công, phải có FILE_END trước đó
        if kind == MessageType.FILE_RESULT and packet.metadata["ok"]:
            if not transfer.end_seen:
                raise ValueError("Successful result requires FILE_END")
            if packet.metadata["sha256"].lower() != transfer.offer.sha256.lower():
                raise ValueError("Result hash does not match offered hash")

    def _forward_plan(
        self, packet: Packet, transfer: RelayTransfer
    ) -> tuple[Packet | None, Session | None]:
        """Trả gói relay hoặc phản hồi đã lưu cùng đích còn online, không đổi trạng thái."""
        if transfer.terminal:
            return self._terminal_reply(packet, transfer)

        if packet.session_id == transfer.owner_id:
            # Gói do bên gửi file gửi đến → chuyển cho bên nhận file.
            destination_id = transfer.recipient_id
        else:
            # Gói do bên nhận file gửi đến → chuyển lại cho bên gửi file.
            destination_id = transfer.owner_id
        destination = self._users.get_session(destination_id)
        if destination is None or not destination.udp_ready.is_set():
            raise FileBusinessError("ENDPOINT_DISCONNECTED", "Transfer endpoint disconnected")

        outgoing = replace(
            packet,
            sender="__server__",
            recipient=destination.username,
            session_id=destination.session_id,
            sequence=0,
            stream_id=f"file-{transfer.owner_id}-{transfer.offer.transfer_id}",
            metadata={
                **packet.metadata,
                "origin_user": packet.sender,
                "target_user": destination.username,
            },
        )
        return outgoing, destination

    def _terminal_reply(
        self, packet: Packet, transfer: RelayTransfer
    ) -> tuple[Packet | None, Session | None]:
        """Trả lại kết quả đã lưu khi có yêu cầu lặp, không mở lại lượt truyền."""
        cached = transfer.cached_reply
        if cached is None:
            return None, None
        repeat_request = (
            packet.session_id == transfer.owner_id
            and packet.kind in {MessageType.FILE_OFFER, MessageType.FILE_END}
            and cached.session_id == transfer.owner_id
        )
        repeat_result = packet.kind == cached.kind and packet.session_id != cached.session_id
        if not (repeat_request or repeat_result):
            return None, None
        destination = self._users.get_session(cached.session_id)
        if destination is None or not destination.udp_ready.is_set():
            return None, None
        return cached, destination

    def _commit_packet(self, packet: Packet, transfer: RelayTransfer, outgoing: Packet) -> None:
        """Cập nhật tiến độ sau khi xếp gói vào hàng đợi và lưu phản hồi cuối khi kết thúc."""
        if transfer.terminal:
            return

        now = time.monotonic()

        if packet.kind == MessageType.FILE_READY and transfer.phase == "OFFERED":
            transfer.phase = "READY"
            transfer.updated_at = now

        elif packet.kind == MessageType.FILE_DATA:
            index = packet.metadata["chunk_index"]
            if index > transfer.highest_chunk:
                transfer.highest_chunk = index
                transfer.updated_at = now

        elif packet.kind == MessageType.FILE_END and not transfer.end_seen:
            transfer.end_seen = True
            transfer.updated_at = now

        elif packet.kind in {MessageType.FILE_RESULT, MessageType.CANCEL}:
            if packet.kind == MessageType.FILE_RESULT:
                transfer.phase = "COMPLETED" if packet.metadata["ok"] else "FAILED"
            else:
                transfer.phase = "CANCELLED"
            transfer.terminal_at = now
            transfer.cached_reply = outgoing

    def _notify_failure(self, transfer: RelayTransfer, session: Session) -> None:
        """Xếp đúng một lỗi kết thúc cho mỗi bên; chỉ ghi nhận khi xếp hàng thành công."""
        if session.session_id in transfer.notified:
            return
        if self._send_control(
            session,
            MessageType.ERROR,
            {
                "scope": "file",
                "terminal": True,
                "code": transfer.failure_code,
                "transfer_id": transfer.offer.transfer_id,
                "error": transfer.failure_reason,
            },
        ):
            transfer.notified.add(session.session_id)

    def _fail(
        self,
        transfer: RelayTransfer,
        reason: str,
        *,
        code: str,
        now: float | None = None,
        notify: bool = True,
    ) -> None:
        """Đánh dấu lượt đang hoạt động là thất bại và tùy chọn báo cho các bên còn kết nối."""
        if transfer.terminal:
            return
        transfer.phase = "FAILED"
        transfer.failure_code = code
        transfer.failure_reason = reason
        transfer.terminal_at = time.monotonic() if now is None else now
        if notify:
            for session_id in {transfer.owner_id, transfer.recipient_id}:
                session = self._users.get_session(session_id)
                if session is not None:
                    self._notify_failure(transfer, session)
