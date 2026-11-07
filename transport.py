"""Reliable UDP: acknowledgements, retries, bounded windows and stream ordering.

The application supplies a single-send callback; this layer owns no file or UI I/O.
"""

from __future__ import annotations

import asyncio
import math
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace

from config import Settings
from congestion import CongestionController
from protocol import (
    FILE_TYPES,
    Address,
    MessageType,
    Packet,
    make_ack,
    validate_packet,
)


@dataclass(slots=True)
class PendingPacket:
    """Bản ghi retry; khóa tra cứu phải gồm peer, session, stream và sequence."""

    packet: Packet
    completion: asyncio.Future[None]
    deadline: float = 0.0
    retries: int = 0
    sent: bool = False
    expires_at: float = 0.0
    later_acked: bool = False


@dataclass(slots=True)
class ReceiveBatch:
    """Kết quả nhận sau xác thực và kiểm tra capacity, trước dispatch nghiệp vụ."""

    deliverable: list[Packet] = field(default_factory=list)
    acknowledgement: Packet | None = None
    duplicate: bool = False


type SendPacket = Callable[[Packet, Address], Awaitable[None]]
type StreamKey = tuple[Address, str, str]
type PacketKey = tuple[Address, str, str, int]
type SessionKey = tuple[Address, str]


@dataclass(slots=True)
class ChannelSession:
    """Waiter giữ đối tượng này để vẫn thấy lỗi dù phiên đã bị xóa khỏi bảng."""

    error: Exception | None = None


class ReliableChannel:
    """Một channel mỗi app, state tách peer/session/stream; không có global next_seq."""

    _settings: Settings
    _send_packet: SendPacket
    _pending: dict[PacketKey, PendingPacket]
    _receive_buffers: dict[StreamKey, dict[int, Packet]]
    _controllers: dict[Address, CongestionController]
    _closed: bool

    def __init__(
        self,
        settings: Settings,
        send_packet: SendPacket,
        *,
        local_user: str | None = None,
        reserve_capacity=None,
        release_capacity=None,
        on_failure: Callable[[Address, str, Exception], None] | None = None,
    ) -> None:
        """Chuẩn bị state, hàng đợi hữu hạn và callback gửi không chứa retry."""

        for name in ("window_packets", "max_peer_pending", "max_receive_buffer"):
            value = getattr(settings, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(settings.max_retries) is not int or settings.max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        for name in ("retry_initial_seconds", "retry_max_seconds", "handshake_seconds"):
            value = getattr(settings, name)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be positive and finite")
        if settings.retry_max_seconds < settings.retry_initial_seconds:
            raise ValueError("retry_max_seconds must be >= retry_initial_seconds")
        if (reserve_capacity is None) != (release_capacity is None):
            raise ValueError("Capacity callbacks must be provided together")

        self._settings = settings
        self._send_packet = send_packet

        # Server truyền "__server__", client truyền username của mình.
        # Dùng khi tạo ACK, không suy đoán danh tính server từ người nhận chat.
        self._local_user = local_user

        # Các packet đang xếp hàng hoặc đang chờ ACK.
        self._pending = {}

        # Sequence tiếp theo sẽ cấp cho từng stream.
        self._send_next = {}

        # Đánh thức scheduler khi có packet mới hoặc ACK.
        self._wakeup = asyncio.Event()

        # Các packet đến sớm, đang chờ packet phía trước.
        self._receive_buffers = {}

        # Sequence tiếp theo cần giao lên ứng dụng.
        self._receive_next = {}

        # Callback giữ/trả chỗ trong hàng đợi nghiệp vụ của app.
        self._reserve_capacity = reserve_capacity
        self._release_capacity = release_capacity

        self._controllers = {}

        self._closed = False

        # Event riêng cho chỗ trống: scheduler không được clear tín hiệu của waiter.
        self._capacity_changed = asyncio.Event()
        self._sessions: dict[SessionKey, ChannelSession] = {}
        # Một bảng duy nhất giữ tác vụ gửi đến khi hoàn tất cả bước dọn dẹp.
        self._sending: dict[PacketKey, asyncio.Task] = {}
        self._runner: asyncio.Task | None = None
        self._on_failure = on_failure
        # Vé chờ tiếp nhận theo stream: gói gọi send() trước được cấp sequence trước,
        # kể cả khi nhiều gói cùng chờ chỗ (ví dụ chunk file lúc hàng đợi peer đầy).
        self._admission_order: dict[StreamKey, deque[object]] = {}

        # Giới hạn chờ queue riêng, sau đó dành đủ thời gian cho các lần retry.
        self._queue_timeout = settings.handshake_seconds
        interval = settings.retry_initial_seconds
        self._retry_budget = interval  # Dự phòng một lượt I/O cuối.
        for _ in range(settings.max_retries + 1):
            self._retry_budget += interval
            interval = min(interval * 2, settings.retry_max_seconds)

    async def send(self, packet: Packet, peer: Address) -> None:
        """Xếp packet tin cậy rồi chờ ACK chặng hiện tại hoặc lỗi hữu hạn."""
        validate_packet(packet)

        if packet.kind == MessageType.ACK or not packet.session_id or not packet.stream_id:
            raise ValueError("Reliable send requires a data packet with session and stream")

        if self._closed:
            raise ConnectionError("Channel is closed")

        # Lấy trạng thái phiên
        state = self._sessions.setdefault((peer, packet.session_id), ChannelSession())

        loop = asyncio.get_running_loop()
        # Tính hạn chót chờ được tiếp nhận vào danh sách gói chờ gửi/ACK.
        admission_deadline = loop.time() + self._queue_timeout

        # Xác định luồng theo địa chỉ bên nhận, mã phiên và mã luồng.
        stream = (peer, packet.session_id, packet.stream_id)

        # Lấy vé ngay khi được gọi (chưa await) để thứ tự sequence theo thứ tự gọi send().
        ticket = object()
        queue = self._admission_order.setdefault(stream, deque())
        queue.append(ticket)
        try:
            # Chờ tới lượt trong stream và đủ chỗ cho peer; báo lỗi nếu quá hạn.
            await self._wait_admission(packet, peer, state, admission_deadline, queue, ticket)
        finally:
            queue.remove(ticket)
            if not queue and self._admission_order.get(stream) is queue:
                del self._admission_order[stream]
            elif queue:
                self._notify_capacity()  # Đánh thức gói kế tiếp của stream.

        # Lấy số thứ tự cho gói hiện tại; luồng mới bắt đầu từ 0.
        sequence = self._send_next.get(stream, 0)
        if sequence >= 2**63:
            raise ConnectionError("Sequence space exhausted; reconnect required")
        self._send_next[stream] = sequence + 1

        # Tạo Packet mới với số thứ tự vừa cấp và bản sao metadata.
        outgoing = replace(packet, sequence=sequence, metadata=dict(packet.metadata))
        completion = loop.create_future()

        # Địa chỉ nhận đã nằm trong khóa; bản ghi chỉ giữ dữ liệu và trạng thái retry.
        pending = PendingPacket(
            outgoing,
            completion,
            expires_at=loop.time() + self._queue_timeout + self._retry_budget,
        )

        # Lưu bản ghi theo khóa (peer, session_id, stream_id, sequence) -> để tìm đúng gói khi xử lý ACK, gửi lại hoặc hết hạn.
        self._pending[(*stream, sequence)] = pending
        self._wakeup.set()

        try:
            async with asyncio.timeout_at(pending.expires_at):
                # Không để cancel của caller tự hủy Future trước bước cleanup toàn phiên.
                await asyncio.shield(completion)

        except (asyncio.CancelledError, TimeoutError) as error:
            if not completion.done():
                failure = (
                    ConnectionError("Send cancelled after allocating sequence; reconnect required")
                    if isinstance(error, asyncio.CancelledError)
                    else TimeoutError("Reliable send deadline exceeded; reconnect required")
                )
                # Đánh dấu toàn bộ phiên với peer đã thất bại
                self._fail_session(peer, packet.session_id, failure)

            # Caller đã rời await: lấy exception để không rò cảnh báo Future.
            if completion.done() and not completion.cancelled():
                completion.exception()

            raise

    async def _wait_admission(
        self,
        packet: Packet,
        peer: Address,
        state: ChannelSession,
        admission_deadline: float,
        queue: deque[object],
        ticket: object,
    ) -> None:
        """Chờ tới lượt của stream và đủ chỗ; báo lỗi nếu phiên lỗi, channel đóng hoặc quá hạn."""

        while True:
            if state.error is not None:
                raise state.error

            if self._closed:
                raise ConnectionError("Channel is closed")

            # Chỉ gói đứng đầu hàng của stream được xét, rồi mới kiểm tra chỗ trống.
            if queue[0] is ticket and self._can_admit(packet, peer):
                break

            # Giữ Event hiện tại để chờ thông báo thay đổi khả năng tiếp nhận gói.
            changed = self._capacity_changed
            async with asyncio.timeout_at(admission_deadline):
                await changed.wait()

    def _can_admit(self, packet: Packet, peer: Address) -> bool:
        """Kiểm tra còn chỗ cho peer; giới hạn riêng gói file để chừa chỗ cho chat"""
        # Lấy các gói đang chờ của đúng địa chỉ nhận.
        pending = [value for key, value in self._pending.items() if key[0] == peer]

        limit = self._settings.max_peer_pending
        if len(pending) >= limit:
            return False

        # Giới hạn gói file ở limit - 1, nhưng luôn cho phép tối thiểu 1 gói file.
        if packet.kind in FILE_TYPES:
            return sum(item.packet.kind in FILE_TYPES for item in pending) < max(1, limit - 1)

        return True

    def next_expected(self, packet: Packet, peer: Address) -> int:
        """Trả về sequence tiếp theo cần nhận của luồng để app chừa chỗ cho gói thiếu."""
        return self._receive_next.get((peer, packet.session_id, packet.stream_id), 0)

    def has_received(self, packet: Packet, peer: Address) -> bool:
        """Kiểm tra gói đã được tiếp nhận để hỗ trợ ACK lại gói trùng."""
        stream = (peer, packet.session_id, packet.stream_id)
        return (
            packet.sequence < self._receive_next.get(stream, 0)
            or packet.sequence
            in self._receive_buffers.get(
                stream, {}
            )  # Gói đã được giữ trong bộ đệm vì đến sai thứ tự.
        )

    def can_accept(self, packet: Packet, peer: Address) -> bool:
        """Kiểm tra cửa sổ và capacity trước khi commit packet vào receive buffer."""

        # Từ chối nếu channel đã đóng hoặc gói là ACK.
        # ACK được xử lý riêng bằng acknowledge(), không đi qua bộ đệm dữ liệu nhận.
        if self._closed or packet.kind == MessageType.ACK:
            return False

        validate_packet(packet)

        if not packet.session_id or not packet.stream_id:
            return False

        state = self._sessions.get((peer, packet.session_id))
        if state is not None and state.error is not None:
            return False

        # Lấy thông tin luồng nhận
        stream = (peer, packet.session_id, packet.stream_id)
        expected = self._receive_next.get(stream, 0)
        buffer = self._receive_buffers.get(stream, {})

        if packet.sequence < expected or packet.sequence in buffer:
            return True

        # Chỉ giữ trong buffer với expected ≤ sequence < expected + window_packets
        if packet.sequence >= expected + self._settings.window_packets:
            return False

        # Chừa một chỗ cho gói đầu đang thiếu; buffer đầy toàn gói đến sớm sẽ kẹt.
        limit = self._settings.max_receive_buffer
        if packet.sequence > expected:
            limit -= 1

        return sum(len(queued) for queued in self._receive_buffers.values()) < limit

    def receive(self, packet: Packet, peer: Address) -> ReceiveBatch:
        """Lưu packet hợp lệ, loại trùng, trả ACK và các message đã đủ thứ tự để dispatch."""

        if not self.can_accept(packet, peer):
            return ReceiveBatch()

        # Lấy thông tin luồng và tạo ACK
        stream = (peer, packet.session_id, packet.stream_id)
        expected = self._receive_next.get(stream, 0)
        buffer = self._receive_buffers.get(stream, {})
        ack = make_ack(packet, self._local_user or packet.recipient)

        # Gói trùng chỉ cần ACK lại, không lưu hoặc chuyển cho ứng dụng lần nữa.
        if packet.sequence < expected or packet.sequence in buffer:
            return ReceiveBatch(acknowledgement=ack, duplicate=True)
        # Nếu có callback, phải đặt được chỗ xử lý ở ứng dụng trước khi nhận gói.
        if self._reserve_capacity is not None:
            reserved = self._reserve_capacity(packet, peer)

            if reserved is False:
                return ReceiveBatch()

        # Đảm bảo phiên và bộ đệm tồn tại, rồi lưu gói mới.
        self._sessions.setdefault((peer, packet.session_id), ChannelSession())
        buffer = self._receive_buffers.setdefault(stream, {})
        buffer[packet.sequence] = packet

        # Lấy ra các gói liên tiếp từ số đang chờ; dừng khi gặp số còn thiếu.
        deliverable = []
        while expected in buffer:
            deliverable.append(buffer.pop(expected))
            expected += 1

        # Lưu số tiếp theo cần nhận và dọn bộ đệm nếu đã rỗng.
        self._receive_next[stream] = expected
        if not buffer:
            self._receive_buffers.pop(stream, None)

        # Ứng dụng xử lý các gói và giải phóng capacity đã đặt trước khi xong.
        return ReceiveBatch(deliverable, ack)

    def acknowledge(self, ack: Packet, peer: Address, now: float) -> bool:
        """Xác nhận gói đã gửi; trả True khi ACK mới và khớp gói đang chờ."""

        if self._closed or ack.kind != MessageType.ACK:
            return False

        try:
            validate_packet(ack)
        except ValueError:
            return False

        # Tìm gói được ACK theo địa chỉ, phiên, luồng và số thứ tự.
        key = (peer, ack.session_id, ack.metadata["ack_stream"], ack.metadata["ack_seq"])
        pending = self._pending.get(key)

        # Gói phải đang chờ, đã được gửi và ACK phải gửi về đúng người gửi gốc.
        if pending is None or not pending.sent or ack.recipient != pending.packet.sender:
            return False

        # Cập nhật bộ điều khiển và bỏ gói đã xác nhận khỏi danh sách chờ.
        self._controller(peer).on_ack(key[1:], now, pending.retries > 0)
        self._pending.pop(key)

        # Ghi nhận các gói trước đó chưa có ACK dù gói phía sau đã được xác nhận.
        for other, waiting in self._pending.items():
            if other[:3] == key[:3] and other[3] < key[3] and waiting.sent:
                waiting.later_acked = True

        # Báo thành công cho send() đang chờ Future của gói.
        if not pending.completion.done():
            pending.completion.set_result(None)

        # Hủy tác vụ gửi I/O còn dư, tránh hủy chính tác vụ hiện tại.
        sending = self._sending.get(key)
        if (
            sending is not None
            and sending is not asyncio.current_task()
            and not sending.cancelling()
        ):
            sending.cancel()  # ACK đã đến: không cần giữ callback I/O đang chờ nữa.

        # Báo có thay đổi về chỗ trống và đánh thức bộ điều phối gửi.
        self._notify_capacity()
        return True

    def _controller(self, peer: Address) -> CongestionController:
        """Lấy bộ điều khiển tắc nghẽn riêng cho peer, tạo nếu chưa có."""

        # Chỉ tạo ở lần đầu; các lần sau dùng lại để giữ trạng thái điều khiển.
        if peer not in self._controllers:
            label = f"{self._local_user or ''}>{peer[0]}:{peer[1]}"
            self._controllers[peer] = CongestionController(self._settings, label)

        return self._controllers[peer]

    async def run(self) -> None:
        """Điều phối gửi mới, gửi lại và kiểm tra thời hạn của các gói chờ."""

        # Không cho hai task cùng chạy bộ điều phối.
        if self._runner is not None:
            raise RuntimeError("ReliableChannel.run is already running")
        if self._closed:
            return

        # Ghi nhận task hiện tại và lấy đồng hồ của event loop.
        self._runner = asyncio.current_task()
        loop = asyncio.get_running_loop()

        try:
            while not self._closed:
                # Xóa tín hiệu cũ trước khi quét, chuẩn bị nhận tín hiệu mới.
                self._wakeup.clear()
                now = loop.time()
                deadlines = []

                # Duyệt bản chụp vì xử lý gói có thể làm thay đổi _pending.
                for key, pending in tuple(self._pending.items()):
                    deadline = self._schedule_packet(key, pending, now)
                    if deadline is not None:
                        deadlines.append(deadline)

                # Có thể channel đã đóng trong quá trình xử lý.
                if self._closed:
                    break

                try:
                    # Chờ sự kiện mới hoặc mốc cần kiểm tra lại gần nhất.
                    # None nghĩa là không đặt timeout cho lần chờ này.
                    deadline = min(deadlines) if deadlines else None
                    async with asyncio.timeout_at(deadline):
                        await self._wakeup.wait()
                except TimeoutError:
                    # Đến giờ kiểm tra lại: tiếp tục vòng lặp, không quét liên tục.
                    pass
        finally:
            # Dọn channel khi bộ điều phối kết thúc, kể cả khi lỗi hoặc bị hủy.
            self._runner = None
            if not self._closed:
                await self.close()

    def _schedule_packet(self, key: PacketKey, pending: PendingPacket, now: float) -> float | None:
        """Lên lịch gửi mới/retry và trả mốc cần kiểm tra lại; None nếu gói đã bị bỏ."""
        if key not in self._pending:
            return None

        if now >= pending.expires_at:
            self._fail_session(key[0], key[1], TimeoutError("Send queue expired"))
            return None

        if key in self._sending:
            return pending.expires_at

        if pending.sent:
            if now < pending.deadline:
                return min(pending.expires_at, pending.deadline)
            if pending.retries >= self._settings.max_retries:
                self._fail_session(key[0], key[1], TimeoutError("Retry limit reached"))
                return None

            pending.retries += 1
            controller = self._controller(key[0])
            if pending.later_acked:
                controller.on_loss(key[1:], now)
            else:
                controller.on_timeout(now)

        elif not self._can_send_new(key):
            return pending.expires_at

        # Tác vụ vào/ra riêng có thời hạn: hàm gọi lại chậm không chặn các nút khác.
        task = asyncio.create_task(self._attempt(key, pending))
        self._sending[key] = task
        task.add_done_callback(lambda completed, key=key: self._attempt_done(key, completed))
        return pending.expires_at

    def _can_send_new(self, key: PacketKey) -> bool:
        """Cửa sổ stream neo ở gói thiếu đầu tiên; tổng in-flight cũng bị chặn theo peer."""
        # Gói đang xét luôn có trong _pending, nên stream luôn có một mốc đầu.
        base = min(other[3] for other in self._pending if other[:3] == key[:3])
        if key[3] >= base + self._settings.window_packets:
            return False

        active = {
            other for other, pending in self._pending.items() if other[0] == key[0] and pending.sent
        }
        active.update(other for other in self._sending if other[0] == key[0])
        if len(active) >= self._settings.window_packets:
            return False

        controller = self._controller(key[0])

        reserved = sum(
            other[0] == key[0] and not pending.sent and other in self._sending
            for other, pending in self._pending.items()
        )
        if controller.send_budget(self._settings.window_packets) <= reserved:
            return False

        if self._pending[key].packet.kind in FILE_TYPES:
            file_active = sum(other[2].startswith("file-") for other in active)
            return file_active < max(1, controller.window_packets - 1)

        return True

    async def _attempt(self, key: PacketKey, pending: PendingPacket) -> None:
        """Một lần gửi; retry dùng lại chính Packet nên không đổi seq/message_id."""
        try:
            if self._pending.get(key) is not pending:
                return

            pending.sent = True
            sent_at = asyncio.get_running_loop().time()

            self._controller(key[0]).on_sent(key[1:], sent_at)

            interval = self._settings.retry_initial_seconds
            for _ in range(pending.retries):
                interval = min(interval * 2, self._settings.retry_max_seconds)
            pending.deadline = sent_at + interval

            # Ghi state TRƯỚC await: callback test có thể trả ACK ngay lập tức.
            async with asyncio.timeout(self._settings.retry_initial_seconds):
                await self._send_packet(pending.packet, key[0])

        except TimeoutError:
            pass  # I/O timeout được tính là một lần gửi không nhận ACK.
        except Exception as error:
            self._fail_session(key[0], key[1], error)

    def _attempt_done(self, key: PacketKey, task: asyncio.Task) -> None:
        """Bỏ tác vụ đã kết thúc, kể cả bị hủy trước khi chạy, rồi đánh thức scheduler."""
        if self._sending.get(key) is task:
            self._sending.pop(key)
        self._wakeup.set()

    def _notify_capacity(self) -> None:
        """Đánh thức tất cả người đang chờ, rồi tạo event cho lần thay đổi tiếp theo."""
        self._capacity_changed.set()
        self._capacity_changed = asyncio.Event()
        self._wakeup.set()

    def _fail_session(
        self, peer: Address, session_id: str, error: Exception, *, notify=True
    ) -> None:
        """Không bỏ riêng một seq: kết thúc cả phiên và yêu cầu app đăng nhập phiên mới."""
        session_key = (peer, session_id)
        state = self._sessions.setdefault(session_key, ChannelSession())
        if state.error is not None:
            return
        state.error = error
        controller = self._controllers.get(peer)
        if controller is not None:
            controller.forget_session(session_id)
        for key, pending in tuple(self._pending.items()):
            if key[:2] == session_key:
                self._pending.pop(key)
                if not pending.completion.done():
                    pending.completion.set_exception(error)
        for key, task in tuple(self._sending.items()):
            if (
                key[:2] == session_key
                and task is not asyncio.current_task()
                and not task.cancelling()
            ):
                task.cancel()
        self._clear_receive_state(session_key)
        self._notify_capacity()
        if notify and self._on_failure is not None:
            self._on_failure(peer, session_id, error)

    def _clear_receive_state(self, session_key: SessionKey) -> None:
        """Giải phóng gói đang đệm và xóa toàn bộ trạng thái sequence của một phiên."""
        peer, _ = session_key
        for stream, buffer in tuple(self._receive_buffers.items()):
            if stream[:2] == session_key:
                self._receive_buffers.pop(stream)
                if self._release_capacity is not None:
                    for packet in buffer.values():
                        self._release_capacity(packet, peer)
        for mapping in (self._send_next, self._receive_next):
            for stream in tuple(mapping):
                if stream[:2] == session_key:
                    mapping.pop(stream)

    def forget_peer(self, peer: Address, session_id: str) -> None:
        """Dọn state đúng phiên của peer đã ngắt và kết thúc mọi Future đang chờ."""
        self._fail_session(peer, session_id, ConnectionError("Session disconnected"), notify=False)
        self._sessions.pop((peer, session_id), None)
        if not any(key[0] == peer for key in self._sessions):
            self._controllers.pop(peer, None)

    def has_session(self, peer: Address, session_id: str) -> bool:
        """Phiên đã có lịch sử data/sequence; không tự reset khi đổi endpoint."""
        return (peer, session_id) in self._sessions

    async def close(self) -> None:
        """Ngừng scheduler, hủy waiter và dọn hàng đợi mà không để task bị treo."""
        current = asyncio.current_task()
        # Callback đang được dọn không chờ ngược lượt đóng đã bắt đầu.
        if self._closed and current in self._sending.values():
            return
        self._closed = True
        for peer, session_id in tuple(self._sessions):
            self.forget_peer(peer, session_id)
        self._controllers.clear()
        self._notify_capacity()
        tasks = set(self._sending.values())
        if self._runner is not None:
            tasks.add(self._runner)
        tasks.discard(current)
        for task in tasks:
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
