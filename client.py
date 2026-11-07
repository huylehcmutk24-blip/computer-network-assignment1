"""UI-independent client core and persistent browser session lifecycle.
Uses asyncio, socket, time, secrets, and logging.
The web bridge calls execute(); the file manager calls emit_event(name, data)."""

from __future__ import annotations

import asyncio
import logging
import math
import secrets
import socket
import time
from collections import OrderedDict
from collections.abc import Coroutine
from contextlib import suppress
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from cryptography.fernet import InvalidToken

from config import Settings, validate_settings
from files import TERMINAL_STATUSES, FileTransferManager
from protocol import (
    DISCOVERY_STREAM,
    FILE_TYPES,
    TERMINAL_FILE_ERROR_CODES,
    Address,
    MessageType,
    Packet,
    chat_payload_limit,
    decode_public_control,
    encode_public_control,
    read_frame,
    validate_identifier,
    validate_username,
    write_frame,
)
from security import SecurityContext, load_keyring
from transport import ReliableChannel

CHAT_TYPES = {MessageType.MSG_PUBLIC, MessageType.MSG_PRIVATE}
AUTO_SERVER = "auto"
# Sau khi phiên rớt ngoài ý muốn, thử đăng nhập lại với độ trễ 1, 2, 4, 4, ... giây
# trong tối đa RECONNECT_WINDOW_SECONDS. Server dọn phiên cũ sau offline_seconds (8 s).
RECONNECT_FIRST_DELAY = 1.0
RECONNECT_MAX_DELAY = 4.0
RECONNECT_WINDOW_SECONDS = 60.0
logger = logging.getLogger(__name__)


async def discover_server(settings: Settings) -> tuple[str, int, int]:
    """Broadcast DISCOVER và trả (IP server, cổng TCP, cổng UDP) từ ANNOUNCE đầu tiên.

    Mỗi lượt dùng message_id ngẫu nhiên; chỉ nhận ANNOUNCE trả lời đúng lượt đó.
    Gửi lại theo cùng nhịp retry của transport, tối đa max_retries + 1 lần."""
    request = Packet(
        MessageType.DISCOVER,
        "",
        "*",
        "__server__",
        DISCOVERY_STREAM,
        0,
        secrets.token_hex(16),
    )
    wire = encode_public_control(request)
    expected_id = f"announce:{request.message_id}"
    started = time.perf_counter()
    target = (settings.discovery_address, settings.discovery_port)
    loop = asyncio.get_running_loop()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        probe.setblocking(False)
        probe.bind(("0.0.0.0", 0))
        delay = settings.retry_initial_seconds
        for _ in range(settings.max_retries + 1):
            await loop.sock_sendto(probe, wire, target)
            try:
                async with asyncio.timeout(delay):
                    while True:
                        try:
                            data, peer = await loop.sock_recvfrom(probe, 2048)
                        except ConnectionResetError:
                            # Windows báo ICMP port unreachable của lần gửi trước bằng lỗi
                            # này khi đọc; bỏ qua và chờ ANNOUNCE khác.
                            continue
                        try:
                            reply = decode_public_control(data, {MessageType.ANNOUNCE})
                        except ValueError:
                            continue
                        if reply.message_id == expected_id:
                            metadata = reply.metadata
                            logger.info(
                                "DISCOVERED server=%s tcp=%d udp=%d online=%d ms=%.1f",
                                peer[0],
                                metadata["tcp_port"],
                                metadata["udp_port"],
                                metadata["online"],
                                (time.perf_counter() - started) * 1000,
                            )
                            return peer[0], metadata["tcp_port"], metadata["udp_port"]
            except TimeoutError:
                delay = min(delay * 2, settings.retry_max_seconds)
    raise ConnectionError("No server answered the discovery broadcast")


class ClientState(StrEnum):
    """Connection states shared by the web bridge and tests."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTED = "CONNECTED"
    AUTHENTICATED = "AUTHENTICATED"
    ONLINE = "ONLINE"
    CLOSING = "CLOSING"


@dataclass(frozen=True, slots=True)
class UICommand:
    """Lệnh được sử dụng bởi HTTP và các bài kiểm thử;
    ClientApp.execute là phương thức xử lý duy nhất.
    Tên lệnh: login, users, public, private, send_file, cancel_file hoặc logout.
    Cácl tham số được kiểm tra tính hợp lệ theo từng tên ệnh."""

    name: str
    args: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UIEvent:
    """Sự kiện về trạng thái, danh sách người dùng, tin nhắn,
    lời mời nhận file, tiến độ truyền file, kết thúc truyền file
    hoặc lỗi; không chứa khóa mật mã."""

    name: str
    data: dict[str, object] = field(default_factory=dict)


class ClientApp:
    """Coordinate sessions and messages; UIs use commands/events instead of mutating state."""

    settings: Settings
    state: ClientState
    session_id: str | None
    events: asyncio.Queue[UIEvent]
    channel: ReliableChannel
    files: FileTransferManager
    security: SecurityContext
    _tcp_socket: socket.socket | None
    _udp_socket: socket.socket | None
    _tasks: set[asyncio.Task[None]]

    def __init__(self, settings: Settings) -> None:
        """Khởi tạo trạng thái và các thành phần client, chưa mở kết nối mạng."""
        validate_settings(settings)
        self.settings = settings
        self.state = ClientState.DISCONNECTED
        self.session_id = None
        self.events = asyncio.Queue(maxsize=settings.ui_queue_size)

        self._tcp_socket = None
        self._udp_socket = None
        self._tasks = set()
        self._challenge: str | None = None
        self._tcp_send_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._stop_event = asyncio.Event()
        self._closed = False
        self._ready = asyncio.Event()
        self._runner: asyncio.Task | None = None
        self._login_lock = asyncio.Lock()
        self._auth_reply: asyncio.Future[Packet] | None = None
        self._bind_id: str | None = None
        self._bind_challenge: str | None = None
        self._bind_changed = asyncio.Event()
        # server_host="auto" được thay bằng địa chỉ tìm thấy qua discovery khi connect().
        self._server_tcp = (settings.server_host, settings.tcp_port)
        self._server_udp_port = settings.udp_port
        self._server_peer = (settings.server_host, settings.udp_port)
        self._last_seen = time.monotonic()
        self._heartbeat_id: str | None = None
        self._heartbeat_sequence = 0
        self._failure: Exception | None = None
        self._users: list[str] = []
        self.max_chat_bytes = chat_payload_limit(settings.max_datagram_bytes)
        self._transfers: OrderedDict[str, dict[str, object]] = OrderedDict()
        # One receive() can release the entire buffer plus the current packet.
        self._receive_reserve = settings.max_receive_buffer + 1
        queue_size = 2 * self._receive_reserve
        self._chat_packets: asyncio.Queue[Packet] = asyncio.Queue(queue_size)
        self._file_packets: asyncio.Queue[Packet] = asyncio.Queue(queue_size)

        keyring = load_keyring(settings.keyring_path)
        if set(keyring) != {settings.key_id}:
            raise ValueError("The client keyring must contain only its own key")

        self.security = SecurityContext(keyring)
        self.channel = ReliableChannel(
            settings,
            self.send_datagram,
            local_user=settings.username,
            on_failure=lambda peer, session_id, error: self._fail(error),
        )
        self.files = FileTransferManager(settings, self.send_message, self.emit_event)

    async def connect(self) -> None:
        """Kết nối TCP, trao đổi HELLO và lưu giá trị thử thách, chưa thực hiện đăng nhập."""

        if self._closed:
            raise ConnectionError("Client has closed; please create a new ClientApp.")

        if self.state != ClientState.DISCONNECTED or self._tcp_socket is not None:
            raise ConnectionError("Client has connected or is currently connecting")

        try:
            if self.settings.server_host == AUTO_SERVER:
                host, tcp_port, udp_port = await discover_server(self.settings)
                self._server_tcp = (host, tcp_port)
                self._server_udp_port = udp_port
            logger.info(
                "CONNECTING user=%s server=%s:%d", self.settings.username, *self._server_tcp
            )
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.setblocking(False)
            self._tcp_socket.bind((self.settings.bind_host, 0))

            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setblocking(False)
            self._udp_socket.bind((self.settings.bind_host, 0))

            # Kết nối TCP, trao đổi HELLO/HELLO_ACK và lưu challenge để dùng khi đăng nhập.
            self._challenge = await self._exchange_hello()

            # Lấy IP server từ kết nối TCP, ghép với cổng UDP cấu hình làm địa chỉ gửi UDP.
            self._server_peer = (self._tcp_socket.getpeername()[0], self._server_udp_port)

            self.state = ClientState.CONNECTED
            logger.info("CONNECTED user=%s | HELLO_ACK received", self.settings.username)

        except BaseException as error:
            # Clean up on timeout or cancellation, then re-raise the original error.
            self._close_sockets()
            logger.info(
                "DISCONNECTED user=%s handshake=%s", self.settings.username, type(error).__name__
            )
            raise

    async def _exchange_hello(self) -> str:
        """Thiết lập kết nối TCP và trao đổi thông điệp HELLO; trả về một challenge hợp lệ."""
        hello = Packet(
            kind=MessageType.HELLO,
            session_id="",
            sender=self.settings.username,
            recipient="__server__",
            stream_id="control",
            sequence=0,
            message_id=secrets.token_hex(16),
        )

        loop = asyncio.get_running_loop()

        async with asyncio.timeout(self.settings.handshake_seconds):
            await loop.sock_connect(self._tcp_socket, self._server_tcp)

            await write_frame(
                self._tcp_socket,
                encode_public_control(hello),
                self._tcp_send_lock,
                self.settings.max_frame_bytes,
            )

            body = await read_frame(
                self._tcp_socket,
                self.settings.max_frame_bytes,
                self.settings.handshake_seconds,
            )

        reply = decode_public_control(body, {MessageType.HELLO_ACK})

        # Lấy thông tin challenge
        challenge = reply.metadata.get("challenge")

        if not isinstance(challenge, str) or not challenge.strip():
            raise ValueError("HELLO_ACK is missing a valid challenge")

        return challenge

    def _close_sockets(self) -> None:
        """Giải phóng các socket TCP/UDP khi kết nối thất bại hoặc khi client tắt."""

        for sock in (self._tcp_socket, self._udp_socket):
            if sock is not None:
                sock.close()

        self._tcp_socket = None
        self._udp_socket = None

    async def login(self, username: str, password: str) -> None:
        """Gửi AUTH được bảo vệ, nhận mã phiên và xác minh đầu mối UDP của client."""

        if username != self.settings.username:
            raise PermissionError(
                "Username must match the account associated with the assigned key"
            )

        if not isinstance(password, str) or not password or len(password.encode()) > 1024:
            raise ValueError("Password must be a non-empty string of at most 1024 UTF-8 bytes")

        # Giới hạn một thao tác đăng nhập tại một thời điểm trên cùng một đối tượng ClientApp
        async with self._login_lock:
            # Client phải hoàn thành connect() và trao đổi HELLO trước khi đăng nhập.
            self._require_state(ClientState.CONNECTED)

            try:
                async with asyncio.timeout(self.settings.handshake_seconds):
                    # Chờ bộ phận nhận phản hồi sẵn sàng.
                    await self._ready.wait()

                    # Kiểm tra lần nữa vì close() cũng gọi _ready.set()
                    self._require_state(ClientState.CONNECTED)

                    # Tạo Future để bộ xử lý phản hồi đặt kết quả hoặc lỗi đăng nhập vào.
                    self._auth_reply = asyncio.get_running_loop().create_future()

                    packet = self._packet(
                        kind=MessageType.AUTH,
                        payload=password.encode(),
                        challenge=self._challenge,
                    )

                    # Bảo vệ gói AUTH rồi gửi tới server qua TCP.
                    await self._send_control(packet)

                    # Chờ tác vụ nhận TCP chuyển phản hồi tới _handle_auth_reply().
                    # Nếu Future được đặt kết quả thì tiếp tục; nếu được đặt lỗi thì phát sinh ngoại lệ.
                    await self._auth_reply

                await self.bind_udp()

            except BaseException:
                await self.close()
                raise

            finally:
                if self._auth_reply is not None and not self._auth_reply.cancelled():
                    if self._auth_reply.done():
                        self._auth_reply.exception()
                    else:
                        self._auth_reply.cancel()

                # Bỏ tham chiếu tới Future của lần xác thực đã kết thúc; mã phiên vẫn được giữ.
                self._auth_reply = None

    async def bind_udp(self) -> None:
        """Gửi UDP_BIND, trả lời thử thách hợp lệ và hoàn tất xác minh đầu mối UDP trước hạn."""

        self._require_state(ClientState.AUTHENTICATED)

        if self._bind_id is not None:
            raise ConnectionError("UDP binding is already in progress or has already completed")

        self._bind_id = secrets.token_hex(16)

        # Khoảng thời gian chờ tín hiệu sau mỗi lượt gửi.
        delay = self.settings.retry_initial_seconds

        try:
            async with asyncio.timeout(self.settings.handshake_seconds):
                for _ in range(self.settings.max_retries + 1):
                    self._require_state(ClientState.AUTHENTICATED)

                    # Đưa cờ về trạng thái chưa bật để lần chờ tiếp theo đợi tín hiệu mớ
                    self._bind_changed.clear()

                    kind = (
                        MessageType.UDP_BIND
                        if self._bind_challenge is None
                        else MessageType.RESPONSE
                    )

                    metadata = {"bind_id": self._bind_id}

                    if self._bind_challenge is not None:
                        metadata["proof"] = self._bind_challenge

                    # Lúc này chỉ gửi, chứ chưa đảm bảo Server đã nhận được gói, Client đã nhận được phản hồi.
                    await self.send_datagram(self._packet(kind, **metadata), self._server_peer)

                    # Chờ Sever xử lí và client nhận phản hồi hợp lệ
                    try:
                        async with asyncio.timeout(delay):
                            await self._bind_changed.wait()
                    except TimeoutError:
                        pass

                    if self.state == ClientState.ONLINE:
                        return

                    delay = min(delay * 2, self.settings.retry_max_seconds)

            raise TimeoutError("BIND_OK was not received within the allowed number of attempts")

        except BaseException:
            self._bind_id = None
            self._bind_challenge = None
            raise

    async def receive_control(self) -> None:
        """Đọc frame điều khiển TCP, xử lý phản hồi xác thực và phát hiện ngắt kết nối."""
        while not self._stop_event.is_set():
            # math.inf: Không đặt thời hạn hữu hạn cho thao tác đọc này
            wire = await read_frame(self._tcp_socket, self.settings.max_frame_bytes, math.inf)

            packet = self._unprotect_server(wire, self.settings.max_frame_bytes)

            await self._handle_control(packet)

    def _unprotect_server(self, wire: bytes, limit: int) -> Packet:
        """Giải mã gói và kiểm tra khóa, định danh server, người nhận và mã phiên."""

        key_id, packet = self.security.unprotect(wire, limit)

        if key_id != self.settings.key_id or packet.sender != "__server__":
            raise PermissionError(
                "Packet must use the expected key and identify the server as its sender"
            )

        if packet.recipient != self.settings.username:
            raise PermissionError("Packet is not addressed to this client")

        if self.session_id is not None and packet.session_id != self.session_id:
            raise PermissionError("Packet belongs to a different session")

        return packet

    async def _handle_control(self, packet: Packet) -> None:
        """Phân loại gói điều khiển TCP, cập nhật trạng thái và phát sự kiện cho giao diện."""

        if packet.kind in {MessageType.AUTH_OK, MessageType.AUTH_ERROR}:
            await self._handle_auth_reply(packet)

        elif packet.kind == MessageType.BIND_OK:
            self._confirm_bind(packet)
            await self.emit_event("state", {"state": self.state.value})

        elif packet.kind == MessageType.USER_LIST:
            self._require_state(ClientState.ONLINE)

            users = packet.metadata.get("users")
            if not isinstance(users, list) or len(users) > self.settings.max_clients:
                raise ValueError("Invalid user list")

            for user in users:
                validate_username(user)

            online_users = list(dict.fromkeys(users))
            if online_users != self._users:
                logger.info(
                    "PRESENCE user=%s online=%d users=%s",
                    self.settings.username,
                    len(online_users),
                    ", ".join(online_users),
                )
            self._users = online_users

            await self.emit_event("users", {"users": self._users})

        elif packet.kind == MessageType.ERROR:
            await self._handle_file_error(packet.metadata)
            await self.emit_event("error", dict(packet.metadata))

        elif packet.kind == MessageType.LOGOUT:
            raise ConnectionError("The server has closed the session")
        else:
            raise ValueError("Message type is not allowed on the TCP control channel")

    async def _handle_file_error(self, metadata: dict[str, object]) -> None:
        """Kết thúc lượt truyền bị lỗi nghiệp vụ mà vẫn giữ phiên chat hoạt động."""
        if metadata.get("scope") != "file" or metadata.get("terminal") is not True:
            return
        identifier, code, reason = (
            metadata.get("transfer_id"),
            metadata.get("code"),
            metadata.get("error"),
        )
        if (
            not isinstance(identifier, str)
            or not isinstance(code, str)
            or code not in TERMINAL_FILE_ERROR_CODES
            or not isinstance(reason, str)
        ):
            return
        try:
            validate_identifier(identifier, "transfer_id", 64)
        except ValueError:
            return
        if any(character in ":." for character in identifier):
            return
        await self.files.fail_transfer(identifier, code, reason)

    async def _handle_auth_reply(self, packet: Packet) -> None:
        """Xử lý kết quả đăng nhập, cập nhật trạng thái và thông báo cho giao diện."""
        if self._auth_reply is None or self._auth_reply.done():
            raise ValueError("AUTH response received without a pending request")

        self._require_state(ClientState.CONNECTED)

        if packet.kind == MessageType.AUTH_ERROR:
            logger.info("AUTH_ERROR user=%s | Login denied", self.settings.username)
            self._auth_reply.set_exception(PermissionError("Login denied"))
            return

        if not isinstance(packet.session_id, str) or not packet.session_id:
            raise ValueError("AUTH_OK is missing a valid session_id")

        limit = packet.metadata.get("max_chat_bytes", self.max_chat_bytes)
        if type(limit) is not int or limit < 0:
            raise ValueError("AUTH_OK has an invalid chat limit")
        self.max_chat_bytes = min(self.max_chat_bytes, limit)

        self.session_id = packet.session_id
        self.state = ClientState.AUTHENTICATED
        logger.info("AUTHENTICATED user=%s | Verifying UDP endpoint", self.settings.username)
        self._auth_reply.set_result(packet)

        await self.emit_event(
            "state", {"state": self.state.value, "max_chat_bytes": self.max_chat_bytes}
        )

    def _confirm_bind(self, packet: Packet) -> None:
        """Kiểm tra xác nhận bind UDP và chuyển client sang trạng thái ONLINE."""
        if self.state not in {ClientState.AUTHENTICATED, ClientState.ONLINE}:
            raise ValueError("BIND_OK received outside the binding phase")

        if self._bind_id is None or packet.metadata.get("bind_id") != self._bind_id:
            raise PermissionError("BIND_OK has an invalid bind_id")

        if self._bind_challenge is None:
            raise ValueError("BIND_OK received before CHALLENGE")

        if self.state != ClientState.ONLINE:
            logger.info("ONLINE user=%s | UDP endpoint confirmed", self.settings.username)
        self.state = ClientState.ONLINE
        self._last_seen = time.monotonic()
        self._bind_changed.set()

    async def receive_datagrams(self) -> None:
        """Nhận, xác thực và chuyển các gói UDP từ server đến hàm xử lý phù hợp."""
        loop = asyncio.get_running_loop()

        while not self._stop_event.is_set():
            try:
                wire, peer = await loop.sock_recvfrom(
                    self._udp_socket, self.settings.max_datagram_bytes + 1
                )
            except ConnectionResetError:
                # Windows báo ICMP "port unreachable" của một gói đã gửi theo cách này.
                continue
            # Bỏ qua gói sai nguồn hoặc đến trước khi có phiên
            if peer != self._server_peer or self.session_id is None:
                continue

            try:
                packet = self._unprotect_server(wire, self.settings.max_datagram_bytes)
            except (ValueError, PermissionError, InvalidToken):
                continue

            if packet.kind == MessageType.CHALLENGE:
                self._handle_challenge(packet)

            elif self.state == ClientState.ONLINE:
                await self._receive_online_packet(packet, peer)

    def _handle_challenge(self, packet: Packet) -> None:
        """Kiểm tra, lưu thử thách UDP và báo cho tác vụ bind tiếp tục xử lý."""
        if self.state != ClientState.AUTHENTICATED or self._bind_id is None:
            return

        if packet.metadata.get("bind_id") != self._bind_id:
            return

        challenge = packet.metadata.get("challenge")

        if not isinstance(challenge, str) or not challenge or len(challenge) > 256:
            return

        # Khi chưa lưu challenge nào và không phải challenge vừa nhận thì return
        if self._bind_challenge not in (None, challenge):
            return

        self._bind_challenge = challenge
        self._bind_changed.set()

    async def _receive_online_packet(self, packet: Packet, peer: Address) -> None:
        """Xử lý ACK, heartbeat và tiếp nhận các gói chat/file khi client online."""

        # Xử lý ACK từ server để xác nhận gói client đã gửi.
        if packet.kind == MessageType.ACK:
            self.channel.acknowledge(packet, peer, time.monotonic())
            return

        if packet.kind == MessageType.HEARTBEAT:
            # Chỉ phản hồi đúng heartbeat gần nhất mới được cập nhật thời gian.
            if packet.metadata.get("reply") is True and packet.message_id == self._heartbeat_id:
                self._last_seen = time.monotonic()
            return

        # Xử lí
        if packet.kind not in FILE_TYPES | CHAT_TYPES:
            return

        queue = self._file_packets if packet.kind in FILE_TYPES else self._chat_packets
        free = queue.maxsize - queue.qsize()

        # Dự phòng đủ chỗ cho cả nhóm gói trước khi tiếp nhận và gửi ACK.
        # Transport đã nhớ gói nhận; gói trùng chỉ cần ACK lại, không chiếm thêm chỗ.
        if free < self._receive_reserve and not self.channel.has_received(packet, peer):
            return

        # Xử lý thứ tự, gói trùng và lấy các gói sẵn sàng chuyển tiếp cùng ACK cần gửi.
        batch = self.channel.receive(packet, peer)

        for item in batch.deliverable:
            item_queue = self._file_packets if item.kind in FILE_TYPES else self._chat_packets

            if item_queue is not queue:
                raise ValueError("A stream must not mix chat and file packets")
            # Ném asyncio.QueueFull ngay khi đầy
            queue.put_nowait(item)

        # Nếu transport tạo ACK, gửi xác nhận về bên gửi.
        if batch.acknowledgement is not None:
            await self.send_datagram(batch.acknowledgement, peer)

        # Có gói được chuyển vào hàng đợi xử lý: ghi nhận server vẫn hoạt động.
        if batch.deliverable:
            self._last_seen = time.monotonic()

    async def _process_packets(self, queue: asyncio.Queue[Packet]) -> None:
        """Lấy gói từ hàng đợi để xử lý và thông báo lỗi cho giao diện."""
        while not self._stop_event.is_set():
            packet = await queue.get()
            try:
                await self.handle_packet(packet)

            except (ValueError, PermissionError, OSError) as error:
                await self.emit_event(
                    "error", {"message": "Could not process packet", "type": type(error).__name__}
                )

            finally:
                queue.task_done()

    async def handle_packet(self, packet: Packet) -> None:
        """Xử lý gói file hoặc chuyển gói chat thành sự kiện cho giao diện."""
        self._require_state(ClientState.ONLINE)

        if packet.sender != "__server__" or packet.session_id != self.session_id:
            raise PermissionError("Packet does not belong to the current server session")

        if packet.kind in FILE_TYPES | {MessageType.MSG_PUBLIC, MessageType.MSG_PRIVATE}:
            origin = packet.metadata.get("origin_user")

            validate_username(origin)

            # Nếu là gói file: chuyển cho bộ quản lý file
            if packet.kind in FILE_TYPES:
                await self.files.handle_packet(replace(packet, sender=origin))
            else:
                # Nếu là chat: ghi log (không ghi nội dung) và tạo sự kiện cho giao diện
                logger.info(
                    "CHAT_RECEIVED user=%s kind=%s from=%s",
                    self.settings.username,
                    "private" if packet.kind == MessageType.MSG_PRIVATE else "public",
                    origin,
                )
                await self.emit_event(
                    "message",
                    {
                        "message_id": packet.message_id,
                        "sender": origin,
                        "recipient": packet.metadata.get("target_user", packet.recipient),
                        "text": packet.payload.decode("utf-8"),
                        "private": packet.kind == MessageType.MSG_PRIVATE,
                    },
                )
        else:
            raise ValueError("Packet is not a chat or file message")

    async def execute(self, command: UICommand) -> dict[str, object]:
        """Tiếp nhận lệnh từ web hoặc kiểm thử, kiểm tra tính hợp lệ và thực thi theo trạng thái client."""
        self.validate_command(command)

        return await self._execute_validated(command)

    @staticmethod
    def validate_command(command: UICommand) -> None:
        """Kiểm tra tên lệnh, các tham số bắt buộc/tùy chọn và kiểu dữ liệu trước khi xử lý."""
        schemas = {
            "login": ({"username", "password"}, set()),
            "users": (set(), set()),
            "public": ({"text"}, set()),
            "private": ({"text", "recipient"}, set()),
            "send_file": ({"path", "recipient"}, set()),
            "cancel_file": ({"transfer_id"}, {"reason"}),
            "logout": (set(), set()),
        }

        if not isinstance(command, UICommand) or command.name not in schemas:
            raise ValueError("Unsupported command")

        required, optional = schemas[command.name]
        args = command.args

        if (
            not isinstance(args, dict)
            or not required <= args.keys()
            or args.keys() - required - optional
        ):
            raise ValueError("Missing or unexpected command arguments")

        for name, value in args.items():
            if name == "path":
                if not isinstance(value, Path):
                    raise ValueError("Bridge must resolve upload_id to a validated Path")
            elif not isinstance(value, str) or not value.strip():
                raise ValueError("Command arguments must be non-empty strings")

    async def _execute_validated(self, command: UICommand) -> dict[str, object]:
        """Thực thi lệnh đã được kiểm tra và trả về kết quả hoặc trạng thái client."""
        args = command.args

        if command.name == "login":
            await self.login(args["username"], args["password"])

        elif command.name == "logout":
            await self.close()

        elif command.name == "users":
            self._require_state(ClientState.ONLINE)
            return {"users": self._users.copy()}

        elif command.name in {"public", "private"}:
            identifier = await self.send_chat(args["text"], args.get("recipient"))
            return {"message_id": identifier, "status": "sent"}

        else:
            return await self._execute_file(command)

        return {"state": self.state.value}

    async def _execute_file(self, command: UICommand) -> dict[str, object]:
        """Thực thi lệnh gửi hoặc hủy truyền tệp; bên nhận tự động chuẩn bị nhận."""
        self._require_state(ClientState.ONLINE)
        args = command.args

        if command.name == "send_file":
            offer = await self.files.offer_file(
                args["path"], self.settings.username, args["recipient"]
            )
            # READY hoặc CANCEL có thể đến trước ACK xác nhận gửi OFFER lên máy chủ.
            status = self._transfers.get(offer.transfer_id, {}).get("status", "OFFERED")
            self._remember_transfer(offer.transfer_id, {**asdict(offer), "status": status})
            if status not in TERMINAL_STATUSES:
                self._spawn(self.files.send_chunks(offer.transfer_id), "send-file", fatal=False)
            return {"transfer_id": offer.transfer_id, "status": "offered"}

        identifier = args["transfer_id"]

        await self.files.cancel(identifier, args.get("reason", "Cancelled by user"))
        return {"transfer_id": identifier, "status": "ok"}

    async def send_chat(self, text: str, recipient: str | None = None) -> str:
        """Gửi tin nhắn công khai hoặc riêng tư một cách tin cậy và trả về mã tin nhắn để theo dõi trên giao diện."""
        self._require_state(ClientState.ONLINE)

        if not isinstance(text, str) or not text.strip():
            raise ValueError("Message must not be empty")

        if recipient is not None:
            validate_username(recipient)
            if recipient == self.settings.username:
                raise ValueError("Cannot send a private message to yourself")

        payload = text.encode("utf-8")
        if len(payload) > self.max_chat_bytes:
            raise ValueError(f"Message exceeds the limit of {self.max_chat_bytes} UTF-8 bytes")

        packet = self._packet(
            MessageType.MSG_PRIVATE if recipient is not None else MessageType.MSG_PUBLIC,
            payload=payload,
            recipient=recipient or "*",
            stream="chat",
        )

        started = time.perf_counter()
        await self.send_message(packet)
        # Thời gian tới khi server ACK (chặng đầu), dùng cho số liệu đo.
        logger.info(
            "CHAT_SENT user=%s kind=%s bytes=%d ack_ms=%.1f",
            self.settings.username,
            "private" if recipient is not None else "public",
            len(payload),
            (time.perf_counter() - started) * 1000,
        )

        return packet.message_id

    async def send_message(self, packet: Packet) -> None:
        """Hàm gọi lại dùng chung cho tin nhắn và tệp, gửi đến máy chủ qua ReliableChannel."""

        self._require_state(ClientState.ONLINE)

        packet = replace(
            packet, sender=self.settings.username, session_id=self.session_id, sequence=0
        )
        # Kiểm tra kích thước trước khi cấp số thứ tự để tránh tạo khoảng trống do gói tin quá lớn.
        self.security.protect(
            replace(packet, sequence=2**63 - 1),
            self.settings.key_id,
            self.settings.max_datagram_bytes,
        )
        try:
            await self.channel.send(packet, self._server_peer)
        except asyncio.CancelledError:
            self._fail(ConnectionError("Send cancelled after handing the packet to the transport"))
            raise
        except Exception as error:
            self._fail(error)
            raise

    async def send_datagram(self, packet: Packet, peer: Address) -> None:
        """Tuần tự hóa, mã hóa gói và gửi một lần qua UDP tới server đã kết nối."""
        if self._udp_socket is None or self._closed:
            raise ConnectionError("UDP socket is closed")

        if peer != self._server_peer:
            raise PermissionError("Client can only send UDP packets to the connected server")

        wire = self.security.protect(
            packet,
            self.settings.key_id,
            self.settings.max_datagram_bytes,
        )

        if len(wire) > self.settings.max_datagram_bytes:
            raise ValueError("Encrypted datagram exceeds the size limit")

        try:
            await asyncio.get_running_loop().sock_sendto(self._udp_socket, wire, peer)
        except OSError as error:
            if self._closed:
                raise
            # Mạng tạm mất (Wi-Fi tắt, rút cáp): coi như gói bị mất; truyền lại và
            # heartbeat sẽ xử lý, phiên chỉ kết thúc khi quá offline_seconds.
            logger.debug("UDP send failed: %s", error)

    async def heartbeat_loop(self) -> None:
        """Kiểm tra server còn hoạt động, độc lập với retry hết hạn file và thao tác đĩa."""
        while not self._stop_event.is_set():
            if self.state == ClientState.ONLINE:
                now = time.monotonic()
                if now - self._last_seen >= self.settings.offline_seconds:
                    raise TimeoutError("Server did not respond to heartbeat")
                packet = replace(
                    self._packet(MessageType.HEARTBEAT, stream="heartbeat", reply=False),
                    sequence=self._heartbeat_sequence,
                )
                self._heartbeat_sequence += 1
                self._heartbeat_id = packet.message_id
                await self.send_datagram(packet, self._server_peer)
            await asyncio.sleep(self.settings.heartbeat_seconds)

    async def expire_files_loop(self) -> None:
        """Dọn lượt truyền hết hạn riêng để việc hủy tin cậy không làm chậm heartbeat."""
        while not self._stop_event.is_set():
            if self.state == ClientState.ONLINE:
                await self.files.expire_idle(time.monotonic())
            await asyncio.sleep(self.settings.heartbeat_seconds)

    async def emit_event(self, name: str, data: dict[str, object]) -> None:
        """Sao chép sự kiện vào hàng đợi UI hữu hạn và xử lý rõ khi hàng đợi đầy."""
        copied = deepcopy(data)
        identifier = copied.get("transfer_id")
        if name == "file_offer":
            copied.setdefault("status", "OFFERED")
        if isinstance(identifier, str) and name.startswith("file_"):
            self._remember_transfer(identifier, copied)
        if name == "file_progress" and self.events.full():
            return  # Keep the latest progress in the snapshot instead of queueing more events.
        try:
            self.events.put_nowait(UIEvent(name, copied))
        except asyncio.QueueFull as error:
            failure = BufferError(
                "UI is not consuming events; stopping the session to avoid losing messages"
            )
            self._fail(failure)
            raise failure from error

    def _remember_transfer(self, identifier: str, data: dict[str, object]) -> None:
        """Gộp cập nhật lượt truyền vào lịch sử snapshot có giới hạn."""
        record = self._transfers.setdefault(identifier, {})
        record.update(data)
        self._transfers.move_to_end(identifier)
        # Một lượt đang hoạt động và lịch sử kết quả gần nhất.
        while len(self._transfers) > 1 + self.settings.max_transfer_history:
            self._transfers.popitem(last=False)

    def snapshot(self) -> dict[str, object]:
        """Trả bản sao trạng thái cho UI/polling, không chứa mật khẩu hoặc khóa."""
        return {
            "username": self.settings.username,
            "state": self.state.value,
            "online": self.state == ClientState.ONLINE,
            "users": self._users.copy(),
            "transfers": deepcopy(list(self._transfers.values())),
            "max_chat_bytes": self.max_chat_bytes,
            "server": f"{self._server_peer[0]}:{self._server_tcp[1]}"
            if self.state in {ClientState.AUTHENTICATED, ClientState.ONLINE}
            else None,
            "error": type(self._failure).__name__ if self._failure else None,
        }

    async def run(self) -> None:
        """Chạy các tác vụ mạng nền cho đến khi có yêu cầu dừng và dọn dẹp phiên khi kết thúc."""
        self._require_state(ClientState.CONNECTED)

        if self._runner is not None:
            raise ConnectionError("Client.run has already been called")

        self._runner = asyncio.current_task()

        try:
            self._spawn(self.receive_control(), "tcp-reader")
            self._spawn(self.receive_datagrams(), "udp-reader")
            self._spawn(self.channel.run(), "reliable-channel")
            self._spawn(self._process_packets(self._chat_packets), "chat-worker")
            self._spawn(self._process_packets(self._file_packets), "file-worker")
            self._spawn(self.heartbeat_loop(), "heartbeat")
            self._spawn(self.expire_files_loop(), "file-expiry")

            self._ready.set()

            await self._stop_event.wait()

            if self._failure is not None:
                raise self._failure

        finally:
            await self.close()

    def _spawn(self, operation: Coroutine, name: str, *, fatal: bool = True) -> None:
        """Quản lý tác vụ nền và chuyển kết quả hoặc lỗi của nó về phiên."""
        task = asyncio.create_task(operation, name=name)
        self._tasks.add(task)

        def completed(done: asyncio.Task) -> None:
            """Bỏ tác vụ đã xong khỏi danh sách và báo lỗi dừng bất ngờ lên UI."""
            self._tasks.discard(done)
            if done.cancelled():
                return
            error = done.exception()
            if self._closed:
                return
            if fatal:
                self._fail(error or ConnectionError(f"Task {name} stopped unexpectedly"))
            elif error is not None:
                try:
                    self.events.put_nowait(
                        UIEvent(
                            "error", {"message": "File send failed", "type": type(error).__name__}
                        )
                    )
                except asyncio.QueueFull:
                    self._fail(
                        BufferError("UI queue is full while reporting a file transfer error")
                    )

        task.add_done_callback(completed)

    def _fail(self, error: Exception) -> None:
        """Ghi lỗi đầu tiên, dừng phiên và đánh thức thao tác xác thực đang chờ."""
        if self._failure is None:
            self._failure = error
            logger.warning(
                "SESSION_FAILURE user=%s reason=%s", self.settings.username, type(error).__name__
            )
        self._stop_event.set()
        self._bind_changed.set()
        if self._auth_reply is not None and not self._auth_reply.done():
            self._auth_reply.set_exception(ConnectionError("Connection ended during login"))

    def _require_state(self, state: ClientState) -> None:
        """Chỉ cho phép thao tác khi phiên còn mở và có đúng trạng thái yêu cầu."""
        if self._closed or self._stop_event.is_set() or self.state != state:
            raise ConnectionError(f"Operation requires state {state.value}")

    def _packet(
        self,
        kind: MessageType,
        *,
        payload: bytes = b"",
        recipient: str = "__server__",
        stream: str = "control",
        **metadata,
    ) -> Packet:
        """Tạo gói gửi với danh tính hiện tại và message_id mới."""
        return Packet(
            kind,
            self.session_id or "",
            self.settings.username,
            recipient,
            stream,
            0,
            secrets.token_hex(16),
            payload,
            metadata,
        )

    async def _send_control(self, packet: Packet) -> None:
        """Mã hóa gói điều khiển và gửi qua TCP theo định dạng frame, dùng khóa để tránh ghi xen kẽ."""

        if self._tcp_socket is None:
            raise ConnectionError("TCP socket is closed")

        wire = self.security.protect(packet, self.settings.key_id, self.settings.max_frame_bytes)

        await write_frame(
            self._tcp_socket,
            wire,
            self._tcp_send_lock,
            self.settings.max_frame_bytes,
        )

    async def close(self) -> None:
        """Thử gửi LOGOUT trong thời hạn ngắn rồi dọn tác vụ, socket và file."""
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            had_connection = self._tcp_socket is not None
            if had_connection:
                logger.info("CLOSING user=%s", self.settings.username)
            self.state = ClientState.CLOSING
            self._stop_event.set()
            self._ready.set()
            self._bind_changed.set()
            if self._auth_reply is not None and not self._auth_reply.done():
                self._auth_reply.set_exception(ConnectionError("Client is closed"))

            try:
                try:
                    if self.session_id and self._tcp_socket is not None:
                        async with asyncio.timeout(self.settings.retry_initial_seconds):
                            await self._send_control(self._packet(MessageType.LOGOUT))
                except (OSError, ValueError, TimeoutError):
                    logging.getLogger(__name__).debug("Could not send LOGOUT; continuing cleanup")
                finally:
                    await self._cancel_tasks()
            finally:
                try:
                    await self.files.close()
                finally:
                    try:
                        await self.channel.close()
                    finally:
                        self._close_sockets()
                        self._tasks.clear()
                        self._challenge = None
                        self._bind_id = None
                        self._bind_challenge = None
                        self._users.clear()
                        self.session_id = None
                        self.state = ClientState.DISCONNECTED
                        if had_connection:
                            logger.info("DISCONNECTED user=%s", self.settings.username)

    async def _cancel_tasks(self) -> None:
        """Hủy và chờ các tác vụ thuộc phiên, trừ tác vụ đang thực hiện cleanup."""
        current = asyncio.current_task()
        tasks = [task for task in self._tasks if task is not current]
        for task in tasks:
            task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logging.getLogger(__name__).error(
                    "Client task ended with error %s", type(result).__name__
                )


class BrowserClient:
    """Keep the local UI alive while replacing failed or logged-out network sessions.

    TCP authentication deadlines begin when the user submits login, not while
    they are opening the page. Each successful retry uses a fresh ClientApp,
    including fresh sockets, reliable-channel state, and file-transfer state.
    When a session fails without a logout (server restart, network outage),
    the client logs in again automatically for up to RECONNECT_WINDOW_SECONDS.
    """

    def __init__(self, settings: Settings) -> None:
        """Tạo trạng thái UI dùng lâu dài và phiên mạng có thể thay mới."""
        self.settings = settings
        self.events: asyncio.Queue[UIEvent] = asyncio.Queue(settings.ui_queue_size)
        self._app = ClientApp(settings)
        self._session_tasks: list[asyncio.Task] = []
        self._session_lock = asyncio.Lock()
        self._stopped = asyncio.Event()
        self._error: str | None = None
        # Thông tin đăng nhập chỉ giữ trong RAM để tự kết nối lại; xóa khi logout.
        self._credentials: dict[str, object] | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._reconnect_attempt = 0

    def snapshot(self) -> dict[str, object]:
        """Trả snapshot của phiên hiện tại kèm lỗi kết nối và số lần đang thử lại."""
        result = self._app.snapshot()
        result["error"] = result["error"] or self._error
        result["reconnecting"] = self._reconnect_attempt
        return result

    async def execute(self, command: UICommand) -> dict[str, object]:
        """Kiểm tra và thực thi lệnh UI; khóa xử lý đăng nhập/đăng xuất, chuyển các lệnh khác cho ClientApp và trả về kết quả."""

        ClientApp.validate_command(command)

        if self._stopped.is_set():
            raise ConnectionError("Client UI has closed")

        if command.name not in {"login", "logout"}:
            return await self._app.execute(command)

        # Người dùng tự đăng nhập/đăng xuất thì dừng vòng tự kết nối lại và bỏ mật khẩu cũ;
        # _login chỉ lưu lại thông tin khi lần đăng nhập mới thành công.
        await self._cancel_reconnect()
        self._credentials = None

        async with self._session_lock:
            if self._stopped.is_set():
                raise ConnectionError("Client UI has closed")
            if command.name == "logout":
                self._credentials = None
                await self._stop_session()
                self._error = None
                self._publish_state()
                return {"state": ClientState.DISCONNECTED.value}

            return await self._login(command)

    async def _login(self, command: UICommand) -> dict[str, object]:
        """Kiểm tra tài khoản, tạo phiên client mới và đăng nhập; dọn phiên nếu lỗi và cập nhật trạng thái UI."""

        if self._app.state not in {ClientState.DISCONNECTED, ClientState.CLOSING}:
            raise ConnectionError("Client already has an active connection")

        if command.args["username"] != self.settings.username:
            raise PermissionError(
                "Username must match the account associated with the configured keys"
            )

        await self._stop_session()
        self._error = None
        self._app = ClientApp(self.settings)

        try:
            await self._app.connect()
            self._session_tasks = [
                asyncio.create_task(self._run_session(self._app)),
                asyncio.create_task(self._forward_events(self._app)),
            ]
            result = await self._app.execute(command)

        except BaseException as error:
            self._error = type(error).__name__
            await self._stop_session()
            self._publish_state()
            raise

        self._credentials = dict(command.args)
        self._reconnect_attempt = 0
        self._publish_state()
        return result

    async def _run_session(self, app: ClientApp) -> None:
        """Chạy phiên client, ghi nhận lỗi và bắt đầu tự kết nối lại nếu phiên rớt."""
        failed = False
        try:
            await app.run()

        except Exception as error:
            failed = True
            self._error = type(error).__name__
            logging.getLogger(__name__).info("Client session ended: %s", self._error)

        finally:
            self._publish_state()
        idle = self._reconnect_task is None or self._reconnect_task.done()
        if (
            failed
            and idle
            and app is self._app
            and self._credentials
            and not self._stopped.is_set()
        ):
            self._reconnect_task = asyncio.create_task(self._reconnect())

    async def _reconnect(self) -> None:
        """Đăng nhập lại bằng thông tin đã lưu, lùi thời gian giữa các lần thử."""
        lost_at = time.monotonic()
        deadline = lost_at + RECONNECT_WINDOW_SECONDS
        delay = RECONNECT_FIRST_DELAY
        try:
            while time.monotonic() < deadline:
                if self._stopped.is_set() or self._credentials is None:
                    return
                self._reconnect_attempt += 1
                attempt = self._reconnect_attempt
                self._publish_state()
                await asyncio.sleep(delay)
                async with self._session_lock:
                    if self._credentials is None or self._stopped.is_set():
                        return
                    if self._app.state not in {ClientState.DISCONNECTED, ClientState.CLOSING}:
                        return  # Đã có phiên mới.
                    try:
                        await self._login(UICommand("login", dict(self._credentials)))
                    except (OSError, ValueError) as error:
                        # PermissionError cũng rơi vào đây: server có thể còn giữ phiên
                        # cũ (đăng nhập trùng) cho tới khi hết offline_seconds.
                        logging.getLogger(__name__).info(
                            "Reconnect attempt %d failed: %s", attempt, type(error).__name__
                        )
                    else:
                        logging.getLogger(__name__).info(
                            "RECONNECTED user=%s attempts=%d after=%.2fs",
                            self.settings.username,
                            attempt,
                            time.monotonic() - lost_at,
                        )
                        return
                delay = min(delay * 2, RECONNECT_MAX_DELAY)
            self._error = "ReconnectFailed"
            self._credentials = None  # Hết thời gian thử: không giữ mật khẩu trong RAM nữa.
        finally:
            self._reconnect_attempt = 0
            self._publish_state()

    async def _cancel_reconnect(self) -> None:
        """Dừng vòng tự kết nối lại, trừ khi chính nó đang gọi."""
        task = self._reconnect_task
        self._reconnect_task = None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _publish_state(self) -> None:
        """Đưa trạng thái hiện tại vào hàng đợi UI; bỏ qua nếu đầy để không chặn xử lý."""
        # Snapshot là nguồn trạng thái chính; việc đóng phiên không được chờ UI.
        with suppress(asyncio.QueueFull):
            self.events.put_nowait(UIEvent("state", self.snapshot()))

    async def _forward_events(self, app: ClientApp) -> None:
        """Liên tục chuyển sự kiện từ phiên client sang hàng đợi phục vụ giao diện."""
        while True:
            await self.events.put(await app.events.get())

    async def _stop_session(self) -> None:
        """Đóng phiên mạng và chờ các tác vụ chuyển tiếp sự kiện kết thúc."""
        await self._app.close()
        current = asyncio.current_task()
        tasks = [task for task in self._session_tasks if task is not current]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._session_tasks.clear()

    async def run(self) -> None:
        """Duy trì client UI qua các lần lỗi mạng; tiến trình sở hữu gọi close() để dừng."""
        await self._stopped.wait()

    async def close(self) -> None:
        """Khóa vòng đời để dừng client UI và đóng phiên mạng an toàn."""
        self._stopped.set()
        await self._cancel_reconnect()
        async with self._session_lock:
            self._credentials = None
            await self._stop_session()
