"""Authenticated sessions, server lifecycle and chat routing.

FileRelayManager owns file-transfer state; ServerApp owns sockets and workers.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import math
import os
import secrets
import socket
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from cryptography.fernet import InvalidToken

from config import Settings
from protocol import (
    FILE_TYPES,
    Address,
    MessageType,
    Packet,
    chat_payload_limit,
    decode_public_control,
    encode_public_control,
    read_frame,
    validate_packet,
    validate_username,
    write_frame,
)
from security import (
    SecurityContext,
    load_keyring,
    verify_password,
)

# Keep the original dataclass imports available to callers of server.py.
from server_relay import FileIngress as FileIngress
from server_relay import FileRelayManager, ForwardItem, OutboundQuota
from server_relay import RelayTransfer as RelayTransfer
from server_relay import SendReservation as SendReservation
from transport import ReliableChannel

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Tài khoản từ file provision; salt/hash là hex, không chứa password thô."""

    username: str
    key_id: int
    password_salt: str
    password_hash: str


@dataclass(slots=True)
class Session:
    """Registry chỉ được cập nhật ở event loop server; UI không sửa trực tiếp."""

    session_id: str
    username: str
    key_id: int
    tcp_socket: socket.socket
    last_seen: float
    udp_address: Address | None = None
    pending_udp_address: Address | None = None
    bind_challenge: str | None = None
    bind_deadline: float = 0.0
    tcp_send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    pending_bind_id: str | None = None  # ID của lần bind đang chờ client chứng minh.
    bind_results: dict[str, tuple[Address, str, float]] = field(default_factory=dict)
    udp_ready: asyncio.Event = field(
        default_factory=asyncio.Event
    )  # Được bật khi server đã xác minh UDP và xếp BIND_OK để gửi.
    # Hàng đợi TCP riêng của từng client.
    # Một client nhận chậm không được làm nghẽn vòng nhận UDP chung.
    control_outbox: asyncio.Queue[Packet] = field(default_factory=lambda: asyncio.Queue(maxsize=64))
    next_control_seq: int = 0  # Sequence cho các thông báo presence server gửi qua TCP.
    data_outbox: asyncio.Queue[ForwardItem] = field(
        default_factory=lambda: asyncio.Queue(maxsize=64)
    )
    file_outbox: asyncio.Queue[ForwardItem] = field(
        default_factory=lambda: asyncio.Queue(maxsize=64)
    )
    outgoing_count: int = 0
    file_outgoing_count: int = 0
    heartbeat_sequence: int = -1
    heartbeat_message_id: str = ""


class UserRegistry:
    """Quản lý user/phiên; không chứa packet serialization hoặc UI."""

    _users: dict[str, UserRecord]
    _sessions: dict[str, Session]
    _max_clients: int

    def __init__(self, users_path: Path, max_clients: int) -> None:
        """Nạp tài khoản từ JSON và chuẩn bị các bảng quản lý phiên."""

        if type(max_clients) is not int or max_clients <= 0:
            raise ValueError("max_clients must be a positive integer")

        # Đọc file thành chuỗi UTF-8, rồi chuyển JSON thành dữ liệu Python.
        records = json.loads(users_path.read_text(encoding="utf-8"))

        if not isinstance(records, list):
            raise ValueError("users.json must contain a list")

        self._users = {}
        self._sessions = {}
        self._by_username: dict[str, str] = {}
        self._max_clients = max_clients

        # Ghi nhớ key_id đã gặp để phát hiện trùng trong lúc đọc file.
        used_keys = set()

        # Mỗi tài khoản phải có đúng bốn trường này.
        expected = {
            "username",
            "key_id",
            "password_salt",
            "password_hash",
        }

        for item in records:
            # Mỗi tài khoản phải là dictionary, không thiếu hoặc thừa trường.
            if not isinstance(item, dict) or set(item) != expected:
                raise ValueError("Invalid user record")

            username = item["username"]
            key_id = item["key_id"]

            # Username phải là chuỗi không rỗng.
            # "__server__" được dành riêng cho định danh của server.
            validate_username(username)

            # Giao thức dành 2 byte cho key_id  và không sử dụng giá trị 0.
            if type(key_id) is not int or not 1 <= key_id <= 65535:
                raise ValueError("Invalid key_id")

            self._validate_password_record(item)

            # Trong thiết kế hiện tại, các tài khoản không được trùng
            # username hoặc dùng chung một key_id.
            if username in self._users or key_id in used_keys:
                raise ValueError("Duplicate username or key_id")

            # Tạo UserRecord từ các trường của dictionary và lưu theo username.
            self._users[username] = UserRecord(**item)

            # Đánh dấu mã khóa đã được sử dụng để kiểm tra tài khoản tiếp theo.
            used_keys.add(key_id)

    @staticmethod
    def _validate_password_record(item: dict) -> None:
        """Yêu cầu salt 16 byte và hash mật khẩu 32 byte được mã hóa dạng hex."""
        # Kiểm tra chung cho salt 16 byte và hash 32 byte.
        # Các giá trị này được lưu dưới dạng chuỗi hex trong JSON.
        for name, size in (("password_salt", 16), ("password_hash", 32)):
            value = item[name]

            # Mỗi byte ứng với 2 ký tự hex:
            # salt cần 32 ký tự, hash cần 64 ký tự.
            if not isinstance(value, str) or len(value) != size * 2:
                raise ValueError(f"Invalid {name}")

            try:
                # Chuyển hex về bytes để kiểm tra các ký tự có hợp lệ không.
                decoded = bytes.fromhex(value)
            except ValueError as error:
                # Báo rõ trường bị lỗi và giữ lại nguyên nhân ban đầu.
                raise ValueError(f"Invalid {name}") from error

            # Kiểm tra số byte thực tế sau chuyển đổi.
            # Cần bước này vì fromhex() có thể bỏ qua khoảng trắng.
            if len(decoded) != size:
                raise ValueError(f"Invalid {name}")

    def _check_login_capacity(self, username: str) -> None:
        """Kiểm tra đăng nhập trùng và giới hạn số phiên của server."""

        if username in self._by_username:
            raise ConnectionError("User is already logged in")

        if len(self._sessions) >= self._max_clients:
            raise ConnectionError("Server is full")

    async def authenticate(
        self,
        username: str,
        password: str,
        key_id: int,
        tcp_socket: socket.socket,
        now: float,
    ) -> Session:
        """Kiểm tra tài khoản/khóa và tạo session khi còn capacity, không cho login trùng."""

        if not isinstance(username, str) or not isinstance(password, str):
            raise PermissionError("Invalid credentials")

        if type(key_id) is not int:
            raise PermissionError("Invalid credentials")

        record = self._users.get(username)

        if record is None or record.key_id != key_id:
            raise PermissionError("Invalid credentials")

        self._check_login_capacity(username)

        valid = await asyncio.to_thread(
            verify_password,
            password,
            record.password_salt,
            record.password_hash,
        )

        if not valid:
            raise PermissionError("Invalid credentials")

        # Kiểm tra lại vì trong lúc await, task khác có thể đã chiếm chỗ cuối
        # hoặc đăng nhập thành công bằng cùng tài khoản này.
        self._check_login_capacity(username)

        # Các kiểm tra đều hợp lệ: tạo phiên cho lần đăng nhập này.
        session = Session(
            session_id=secrets.token_urlsafe(
                32
            ),  # tạo 32 byte ngẫu nhiên, rồi mã hóa thành chuỗi có thể dùng trong URL
            username=username,
            key_id=key_id,
            tcp_socket=tcp_socket,
            # Khởi tạo mốc hoạt động gần nhất bằng thời gian bên gọi truyền vào.
            # Giá trị này không tự cập nhật; phần xử lý hoạt động phải cập nhật sau.
            last_seen=now,
        )

        # session_id -> Session: tra thông tin phiên bằng mã phiên.
        self._sessions[session.session_id] = session

        # username -> session_id: tra phiên theo tài khoản và phát hiện đăng nhập trùng.
        self._by_username[session.username] = session.session_id

        # Trả phiên cho bên gọi tiếp tục xử lý, chẳng hạn gửi AUTH_OK.
        # Hàm này chưa tự gửi phản hồi qua socket.
        return session

    def require_session(self, session_id: str, key_id: int) -> Session:
        """Lấy phiên theo session_id; báo lỗi nếu phiên không tồn tại hoặc key_id không khớp."""

        if not isinstance(session_id, str) or type(key_id) is not int:
            raise PermissionError("Invalid session")

        session = self._sessions.get(session_id)

        if session is None or session.key_id != key_id:
            raise PermissionError("Invalid session")

        return session

    def _prune_bind_results(self, session: Session, now: float) -> None:
        """Xóa các kết quả bind đã hết hạn khỏi phiên, giữ lại những kết quả còn hiệu lực."""
        session.bind_results = {
            bind_id: result
            for bind_id, result in session.bind_results.items()
            if now < result[2]  # bind_id: (address, proof, expires_at)
        }

    def begin_udp_bind(
        self,
        session: Session,
        address: Address,
        now: float,
        timeout: float,
        *,
        bind_id: str | None = None,
    ) -> str:
        """Tạo challenge cho endpoint UDP mới; chỉ thay endpoint cũ sau khi xác minh thành công."""

        if bind_id is None:
            bind_id = secrets.token_hex(16)

        # Không cho một đối tượng Session cũ thay đổi phiên hiện tại.
        if self.require_session(session.session_id, session.key_id) is not session:
            raise PermissionError("Stale session")

        self._prune_bind_results(session, now)

        completed = session.bind_results.get(bind_id)

        #  Trường hợp client gửi lại yêu cầu của một lần bind đã hoàn tất.
        if completed is not None:
            old_address, proof, _ = completed

            if address != old_address or address != session.udp_address:
                raise PermissionError("Old bind belongs to another endpoint")

            return proof

        #  Trường hợp client gửi lại yêu cầu của lần bind đang chờ.
        if session.pending_bind_id == bind_id:
            if address != session.pending_udp_address or now >= session.bind_deadline:
                raise PermissionError("Invalid or expired bind retry")
            return session.bind_challenge

        # Chỉ cho một lần bind đang chờ trên mỗi session.
        if session.pending_bind_id is not None and now < session.bind_deadline:
            raise PermissionError("Another bind is still pending")

        # Giới hạn bộ nhớ lưu kết quả gần đây của một session.
        if len(session.bind_results) >= 8:
            raise PermissionError("Too many recent binds")

        session.pending_bind_id = bind_id
        session.pending_udp_address = address
        session.bind_challenge = secrets.token_hex(16)
        session.bind_deadline = now + timeout

        # Chưa thay udp_address, vì client chưa trả lời challenge.
        return session.bind_challenge

    def confirm_udp_bind(
        self,
        session: Session,
        address: Address,
        proof: str,
        now: float,
        *,
        bind_id: str | None = None,
        retention: float = 30.0,
    ) -> None:
        """Xác minh challenge, hạn và nguồn gửi trước khi coi client ONLINE."""

        if self.require_session(session.session_id, session.key_id) is not session:
            raise PermissionError("Stale session")

        # Nếu không truyền bind_id, dùng mã của lần bind đang chờ xác nhận.
        if bind_id is None:
            bind_id = session.pending_bind_id

        # Không có mã bind để xác định lần cần xác nhận.
        if bind_id is None:
            raise PermissionError("No pending bind")

        if not isinstance(proof, str):
            raise PermissionError("Invalid proof")

        self._prune_bind_results(session, now)

        # Tra kết quả để nhận biết phản hồi của lần bind đã hoàn tất.
        completed = session.bind_results.get(bind_id)

        if completed is not None:
            old_address, old_proof, _ = completed

            # RESPONSE trùng chỉ hợp lệ nếu vẫn đúng endpoint và proof.
            if (
                address != old_address
                or address != session.udp_address
                or not hmac.compare_digest(proof.encode(), old_proof.encode())
            ):
                raise PermissionError("Invalid repeated response")

            # Không tạo phiên mới, không kéo dài thời gian lưu kết quả.
            return

        # Chưa hoàn tất: yêu cầu đúng lần bind đang chờ, đúng địa chỉ,
        # Có challenge, chưa hết hạn và proof khớp challenge.
        if (
            session.pending_bind_id != bind_id
            or address != session.pending_udp_address
            or session.bind_challenge is None
            or now >= session.bind_deadline
            or not hmac.compare_digest(
                proof.encode(),
                session.bind_challenge.encode(),
            )
        ):
            raise PermissionError("Invalid bind response")

        # Tất cả kiểm tra đã đúng: công nhận endpoint.
        session.udp_address = address
        session.last_seen = now

        # Lưu để xử lý RESPONSE gửi lại trong thời gian retention.
        session.bind_results[bind_id] = (
            address,
            proof,
            now + retention,
        )

        # Xóa trạng thái đang chờ.
        session.pending_bind_id = None
        session.pending_udp_address = None
        session.bind_challenge = None
        session.bind_deadline = 0.0

    def touch(self, session_id: str, now: float) -> None:
        """Cập nhật last_seen chỉ khi packet đã xác thực và thuộc phiên hiện tại."""
        session = self._sessions.get(session_id)

        if session is None:
            raise PermissionError("Unknown session")

        # Kiểm tra thời điểm có hợp lệ không
        if not math.isfinite(now):
            raise ValueError("Invalid activity timestamp")

        session.last_seen = max(session.last_seen, now)

    def list_online(self) -> list[str]:
        """Lấy danh sách username đã auth và đã chứng minh endpoint UDP."""
        return sorted(
            session.username
            for session in self._sessions.values()
            if session.udp_address is not None
        )

    def expired_sessions(self, now: float, offline_seconds: float) -> list[Session]:
        """Tìm các session quá hạn để server cleanup tập trung."""
        return [
            session
            for session in self._sessions.values()
            if now - session.last_seen >= offline_seconds
        ]

    def remove(self, session_id: str) -> Session | None:
        """Xóa phiên và liên kết username tương ứng, trả về phiên đã xóa để server dọn tài nguyên."""
        session = self._sessions.pop(session_id, None)

        if session is not None:
            if self._by_username.get(session.username) == session_id:
                self._by_username.pop(session.username)

            return session

    def get_session(self, session_id: str) -> Session | None:
        """Trả về phiên theo session_id"""
        return self._sessions.get(session_id)

    def is_current(self, session: Session) -> bool:
        """ "Kiểm tra session có đúng là đối tượng phiên hiện đang được lưu hay không."""
        return self._sessions.get(session.session_id) is session

    def snapshot(self) -> tuple[Session, ...]:
        """Trả về tuple các phiên hiện có để duyệt an toàn khi các phiên bị thêm hoặc xóa."""
        return tuple(self._sessions.values())

    def prune_bind_results(self, now: float) -> None:
        """Xóa các kết quả bind đã hết hạn khỏi mọi phiên, dựa trên thời điểm now."""
        for session in self.snapshot():
            self._prune_bind_results(session, now)

    def find_user(self, username: str) -> Session | None:
        """Tìm phiên online của người nhận"""
        session_id = self._by_username.get(username)
        session = self._sessions.get(session_id)
        if session is None or session.udp_address is None or not session.udp_ready.is_set():
            return None
        return session


class ServerApp:
    """Quản lý lifecycle, nhận packet và routing; file chỉ được relay qua queue hữu hạn theo đích."""

    settings: Settings
    users: UserRegistry
    security: SecurityContext
    channel: ReliableChannel
    _tcp_socket: socket.socket | None
    _udp_socket: socket.socket | None
    _tasks: set[asyncio.Task[None]]

    def __init__(self, settings: Settings) -> None:
        """Tạo registry/security/channel, hàng đợi và tập task sở hữu bởi app."""

        self.settings = settings
        self.max_chat_bytes = chat_payload_limit(settings.max_datagram_bytes)

        # Chưa khởi động nên chưa có socket lắng nghe
        self._tcp_socket = None

        # Những socket đang giao tiếp với client.
        self._client_sockets: set[socket.socket] = set()

        # Các công việc bất đồng bộ do server tạo ra.
        self._tasks: set[asyncio.Task[None]] = set()

        # Cho biết server đang hoặc đã đóng.
        self._closing = False

        # Tránh hai nơi cùng thực hiện việc đóng server.
        self._close_lock = asyncio.Lock()

        self.users = UserRegistry(
            settings.users_path,
            settings.max_clients,
        )

        # Nạp bảng khóa từ file và tạo bộ xử lý bảo mật.
        # Bảng khóa ánh xạ key_id tới khóa Fernet tương ứng.
        self.security = SecurityContext(load_keyring(settings.keyring_path))

        # socket TCP -> session_id: tra phiên đăng nhập gắn với từng kết nối.
        # Có thể dùng để tìm và dọn phiên khi kết nối đóng.
        self._tcp_sessions: dict[socket.socket, str] = {}

        # socket TCP -> khóa bất đồng bộ: điều phối việc gửi trên từng kết nối.
        # Các task gửi phải cùng sử dụng khóa này để tránh dữ liệu của các packet bị xen kẽ khi nhiều task cùng gửi qua một socket.
        self._tcp_send_locks: dict[socket.socket, asyncio.Lock] = {}

        # Chưa start thì chưa có socket UDP.
        self._udp_socket = None

        # Socket UDP riêng nhận DISCOVER broadcast trong LAN.
        self._discovery_socket: socket.socket | None = None

        # Theo dõi task xử lý TCP của từng client.
        # Dùng để dừng đúng client khi hàng đợi gửi của nó bị đầy.
        self._client_handlers: dict[socket.socket, asyncio.Task] = {}

        # Chỗ giữ packet bao gồm cả reorder buffer và queue đang chờ routing.
        self._chat_slots = 0
        # Chunk file đến khi hàng đợi chuyển tiếp của đích đang đầy: giữ lại, CHƯA ACK,
        # và nhận tiếp ngay khi có chỗ. ACK đến muộn làm bên gửi tự chậm lại theo tốc độ
        # chặng sau (ACK clocking) thay vì mất gói và chờ retry 0,5 s.
        self._parked: dict[tuple[Address, str, str, int], tuple[Packet, Session, Address]] = {}
        self._capacity_freed = asyncio.Event()
        self._incoming_chat = asyncio.Queue(maxsize=settings.max_receive_buffer)
        if type(settings.max_transfer_history) is not int or settings.max_transfer_history < 1:
            raise ValueError("max_transfer_history must be a positive integer")
        for name in (
            "transfer_idle_seconds",
            "completed_retention_seconds",
            "heartbeat_seconds",
            "offline_seconds",
        ):
            value = getattr(settings, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be positive and finite")
        if settings.heartbeat_seconds >= settings.offline_seconds:
            raise ValueError("heartbeat_seconds must be less than offline_seconds")
        self.channel = ReliableChannel(
            settings,
            self.send_datagram,
            local_user="__server__",
            reserve_capacity=self._reserve_chat,
            release_capacity=self._release_chat,
            on_failure=self._transport_failed,
        )
        self.outbound = OutboundQuota(settings, self.users, self.security)
        self.file_relays = FileRelayManager(
            settings, self.users, self.channel, self.outbound, self._queue_control
        )

    @property
    def tcp_address(self) -> Address:
        """Địa chỉ TCP thực sau start, kể cả khi cấu hình port=0 để test."""

        if self._tcp_socket is None:
            raise ConnectionError("Server TCP has not started or has closed")

        # Dùng getsockname() để lấy cổng thực tế, vì khi cấu hình cổng 0, hệ điều hành sẽ tự chọn một cổng trống.
        # Lấy địa chỉ IP và cổng cục bộ mà socket TCP của server đang gắn vào.
        host, port = self._tcp_socket.getsockname()[:2]

        return host, port

    @property
    def udp_address(self) -> Address:
        """Địa chỉ UDP thực sau start để client test kết nối cổng động."""

        if self._udp_socket is None:
            raise ConnectionError("UDP server is not running")

        host, port = self._udp_socket.getsockname()[:2]

        return host, port

    @property
    def discovery_address(self) -> Address:
        """Địa chỉ nhận DISCOVER sau start, kể cả khi cấu hình cổng 0 để test."""
        if self._discovery_socket is None:
            raise ConnectionError("Discovery listener is not running")
        host, port = self._discovery_socket.getsockname()[:2]
        return host, port

    def _discovery_bind_host(self) -> str:
        """Server chỉ nghe loopback thì discovery cũng chỉ ở loopback.

        Còn lại bind 0.0.0.0: socket bind vào một IP unicast cụ thể không nhận được
        datagram gửi tới địa chỉ broadcast 255.255.255.255."""
        try:
            if ipaddress.ip_address(self.settings.bind_host).is_loopback:
                return self.settings.bind_host
        except ValueError:
            pass
        return "0.0.0.0"

    def _open_discovery(self) -> socket.socket | None:
        """Mở socket discovery; nếu cổng bận thì server vẫn chạy, chỉ không trả lời DISCOVER."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            sock.bind((self._discovery_bind_host(), self.settings.discovery_port))
        except OSError as error:
            sock.close()
            logger.warning("DISCOVERY_DISABLED port=%s: %s", self.settings.discovery_port, error)
            return None
        return sock

    async def start(self) -> None:
        """Bind TCP/UDP và chạy các tác vụ nhận gói, lập lịch gửi, watchdog."""

        if self._closing:
            raise RuntimeError("Create a new ServerApp after closing")

        # Đã khởi động thì không mở thêm socket.
        if self._tcp_socket is not None:
            return

        # List chứa các socket
        opened = []

        try:
            # Socket 1: TCP login/control.
            # Socket 2: UDP bind, sau này là chat/file.
            # Socket 3: UDP discovery, trả lời DISCOVER broadcast bằng ANNOUNCE.

            for kind, host, port in (
                (socket.SOCK_STREAM, self.settings.bind_host, self.settings.tcp_port),
                (socket.SOCK_DGRAM, self.settings.bind_host, self.settings.udp_port),
            ):
                # AF_INET: sử dụng địa chỉ IPv4, chẳng hạn 127.0.0.1.
                # kind: quyết định socket TCP hay UDP.
                sock = socket.socket(socket.AF_INET, kind)

                opened.append(sock)

                # Đặt socket ở chế độ không chặn
                sock.setblocking(False)

                # Khởi động lại ngay sau khi tắt: trên Linux/macOS các kết nối cũ ở TIME_WAIT
                # chặn bind nếu thiếu SO_REUSEADDR. Windows không chặn trường hợp này, còn
                # SO_REUSEADDR ở đó lại cho phép chiếm cổng, nên chỉ bật ngoài Windows
                # (giống asyncio.start_server).
                if kind == socket.SOCK_STREAM and os.name != "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Yêu cầu HĐH gán socket với một địa chỉ IP và cổng trên máy server.
                sock.bind((host, port))

            # Chỉ TCP cần listen().
            # Chuyển socket TCP sang trạng thái sẵn sàng nhận yêu cầu kết nối từ client.
            opened[0].listen(self.settings.max_clients)

        except Exception:
            # Nếu một socket không mở được, đóng cả những socket mở trước đó.
            for sock in opened:
                sock.close()
            raise

        self._tcp_socket = opened[0]
        self._udp_socket = opened[1]
        self._discovery_socket = self._open_discovery()

        # Socket đã sẵn sàng; chạy cả vòng nhận, scheduler retry và worker routing.
        for coroutine in (
            self.watchdog(),
            self._chat_worker(),
            self._parked_worker(),
            self.channel.run(),
            self.receive_datagrams(),
            self.accept_clients(),
            self.serve_discovery(),
        ):
            task = asyncio.create_task(coroutine)
            self._tasks.add(task)
            task.add_done_callback(self._tasks_done)

    def _tasks_done(self, task: asyncio.Task[None]) -> None:
        """Bỏ tác vụ đã kết thúc khỏi tập hợp theo dõi và ghi log nếu có lỗi."""

        # Xóa task khỏi tập hợp; nếu không có thì bỏ qua, không báo lỗi.
        self._tasks.discard(task)

        # Nếu task đã bị hủy thì dừng xử lý.
        if task.cancelled():
            return

        # Lấy lỗi khiến task thất bại; nếu hoàn thành bình thường thì nhận None.
        error = task.exception()

        if error is not None:
            logger.error(
                "Server task failed",
                exc_info=(
                    type(error),
                    error,
                    error.__traceback__,
                ),
            )

    async def accept_clients(self) -> None:
        """Chờ kết nối TCP mới và tạo tác vụ xử lý riêng cho mỗi client,
        đồng thời giới hạn số kết nối mà server giữ."""

        # Lấy socket lắng nghe đã được tạo trong start(), không tạo socket mới.
        listener = self._tcp_socket

        if listener is None:
            raise ConnectionError("Server TCP has not started")

        loop = asyncio.get_running_loop()

        # Tiếp tục nhận kết nối khi server chưa bắt đầu đóng.
        while not self._closing:
            # Chờ client kết nối:
            # sock là socket phía server dành riêng cho kết nối vừa nhận.
            # address là địa chỉ của client; listener vẫn chờ các kết nối khác.
            try:
                sock, address = await loop.sock_accept(listener)
            except OSError as error:
                # Một kết nối bị reset trước khi accept (ECONNABORTED) hoặc hết file
                # descriptor (EMFILE) không được làm dừng việc nhận các client khác.
                if self._closing:
                    return
                logger.warning("ACCEPT_FAILED reason=%s: %s", type(error).__name__, error)
                await asyncio.sleep(0.1)
                continue

            sock.setblocking(False)

            if len(self._client_sockets) >= self.settings.max_clients:
                sock.close()
                continue

            self._client_sockets.add(sock)

            # Tạo tác vụ xử lý client, không chờ nó kết thúc tại đây.
            # Vòng lặp có thể tiếp tục nhận các client khác.
            task = asyncio.create_task(self.handle_client(sock, address))
            self._tasks.add(task)

            # Khi tác vụ kết thúc, gọi _task_done(task) để dọn và ghi log lỗi.
            task.add_done_callback(self._tasks_done)

    async def handle_client(self, sock: socket.socket, address: Address | None = None) -> None:
        """Xử lý HELLO/challenge, AUTH bảo vệ và control frame của một kết nối."""

        # Lưu task sở hữu kết nối để có thể dừng riêng một client nhận quá chậm.
        self._client_handlers[sock] = asyncio.current_task()
        send_lock = asyncio.Lock()

        self._tcp_send_locks[sock] = send_lock
        phase = "HELLO"
        # Địa chỉ lấy từ accept(): vẫn ghi được vào log khi client đã reset kết nối
        # trước lúc getpeername() chạy.
        peer = address

        try:
            peer = address or sock.getpeername()
            logger.info("TCP_CONNECTED peer=%s | Waiting for HELLO", peer)
            async with asyncio.timeout(self.settings.handshake_seconds):
                # Đọc đủ một frame TCP và lấy body, không gồm prefix 4 byte.
                body = await read_frame(
                    sock,
                    self.settings.max_frame_bytes,
                    self.settings.handshake_seconds,
                )

                # Mở gói và kiểm tra: ở bước này chỉ chấp nhận HELLO.
                hello = decode_public_control(
                    body,
                    {MessageType.HELLO},
                )
                logger.info("RX TCP HELLO user=%s peer=%s", hello.sender, peer)

                # Tạo 16 byte ngẫu nhiên, biểu diễn thành chuỗi hex 32 ký tự.
                # Challenge sẽ được dùng để kiểm tra ở bước AUTH
                challenge = secrets.token_hex(16)

                reply = Packet(
                    kind=MessageType.HELLO_ACK,
                    session_id="",
                    sender="__server__",
                    recipient=hello.sender,
                    stream_id=hello.stream_id,
                    sequence=0,
                    message_id=f"hello-ack:{hello.message_id}",
                    payload=b"",
                    metadata={
                        "challenge": challenge,  # Gửi challenge cho client.
                    },
                )

                await write_frame(
                    sock,
                    encode_public_control(reply),
                    send_lock,
                    self.settings.max_frame_bytes,
                )
                logger.info("TX TCP HELLO_ACK user=%s", hello.sender)

            phase = "AUTH"
            async with asyncio.timeout(self.settings.handshake_seconds):
                body = await read_frame(
                    sock,
                    self.settings.max_frame_bytes,
                    self.settings.handshake_seconds,
                )

                key_id, packet = self.security.unprotect(
                    body,
                    self.settings.max_frame_bytes,
                )

                await self.handle_control(
                    packet,
                    key_id,
                    sock,
                    challenge,
                )

            # AUTH thất bại: đã gửi AUTH_ERROR, kết thúc kết nối.
            if sock not in self._tcp_sessions:
                return

            session_id = self._tcp_sessions[sock]
            session = self.users.get_session(session_id)
            if session is not None:
                await self._serve_authenticated(session)

        except (ValueError, OSError, InvalidToken) as error:
            # Ghi lý do kết thúc khi dữ liệu không hợp lệ, hết hạn chờ hoặc gặp lỗi kết nối thuộc các nhóm trên
            logger.info(
                "CONNECTION_CLOSED peer=%s phase=%s reason=%s: %s",
                peer,
                phase,
                type(error).__name__,
                error,
            )

        finally:
            # Dọn tài nguyên khi thoát khối try, kể cả khi có lỗi hoặc return.
            removed = None
            session_id = self._tcp_sessions.pop(sock, None)

            if session_id is not None:
                removed = self.users.remove(session_id)
                if removed is not None:
                    self._cleanup_session(removed)
                    logger.info(
                        "DISCONNECTED user=%s online=%d",
                        removed.username,
                        len(self.users.list_online()),
                    )

            self._tcp_send_locks.pop(sock, None)
            self._client_handlers.pop(sock, None)
            self._client_sockets.discard(sock)
            sock.close()

            # User rời đi thì gửi danh sách mới cho những người còn online.
            if removed is not None and removed.udp_address is not None and not self._closing:
                await self.broadcast_users()

    async def handle_control(
        self, packet: Packet, key_id: int, sock: socket.socket, challenge: str
    ) -> None:
        """Auth/control dispatch sau decode; đối chiếu challenge, key và socket sở hữu phiên."""

        validate_packet(packet)
        # Chỉ nhận AUTH trên kết nối chưa được gắn với một phiên đăng nhập.
        if packet.kind != MessageType.AUTH or sock in self._tcp_sessions:
            raise ValueError("Expected the first AUTH on this connection")
        logger.info("RX TCP AUTH user=%s", packet.sender)

        try:
            received = packet.metadata["challenge"]

            # compare_digest() so sánh theo cách hạn chế rò rỉ qua thời gian;
            if not hmac.compare_digest(
                received.encode("utf-8"),
                challenge.encode("utf-8"),
            ):
                raise PermissionError("Invalid challenge")

            session = await self.users.authenticate(
                packet.sender,
                packet.payload.decode("utf-8"),
                key_id,
                sock,
                time.monotonic(),  # monotonic() cung cấp mốc thời gian để theo dõi hoạt động của phiên
            )

        except (PermissionError, ConnectionError):
            # Xác thực không hợp lệ, tài khoản đã đăng nhập hoặc server đầy:
            reply_kind = MessageType.AUTH_ERROR
            session_id = ""
            metadata = {"error": "Authentication failed"}

        else:
            # Dùng cùng một đối tượng khóa gửi cho phiên và kết nối TCP.
            # Các task gửi qua socket này phải dùng chung khóa để phối hợp.
            session.tcp_send_lock = self._tcp_send_locks[sock]
            session.control_outbox = asyncio.Queue(maxsize=self.settings.max_peer_pending)
            # Chuẩn bị toàn bộ queue trước await gửi AUTH_OK. Client có thể bind
            # trong lúc write_frame nhường event loop; không thay queue đã nhận data.
            session.data_outbox = asyncio.Queue(maxsize=self.settings.max_peer_pending)
            session.file_outbox = asyncio.Queue(maxsize=self.settings.max_peer_pending)

            self._tcp_sessions[sock] = session.session_id

            reply_kind = MessageType.AUTH_OK
            logger.info("AUTHENTICATED user=%s | Waiting for UDP bind", session.username)
            session_id = session.session_id
            metadata = {"max_chat_bytes": self.max_chat_bytes}

        reply = Packet(
            kind=reply_kind,
            session_id=session_id,
            sender="__server__",
            recipient=packet.sender,
            stream_id=packet.stream_id,
            sequence=packet.sequence,
            message_id=f"auth-result:{packet.message_id}",
            payload=b"",
            metadata=metadata,
        )

        # Bảo vệ packet bằng khóa ứng với key_id, với giới hạn kích thước đã cấu hình.
        body = self.security.protect(
            reply,
            key_id,
            self.settings.max_frame_bytes,
        )

        await write_frame(
            sock,
            body,
            self._tcp_send_locks[sock],
            self.settings.max_frame_bytes,
        )
        logger.info("TX TCP %s user=%s", reply_kind.value, packet.sender)

    def _queue_control(self, session: Session, kind: MessageType, metadata: dict) -> bool:
        """Xếp control vào queue riêng, không chặn vòng nhận UDP vì TCP chậm."""

        packet = Packet(
            kind=kind,
            session_id=session.session_id,
            sender="__server__",
            recipient=session.username,
            stream_id="presence",
            sequence=session.next_control_seq,
            message_id=secrets.token_hex(16),
            payload=b"",
            metadata=dict(metadata),
        )
        try:
            session.control_outbox.put_nowait(packet)
        except asyncio.QueueFull:
            # Không bỏ âm thầm BIND_OK/USER_LIST. Kết thúc phiên nhận quá chậm;
            # finally của handle_client sẽ dọn socket và thông báo user rời đi.
            owner = self._client_handlers.get(session.tcp_socket)
            if owner is not None:
                owner.cancel()
            return False

        session.next_control_seq += 1
        return True

    async def _control_writer(self, session: Session) -> None:
        """Gửi control theo thứ tự FIFO, luôn dùng lock ghi của kết nối."""

        while True:
            packet = await session.control_outbox.get()
            try:
                wire = self.security.protect(
                    packet,
                    session.key_id,
                    self.settings.max_frame_bytes,
                )
                async with asyncio.timeout(self.settings.handshake_seconds):
                    await write_frame(
                        session.tcp_socket,
                        wire,
                        session.tcp_send_lock,
                        self.settings.max_frame_bytes,
                    )
                logger.info("TX TCP %s user=%s", packet.kind.value, session.username)
            finally:
                session.control_outbox.task_done()

    async def _wait_initial_bind(self, session: Session) -> None:
        """Giới hạn thời gian từ AUTH xong tới khi chứng minh được UDP."""

        async with asyncio.timeout(self.settings.handshake_seconds):
            await session.udp_ready.wait()

    async def _serve_authenticated(self, session: Session) -> None:
        """Giữ TCP sau AUTH; một reader, một writer và một deadline bind."""

        try:
            # TaskGroup chờ/cancel đủ task con khi kết nối kết thúc.
            async with asyncio.TaskGroup() as group:
                writer = group.create_task(self._control_writer(session))
                bind_guard = group.create_task(self._wait_initial_bind(session))
                data_writer = group.create_task(self._data_writer(session))

                try:
                    # Sau AUTH, client chỉ gửi LOGOUT qua TCP; đọc một frame là đủ.
                    wire = await read_frame(
                        session.tcp_socket,
                        self.settings.max_frame_bytes,
                        self.settings.handshake_seconds,
                        wait_for_data=True,
                    )
                    key_id, packet = self.security.unprotect(
                        wire,
                        self.settings.max_frame_bytes,
                    )
                    validate_packet(packet)

                    if (
                        key_id != session.key_id
                        or packet.session_id != session.session_id
                        or packet.sender != session.username
                        or packet.recipient != "__server__"
                    ):
                        raise PermissionError("Invalid TCP session identity")

                    if packet.kind != MessageType.LOGOUT:
                        raise ValueError("Unsupported TCP control")
                    logger.info("RX TCP LOGOUT user=%s", session.username)

                finally:
                    writer.cancel()
                    bind_guard.cancel()
                    data_writer.cancel()

        except* (OSError, ValueError, InvalidToken) as errors:
            # TaskGroup gom lỗi task con thành ExceptionGroup.
            # Không bắt CancelledError: close() phải dừng được cả kết nối.
            logger.info(
                "SESSION_ENDED user=%s reason=%s",
                session.username,
                ", ".join(type(error).__name__ for error in errors.exceptions),
            )

    async def receive_datagrams(self) -> None:
        """Nhận UDP, unprotect, validate session và đưa vào hàng đợi hữu hạn."""

        loop = asyncio.get_running_loop()

        while True:
            try:
                # Đọc cả datagram IPv4, sau đó mới kiểm tra giới hạn ứng dụng.
                # Tránh đọc thiếu rồi hiểu nhầm một datagram bị cắt là hợp lệ.
                # wire: Dữ liệu nhận được dưới dạng bytes
                # peer: Tuple (IP nguồn, cổng nguồn) của datagram
                wire, peer = await loop.sock_recvfrom(
                    self._udp_socket,
                    65535,
                )

                if len(wire) > self.settings.max_datagram_bytes:
                    continue

                # Kiểm tra envelope, giải mã và validate packet.
                key_id, packet = self.security.unprotect(
                    wire,
                    self.settings.max_datagram_bytes,
                )

                # peer là địa chỉ nguồn do hệ điều hành cung cấp.
                await self.dispatch_packet(packet, peer, key_id)

            except (ValueError, InvalidToken):
                # Một packet không hợp lệ không được làm chết server.
                # Không bắt CancelledError để close() vẫn dừng task được.
                continue
            except OSError as error:
                # OSError gồm PermissionError, ConnectionError, TimeoutError và cả lỗi
                # gửi ACK/heartbeat như EHOSTUNREACH, ENOBUFS: chỉ mất một datagram,
                # vòng nhận UDP chung vẫn chạy cho các phiên khác.
                if self._closing or self._udp_socket is None:
                    return
                if not isinstance(error, (PermissionError, ConnectionError, TimeoutError)):
                    logger.warning("UDP_ERROR ignored reason=%s: %s", type(error).__name__, error)
                    await asyncio.sleep(0.01)  # Không quay vòng nếu lỗi lặp lại liên tục.
                continue

    async def serve_discovery(self) -> None:
        """Trả lời DISCOVER broadcast bằng ANNOUNCE gửi thẳng về địa chỉ nguồn.

        Gói không mã hóa vì client chưa đăng nhập; ANNOUNCE chỉ có cổng và số người
        online, không có username. Một ANNOUNCE giả chỉ dẫn client tới server không
        có khóa của user, nên AUTH sẽ thất bại thay vì lộ mật khẩu."""
        loop = asyncio.get_running_loop()
        while self._discovery_socket is not None:
            try:
                data, peer = await loop.sock_recvfrom(self._discovery_socket, 2048)
                request = decode_public_control(data, {MessageType.DISCOVER})
                reply = Packet(
                    MessageType.ANNOUNCE,
                    "",
                    "__server__",
                    "*",
                    request.stream_id,
                    0,
                    f"announce:{request.message_id}"[:128],
                    metadata={
                        "tcp_port": self.tcp_address[1],
                        "udp_port": self.udp_address[1],
                        "online": len(self.users.list_online()),
                        "capacity": self.settings.max_clients,
                    },
                )
                async with asyncio.timeout(self.settings.retry_initial_seconds):
                    await loop.sock_sendto(
                        self._discovery_socket, encode_public_control(reply), peer
                    )
                logger.debug("DISCOVER from=%s | ANNOUNCE sent", peer)
            except (ValueError, OSError) as error:
                if self._closing or self._discovery_socket is None:
                    return
                logger.debug("Discovery datagram ignored: %s", error)

    async def dispatch_packet(self, packet: Packet, peer: Address, key_id: int) -> None:
        """Điều phối bind, heartbeat, chat, file và ACK tới module đúng."""
        # Session phải tồn tại và thuộc đúng key đã giải mã packet.

        validate_packet(packet)
        session = self.users.require_session(packet.session_id, key_id)

        if packet.sender != session.username or (
            packet.kind not in {MessageType.MSG_PRIVATE, MessageType.MSG_PUBLIC} | FILE_TYPES
            and packet.recipient != "__server__"
        ):
            raise PermissionError("Packet identity does not match session")

        now = time.monotonic()

        if packet.kind in {MessageType.UDP_BIND, MessageType.RESPONSE}:
            logger.info("RX UDP %s user=%s peer=%s", packet.kind.value, session.username, peer)
            await self._dispatch_bind(packet, session, peer, now)
            return

        if peer != session.udp_address or not session.udp_ready.is_set():
            raise PermissionError("Data must come from the verified UDP endpoint")

        if packet.kind == MessageType.ACK:
            if self.channel.acknowledge(packet, peer, now):
                self.users.touch(session.session_id, now)
            return

        if packet.kind == MessageType.HEARTBEAT:
            await self._heartbeat(packet, session, peer, now)
            return

        await self._receive_data(packet, session, peer, now)

    async def _receive_data(
        self, packet: Packet, session: Session, peer: Address, now: float
    ) -> None:
        """Giữ chỗ, giao gói đúng thứ tự và gửi ACK xác nhận chặng hiện tại."""
        if not self._validate_data(packet, session, peer, now):
            return

        try:
            batch = self.channel.receive(packet, peer)
        except (ValueError, ConnectionError) as error:
            # Invalid application packets remain unacknowledged; business failures
            # are admitted as terminal file records by FileRelayManager instead.
            self._report_packet_error(session, packet, str(error))
            return

        for ready in batch.deliverable:
            self._incoming_chat.put_nowait((ready, peer, session))

        if batch.acknowledgement is not None:
            if not batch.duplicate:
                self.users.touch(session.session_id, now)
            # Bản gửi lại đã được nhận thẳng: bỏ bản cũ đang giữ để khỏi xử lý lại.
            self._parked.pop((peer, packet.session_id, packet.stream_id, packet.sequence), None)

            await self.send_datagram(batch.acknowledgement, peer)
        elif packet.kind == MessageType.FILE_DATA and self.channel.can_accept(packet, peer):
            # Gói hợp lệ, nằm trong cửa sổ, chỉ thiếu chỗ chuyển tiếp: giữ lại chờ chỗ.
            self._park(packet, session, peer)

    def _park(self, packet: Packet, session: Session, peer: Address) -> None:
        """Giữ chunk chưa ACK; bản gửi lại trùng khóa chỉ thay bản cũ, không tăng số lượng."""
        key = (peer, packet.session_id, packet.stream_id, packet.sequence)
        if key not in self._parked and len(self._parked) >= self.settings.max_receive_buffer:
            return  # Quá giới hạn: bỏ như trước, bên gửi sẽ gửi lại.
        self._parked[key] = (packet, session, peer)

    async def _parked_worker(self) -> None:
        """Mỗi khi có chỗ được trả, nhận lại các chunk đang giữ theo thứ tự đến."""
        while True:
            await self._capacity_freed.wait()
            self._capacity_freed.clear()
            for key, (packet, session, peer) in tuple(self._parked.items()):
                if key not in self._parked:
                    continue
                if not self.users.is_current(session):
                    self._parked.pop(key, None)
                    continue
                try:
                    # Nhận được thì _receive_data bỏ khóa; chưa có chỗ thì _park ghi đè
                    # đúng khóa cũ nên gói vẫn giữ vị trí đầu hàng.
                    await self._receive_data(packet, session, peer, time.monotonic())
                except (ValueError, OSError) as error:
                    self._parked.pop(key, None)
                    logger.debug("Parked packet dropped: %s", error)
                    continue
                if key in self._parked:
                    break  # Vẫn chưa có chỗ: giữ thứ tự, chờ lần trả chỗ tiếp theo.

    async def _dispatch_bind(
        self, packet: Packet, session: Session, peer: Address, now: float
    ) -> None:
        """Xử lý UDP_BIND và RESPONSE để xác minh địa chỉ UDP, xác nhận bind và cập nhật danh sách online."""
        # Sau khi có data, đổi endpoint cần login phiên mới để hai đầu không lệch seq.
        if (
            session.udp_address is not None
            and session.udp_address != peer
            and self.channel.has_session(session.udp_address, session.session_id)
        ):
            raise PermissionError(
                "Reconnect before changing the UDP endpoint of an active data session"
            )

        if packet.kind == MessageType.UDP_BIND:
            bind_id = packet.metadata["bind_id"]

            challenge = self.users.begin_udp_bind(
                session,
                peer,
                now,
                self.settings.handshake_seconds,
                bind_id=bind_id,
            )

            reply = Packet(
                MessageType.CHALLENGE,
                session.session_id,
                "__server__",
                session.username,
                packet.stream_id,
                0,
                f"challenge:{bind_id}",
                metadata={
                    "bind_id": bind_id,
                    "challenge": challenge,
                },
            )

            # Gửi challenge về chính địa chỉ vừa gửi UDP_BIND.
            await self.send_datagram(reply, peer)
            logger.info("TX UDP CHALLENGE user=%s", session.username)
            return

        if packet.kind == MessageType.RESPONSE:
            bind_id = packet.metadata["bind_id"]

            self.users.confirm_udp_bind(
                session,
                peer,
                packet.metadata["proof"],
                now,
                bind_id=bind_id,
                retention=self.settings.completed_retention_seconds,
            )

            was_online = session.udp_ready.is_set()

            # BIND_OK phải vào hàng đợi trước USER_LIST.
            if self._queue_control(
                session,
                MessageType.BIND_OK,
                {"bind_id": bind_id},
            ):
                session.udp_ready.set()

                # RESPONSE trùng chỉ cần xác nhận lại.
                # Không cần broadcast danh sách không thay đổi.
                if not was_online:
                    logger.info(
                        "ONLINE user=%s udp=%s online=%d",
                        session.username,
                        peer,
                        len(self.users.list_online()),
                    )
                    await self.broadcast_users()

            return

    def _validate_data(self, packet: Packet, session: Session, peer: Address, now: float) -> bool:
        """Kiểm giới hạn chat và quyền sở hữu gói file gửi lại trước khi tiếp nhận."""
        if packet.kind in FILE_TYPES and self.channel.has_received(packet, peer):
            # A retry skips admission, but must still belong to the original parties.
            # inspect skips phase/endpoint checks for an already consumed sequence.
            try:
                self.file_relays.inspect(packet, session, peer)
            except (ValueError, ConnectionError) as error:
                self._report_packet_error(session, packet, str(error))
                return False

        if packet.kind in {MessageType.MSG_PRIVATE, MessageType.MSG_PUBLIC}:
            if (
                packet.stream_id != "chat"
                or not 1 <= len(packet.message_id) <= 255
                or not packet.payload
            ):
                raise ValueError("Chat requires stream, message ID and text")
            packet.payload.decode("utf-8")  # Validate trước ACK; codec vẫn hỗ trợ binary.
            if len(packet.payload) > self.max_chat_bytes:
                raise ValueError("Chat exceeds negotiated byte limit")
            if packet.kind == MessageType.MSG_PRIVATE and packet.recipient in {"*", "__server__"}:
                raise ValueError("Private chat requires a username")

        if (
            packet.kind
            not in {
                MessageType.MSG_PRIVATE,
                MessageType.MSG_PUBLIC,
            }
            | FILE_TYPES
        ):
            raise ValueError("Unsupported UDP message")
        return True

    async def _heartbeat(self, packet: Packet, session: Session, peer: Address, now: float) -> None:
        """Từ chối heartbeat cũ, cập nhật hoạt động phiên và phản hồi heartbeat hợp lệ."""
        if packet.sequence < session.heartbeat_sequence:
            raise PermissionError("Stale heartbeat")

        if packet.sequence == session.heartbeat_sequence:
            if packet.message_id != session.heartbeat_message_id:
                raise PermissionError("Heartbeat sequence reused")
        else:
            session.heartbeat_sequence = packet.sequence
            session.heartbeat_message_id = packet.message_id
            self.users.touch(session.session_id, now)

        reply = replace(
            packet, sender="__server__", recipient=session.username, metadata={"reply": True}
        )

        await self.send_datagram(reply, peer)

    def _reserve_chat(self, packet: Packet, peer: Address) -> bool:
        """Giữ ingress và, với file, cả egress của đích TRƯỚC khi ACK."""
        if self._chat_slots >= self.settings.max_receive_buffer:
            return False
        if packet.kind in FILE_TYPES:
            source = self.users.get_session(packet.session_id)
            if source is None or not self.file_relays.reserve(packet, source, peer):
                return False
        self._chat_slots += 1
        return True

    def _release_chat(self, packet: Packet, peer: Address) -> None:
        """Giải phóng dung lượng đã giữ cho file và vị trí trong hàng đợi nhận chung."""
        self.file_relays.release(packet, peer)
        self._chat_slots -= 1
        if self._parked:
            self._capacity_freed.set()

    async def _chat_worker(self) -> None:
        """Chuyển tiếp gói đã nhận và luôn giải phóng dung lượng đã giữ, kể cả khi có lỗi."""
        while True:
            packet, peer, source = await self._incoming_chat.get()
            try:
                if self.users.is_current(source):
                    if packet.kind in FILE_TYPES:
                        self.file_relays.relay(packet, source)
                    else:
                        await self.route_message(packet, source)
            except (OSError, ValueError) as error:
                # Lỗi một yêu cầu không làm chết worker chung của những người khác.
                self._report_packet_error(source, packet, str(error))
            finally:
                self._release_chat(packet, peer)
                self._incoming_chat.task_done()

    def _transport_failed(self, peer: Address, session_id: str, error: Exception) -> None:
        """Dừng đúng tác vụ sở hữu TCP để khối finally của nó dọn phiên."""
        session = self.users.get_session(session_id)
        if session is None or session.udp_address != peer:
            return
        session.udp_ready.clear()
        logger.info("UDP session ended for %s: %s", session.username, error)
        handler = self._client_handlers.get(session.tcp_socket)
        if handler is not None and not handler.done() and not handler.cancelling():
            handler.cancel()

    async def _data_writer(self, session: Session) -> None:
        """Số worker hữu hạn cho mỗi đích; đích chậm không giữ vòng nhận UDP."""
        async with asyncio.TaskGroup() as group:
            # Chat luôn có worker riêng, không phải xếp sau các worker đang chờ ACK file.
            group.create_task(self._data_sender(session, session.data_outbox))
            for _ in range(
                max(
                    1,
                    min(
                        self.settings.window_packets - 1,
                        self.settings.max_peer_pending - 1,
                    ),
                )
            ):
                group.create_task(self._data_sender(session, session.file_outbox))

    async def _data_sender(self, session: Session, outbox: asyncio.Queue[ForwardItem]) -> None:
        """Gửi gói trong hàng đợi tin cậy, trả quota và ngắt phiên đích nếu gửi thất bại."""
        while True:
            item = await outbox.get()
            try:
                transfer = item.reservation.transfer
                if (
                    transfer is not None
                    and transfer.terminal
                    and item.packet.kind
                    not in {
                        MessageType.FILE_RESULT,
                        MessageType.CANCEL,
                    }
                ):
                    continue  # Chưa cấp seq: bỏ việc đã hủy không tạo lỗ transport.
                await self.send_to_session(item.packet, session)

            except (OSError, ValueError) as error:
                self._report_forward_failure(item)
                await self.disconnect(session.session_id, str(error))
                return
            except asyncio.CancelledError:
                self._report_forward_failure(item)
                raise
            finally:
                # Bao gồm thời gian đang gửi/chờ ACK, không chỉ thời gian nằm trong queue.
                self.outbound.release(item.reservation)
                outbox.task_done()
                if self._parked:
                    self._capacity_freed.set()

    async def route_message(self, packet: Packet, source: Session) -> None:
        """Chuyển chat tới các đích online, không gửi lại bản sao cho chính nguồn."""
        if packet.kind == MessageType.MSG_PUBLIC:
            destinations = self.users.snapshot()
        else:
            recipient = self.users.find_user(packet.recipient)
            if recipient is None or recipient is source:
                self._report_packet_error(
                    source,
                    packet,
                    "Recipient is offline"
                    if recipient is None
                    else "Cannot send a private message to yourself",
                )
                return
            destinations = (recipient,)

        for destination in destinations:
            if destination is source or not destination.udp_ready.is_set():
                continue
            try:
                self._queue_chat(packet, source, destination)
            except ValueError as error:
                self._report_packet_error(source, packet, str(error))
            except asyncio.QueueFull:
                # Không âm thầm bỏ message đã ACK. Báo lỗi và dừng đích quá chậm.
                self._report_packet_error(source, packet, "Recipient queue is full")
                await self.disconnect(destination.session_id, "Outgoing chat queue is full")

    def _queue_chat(self, packet: Packet, source: Session, destination: Session) -> None:
        """Tạo gói relay, kiểm kích thước và giữ chỗ trong hàng đợi của đích."""
        outgoing = replace(
            packet,
            sender="__server__",
            recipient=destination.username,
            session_id=destination.session_id,
            sequence=0,
            metadata={
                "origin_user": source.username,
                "target_user": packet.recipient,
            },
        )

        self.outbound.check_size(outgoing, destination)

        reservation = self.outbound.reserve(destination)
        if reservation is None:
            raise asyncio.QueueFull

        try:
            destination.data_outbox.put_nowait(
                ForwardItem(outgoing, reservation, source.session_id)
            )
        except BaseException:
            self.outbound.release(reservation)
            raise

    def _report_packet_error(self, source: Session, packet: Packet, reason: str) -> None:
        """Báo lỗi gắn với tin nhắn và lượt truyền gốc khi phiên nguồn còn tồn tại."""
        metadata = {"error": reason, "message_id": packet.message_id}
        if "transfer_id" in packet.metadata:
            metadata["transfer_id"] = packet.metadata["transfer_id"]
        if self.users.is_current(source):
            self._queue_control(source, MessageType.ERROR, metadata)

    def _report_forward_failure(self, item: ForwardItem) -> None:
        """Báo lỗi chat đã xác định khi chuyển tiếp, không theo dõi receipt giao nhận."""
        if self._closing or item.source_id is None:
            return
        source = self.users.get_session(item.source_id)
        if source is not None:
            self._queue_control(
                source,
                MessageType.ERROR,
                {
                    "error": "Recipient disconnected before reliable send completed",
                    "message_id": item.packet.message_id,
                    "recipient": item.packet.recipient,
                },
            )

    async def broadcast_users(self) -> None:
        """Gửi snapshot danh sách online tới các phiên còn sống."""

        names = self.users.list_online()
        for session in self.users.snapshot():
            if session.udp_ready.is_set() and session.udp_address is not None:
                self._queue_control(session, MessageType.USER_LIST, {"users": names})

    async def send_to_session(self, packet: Packet, destination: Session) -> None:
        """Gửi message tin cậy tới endpoint đã verify của một user."""
        if (
            not self.users.is_current(destination)
            or destination.udp_address is None
            or not destination.udp_ready.is_set()
        ):
            raise ConnectionError("Destination is offline")
        outgoing = replace(
            packet,
            session_id=destination.session_id,
            sender="__server__",
            recipient=destination.username,
        )
        await self.channel.send(outgoing, destination.udp_address)

    async def send_datagram(self, packet: Packet, peer: Address) -> None:
        """Gửi một lần cho ReliableChannel; chọn khóa của đích và bảo vệ gói trước khi gửi."""

        # Lookup bằng session ID để không gửi sang phiên mới của cùng username.
        session = self.users.get_session(packet.session_id)

        if session is None or packet.recipient != session.username:
            raise PermissionError("Unknown destination session")

        # CHALLENGE được phép gửi tới endpoint đang kiểm chứng.
        if peer not in (
            session.pending_udp_address,
            session.udp_address,
        ):
            raise PermissionError("Unexpected destination endpoint")

        wire = self.security.protect(
            packet,
            session.key_id,
            self.settings.max_datagram_bytes,
        )

        # Hàm này gửi đúng một lần.
        # Client chịu trách nhiệm retry quá trình bootstrap.
        async with asyncio.timeout(self.settings.retry_initial_seconds):
            await asyncio.get_running_loop().sock_sendto(
                self._udp_socket,
                wire,
                peer,
            )

    async def watchdog(self) -> None:
        """Chỉ áp dụng offline_seconds cho phiên ONLINE; bước bind ban đầu có thời hạn riêng."""
        interval = min(
            1.0,
            self.settings.heartbeat_seconds,
            self.settings.offline_seconds / 4,
            self.settings.completed_retention_seconds / 4,
        )
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            for session in self.users.expired_sessions(now, self.settings.offline_seconds):
                if (
                    session.udp_ready.is_set()
                    and now - session.last_seen >= self.settings.offline_seconds
                ):
                    await self.disconnect(session.session_id, "Heartbeat timeout")
            self.users.prune_bind_results(now)
            self.file_relays.expire(now, notify=not self._closing)

    async def disconnect(self, session_id: str, reason: str) -> None:
        """Dọn phiên an toàn khi gọi lặp, cập nhật danh sách online và hủy relay liên quan."""
        session = self.users.remove(session_id)
        if session is None:
            return
        self._cleanup_session(session)
        handler = self._client_handlers.get(session.tcp_socket)
        if handler is not None and not handler.done():
            if handler is not asyncio.current_task() and not handler.cancelling():
                handler.cancel()
            # Owner đóng socket trong finally, SAU khi cancel các I/O đang chờ.
            # Đóng handle trước sẽ gây WinError 6 với ProactorEventLoop trên Windows.
        else:
            session.tcp_socket.close()
        logger.info(
            "DISCONNECTED user=%s online=%d reason=%s",
            session.username,
            len(self.users.list_online()),
            reason,
        )
        if not self._closing:
            await self.broadcast_users()

    def _cleanup_session(self, session: Session) -> None:
        """Đánh dấu file thất bại, dọn transport rồi giải phóng việc đang chờ theo thứ tự.

        Gói file đã ACK có thể còn giữ chỗ ở phiên khác. Đặt trạng thái cuối trước
        để worker không chuyển tiếp trong lúc transport và outbox trả chỗ giữ riêng."""
        session.udp_ready.clear()

        for key, (_, owner, _) in tuple(self._parked.items()):
            if owner is session:
                self._parked.pop(key, None)

        self.file_relays.fail_session(session.session_id, notify=not self._closing)

        if session.udp_address is not None:
            self.channel.forget_peer(session.udp_address, session.session_id)

        self.file_relays.release_destination(session)

        for outbox in (session.data_outbox, session.file_outbox):
            while not outbox.empty():
                item = outbox.get_nowait()
                self._report_forward_failure(item)
                self.outbound.release(item.reservation)
                outbox.task_done()

        self.file_relays.forget_session()

    async def close(self) -> None:
        """Yêu cầu các tác vụ dừng, chờ chúng kết thúc và đóng socket của server."""

        # Chỉ cho một tác vụ thực hiện quá trình đóng server tại một thời điểm.
        async with self._close_lock:
            # Báo cho các phần khác biết server đang đóng.
            self._closing = True

            # Giải phóng cả waiter chờ ACK lẫn waiter đang chờ chỗ trong queue.
            await self.channel.close()

            # Chụp lại nhóm tác vụ cần dừng; không tạo tác vụ mới.
            # Callback có thể xóa tác vụ khỏi self._tasks khi chúng kết thúc.
            tasks = tuple(self._tasks)

            for task in tasks:
                task.cancel()

            try:
                # Chờ tất cả tác vụ kết thúc, kể cả phần finally dọn tài nguyên.
                await asyncio.gather(
                    *tasks,
                    return_exceptions=True,
                )

            finally:
                # Dọn socket khi rời khối try, kể cả khi việc chờ bị gián đoạn.
                if self._tcp_socket is not None:
                    self._tcp_socket.close()
                    self._tcp_socket = None

                # Vòng nhận đã dừng; đóng socket UDP do app sở hữu.
                if self._udp_socket is not None:
                    self._udp_socket.close()
                    self._udp_socket = None

                if self._discovery_socket is not None:
                    self._discovery_socket.close()
                    self._discovery_socket = None

                for sock in tuple(self._client_sockets):
                    sock.close()

                self._client_sockets.clear()

                self._tasks.clear()

                while not self._incoming_chat.empty():
                    packet, peer, _ = self._incoming_chat.get_nowait()
                    self._release_chat(packet, peer)
                    self._incoming_chat.task_done()

                self.file_relays.clear()
