"""Packet schemas, serialization and TCP framing shared by client and server.

The wire contract is documented in README.md. Invalid packets raise ValueError.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import PureWindowsPath

type Address = tuple[str, int]

MAX_USERNAME_BYTES = 64
MAX_SESSION_BYTES = 43
MAX_CHAT_MESSAGE_ID_BYTES = 32
MAX_SEQUENCE = 2**63 - 1
TERMINAL_FILE_ERROR_CODES = frozenset(
    {
        "RECIPIENT_OFFLINE",
        "TRANSFER_LIMIT",
        "ENDPOINT_DISCONNECTED",
        "TRANSFER_TIMEOUT",
        "TRANSFER_RETIRED",
        "RELAY_TOO_LARGE",
    }
)
_IDENTIFIER_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:."
)
_TRANSFER_ID_CHARACTERS = _IDENTIFIER_CHARACTERS - {":", "."}
# Ký tự điều khiển C0 và DEL; một lần quét regex thay cho vòng lặp từng ký tự.
_CONTROL_CHARACTERS = re.compile("[\x00-\x1f\x7f]")


def validate_username(value: object) -> str:
    """Giới hạn cả byte UTF-8 và JSON sau escape, vẫn cho phép tên Unicode."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value in {"*", "__server__"}
        or _CONTROL_CHARACTERS.search(value)
    ):
        raise ValueError("Invalid username")
    try:
        raw_size = len(value.encode("utf-8"))
        json_size = len(json.dumps(value, ensure_ascii=False).encode("utf-8")) - 2
    except UnicodeError as error:
        raise ValueError("Username must be valid UTF-8") from error
    if max(raw_size, json_size) > MAX_USERNAME_BYTES:
        raise ValueError(f"Username exceeds {MAX_USERNAME_BYTES} encoded bytes")
    return value


def validate_identifier(
    value: object, name: str, limit: int = 128, *, allow_empty: bool = False
) -> str:
    """Kiểm mã định danh ASCII có giới hạn; cho phép dấu câu dùng trong tiền tố sinh tự động."""
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > limit
        or not _IDENTIFIER_CHARACTERS.issuperset(value)
    ):
        raise ValueError(f"Invalid {name}")
    return value


def validate_filename(value: object) -> str:
    """Kiểm tên file an toàn đa nền tảng; việc tồn tại và symlink do lớp filesystem kiểm."""
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or value.endswith((" ", "."))
        or any(char in '<>:"/\\|?*' or ord(char) < 32 or ord(char) == 127 for char in value)
        or PureWindowsPath(value).is_reserved()
    ):
        raise ValueError("Unsafe filename")
    try:
        if len(value.encode("utf-8")) > 255:
            raise ValueError("Filename exceeds 255 UTF-8 bytes")
    except UnicodeError as error:
        raise ValueError("Filename must be valid UTF-8") from error
    return value


def validate_file_offer_identity(transfer_id: object, sender: object, recipient: object) -> None:
    """Dùng chung quy tắc transfer_id và hai bên tham gia cho file manager và codec."""

    validate_identifier(transfer_id, "transfer_id", 64)

    if any(char in ":." for char in transfer_id):
        raise ValueError("Invalid transfer_id characters")

    validate_username(sender)
    validate_username(recipient)


def validate_file_metadata(metadata: Mapping[str, object]) -> None:
    """Kiểm dữ liệu OFFER thuần; giới hạn cấu hình, quota và đường dẫn được kiểm theo ngữ cảnh."""
    if not isinstance(metadata, Mapping):
        raise ValueError("File metadata must be a mapping")

    validate_file_offer_identity(
        metadata.get("transfer_id"), metadata.get("sender"), metadata.get("recipient")
    )

    validate_filename(metadata.get("filename"))

    for name in ("size_bytes", "chunk_size", "total_chunks"):
        value = metadata.get(name)
        if type(value) is not int or value < (1 if name == "chunk_size" else 0):
            raise ValueError(f"Invalid {name}")

    expected = (metadata["size_bytes"] + metadata["chunk_size"] - 1) // metadata["chunk_size"]

    if metadata["total_chunks"] != expected:
        raise ValueError("total_chunks does not match file size")

    _file_hash(metadata.get("sha256"))


class MessageType(StrEnum):
    """Tên message trên wire; không rải chuỗi tương tự trong các module khác."""

    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    AUTH = "AUTH"
    AUTH_OK = "AUTH_OK"
    AUTH_ERROR = "AUTH_ERROR"
    UDP_BIND = "UDP_BIND"
    CHALLENGE = "CHALLENGE"
    RESPONSE = "RESPONSE"
    HEARTBEAT = "HEARTBEAT"
    USER_LIST = "USER_LIST"
    LOGOUT = "LOGOUT"
    MSG_PUBLIC = "MSG_PUBLIC"
    MSG_PRIVATE = "MSG_PRIVATE"
    ACK = "ACK"
    FILE_OFFER = "FILE_OFFER"
    FILE_READY = "FILE_READY"
    FILE_DATA = "FILE_DATA"
    FILE_END = "FILE_END"
    FILE_RESULT = "FILE_RESULT"
    ERROR = "ERROR"
    CANCEL = "CANCEL"
    BIND_OK = "BIND_OK"
    DISCOVER = "DISCOVER"
    ANNOUNCE = "ANNOUNCE"


# Các loại thông điệp điều khiển được phép trao đổi không mã hóa
# Để chào kết nối; không được chứa thông tin bí mật.
# Dùng frozenset để tránh vô tình thêm hoặc xóa loại thông điệp khi chạy.
PUBLIC_CONTROL_TYPES = frozenset(
    {
        MessageType.HELLO,  # Client gửi lời chào đến server.
        MessageType.HELLO_ACK,  # Server trả lời lời chào, kèm challenge.
        MessageType.DISCOVER,  # Client broadcast UDP để tìm server trong LAN.
        MessageType.ANNOUNCE,  # Server trả lời địa chỉ cổng; không có tên người dùng.
    }
)

# Discovery chạy trước đăng nhập nên chưa có khóa; gói chỉ chứa cổng và số lượng.
DISCOVERY_TYPES = frozenset({MessageType.DISCOVER, MessageType.ANNOUNCE})
DISCOVERY_STREAM = "discovery"

# Cả server, client và transport dùng chung danh sách này.
FILE_TYPES = frozenset(
    {
        MessageType.FILE_OFFER,
        MessageType.FILE_READY,
        MessageType.FILE_DATA,
        MessageType.FILE_END,
        MessageType.FILE_RESULT,
        MessageType.CANCEL,
    }
)


def _file_text(value: object, name: str, limit: int = 255) -> str:
    """Trả lại chuỗi không rỗng dài tối đa limit ký tự; báo ValueError nếu không hợp lệ."""
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        raise ValueError(f"Invalid {name}")
    return value


def _file_hash(value: object) -> None:
    """Kiểm tra chuỗi SHA-256 gồm 64 ký tự hex; báo ValueError nếu sai định dạng."""
    # SHA-256 có 256 bit; mỗi ký tự hex biểu diễn 4 bit nên cần 64 ký tự.
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in value)
    ):
        raise ValueError("Invalid SHA-256")


def _validate_file_identity(packet: Packet) -> None:
    """Kiểm tra các trường định danh của gói truyền file; báo ValueError nếu không hợp lệ."""
    for name in ("session_id", "sender", "recipient", "stream_id", "message_id"):
        _file_text(getattr(packet, name), name)

    # File phải gửi đến một người dùng cụ thể.
    if packet.recipient in {"*", "__server__"}:
        raise ValueError("File requires a user recipient")

    metadata = packet.metadata
    # Mã lượt truyền phải có 1–64 ký tự; thiếu transfer_id cũng bị từ chối.
    transfer_id = validate_identifier(metadata.get("transfer_id"), "transfer_id", 64)
    # Chỉ chấp nhận chữ cái tiếng Anh, chữ số, dấu gạch ngang và gạch dưới.
    if not _TRANSFER_ID_CHARACTERS.issuperset(transfer_id):
        raise ValueError("Invalid transfer_id characters")

    # Luồng truyền file phải có tên bắt đầu bằng "file-".
    if not packet.stream_id.startswith("file-"):
        raise ValueError("File requires a file- stream")


def _validate_file_fields(packet: Packet) -> None:
    """Kiểm tra nội dung gói truyền file theo loại thông điệp; báo ValueError nếu sai."""

    _validate_file_identity(packet)

    metadata = packet.metadata

    # FILE_DATA mang dữ liệu của một chunk, được đánh số từ 0.
    if packet.kind == MessageType.FILE_DATA:
        index = metadata.get("chunk_index")
        if type(index) is not int or index < 0 or not packet.payload:
            raise ValueError("Invalid file chunk")
        return

    # Gói điều khiển dùng metadata; không được mang dữ liệu file trong payload.
    if packet.payload:
        raise ValueError("File control payload must be empty")

    if packet.kind == MessageType.FILE_OFFER:
        validate_file_metadata(metadata)

    elif packet.kind == MessageType.FILE_RESULT:
        # Kết quả truyền file phải thể hiện rõ thành công hoặc thất bại.
        if type(metadata.get("ok")) is not bool:
            raise ValueError("FILE_RESULT requires boolean ok")
        if metadata["ok"]:
            _file_hash(metadata.get("sha256"))
        else:
            _file_text(metadata.get("error"), "error", 512)

    elif packet.kind == MessageType.CANCEL and "reason" in metadata:
        _file_text(metadata["reason"], "reason", 512)


def _validate_common_fields(packet: Packet) -> None:
    "Kiểm tra kiểu dữ liệu và giới hạn các trường chung của packet; báo ValueError nếu sai"

    if not isinstance(packet, Packet):
        raise ValueError("Input must be a Packet instance")

    # Loại của packet phải thuộc enum MessageType.
    if not isinstance(packet.kind, MessageType):
        raise ValueError("Invalid message type")

    validate_identifier(packet.session_id, "session_id", MAX_SESSION_BYTES, allow_empty=True)
    validate_identifier(packet.stream_id, "stream_id")
    validate_identifier(packet.message_id, "message_id")
    for name in ("sender", "recipient"):
        value = getattr(packet, name)
        # "*" là người nhận chung; DISCOVER dùng "*" làm người gửi ẩn danh.
        anonymous = value == "*" and (name == "recipient" or packet.kind == MessageType.DISCOVER)
        if value != "__server__" and not anonymous:
            validate_username(value)

    if type(packet.sequence) is not int or not 0 <= packet.sequence < 2**63:
        raise ValueError("Sequence must be an integer in [0, 2**63)")

    if not isinstance(packet.payload, bytes):
        raise ValueError("Payload must be bytes")

    try:
        if not isinstance(packet.metadata, dict):
            raise ValueError("metadata must be a dictionary")

        # Thử chuyển metadata thành JSON (chưa chuyển hẳn) để kiểm tra tính hợp lệ.
        # Không cho phép các giá trị NaN và Infinity.
        json.dumps(packet.metadata, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as ex:
        raise ValueError("metadata cannot be represented as valid JSON") from ex


def validate_packet(packet: Packet) -> None:
    """Kiểm tra cấu trúc chung và quy tắc riêng theo loại packet; báo ValueError nếu sai."""
    _validate_common_fields(packet)

    if packet.kind in FILE_TYPES:
        _validate_file_fields(packet)

    elif packet.kind == MessageType.HEARTBEAT:
        _validate_heartbeat(packet)

    elif packet.kind in DISCOVERY_TYPES:
        _validate_discovery(packet)

    elif packet.kind in {
        MessageType.HELLO,
        MessageType.HELLO_ACK,
        MessageType.AUTH,
        MessageType.AUTH_OK,
        MessageType.AUTH_ERROR,
    }:
        _validate_login_fields(packet)

    elif packet.kind in {
        MessageType.UDP_BIND,
        MessageType.CHALLENGE,
        MessageType.RESPONSE,
        MessageType.BIND_OK,
        MessageType.USER_LIST,
        MessageType.LOGOUT,
    }:
        _validate_control_fields(packet)
    else:
        _validate_message_fields(packet)


def _validate_heartbeat(packet: Packet) -> None:
    """Kiểm tra cấu trúc và hướng gửi/nhận của heartbeat giữa client và server."""
    for name in ("session_id", "sender", "recipient", "message_id"):
        _file_text(getattr(packet, name), name)

    # Heartbeat không mang dữ liệu và dùng luồng có tên "heartbeat".
    if packet.payload or packet.stream_id != "heartbeat":
        raise ValueError("Heartbeat requires empty payload and heartbeat stream")

    # Metadata chỉ được chứa reply, có giá trị True hoặc False.
    if set(packet.metadata) != {"reply"} or type(packet.metadata["reply"]) is not bool:
        raise ValueError("Heartbeat requires boolean reply")

    # Client gửi yêu cầu (False); server gửi phản hồi (True).
    from_server = packet.sender == "__server__"
    if packet.metadata["reply"] != from_server:
        raise ValueError("Invalid heartbeat direction")

    # Client phải gửi đến server; server phải gửi đến một client.
    # Không chấp nhận người nhận "*" vì heartbeat không dùng để gửi chung.
    if (packet.recipient == "__server__") == from_server or packet.recipient == "*":
        raise ValueError("Invalid heartbeat recipient")


def _validate_discovery(packet: Packet) -> None:
    """Kiểm DISCOVER/ANNOUNCE: không phiên, không payload, chỉ chứa cổng và số đếm."""
    if (
        packet.session_id
        or packet.payload
        or packet.sequence != 0
        or packet.stream_id != DISCOVERY_STREAM
    ):
        raise ValueError("Discovery packets carry no session, payload or sequence")

    if packet.kind == MessageType.DISCOVER:
        # Người gửi ẩn danh để broadcast không làm lộ username trên LAN.
        if packet.sender != "*" or packet.recipient != "__server__" or packet.metadata:
            raise ValueError("Invalid DISCOVER")
        return

    if packet.sender != "__server__" or packet.recipient != "*":
        raise ValueError("Invalid ANNOUNCE identity")
    if set(packet.metadata) != {"tcp_port", "udp_port", "online", "capacity"}:
        raise ValueError("Unexpected ANNOUNCE fields")
    for name in ("tcp_port", "udp_port"):
        value = packet.metadata[name]
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError(f"Invalid {name}")
    capacity, online = packet.metadata["capacity"], packet.metadata["online"]
    if type(capacity) is not int or type(online) is not int or not 0 <= online <= capacity:
        raise ValueError("Invalid ANNOUNCE counts")


def _validate_control_identity(packet: Packet) -> None:
    """Kiểm tra người gửi, người nhận và session của các thông điệp điều khiển."""

    # Gói điều khiển không mang payload; các trường định danh dưới đây không được rỗng.
    if packet.payload or not all(
        (
            packet.sender,
            packet.recipient,
            packet.stream_id,
            packet.message_id,
        )
    ):
        raise ValueError("Invalid control packet")

    kind = packet.kind

    # Xác định loại thông điệp nào phải do client gửi.
    from_client = kind in {
        MessageType.UDP_BIND,
        MessageType.RESPONSE,
        MessageType.LOGOUT,
    }

    if from_client:
        if packet.sender in {"__server__", "*"} or packet.recipient != "__server__":
            raise ValueError("Invalid client control identity")
    elif packet.sender != "__server__" or packet.recipient in {"__server__", "*"}:
        raise ValueError("Invalid server control identity")

    if not packet.session_id:
        raise ValueError("Authenticated control requires a session")


def _validate_control_fields(packet: Packet) -> None:
    """Kiểm tra metadata của các gói bind UDP, danh sách online và đăng xuất."""

    # Kiểm tra người gửi, người nhận, payload và session trước.
    _validate_control_identity(packet)

    # Xây dựng danh sách trường bắt buộc theo loại thông điệp.
    kind = packet.kind
    required = []
    if kind in {
        MessageType.UDP_BIND,
        MessageType.CHALLENGE,
        MessageType.RESPONSE,
        MessageType.BIND_OK,
    }:
        required.append("bind_id")
    if kind == MessageType.CHALLENGE:
        required.append("challenge")
    if kind == MessageType.RESPONSE:
        required.append("proof")

    # Các trường bind bắt buộc phải là chuỗi dài từ 1 đến 64 ký tự.
    for name in required:
        value = packet.metadata.get(name)
        if not isinstance(value, str) or not 1 <= len(value) <= 64:
            raise ValueError(f"Invalid {name}")

    # Gói bind phải có đúng các trường yêu cầu; LOGOUT phải có metadata rỗng.
    if (required or kind == MessageType.LOGOUT) and set(packet.metadata) != set(required):
        raise ValueError("Unexpected bind/logout fields")

    if kind == MessageType.USER_LIST:
        _validate_user_list(packet.metadata.get("users"))


def _validate_user_list(users: object) -> None:
    """Yêu cầu danh sách username hợp lệ, không trùng trong snapshot người dùng online."""
    if not isinstance(users, list):
        raise ValueError("Invalid online list")
    for user in users:
        validate_username(user)
    if len(set(users)) != len(users):
        raise ValueError("Duplicate online user")


def _validate_login_identity(packet: Packet) -> None:
    """Kiểm tra các trường định danh và hướng gửi/nhận của gói chào kết nối, đăng nhập."""
    for name in ("sender", "recipient", "stream_id"):
        _file_text(getattr(packet, name), name)

    # Mỗi gói đăng nhập phải có mã thông điệp.
    if not packet.message_id:
        raise ValueError("Login requires a message_id")

    if packet.kind in {MessageType.HELLO, MessageType.AUTH}:
        # Yêu cầu chào kết nối và đăng nhập phải đi từ client đến server.
        if packet.sender in {"__server__", "*"} or packet.recipient != "__server__":
            raise ValueError("Invalid login request identity")

    elif packet.sender != "__server__" or packet.recipient in {"__server__", "*"}:
        # Phản hồi phải đi từ server đến một client cụ thể.
        raise ValueError("Invalid login response identity")


def _validate_login_fields(packet: Packet) -> None:
    """Kiểm tra session, payload và metadata của HELLO, AUTH và các phản hồi đăng nhập."""
    _validate_login_identity(packet)

    # Trong nhóm đăng nhập, chỉ AUTH_OK phải có session; các loại khác phải để rỗng.
    if bool(packet.session_id) != (packet.kind == MessageType.AUTH_OK):
        raise ValueError("Only AUTH_OK must have a non-empty session_id")

    if packet.kind == MessageType.AUTH:
        # AUTH phải mang mật khẩu không rỗng trong payload.
        if not packet.payload:
            raise ValueError("AUTH requires a password")
        try:
            packet.payload.decode("utf-8")
        except UnicodeError as error:
            raise ValueError("AUTH password must be UTF-8") from error

    elif packet.payload:
        # HELLO và các phản hồi đăng nhập không được mang payload.
        raise ValueError("HELLO and login responses must have an empty payload")

    _validate_login_metadata(packet)


def _validate_login_metadata(packet: Packet) -> None:
    """Kiểm trường đăng nhập được phép, challenge/lỗi và giới hạn chat nếu có."""
    # Tra cứu tập hợp trường metadata được yêu cầu cho loại packet hiện tại.
    expected = {
        MessageType.HELLO: set(),
        MessageType.HELLO_ACK: {"challenge"},
        MessageType.AUTH: {"challenge"},
        MessageType.AUTH_OK: set(),
        MessageType.AUTH_ERROR: {"error"},
    }[packet.kind]

    # Không chấp nhận metadata thiếu hoặc thừa trường.
    optional = {"max_chat_bytes"} if packet.kind == MessageType.AUTH_OK else set()
    if not expected <= packet.metadata.keys() or packet.metadata.keys() - expected - optional:
        raise ValueError("Unexpected login fields")
    if "max_chat_bytes" in packet.metadata:
        limit = packet.metadata["max_chat_bytes"]
        if type(limit) is not int or not 0 <= limit <= 65507:
            raise ValueError("Invalid max_chat_bytes")

    # HELLO_ACK và AUTH phải chứa challenge dài từ 1 đến 64 ký tự.
    if "challenge" in expected:
        _file_text(packet.metadata["challenge"], "challenge", 64)

    # Đăng nhập thất bại phải có thông báo lỗi không rỗng, tối đa 255 ký tự.
    if packet.kind == MessageType.AUTH_ERROR:
        _file_text(packet.metadata["error"], "authentication error")


def _validate_message_fields(packet: Packet) -> None:
    """Kiểm tra các trường của gói chat, ACK và thông báo lỗi ERROR."""

    # Hàm này chỉ xử lý bốn loại thông điệp dưới đây.
    if packet.kind not in {
        MessageType.MSG_PRIVATE,
        MessageType.MSG_PUBLIC,
        MessageType.ACK,
        MessageType.ERROR,
    }:
        raise ValueError("Unsupported message type")

    # Các gói này phải mang mã phiên và có người nhận.
    if not packet.session_id or not packet.recipient:
        raise ValueError("Message requires a non-empty session_id and recipient")

    if packet.kind in {MessageType.MSG_PRIVATE, MessageType.MSG_PUBLIC}:
        _validate_chat_identity(packet)

    if packet.kind == MessageType.ACK:
        # Xác định luồng và số thứ tự của packet đang được xác nhận
        ack_stream = packet.metadata.get("ack_stream")
        ack_seq = packet.metadata.get("ack_seq")
        if not isinstance(ack_stream, str) or not ack_stream:
            raise ValueError("ACK must contain a non-empty string ack_stream")
        if type(ack_seq) is not int or ack_seq < 0:
            raise ValueError("ACK must contain a non-negative integer ack_seq")
        # ACK chỉ chứa thông tin xác nhận trong metadata.
        if packet.payload:
            raise ValueError("ACK payload must be empty")

    elif packet.kind == MessageType.ERROR and (
        # ERROR phải do server gửi, không có payload và có thông báo lỗi không rỗng.
        packet.sender != "__server__"
        or packet.payload
        or not isinstance(packet.metadata.get("error"), str)
        or not packet.metadata["error"]
    ):
        raise ValueError("Invalid server error")


def _validate_chat_identity(packet: Packet) -> None:
    """Kiểm luồng chat, độ dài message_id, người nhận và danh tính trong gói relay."""
    validate_identifier(packet.message_id, "chat message_id", MAX_CHAT_MESSAGE_ID_BYTES)
    if packet.stream_id != "chat":
        raise ValueError("Chat requires the chat stream")
    if (
        packet.kind == MessageType.MSG_PUBLIC
        and packet.sender != "__server__"
        and packet.recipient != "*"
    ):
        raise ValueError("Public chat must target '*'")
    for name in ("origin_user", "target_user"):
        if name in packet.metadata:
            value = packet.metadata[name]
            if not (name == "target_user" and value == "*"):
                validate_username(value)


def serialize_packet(packet: Packet) -> bytes:
    """Kiểm tra và đóng gói Packet thành bytes gồm: độ dài header (2 byte),
    header JSON UTF-8 và payload, để chuẩn bị truyền qua mạng."""

    validate_packet(packet)

    # Tạo header chứa thông tin giúp bên nhận hiểu và xử lý gói tin.
    # Payload được ghép riêng phía sau header, không đưa vào JSON.

    header = {
        "version": PROTOCOL_VERSION,
        "type": packet.kind.value,
        "session_id": packet.session_id,
        "sender": packet.sender,
        "recipient": packet.recipient,
        "stream_id": packet.stream_id,
        "seq": packet.sequence,
        "message_id": packet.message_id,
        "payload_length": len(packet.payload),
        "metadata": packet.metadata,
    }

    try:
        # Chuyển dictionary thành chuỗi JSON, sau đó mã hóa UTF-8 thành bytes.
        header_bytes = json.dumps(
            header,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as ex:
        # Báo lỗi nếu không thể chuyển header thành JSON hoặc mã hóa UTF-8.
        raise ValueError("Header cannot be encoded as UTF-8 JSON") from ex

    if len(header_bytes) > 65535:
        raise ValueError("Header is too long")

    # Đóng gói độ dài header thành một đối tượng bytes chứa đúng 2 byte.
    prefix = struct.pack("!H", len(header_bytes))

    # [Độ dài header: 2 byte][Header JSON UTF-8][Payload dạng bytes]
    return prefix + header_bytes + packet.payload


def protected_packet_size(plaintext_bytes: int) -> int:
    """Tính đúng số byte envelope 5 byte và token Fernet, gồm padding PKCS7 và base64."""
    if type(plaintext_bytes) is not int or plaintext_bytes < 0:
        raise ValueError("Invalid plaintext length")
    padded = 16 * (plaintext_bytes // 16 + 1)
    token_bytes = 57 + padded  # Fernet version, timestamp, IV, ciphertext and HMAC.
    return UDP_ENVELOPE_BYTES + 4 * ((token_bytes + 2) // 3)


def chat_payload_limit(max_datagram_bytes: int) -> int:
    """Tìm payload UTF-8 lớn nhất vẫn vừa mọi gói chat relay khi sequence đạt tối đa.

    Giới hạn tên theo JSON sau escape bao quát cả Unicode và dấu nháy/gạch chéo.
    Gói relay có thêm metadata origin_user/target_user nên lớn hơn gói gửi lên."""
    if type(max_datagram_bytes) is not int or not 1 <= max_datagram_bytes <= 65507:
        raise ValueError("Invalid datagram limit")
    worst_name = "u" * MAX_USERNAME_BYTES
    template = Packet(
        MessageType.MSG_PRIVATE,
        "s" * MAX_SESSION_BYTES,
        "__server__",
        worst_name,
        "chat",
        MAX_SEQUENCE,
        "m" * MAX_CHAT_MESSAGE_ID_BYTES,
        metadata={"origin_user": worst_name, "target_user": worst_name},
    )
    low, high = 0, max_datagram_bytes
    while low < high:
        middle = (low + high + 1) // 2
        packet = replace(template, payload=b"x" * middle)
        if protected_packet_size(len(serialize_packet(packet))) <= max_datagram_bytes:
            low = middle
        else:
            high = middle - 1
    return low


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Không để key trùng âm thầm ghi đè username/challenge hoặc field khác."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def deserialize_packet(data: bytes) -> Packet:
    """Giải mã bytes gồm prefix, header JSON UTF-8 và payload thành Packet"""

    if not isinstance(data, bytes) or len(data) < METADATA_PREFIX_BYTES:
        raise ValueError("Packet data must be bytes and include the prefix")

    # lấy độ dài của header, và vị trí header cuối
    header_length = struct.unpack("!H", data[:METADATA_PREFIX_BYTES])[0]
    header_end = METADATA_PREFIX_BYTES + header_length

    if header_end > len(data):
        raise ValueError("Incomplete header data")

    try:
        header = json.loads(
            data[METADATA_PREFIX_BYTES:header_end].decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, ValueError, RecursionError) as ex:
        raise ValueError("Header is not valid UTF-8 JSON") from ex

    expected_fields = {
        "version",
        "type",
        "session_id",
        "sender",
        "recipient",
        "stream_id",
        "seq",
        "message_id",
        "payload_length",
        "metadata",
    }

    if not isinstance(header, dict) or set(header) != expected_fields:
        raise ValueError("Header contains missing or unexpected fields")

    if type(header["version"]) is not int or header["version"] != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version")

    payload = data[header_end:]

    if type(header["payload_length"]) is not int or header["payload_length"] != len(payload):
        raise ValueError("Invalid or mismatched payload length")

    try:
        kind = MessageType(header["type"])
    except (TypeError, ValueError) as ex:
        raise ValueError("Unknown message type") from ex

    packet = Packet(
        kind=kind,
        session_id=header["session_id"],
        sender=header["sender"],
        recipient=header["recipient"],
        stream_id=header["stream_id"],
        sequence=header["seq"],
        message_id=header["message_id"],
        payload=payload,
        metadata=header["metadata"],
    )

    validate_packet(packet)
    return packet


def encode_public_control(packet: Packet) -> bytes:
    """Kiểm tra và đóng gói thông điệp điều khiển công khai thành bytes."""

    # Chỉ chấp nhận các loại thông điệp được phép truyền công khai.
    if packet.kind not in PUBLIC_CONTROL_TYPES:
        raise ValueError("Message type cannot be sent as public control")

    # Kiểm tra và chuyển Packet thành bytes.
    data = serialize_packet(packet)

    if len(data) > 65536:
        raise ValueError("Public control packet is too large")

    return data


def decode_public_control(data: bytes, allowed: set[MessageType]) -> Packet:
    """Mở gói bytes thành Packet và kiểm tra thông điệp"""

    if not isinstance(data, bytes) or len(data) > 65536:
        raise ValueError("Invalid public control data")

    # Chuyển bytes thành Packet và kiểm tra tính hợp lệ của gói tin.
    packet = deserialize_packet(data)

    # Kiểm tra thông điệp thuộc nhóm được phép truyền công khai.
    if packet.kind not in PUBLIC_CONTROL_TYPES:
        raise ValueError("Message type is not public control")

    # Kiểm tra thông điệp phù hợp với bước xử lý hiện tại.
    if packet.kind not in allowed:
        raise ValueError("Message type is not allowed at this stage")

    return packet


async def read_exactly(sock: socket.socket, count: int) -> bytes:
    """Đọc đủ count byte từ socket TCP; báo lỗi nếu kết nối đóng trước
    khi nhận đủ dữ liệu. Socket phải được đặt ở chế độ non-blocking."""

    if type(count) is not int or count < 0:
        raise ValueError("Byte count must be a non-negative integer")

    # Lấy event loop đang chạy để nhận dữ liệu bất đồng bộ.
    loop = asyncio.get_running_loop()
    result = bytearray()

    while len(result) < count:
        remaining = count - len(result)

        # Nhận tối đa số byte còn thiếu; mỗi lần có thể nhận ít hơn.
        # Trong lúc chờ, cho phép event loop chạy công việc khác.
        chunk = await loop.sock_recv(sock, remaining)

        # Bytes rỗng cho biết phía bên kia đã kết thúc luồng gửi.
        if not chunk:
            raise ConnectionError("Connection closed before all requested bytes were received")

        result.extend(chunk)

    return bytes(result)


async def read_frame(
    sock: socket.socket,
    max_bytes: int,
    timeout: float,
    *,
    wait_for_data: bool = False,
) -> bytes:
    """Đọc một frame TCP trong thời gian cho phép và trả về body.
    Body phải có từ 1 đến max_bytes byte; socket phải ở chế độ non-blocking."""

    # Sau AUTH, cho phép client im lặng. Khi có byte đầu tiên thì vẫn phải
    # nhận đủ frame trong deadline; không để một frame dở dang chờ vô hạn.
    first = await read_exactly(sock, 1) if wait_for_data else b""

    async with asyncio.timeout(timeout):
        # Đọc đủ 4 byte prefix chứa độ dài body.
        prefix = first + await read_exactly(sock, TCP_PREFIX_BYTES - len(first))
        body_length = struct.unpack("!I", prefix)[0]

        if not (1 <= body_length <= max_bytes):
            raise ValueError("Invalid frame body length")

        # Đọc đủ body rồi trả về, không bao gồm prefix 4 byte.
        return await read_exactly(sock, body_length)


async def write_frame(
    sock: socket.socket,
    body: bytes,
    lock: asyncio.Lock,
    max_bytes: int,
) -> None:
    """Đóng gói body thành frame TCP và gửi qua socket non-blocking.
    Các công việc gửi trên cùng socket phải dùng chung một khóa."""

    if not isinstance(body, bytes) or not (1 <= len(body) <= max_bytes):
        raise ValueError("Invalid TCP frame body")

    # Tạo prefix 4 byte chứa độ dài body theo thứ tự big-endian, rồi nối với body để tạo frame hoàn chỉnh.
    frame = struct.pack("!I", len(body)) + body
    loop = asyncio.get_running_loop()

    # Chờ lấy khóa, đảm bảo chỉ một công việc gửi trên socket tại một thời điểm.
    async with lock:
        # Gửi toàn bộ frame; trong lúc chờ, event loop có thể chạy việc khác.
        # Hoàn tất gửi chưa có nghĩa là ứng dụng bên nhận đã xử lý dữ liệu.
        await loop.sock_sendall(sock, frame)


def pack_envelope(key_id: int, protected_body: bytes) -> bytes:
    """Ghép mã nhận diện, phiên bản, mã khóa và dữ liệu đã được bảo vệ
    thành envelope dạng bytes; hàm không tự mã hóa dữ liệu."""

    # Mã khóa phải là số nguyên từ 1 đến 65535, không chấp nhận bool.
    if type(key_id) is not int or not 1 <= key_id <= 65535:
        raise ValueError("key_id must be an integer between 1 and 65535")

    if not isinstance(protected_body, bytes) or not protected_body:
        raise ValueError("Protected body must be non-empty bytes")

    # Cấu trúc: [MAGIC: 2 byte][Version: 1 byte][key_id: 2 byte][Body].
    # MAGIC: Dấu nhận diện cố định ở đầu envelope, giúp kiểm tra dữ liệu có đúng định dạng giao thức của ứng dụng không.
    return MAGIC + bytes([PROTOCOL_VERSION]) + struct.pack("!H", key_id) + protected_body


def unpack_envelope(datagram: bytes) -> tuple[int, bytes]:
    """Kiểm tra cấu trúc envelope và tách mã khóa cùng dữ liệu được bảo vệ;
    hàm chưa xác thực hoặc giải mã nội dung."""

    # Header dài 5 byte; datagram phải có thêm ít nhất 1 byte body.
    if not isinstance(datagram, bytes) or len(datagram) <= UDP_ENVELOPE_BYTES:
        raise ValueError("Envelope must be bytes and include a non-empty body")

    if datagram[:2] != MAGIC:
        raise ValueError("Invalid magic")

    if datagram[2] != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version")

    key_id = struct.unpack("!H", datagram[3:5])[0]

    # Giao thức không chấp nhận mã khóa bằng 0.
    if key_id == 0:
        raise ValueError("key_id must not be zero")

    # Trả về mã khóa để tra cứu và toàn bộ body nằm sau header 5 byte.
    return key_id, datagram[UDP_ENVELOPE_BYTES:]


def make_ack(packet: Packet, local_user: str) -> Packet:
    """Tạo Packet ACK để xác nhận gói tin đã nhận và gửi về bên gửi gốc.
    Hàm không sửa packet đầu vào và chưa gửi ACK qua mạng."""

    validate_packet(packet)

    # Không xác nhận một ACK để tránh vòng lặp xác nhận qua lại.
    if packet.kind == MessageType.ACK:
        raise ValueError("Cannot create an ACK for another ACK")

    # Định danh bên tạo ACK phải là chuỗi không rỗng.
    if not isinstance(local_user, str) or not local_user:
        raise ValueError("ACK sender must be a non-empty string")

    # Tạo Packet mới bằng dataclasses.replace(), giữ nguyên gói tin gốc.
    # Các trường không được chỉ định bên dưới giữ giá trị từ packet.
    ack = replace(
        packet,
        kind=MessageType.ACK,
        sender=local_user,
        recipient=packet.sender,
        message_id=f"ack:{packet.message_id}",
        payload=b"",
        metadata={
            "ack_stream": packet.stream_id,
            "ack_seq": packet.sequence,
        },
    )

    validate_packet(ack)
    return ack


@dataclass(frozen=True, slots=True)
class Packet:
    """Message sau giải mã; seq của một chặng khác ID message logic end-to-end."""

    kind: MessageType
    session_id: str
    sender: str
    recipient: str
    stream_id: str
    sequence: int
    message_id: str
    payload: bytes = b""
    metadata: dict[str, object] = field(default_factory=dict)


MAGIC = b"SC"
PROTOCOL_VERSION = 1
TCP_PREFIX_BYTES = 4
UDP_ENVELOPE_BYTES = 5
METADATA_PREFIX_BYTES = 2
