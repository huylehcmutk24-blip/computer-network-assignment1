"""Shared validated configuration. Never load configuration at import time.

Uses json, pathlib, dataclasses and logging. Relative data paths are resolved
against PROJECT_ROOT."""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path

from protocol import chat_payload_limit, validate_username

PROJECT_ROOT = Path(__file__).resolve().parent

PORT_FIELDS = {
    "tcp_port",
    "udp_port",
    "bridge_port",
    "discovery_port",
}

LOG_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "NOTSET",
}


@dataclass(frozen=True, slots=True)
class Settings:
    """Initial LAN defaults; validate settings and measure behavior during integration."""

    bind_host: str = "127.0.0.1"
    server_host: str = "127.0.0.1"

    tcp_port: int = 9000
    udp_port: int = 9001
    bridge_port: int = 8765
    # server_host="auto": client broadcasts DISCOVER to this address and port.
    discovery_port: int = 9002
    discovery_address: str = "255.255.255.255"

    username: str = "client01"
    key_id: int = 1

    keyring_path: Path = PROJECT_ROOT / "config/secrets/client01.keys.json"
    users_path: Path = PROJECT_ROOT / "config/secrets/users.json"
    receive_dir: Path = PROJECT_ROOT / "downloads"
    log_path: Path = PROJECT_ROOT / "logs/app.log"

    max_frame_bytes: int = 65_536
    max_datagram_bytes: int = 1200
    chunk_size: int = 256

    window_packets: int = 8
    max_peer_pending: int = 64
    max_receive_buffer: int = 128

    max_file_bytes: int = 100 * 1024 * 1024
    # Bound file stream history for each authenticated session.
    max_transfer_history: int = 128
    max_clients: int = 20

    retry_initial_seconds: float = 0.5
    retry_max_seconds: float = 2.0
    max_retries: int = 5

    heartbeat_seconds: float = 2.0
    offline_seconds: float = 8.0
    handshake_seconds: float = 10.0
    transfer_idle_seconds: float = 30.0
    completed_retention_seconds: float = 30.0

    ui_queue_size: int = 256
    bridge_event_history: int = 512
    log_level: str = "INFO"


def load_settings(
    path: Path | None,
    overrides: Mapping[str, object] | None = None,
) -> Settings:
    """Áp dụng lần lượt mặc định, JSON rồi các tùy chọn ghi đè được truyền rõ.

    Chỉ ghi đè những cờ người gọi thực sự cung cấp.
    Đường dẫn dữ liệu tương đối được tính từ PROJECT_ROOT."""
    values: dict[str, object] = {}
    known_fields = {item.name: item for item in fields(Settings)}

    if path is not None:
        with path.open(encoding="utf-8-sig") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Configuration file must contain a JSON object")

        values.update(data)

    # Validate both sources before merging them.
    for source in (values, overrides or {}):
        for name in source:
            if name not in known_fields:
                raise ValueError(f"Unsupported configuration field: {name!r}")

    if overrides is not None:
        values.update(overrides)

    # JSON stores paths as strings; application code uses Path objects.
    for name, value in values.items():
        if isinstance(known_fields[name].default, Path):
            values[name] = _normalize_path(name, value)

    settings = Settings(**values)
    validate_settings(settings)
    return settings


def _normalize_path(name: str, value: object) -> Path:
    """Chuẩn hóa đường dẫn mà không tạo file hoặc thư mục."""
    if not isinstance(value, (str, Path)):
        raise ValueError(f"{name} must be a path string or Path")

    text = str(value)
    if not text.strip() or "\x00" in text or "<" in text or ">" in text:
        raise ValueError(f"{name} is empty or contains placeholders or invalid characters")

    path = Path(value).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _validate_field(name: str, value: object, default: object) -> None:
    """Kiểm kiểu và miền giá trị cơ bản theo các mặc định trong Settings."""
    if isinstance(default, int):
        minimum = 0 if name in PORT_FIELDS or name == "max_retries" else 1

        # bool subclasses int but is not valid for ports, sizes, or windows.
        valid = type(value) is int and value >= minimum

    elif isinstance(default, float):
        # Accept both 2 and 2.0; reject bool, NaN, and infinity.
        valid = type(value) in (int, float) and 0 < value < math.inf

    elif isinstance(default, Path):
        valid = isinstance(value, Path)

    else:
        valid = isinstance(value, str) and bool(value.strip())

    if not valid:
        raise ValueError(f"{name}: invalid type or value outside the allowed range")


def _retry_horizon(settings: Settings) -> float:
    """Trả tổng thời gian chờ của lần gửi đầu và toàn bộ các lần retry."""
    delay = settings.retry_initial_seconds
    total = 0.0

    for _ in range(settings.max_retries + 1):
        total += delay
        delay = min(delay * 2, settings.retry_max_seconds)

    return total


def validate_settings(settings: Settings) -> None:
    """Kiểm cấu hình trước khi mở socket.

    Cho phép cổng 0 để bind cổng động trong kiểm thử.
    Khi kết nối, client phải dùng cổng đích trong khoảng 1..65535."""
    for item in fields(Settings):
        value = getattr(settings, item.name)
        _validate_field(item.name, value, item.default)

        if isinstance(item.default, Path):
            _normalize_path(item.name, value)

    for name in PORT_FIELDS:
        if getattr(settings, name) > 65535:
            raise ValueError(f"{name} must be in the range 0..65535")

    checks = (
        (
            settings.key_id <= 65535,
            "key_id must be in the range 1..65535",
        ),
        (
            settings.max_frame_bytes <= 0xFFFFFFFF,
            "max_frame_bytes exceeds uint32",
        ),
        (
            settings.max_datagram_bytes <= 65507,
            "Datagram exceeds the UDP IPv4 limit",
        ),
        (
            settings.chunk_size < settings.max_datagram_bytes,
            "Chunk size must be smaller than the datagram limit",
        ),
        (
            settings.window_packets <= settings.max_peer_pending,
            "Pending capacity must fit one window",
        ),
        (
            settings.window_packets <= settings.max_receive_buffer,
            "Receive buffer capacity must fit one window",
        ),
        (
            settings.heartbeat_seconds < settings.offline_seconds,
            "heartbeat_seconds must be smaller than offline_seconds",
        ),
        (
            settings.retry_initial_seconds <= settings.retry_max_seconds,
            "Initial retry delay exceeds the maximum retry delay",
        ),
        (
            settings.log_level in LOG_LEVELS,
            "Invalid log_level; use an uppercase level name",
        ),
        (
            chat_payload_limit(settings.max_datagram_bytes) >= 1,
            "Datagram limit is too small for the supported chat identities",
        ),
    )

    for valid, message in checks:
        if not valid:
            raise ValueError(message)

    validate_username(settings.username)

    if settings.completed_retention_seconds <= _retry_horizon(settings):
        raise ValueError("Retention must exceed the full retry horizon")

    for name in ("bind_host", "server_host", "username", "discovery_address"):
        value = getattr(settings, name)

        if value != value.strip() or any(char in value for char in "<>\r\n\x00"):
            raise ValueError(f"{name} contains placeholders or invalid characters")


def configure_logging(settings: Settings) -> None:
    """Thiết lập logging UTF-8 một lần từ entry point.

    Các module dùng logging.getLogger(__name__).
    Không ghi mật khẩu, khóa hoặc toàn bộ đối tượng cấu hình vào log."""
    validate_settings(settings)

    log_path = _normalize_path("log_path", settings.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        handlers=[logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()],
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
