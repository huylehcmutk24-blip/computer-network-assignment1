"""Fernet packet protection and salted scrypt password verification.

Keys are provisioned out of band, separately for each user. Session ownership
and replay checks belong to the server and reliable transport.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from protocol import Packet, deserialize_packet, pack_envelope, serialize_packet, unpack_envelope

MAX_PASSWORD_BYTES = 1024


def _decode_base64(value: bytes) -> bytes:
    """Giải mã Base64 URL-safe và từ chối dữ liệu sai định dạng hoặc không ở dạng chuẩn"""

    # Giải mã nghiêm ngặt, không bỏ qua ký tự không hợp lệ.
    decoded = base64.b64decode(value, altchars=b"-_", validate=True)

    # Mã hóa lại để bảo đảm đầu vào đúng dạng URL-safe chuẩn.
    if base64.urlsafe_b64encode(decoded) != value:
        raise ValueError("Noncanonical Base64")

    return decoded


def _validate_key_id(key_id: int) -> None:
    """Kiểm tra mã khóa là số nguyên từ 1 đến 65535; báo ValueError nếu sai."""
    if type(key_id) is not int or not 1 <= key_id <= 65535:
        raise ValueError("key_id must be an integer between 1 and 65535")


def _validate_keyring(keyring: dict[int, bytes]) -> dict[int, bytes]:
    """Kiểm tra keyring và trả về bản sao khi các mã khóa, khóa Fernet đều hợp lệ và không trùng."""
    if not isinstance(keyring, dict) or not keyring:
        raise ValueError("Keyring must be a non-empty object")

    validated = {}
    seen = set()

    for key_id, key in keyring.items():
        _validate_key_id(key_id)

        # Khóa Fernet dạng Base64 chuẩn gồm 44 byte ASCII.
        if not isinstance(key, bytes) or len(key) != 44:
            raise ValueError("Invalid Fernet key")

        # Giải mã Base64; thông báo lỗi nếu định dạng không hợp lệ.
        try:
            raw_key = _decode_base64(key)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid Fernet key") from None

        # Nội dung khóa sau khi giải mã phải dài đúng 32 byte.
        if len(raw_key) != 32:
            raise ValueError("Invalid Fernet key")

        # Mỗi mã khóa phải sử dụng một nội dung khóa riêng.
        if raw_key in seen:
            raise ValueError("Each key_id must use a distinct key")

        seen.add(raw_key)
        # Giữ khóa ở dạng Base64 để dùng với Fernet.
        validated[key_id] = key

    return validated


def _unique_key_entries(pairs: list[tuple[str, object]]) -> dict:
    """Tạo dictionary từ các cặp trong JSON; báo lỗi nếu tên trường bị trùng."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key_id")
        result[key] = value
    return result


def load_keyring(path: Path) -> dict[int, bytes]:
    """Đọc bộ khóa từ JSON, chuyển kiểu dữ liệu và kiểm tra tính hợp lệ"""
    try:
        # Đọc JSON và kiểm tra tên trường trùng trong quá trình phân tích.
        records = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_key_entries,
        )

    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid keyring JSON") from None

    # Bộ khóa phải là JSON object, tương ứng với dictionary
    if not isinstance(records, dict):
        raise ValueError("Keyring must be an object")

    keyring = {}
    for name, value in records.items():
        # ID trong JSON phải gồm chữ số ASCII, tối đa 5 ký tự.
        if not name.isascii() or not name.isdecimal() or len(name) > 5:
            raise ValueError("Invalid key_id")

        key_id = int(name)

        # Từ chối các cách viết như "01" hoặc "001".
        if name != str(key_id):
            raise ValueError("key_id must use canonical decimal notation")

        # Khóa trong JSON phải được lưu dưới dạng chuỗi.
        if not isinstance(value, str):
            raise ValueError("Invalid Fernet key")

        try:
            # Chuyển chuỗi Base64 sang bytes, chưa giải mã Base64.
            keyring[key_id] = value.encode("ascii")
        except UnicodeError:
            raise ValueError("Invalid Fernet key") from None

    # Kiểm tra phạm vi ID, định dạng khóa Fernet và khóa trùng.
    return _validate_keyring(keyring)


def generate_key() -> bytes:
    """Tạo khóa Fernet ngẫu nhiên ở dạng Base64 URL-safe."""
    return Fernet.generate_key()


def hash_password(password: str, salt: bytes) -> str:
    """Băm mật khẩu bằng scrypt với salt 16 byte, trả về chuỗi hex 64 ký tự."""
    # Kiểm tra kiểu, độ dài sơ bộ và từ chối mật khẩu rỗng.
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_BYTES:
        raise ValueError("Password must contain 1 to 1024 UTF-8 bytes")

    # Chuyển mật khẩu sang bytes để đưa vào scrypt.
    try:
        encoded = password.encode("utf-8")
    except UnicodeError:
        raise ValueError("Password must be valid UTF-8") from None

    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError("Password must contain 1 to 1024 UTF-8 bytes")

    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("Password salt must contain 16 bytes")

    # Tạo kết quả 32 byte bằng scrypt, rồi biểu diễn thành 64 ký tự he
    return hashlib.scrypt(encoded, salt=salt, n=16384, r=8, p=1, dklen=32).hex()


def verify_password(password: str, record_salt: str, expected_hash: str) -> bool:
    """Kiểm tra mật khẩu bằng salt và hash đã lưu; trả False nếu sai dữ liệu hoặc không khớp."""
    # Salt 16 byte được lưu thành 32 ký tự hex; hash 32 byte thành 64 ký tự hex.
    if (
        not isinstance(record_salt, str)
        or len(record_salt) != 32
        or not isinstance(expected_hash, str)
        or len(expected_hash) != 64
    ):
        return False
    try:
        # Chuyển dữ liệu đã lưu từ chuỗi hex về bytes
        salt = bytes.fromhex(record_salt)
        expected = bytes.fromhex(expected_hash)
        # Kiểm tra kích thước thực tế sau khi chuyển đổi.
        if len(salt) != 16 or len(expected) != 32:
            return False
        # Băm lại mật khẩu vừa nhập bằng salt đã lưu.
        actual = bytes.fromhex(hash_password(password, salt))
    except (TypeError, ValueError):
        return False
    # So sánh hash theo cách hạn chế lộ thông tin qua thời gian xử lý.
    return hmac.compare_digest(actual, expected)


def _validate_limit(max_bytes: int) -> None:
    """Kiểm tra giới hạn số byte là số nguyên dương; báo ValueError nếu sai."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")


class SecurityContext:
    """Quản lý Fernet theo mã khóa để bảo vệ packet; quyền truy cập do ứng dụng kiểm tra."""

    def __init__(self, keyring: dict[int, bytes]) -> None:
        """Kiểm tra bộ khóa và tạo một đối tượng Fernet cho mỗi mã khóa."""
        self._ciphers = {key_id: Fernet(key) for key_id, key in _validate_keyring(keyring).items()}

    def _cipher(self, key_id: int) -> Fernet:
        """Lấy đối tượng Fernet theo mã khóa; báo ValueError nếu mã không hợp lệ hoặc không có."""
        _validate_key_id(key_id)

        try:
            return self._ciphers[key_id]
        except KeyError:
            raise ValueError("Unknown key_id") from None

    def protect(self, packet: Packet, key_id: int, max_bytes: int) -> bytes:
        """Mã hóa packet và tạo envelope; báo lỗi nếu toàn bộ kết quả vượt giới hạn byte."""
        # Kiểm tra giới hạn và lấy đối tượng Fernet theo mã khóa.
        _validate_limit(max_bytes)
        cipher = self._cipher(key_id)

        # Kiểm tra và đóng gói packet thành bytes chưa mã hóa.
        plaintext = serialize_packet(packet)
        # Kết quả mã hóa sẽ lớn hơn đầu vào, nên loại sớm dữ liệu đã vượt giới hạn.
        if len(plaintext) > max_bytes:
            raise ValueError("Protected packet exceeds size limit")

        # Mã hóa packet rồi thêm header envelope, gồm mã khóa để bên nhận tra cứu.
        wire = pack_envelope(key_id, cipher.encrypt(plaintext))

        # Kiểm tra kích thước cuối cùng, bao gồm cả token Fernet và header envelope.
        if len(wire) > max_bytes:
            raise ValueError("Protected packet exceeds size limit")
        return wire

    def unprotect(self, wire: bytes, max_bytes: int) -> tuple[int, Packet]:
        """Kiểm tra và giải mã dữ liệu nhận được, trả về mã khóa cùng packet hợp lệ."""
        _validate_limit(max_bytes)

        if not isinstance(wire, bytes) or len(wire) > max_bytes:
            raise ValueError("Invalid protected packet size")

        # Lấy mã khóa và token Fernet.
        key_id, token = unpack_envelope(wire)
        cipher = self._cipher(key_id)

        try:
            # Chỉ kiểm tra Base64 chuẩn; vẫn giữ token ban đầu để đưa vào Fernet.
            _decode_base64(token)
        except (ValueError, binascii.Error):
            raise InvalidToken from None

        # Fernet kiểm tra tính toàn vẹn và giải mã;
        # deserialize_packet dựng lại đối tượng và kiểm tra schema.
        return key_id, deserialize_packet(cipher.decrypt(token))
