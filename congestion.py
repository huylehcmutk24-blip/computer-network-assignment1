"""CUBIC rút gọn cho đồ án: cửa sổ hữu hạn, tăng theo ACK, giảm khi mất gói.

Giữ đường cong cubic cơ bản; không mô phỏng đầy đủ TCP CUBIC/RFC 9438.
Không có pacing, RTT estimator, slow start hay các nhánh tối ưu nâng cao.
Transport quản lý timeout/retry; thời gian truyền vào dùng đồng hồ monotonic.
"""

from __future__ import annotations

import math
import os
import time

from config import Settings

type SegmentId = tuple[str, str, int]

CUBIC_C = 0.4
BETA = 0.7

# Chế độ đo: đặt biến môi trường STREAMCOLLAB_CWND_TRACE=<file> để ghi mỗi lần cwnd đổi
# thành dòng "thời_gian,user>peer,cwnd,sự_kiện" (tools/collect_metrics.py dựng hình từ file này).
_TRACE_PATH = os.environ.get("STREAMCOLLAB_CWND_TRACE")
_trace_file = None


def _trace(label: str, cwnd: float, event: str) -> None:
    """Ghi một mẫu cwnd khi chế độ đo được bật; không làm gì nếu biến môi trường trống."""
    global _trace_file
    if not _TRACE_PATH:
        return
    if _trace_file is None:
        _trace_file = open(_TRACE_PATH, "a", encoding="utf-8", buffering=1)  # noqa: SIM115
    _trace_file.write(f"{time.time():.4f},{label},{cwnd:.3f},{event}\n")


class CongestionController:
    """Một controller mỗi peer; mọi stream dùng chung ngân sách gửi của peer đó."""

    def __init__(self, settings: Settings, label: str = "") -> None:
        """Khởi tạo cửa sổ tắc nghẽn có giới hạn, chưa có gói nào đang gửi."""
        if type(settings.window_packets) is not int or settings.window_packets < 1:
            raise ValueError("window_packets must be a positive integer")
        self._label = label
        self._limit = settings.window_packets
        self._cwnd = float(self._limit)
        self._in_flight: dict[SegmentId, float] = {}  # Thời điểm gửi đầu tiên.
        self._last_max_window = self._cwnd
        self._epoch_started_at: float | None = None
        self._k = 0.0
        self._recovery_started_at = -math.inf
        _trace(self._label, self._cwnd, "start")

    @property
    def window_packets(self) -> int:
        """Trả số gói nguyên được phép trong cửa sổ, tối thiểu là một gói."""
        return max(1, math.floor(self._cwnd))

    def send_budget(self, receive_capacity: int) -> int:
        """Trả số gói còn được gửi theo cửa sổ tắc nghẽn và chỗ trống phía nhận."""
        if type(receive_capacity) is not int or receive_capacity < 0:
            raise ValueError("receive_capacity must be a non-negative integer")
        return max(0, min(receive_capacity, self.window_packets - len(self._in_flight)))

    def on_sent(self, segment: SegmentId, sent_at: float) -> None:
        """Ghi nhận lần gửi đầu và bắt đầu tăng lại sau lúc rảnh; retry dùng slot cũ."""
        if not math.isfinite(sent_at):
            raise ValueError("Invalid send sample")
        if segment in self._in_flight:
            return  # Retry không chiếm thêm slot hay đổi thời điểm gửi đầu tiên.
        if not self._in_flight:
            self._epoch_started_at = sent_at  # Không tích lũy tăng trưởng lúc idle.
            self._k = math.cbrt(max(0.0, self._last_max_window - self._cwnd) / CUBIC_C)
        self._in_flight[segment] = sent_at

    def on_ack(self, segment: SegmentId, now: float, retransmitted: bool) -> None:
        """Giải phóng gói đã biết và chỉ tăng cửa sổ cho ACK lần gửi đầu đủ điều kiện."""
        sent_at = self._in_flight.pop(segment, None)
        if sent_at is None:
            return  # ACK trùng/lạ không giải phóng slot hoặc tăng cửa sổ.
        if not retransmitted and sent_at > self._recovery_started_at:
            start = self._epoch_started_at if self._epoch_started_at is not None else now
            elapsed = max(0.0, now - start)
            target = CUBIC_C * (elapsed - self._k) ** 3 + self._last_max_window
            # Mức tăng tối thiểu giúp phục hồi cả khi window=1; tối đa 1 gói/ACK.
            increase = min(1.0, max(1.0 / self._cwnd, (target - self._cwnd) / self._cwnd))
            before = self._cwnd
            self._cwnd = min(self._limit, self._cwnd + increase)
            if self._cwnd != before:
                _trace(self._label, self._cwnd, "ack")
        if not self._in_flight:
            self._epoch_started_at = None

    def on_loss(self, segment: SegmentId, now: float) -> None:
        """Giảm cửa sổ một lần cho mỗi nhóm gói mất vừa phát hiện."""

        sent_at = self._in_flight.get(segment)

        if sent_at is not None and sent_at > self._recovery_started_at:
            self._reduce_window(max(1.0, self._cwnd * BETA), now)
            _trace(self._label, self._cwnd, "loss")

    def on_timeout(self, now: float) -> None:
        """Giảm cửa sổ xuống một gói khi các gói đang gửi hết thời gian chờ."""
        if self._in_flight:
            self._reduce_window(1.0, now)
            _trace(self._label, self._cwnd, "timeout")

    def _reduce_window(self, window: float, now: float) -> None:
        """Đặt cửa sổ đã giảm và bắt đầu lại đường cong phục hồi CUBIC."""
        self._last_max_window = self._cwnd
        self._cwnd = window
        self._epoch_started_at = now
        self._k = math.cbrt((self._last_max_window - self._cwnd) / CUBIC_C)
        # Cùng nhóm gói cũ chỉ giảm một lần; ACK của nhóm đó không tăng trở lại.
        self._recovery_started_at = now

    def forget_session(self, session_id: str) -> None:
        """Bỏ các gói của phiên đã đóng khỏi số gói đang gửi dùng chung."""
        for segment in tuple(self._in_flight):
            if segment[0] == session_id:
                self._in_flight.pop(segment)
        if not self._in_flight:
            self._epoch_started_at = None
