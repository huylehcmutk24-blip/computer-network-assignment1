"""Record the machine a measurement ran on (OS, CPU, memory, Python, network addresses).

Run once on each machine:
    python evidence/machine_info.py --role A      (on the server machine)
    python evidence/machine_info.py --role B      (on the second machine)
Writes evidence/out/machine_<role>.txt and .json.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import socket
import subprocess
import sys

from _common import Report


def memory_gib() -> float | None:
    """Tổng RAM (GiB) trên Windows qua GlobalMemoryStatusEx, trên Linux qua sysconf."""
    if sys.platform == "win32":

        class Status(ctypes.Structure):
            """Cấu trúc MEMORYSTATUSEX của Windows."""

            _fields_ = [
                ("length", ctypes.c_ulong),
                ("load", ctypes.c_ulong),
                ("total", ctypes.c_ulonglong),
                ("available", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong),
                ("available_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("extended", ctypes.c_ulonglong),
            ]

        status = Status()
        status.length = ctypes.sizeof(Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return round(status.total / 2**30, 1)
        return None
    try:
        return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1)
    except (ValueError, OSError, AttributeError):
        return None


def cpu_name() -> str:
    """Tên CPU: registry trên Windows, /proc/cpuinfo trên Linux."""
    if sys.platform == "win32":
        import winreg

        key = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
            return str(winreg.QueryValueEx(handle, "ProcessorNameString")[0]).strip()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def lan_address() -> str:
    """IP mà máy dùng để ra mạng LAN (không gửi gói nào: UDP connect chỉ chọn route)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return probe.getsockname()[0]
    except OSError:
        return "unknown"
    finally:
        probe.close()


def adapter() -> str:
    """Kết nối Wi-Fi (SSID và tốc độ) hoặc Ethernet, theo netsh trên Windows."""
    if sys.platform != "win32":
        return "not Windows"
    try:
        output = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    fields = {}
    for line in output.splitlines():
        name, _, value = line.partition(":")
        fields[name.strip().lower()] = value.strip()
    if "state" not in fields:
        return "unknown (netsh output not in English)"
    if fields["state"] == "connected":
        parts = [fields.get("radio type", ""), fields.get("receive rate (mbps)", "")]
        return "Wi-Fi " + " ".join(part for part in parts if part).strip()
    return "Ethernet (no Wi-Fi connection)"


def main() -> int:
    """Ghi thông tin máy vào evidence/out/machine_<role>.*."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["A", "B"], required=True)
    args = parser.parse_args()
    report = Report(f"machine_{args.role}", "two-machine")
    info = {
        "role": args.role,
        "os": platform.platform(),
        "cpu": cpu_name(),
        "cores": os.cpu_count(),
        "memory_gib": memory_gib(),
        "lan_ip": lan_address(),
        "link": adapter(),
    }
    report.data.update(info)
    for name, value in info.items():
        report.line(f"{name}: {value}")
    report.check(True, "machine described")
    return report.save()


if __name__ == "__main__":
    sys.exit(main())
