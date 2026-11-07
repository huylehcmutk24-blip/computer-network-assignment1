"""Turn the logs and results of the two-host measurement into report/numbers.tex.

Run on host A (the server host) from the project folder, after copying host B's `logs`
and `evidence/out` folders to measurements/B/logs and measurements/B/out:
    python -m tools.collect_metrics
Reads
  host A: logs/server.log, evidence/out/*.json (self check, Ruff, comments, machine_A)
  host B: measurements/B/logs/clientNN.log, cwnd_hol.csv, measurements/B/out/*.json
(a client log is looked for on both hosts) and writes measurements/report/numbers.tex,
cwnd_trace.csv and summary.txt. Copy the first two into the Overleaf project (numbers.tex
and data/cwnd_trace.csv). A value that cannot be found stays as a red [?] in the report and
is listed in summary.txt. Script results that were not produced against a server on another
host (mode two-machine) are refused.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMALL_BYTES = 4 * 1024 * 1024
BIG_BYTES = 32 * 1024 * 1024
MAX_TRACE_POINTS = 1500

LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}) (\w+) (\S+): (.*)$")
TRANSFER = re.compile(
    r"TRANSFER_(\w+) role=(\w+) id=(\S+) file=(.*) bytes=(\d+) seconds=([\d.]+) "
    r"mbps=([\d.]+) sha256=(\w+) code=(\S+) ended=([\d.]+)"
)
CHAT = re.compile(r"CHAT_SENT user=(\S+) kind=(\S+) bytes=(\d+) ack_ms=([\d.]+)")
RECEIVED = re.compile(r"CHAT_RECEIVED user=(\S+) kind=(\S+) from=(\S+)")
ONLINE = re.compile(r"ONLINE user=(\S+) udp=\('([\d.]+)', (\d+)\)")
HELLO = re.compile(r"RX TCP HELLO user=(\S+) peer=\('([\d.]+)', (\d+)\)")
CLOSED = re.compile(r"CONNECTION_CLOSED peer=\('([\d.]+)', (\d+)\) phase=(\S+) reason=(\w+)")
LEFT = re.compile(r"(DISCONNECTED|SESSION_ENDED) user=(\S+)(.*)$")


def esc(text: object) -> str:
    """Thoát ký tự đặc biệt của LaTeX."""
    table = {
        "\\": r"\textbackslash{}",
        "{": r"\{",
        "}": r"\}",
        "_": r"\_",
        "%": r"\%",
        "&": r"\&",
        "#": r"\#",
        "$": r"\$",
        "^": r"\^{}",
        "~": r"\textasciitilde{}",
    }
    return "".join(table.get(char, char) for char in str(text))


def read_log(path: Path) -> list[tuple[datetime, str]]:
    """Đọc file log thành danh sách (thời điểm, nội dung); file thiếu cho danh sách rỗng."""
    if not path.exists():
        return []
    entries = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        found = LINE.match(raw)
        if found:
            when = datetime.strptime(found.group(1), "%Y-%m-%d %H:%M:%S,%f")
            entries.append((when, found.group(4)))
    return entries


def transfers(entries) -> list[dict]:
    """Các dòng TRANSFER_* của một log."""
    result = []
    for when, message in entries:
        found = TRANSFER.search(message)
        if found:
            status, role, tid, name, size, seconds, mbps, sha, code, ended = found.groups()
            result.append(
                {
                    "at": when,
                    "status": status,
                    "role": role,
                    "id": tid,
                    "file": name,
                    "bytes": int(size),
                    "seconds": float(seconds),
                    "mbps": float(mbps),
                    "sha256": sha,
                    "code": code,
                    "ended": float(ended),
                }
            )
    return result


def chats(entries) -> list[tuple[datetime, float]]:
    """Các lần gửi chat (thời điểm, ms tới khi server ACK)."""
    return [
        (when, float(found.group(4)))
        for when, message in entries
        if (found := CHAT.search(message))
    ]


class Collector:
    """Gom các macro LaTeX và ghi lại giá trị còn thiếu."""

    def __init__(self, allow_any: bool) -> None:
        """Bắt đầu với danh sách macro rỗng."""
        self.values: dict[str, str | None] = {}
        self.notes: list[str] = []
        self.allow_any = allow_any

    def set(self, name: str, value: object | None) -> None:
        """Đặt một macro; None nghĩa là chưa đo được."""
        self.values[name] = None if value is None else str(value)

    def results(self, folder: Path, name: str, need_two_machines: bool = True) -> dict | None:
        """Đọc evidence/out/<name>.json, chỉ nhận kết quả đo với server ở host khác."""
        path = folder / f"{name}.json"
        if not path.exists():
            self.notes.append(f"missing {path}")
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not self.allow_any and need_two_machines and data.get("mode") != "two-machine":
            self.notes.append(f"refused {path}: mode {data.get('mode')}, not two-machine")
            return None
        if data.get("result") != "ALL PASS":
            self.notes.append(f"{path}: result {data.get('result')} (values kept, check the .txt)")
        return data

    def write(self, out: Path) -> None:
        """Ghi numbers.tex và summary.txt."""
        lines = [
            "% Generated by tools/collect_metrics.py from the logs and results of the run.",
            "% \\Missing marks a value that was not found; rerun the tool after measuring it.",
        ]
        summary = []
        for name, value in self.values.items():
            body = value if value is not None else f"\\Missing{{{name}}}"
            lines.append(f"\\newcommand{{\\{name}}}{{{body}}}")
            summary.append(f"{name:<18} {value if value is not None else 'MISSING'}")
        (out / "numbers.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")
        missing = sum(value is None for value in self.values.values())
        summary += ["", f"{missing} of {len(self.values)} values missing", *self.notes]
        (out / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
        print("\n".join(summary))


def short_sha(sha: str) -> str:
    """Rút gọn SHA-256 thành 8 ký tự đầu và 8 ký tự cuối."""
    return f"{sha[:8]}\\dots {sha[-8:]}"


def verdict(ok: bool | None) -> str | None:
    """PASS/FAIL cho cột Result; None khi chưa có dữ liệu."""
    if ok is None:
        return None
    return "PASS" if ok else "\\textbf{FAIL}"


def passed(data: dict | None) -> bool | None:
    """Kết quả chung của một script: True nếu ALL PASS, None nếu chưa chạy."""
    return None if data is None else data.get("result") == "ALL PASS"


def kinds(entries, pattern: re.Pattern) -> list[str]:
    """Loại tin (public/private) của các dòng CHAT_SENT hoặc CHAT_RECEIVED."""
    return [found.group(2) for _, message in entries if (found := pattern.search(message))]


def first_addresses(server: list, pattern: re.Pattern) -> dict[str, tuple[str, str]]:
    """Địa chỉ đầu tiên server ghi cho mỗi user theo một mẫu log (HELLO hoặc ONLINE)."""
    result: dict[str, tuple[str, str]] = {}
    for _, message in server:
        if (found := pattern.search(message)) and found.group(1) not in result:
            result[found.group(1)] = (found.group(2), found.group(3))
    return result


def file_results(c: Collector, sent: list, received: dict) -> None:
    """S3 và S4: thời gian, tốc độ và SHA-256 của hai file từ bên gửi tới bên nhận."""
    for size, prefix in ((SMALL_BYTES, "Small"), (BIG_BYTES, "Big")):
        item = next((t for t in sent if t["bytes"] == size), None)
        match = item and received.get(item["id"])
        verified = bool(match and match["status"] == "DONE" and match["sha256"] == item["sha256"])
        if item and not verified:
            c.notes.append(f"{prefix}: no verified receiver line for {item['id']}")
        c.set(f"{prefix}Seconds", f"{item['seconds']:.1f}" if verified else None)
        c.set(f"{prefix}Mbps", f"{item['mbps']:.2f}" if verified else None)
        c.set(f"Sha{prefix}", short_sha(item["sha256"]) if verified else None)
        c.set(f"Res{prefix}", verdict(verified if item else None))


def chat_results(c: Collector, logs: dict, roles: dict, sent: list, received: dict) -> None:
    """S2 và S5: độ trễ tới ACK của chat, và của chat gửi trong lúc truyền file 32 MiB."""
    big_sent = next((t for t in sent if t["bytes"] == BIG_BYTES), None)
    windows = []
    if big_sent:
        # Mỗi log so với cửa sổ truyền ghi trên đồng hồ của chính host đó: bên gửi và
        # client còn lại cùng host với bên gửi, bên nhận dùng bản ghi của chính nó.
        windows.append((logs[roles["sender"]], big_sent))
        if roles["outsider"] not in (roles["sender"], roles["receiver"]):
            windows.append((logs[roles["outsider"]], big_sent))
        if big_sent["id"] in received:
            windows.append((logs[roles["receiver"]], received[big_sent["id"]]))
    during = []
    for entries, item in windows:
        end = item["at"].timestamp()
        during += [
            ms for when, ms in chats(entries) if end - item["seconds"] <= when.timestamp() <= end
        ]
    c.set("ResDuring", verdict(bool(during)) if big_sent else None)
    c.set("ChatDuringCount", len(during) if during else None)
    c.set("ChatDuringFile", f"{max(during):.0f}" if during else None)
    acks = [ms for entries in logs.values() for _, ms in chats(entries)]
    c.set("ChatCount", len(acks) if acks else None)
    c.set("ChatAckMedian", f"{statistics.median(acks):.1f}" if acks else None)
    c.set("ChatAckMax", f"{max(acks):.1f}" if acks else None)
    sent_kinds = [kind for entries in logs.values() for kind in kinds(entries, CHAT)]
    seen_by_03 = kinds(logs[roles["outsider"]], RECEIVED)
    chat_ok = "public" in sent_kinds and "private" in sent_kinds and "public" in seen_by_03
    c.set("ResChat", verdict(chat_ok and "private" not in seen_by_03) if acks else None)


def killed_client(c: Collector, server: list, name: str, peer: tuple[str, str] | None) -> None:
    """S6: lần đầu client bị kill rời server và lý do server ghi cho kết nối TCP của nó."""
    reason = left = None
    for _, message in server:
        found = CLOSED.search(message)
        if found and peer and (found.group(1), found.group(2)) == peer and reason is None:
            reason = found.group(4)
        found = LEFT.search(message)
        if found and found.group(2) == name:
            left = message.split(" | ")[0]
            if "reason=" in left:
                left, _, logged = left.partition(" reason=")
                reason = reason or logged
            break
    c.set("KillLine", f"\\code{{{esc(left)}}}" if left else None)
    c.set("KillReason", f"\\code{{{esc(reason)}}}" if reason else "end of stream" if left else None)
    c.set("ResKill", verdict(True) if left else None)


def client_log(folders: list[Path], name: str) -> list[tuple[datetime, str]]:
    """Log của một client, tìm lần lượt trong các thư mục log của hai host."""
    for folder in folders:
        if (folder / f"{name}.log").exists():
            return read_log(folder / f"{name}.log")
    return []


def manual_session(c: Collector, folders: list[Path], server: list, roles: dict) -> None:
    """S1 đến S6: phiên dùng ba trang web."""
    logs = {name: client_log(folders, name) for name in ("client01", "client02", "client03")}
    sent = [
        t
        for t in transfers(logs[roles["sender"]])
        if t["role"] == "sender" and t["status"] == "DONE"
    ]
    received = {t["id"]: t for t in transfers(logs[roles["receiver"]]) if t["role"] == "receiver"}
    file_results(c, sent, received)
    chat_results(c, logs, roles, sent, received)
    hello = first_addresses(server, HELLO)
    online = first_addresses(server, ONLINE)
    remote = roles["remote"]
    c.set("SessionTcp", ":".join(hello[remote]) if remote in hello else None)
    c.set("SessionUdp", ":".join(online[remote]) if remote in online else None)
    denied = any(
        "AUTH_ERROR user=" in message for entries in logs.values() for _, message in entries
    )
    three = all(name in online for name in logs)
    c.set("ResLogin", verdict(denied and three) if server and any(logs.values()) else None)
    killed_client(c, server, roles["outsider"], hello.get(roles["outsider"]))


def read_trace(path: Path) -> list[tuple[float, str, float, str]]:
    """Đọc file trace cwnd: thời_gian,peer,cwnd,sự_kiện."""
    rows = []
    if path.exists():
        for row in csv.reader(path.read_text(encoding="utf-8").splitlines()):
            if len(row) == 4:
                rows.append((float(row[0]), row[1], float(row[2]), row[3]))
    return rows


def cwnd_trace(c: Collector, b_logs: Path, b_out: Path, out: Path) -> None:
    """cwnd của bên gửi trong lượt truyền của S5b (hol_check, một chunk bị giữ lại)."""
    for name in (
        "CwndLosses",
        "CwndTimeouts",
        "CwndMin",
        "CwndSeconds",
        "CwndLossAt",
        "CwndRecoverMs",
    ):
        c.set(name, None)
    hol_path = b_out / "hol_check.json"
    hol = json.loads(hol_path.read_text(encoding="utf-8")) if hol_path.exists() else {}
    rows = read_trace(b_logs / "cwnd_hol.csv")
    if not rows or "file_started_epoch" not in hol:
        c.notes.append("cwnd: need logs/cwnd_hol.csv and hol_check.json of the same run")
        return
    start, end = hol["file_started_epoch"], hol["file_finished_epoch"]
    labels = Counter(label for at, label, _, _ in rows if at <= end)
    label = labels.most_common(1)[0][0]
    rows = [row for row in rows if row[1] == label]
    before = [cwnd for at, _, cwnd, _ in rows if at < start]
    current = before[-1] if before else 8.0
    inside = [(at - start, cwnd, event) for at, _, cwnd, event in rows if start <= at <= end]
    points = [
        (0.0, current, "begin"),
        *inside,
        (end - start, inside[-1][1] if inside else current, "end"),
    ]
    if len(points) > MAX_TRACE_POINTS:
        step = len(points) // MAX_TRACE_POINTS + 1
        points = [
            point
            for index, point in enumerate(points)
            if point[2] != "ack" or index % step == 0 or index == len(points) - 1
        ]
    with (out / "cwnd_trace.csv").open("w", encoding="utf-8", newline="") as handle:
        handle.write("t,cwnd,event\n")
        for t, cwnd, event in points:
            handle.write(f"{t:.4f},{cwnd:.3f},{event}\n")
    events = Counter(event for _, _, event in inside)
    c.set("CwndLosses", events["loss"])
    c.set("CwndTimeouts", events["timeout"])
    c.set("CwndMin", f"{min(cwnd for _, cwnd, _ in points):g}")
    c.set("CwndSeconds", f"{end - start:.2f}")
    drops = [index for index, point in enumerate(points) if point[2] in ("loss", "timeout")]
    if drops:
        first = points[drops[0]]
        full = next((t for t, cwnd, _ in points[drops[0] :] if cwnd >= current), None)
        c.set("CwndLossAt", f"{first[0]:.2f}")
        c.set("CwndRecoverMs", f"{(full - first[0]) * 1000:.0f}" if full is not None else None)


def number(value: int) -> str:
    """Số có dấu cách mảnh giữa các nhóm nghìn."""
    return f"{value:,}".replace(",", "\\,")


def hol_and_encryption(c: Collector, b_out: Path) -> None:
    """S5b, S7 (hol_check) và S10 (encryption_check)."""
    hol = c.results(b_out, "hol_check")
    c.set("HolGapMs", hol and hol["gap_ms"])
    c.set("HolIdleMedian", hol and hol["idle_median_ms"])
    c.set("HolGapCount", hol and hol["gap_messages"])
    c.set("HolGapRange", hol and f"{hol['gap_min_ms']} to {hol['gap_max_ms']}")
    c.set("HolDuringMedian", hol and hol.get("during_median_ms"))
    c.set("HolDuringMax", hol and hol.get("during_max_ms"))
    c.set("HolSends", hol and number(hol["file_sends"]))
    c.set("HolChunks", hol and number(hol["chunks"]))
    c.set("ResHol", verdict(passed(hol)))
    lost_ok = hol and hol["file_sends"] == hol["chunks"] + 1 and hol["sha256_equal"]
    c.set("ResLost", verdict(bool(lost_ok)) if hol else None)
    enc = c.results(b_out, "encryption_check")
    c.set("EncDatagrams", enc and enc["datagrams"])
    c.set("EncTcp", enc and enc["tcp_chunks"])
    c.set("EncFlips", enc and number(enc["bit_flips"]))
    c.set("EncAccepted", enc and enc["flips_accepted"])
    c.set("ResEnc", verdict(passed(enc)))


def logins(c: Collector, b_out: Path, server: list) -> None:
    """S8 và S11 (concurrent_login), đối chiếu địa chỉ với log server của máy A."""
    login = c.results(b_out, "concurrent_login")
    c.set("LoginClients", login and login["clients"])
    c.set("LoginOnline", login and login.get("online_users"))
    c.set("LoginConcurrent", login and f"{login['concurrent_s']:.2f}")
    c.set("LoginSequential", login and f"{login['sequential_s']:.2f}")
    c.set("LeaveCount", login and login["leaving"])
    c.set("LeaveSeen", login and f"{login['leave_seen_s'] * 1000:.0f}")
    seen = {
        (found.group(1), found.group(2), int(found.group(3)))
        for _, message in server
        if (found := ONLINE.search(message))
    }
    if login and server:
        matches = sum(
            (name, item["tcp"][0], item["udp_port"]) in seen
            for name, item in login["addresses"].items()
        )
        c.set("AddrMatch", f"{matches} of {len(login['addresses'])}")
        c.set("ResLogins", verdict(passed(login) and matches == len(login["addresses"])))
    else:
        c.set("AddrMatch", None)
        c.set("ResLogins", None)
    c.set("ResScale", verdict(login.get("online_users", 0) >= 20) if login else None)


def close_reasons(server: list, ip: str, ports: set[str]) -> Counter:
    """Đếm lý do CONNECTION_CLOSED của server cho các kết nối thử từ (ip, port)."""
    return Counter(
        found.group(4)
        for _, message in server
        if (found := CLOSED.search(message)) and found.group(1) == ip and found.group(2) in ports
    )


def resilience(c: Collector, b_out: Path, server: list) -> None:
    """S12 (resilience_check), lý do đóng kết nối lấy từ log server của máy A."""
    res = c.results(b_out, "resilience_check")
    reasons = quiet = Counter()
    wanted: set[str] = set()
    if res and server:
        ports = res.get("probe_ports", {})
        wanted = {str(p) for kind in ("zero_frame", "reset") for p in ports.get(kind, [])}
        reasons = close_reasons(server, res["client_ip"], wanted)
        quiet_ports = {str(p) for kind in ("silent", "half") for p in ports.get(kind, [])}
        quiet = close_reasons(server, res["client_ip"], quiet_ports)
    text = ", ".join(f"{count} \\code{{{esc(name)}}}" for name, count in reasons.most_common())
    missing = len(wanted) - sum(reasons.values())
    if reasons and missing:
        text += f", {missing} without a log line"
    c.set("ResetReasons", text or None)
    c.set("QuietReason", ", ".join(f"\\code{{{esc(name)}}}" for name in quiet) or None)
    c.set("ResetChat", res and res["chat_after_ms"])
    c.set("ResetLogin", res and res["login_after_ms"])
    c.set("SilentClose", res and f"{res['silent_close_s']:.2f}")
    c.set("HalfClose", res and f"{res['half_close_s']:.2f}")
    c.set("VanishMs", res and res["vanished_ms"])
    c.set("LogoutMs", res and res["logout_ms"])
    c.set("MidFileMs", res and res["mid_file_ms"])
    c.set("ResFaults", verdict(passed(res)))


def outcome(item: dict, restored: str) -> str:
    """Câu mô tả một lần gián đoạn của interruption_check (thời gian tính từ phím Enter đầu)."""
    events = item["timeline"]
    attempts = max((event["attempt"] for event in events), default=0)
    if not item["session_ended"]:
        return "the session stayed \\code{ONLINE}"
    lost = next(event["t"] for event in events if event["state"] != "ONLINE")
    ended = f"the session ended after {lost:.1f}~s" if lost > 0.5 else "the session ended at once"
    if item["online_again_s"] is None:
        return f"{ended} and the client did not come back"
    back = item["online_again_s"] - item["interruption_s"]
    return (
        f"{ended}, and the client was \\code{{ONLINE}} again {back:.1f}~s after {restored} "
        f"(attempt {attempts})"
    )


def restart_from_log(server: list, user: str) -> tuple[float, float] | None:
    """S16 theo log server: thời gian server dừng và lúc user ONLINE lại sau khi chạy lại."""
    stopped = None
    for index, (when, message) in enumerate(server):
        if "SERVER STOPPED" in message:
            stopped = when
        elif "Server started" in message and stopped is not None:
            for later, text in server[index + 1 :]:
                if f"ONLINE user={user} " in text:
                    return (when - stopped).total_seconds(), (later - when).total_seconds()
            return None
    return None


def interruptions(c: Collector, b_out: Path, server: list) -> None:
    """S13 và S16 (interruption_check): mất mạng ngắn, dài và khởi động lại server."""
    stop = c.results(b_out, "interruption_check")
    for key, prefix, restored in (
        ("short_outage", "Short", "the link came back"),
        ("long_outage", "Long", "the link came back"),
        ("server_restart", "Restart", "the server was started again"),
    ):
        item = stop and stop.get(key)
        c.set(f"{prefix}Gap", item and f"{item['interruption_s']:.1f}")
        c.set(f"{prefix}Result", item and outcome(item, restored))
    restart = restart_from_log(server, "client04") if stop else None
    attempts = None
    if stop and stop.get("server_restart"):
        attempts = max(e["attempt"] for e in stop["server_restart"]["timeline"])
    c.set("RestartDown", restart and f"{restart[0]:.1f}")
    c.set("RestartBack", restart and f"{restart[1]:.1f}")
    c.set("RestartAttempt", attempts)
    if stop:
        short, long = stop.get("short_outage"), stop.get("long_outage")
        outage_ok = bool(short and long and short["online_at_end"] and long["online_at_end"])
        restart = stop.get("server_restart")
        c.set("ResOutage", verdict(outage_ok))
        c.set("ResRestart", verdict(bool(restart and restart["online_at_end"])))
    else:
        c.set("ResOutage", None)
        c.set("ResRestart", None)


def discovery_and_bridge(c: Collector, b_out: Path) -> None:
    """S14 (discovery_check) và S15 (http_bridge_check)."""
    disc = c.results(b_out, "discovery_check")
    c.set("DiscoveryMs", disc and disc["discovery_median_ms"])
    c.set("DiscoveryMax", disc and disc["discovery_max_ms"])
    c.set("DiscoveredIp", disc and disc["server_ip"])
    c.set("AnnounceBytes", disc and disc["announce_bytes"])
    c.set("ResDiscovery", verdict(passed(disc)))
    bridge = c.results(b_out, "http_bridge_check")
    if bridge:
        good = sum(bridge["statuses"][k] == v for k, v in bridge.get("expected", {}).items())
        c.set("BridgeResult", f"{good} of {len(bridge['statuses'])}")
    else:
        c.set("BridgeResult", None)
    c.set("ResBridge", verdict(passed(bridge)))


def scripts(c: Collector, b_out: Path, server: list) -> None:
    """Các script chạy trên máy B (S5b, S7, S8, S10 đến S16)."""
    hol_and_encryption(c, b_out)
    logins(c, b_out, server)
    resilience(c, b_out, server)
    interruptions(c, b_out, server)
    discovery_and_bridge(c, b_out)


def machine_a(c: Collector, a_out: Path) -> None:
    """Self check, Ruff và số chú thích chạy trên máy A."""
    demo = c.results(a_out, "self_check", need_two_machines=False)
    c.set("DemoRuns", demo and f"{demo['passed']} of {demo['runs']}")
    c.set("DemoSameSeq", demo and f"{demo.get('same_seq', 0)} of {demo['runs']}")
    times = demo and demo["seconds"]
    c.set("DemoTimes", times and f"{min(times):.1f} to {max(times):.1f}")
    ruff = c.results(a_out, "ruff", need_two_machines=False)
    c.set("RuffVersion", ruff and esc(ruff["version"].replace("ruff ", "")))
    c.set("RuffFiles", ruff and ruff.get("formatted_files"))
    c.set("RuffResult", ruff and ("no finding" if ruff["result"] == "ALL PASS" else "findings"))
    count = c.results(a_out, "comment_count", need_two_machines=False)
    c.set("CommentDocs", count and f"{count['documented']} of {count['functions']}")
    c.set("CommentCount", count and count["comments"])
    c.set("CommentVi", count and count["comments_vietnamese"])
    c.set("CommentJs", count and count["js_functions"])


def main() -> int:
    """Đọc dữ liệu hai máy và ghi numbers.tex, cwnd_trace.csv, summary.txt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--a-logs", type=Path, default=ROOT / "logs")
    parser.add_argument("--a-out", type=Path, default=ROOT / "evidence" / "out")
    parser.add_argument("--b", type=Path, default=ROOT / "measurements" / "B")
    parser.add_argument("--out", type=Path, default=ROOT / "measurements" / "report")
    parser.add_argument("--sender", default="client02", help="client that sent the files")
    parser.add_argument("--receiver", default="client01", help="client that received them")
    parser.add_argument("--outsider", default="client03", help="client killed in S6")
    parser.add_argument("--remote", default="client02", help="client whose addresses S1 reports")
    parser.add_argument("--allow-any", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    c = Collector(args.allow_any)
    b_logs, b_out = args.b / "logs", args.b / "out"

    info_a = c.results(args.a_out, "machine_A", need_two_machines=False)
    info_b = c.results(b_out, "machine_B")
    c.set("MeasureDate", info_b and info_b["date"])
    c.set("AddrA", info_a and info_a["lan_ip"])
    c.set("AddrB", info_b and info_b["lan_ip"])

    server = read_log(args.a_logs / "server.log")
    if not server:
        c.notes.append(f"missing {args.a_logs / 'server.log'}")
    roles = {key: getattr(args, key) for key in ("sender", "receiver", "outsider", "remote")}
    manual_session(c, [args.a_logs, b_logs], server, roles)
    two = info_a and info_b and info_a["lan_ip"] != info_b["lan_ip"]
    lan = c.values.get("SessionTcp")
    c.set("ResLan", verdict(bool(two and lan.startswith(info_b["lan_ip"] + ":"))) if lan else None)
    cwnd_trace(c, b_logs, b_out, args.out)
    scripts(c, b_out, server)
    machine_a(c, args.a_out)
    c.write(args.out)
    print(f"\nWrote {args.out / 'numbers.tex'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
