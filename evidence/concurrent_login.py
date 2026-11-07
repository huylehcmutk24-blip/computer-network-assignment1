"""S11: many logins at once, address tracking, and half of the clients leaving at once.

Run on machine B while the server runs on machine A, with client01 logged in on machine A
and client02 to client20 not logged in:
    python evidence/concurrent_login.py --server <IP of A>
client02 to client20 (19 clients, 20 users with client01) log in one after another, log
out, then log in all at once. The script records each client's own TCP and UDP ports;
tools/collect_metrics.py compares them with the addresses in the server log of machine A.
"""

from __future__ import annotations

import asyncio
import sys
import time

from _common import Lab, Report, parse_args, quiet_logs, wait_until

NUMBERS = range(2, 21)


async def login_all(lab: Lab, concurrent: bool) -> tuple[float, list]:
    """Đăng nhập các client cùng lúc hoặc lần lượt; trả thời gian tới khi ai cũng thấy đủ."""
    names = {f"client{n:02}" for n in NUMBERS}
    start = time.perf_counter()
    if concurrent:
        sessions = list(await asyncio.gather(*(lab.open(n) for n in NUMBERS)))
    else:
        sessions = [await lab.open(n) for n in NUMBERS]
    await wait_until(lambda: all(names <= set(s.users()) for s in sessions), 30)
    return time.perf_counter() - start, sessions


async def main() -> int:
    """Chạy kịch bản và ghi evidence/out/concurrent_login.*."""
    args = parse_args(__doc__)
    async with Lab(args) as lab:
        report = Report("concurrent_login", lab.mode)
        count = len(NUMBERS)
        sequential, sessions = await login_all(lab, concurrent=False)
        for session in sessions:
            await session.close()
        await asyncio.sleep(1)
        concurrent, sessions = await login_all(lab, concurrent=True)
        report.line(
            f"{count} logins one after another: {sequential:.3f} s; at once: {concurrent:.3f} s"
        )
        online = len(sessions[0].users())
        report.check(True, f"every online list shows the {count} clients ({online} users online)")

        addresses = {}
        for session in sessions:
            tcp = session.client._tcp_socket.getsockname()[:2]
            udp = session.client._udp_socket.getsockname()[:2]
            addresses[session.name] = {"tcp": list(tcp), "udp_port": udp[1]}
        first = sessions[0].name
        report.line(
            f"{first}: TCP {addresses[first]['tcp']}, UDP port {addresses[first]['udp_port']}"
        )
        if lab.server is not None:  # Chế độ local: đọc thẳng bảng phiên của server.
            matches = sum(
                lab.server.users.find_user(name).udp_address[1] == item["udp_port"]
                for name, item in addresses.items()
            )
            report.check(matches == count, f"{matches} of {count} server records match")

        leaving, staying = sessions[count // 2 :], sessions[: count // 2]
        await asyncio.gather(*(session.close() for session in leaving))
        gone = {session.name for session in leaving}
        seen = await wait_until(lambda: all(not gone & set(s.users()) for s in staying), 15)
        report.line(f"{len(leaving)} clients closed together; the others saw it {seen:.3f} s later")
        report.data.update(
            clients=count,
            online_users=online,
            sequential_s=round(sequential, 3),
            concurrent_s=round(concurrent, 3),
            leaving=len(leaving),
            leave_seen_s=round(seen, 3),
            addresses=addresses,
        )
        for session in staying:
            await session.close()
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
