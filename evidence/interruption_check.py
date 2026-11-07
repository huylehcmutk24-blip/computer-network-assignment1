"""S13 and S16: real network outages of machine B and a restart of the server on machine A.

Run on machine B while the server runs on machine A, and follow the prompts:
    python evidence/interruption_check.py --server <IP of A>
A browser client for client04 runs in this process (the same code as the web page uses)
and logs in. The script records every change of its state with a timestamp while you:
  1. turn off the network of machine B for about 3 s (Wi-Fi off or cable out), then on;
  2. turn it off for about 20 s, then on;
  3. stop the server on machine A (Ctrl+C), wait about 3 s, start it again.
Press Enter at the moments the prompts ask for; nothing is simulated.
"""

from __future__ import annotations

import asyncio
import sys
import time

from _common import Lab, Report, parse_args, quiet_logs

from client import BrowserClient, UICommand

PHASES = [
    (
        "short_outage",
        "Turn OFF the network of machine B now and press Enter at once.",
        "After about 3 s turn the network back ON and press Enter at once.",
    ),
    (
        "long_outage",
        "Turn OFF the network of machine B now and press Enter at once.",
        "After about 20 s turn the network back ON and press Enter at once.",
    ),
    (
        "server_restart",
        "Stop the server on machine A now (Ctrl+C in its terminal) and press Enter here.",
        "Wait about 3 s, start the server again (python main.py server) and press Enter here.",
    ),
]


async def watch(browser: BrowserClient, timeline: list, stop: asyncio.Event) -> None:
    """Ghi mỗi lần (state, số lần thử lại, lỗi) thay đổi kèm thời điểm."""
    last = None
    while not stop.is_set():
        snapshot = browser.snapshot()
        key = (snapshot["state"], snapshot["reconnecting"], snapshot["error"])
        if key != last:
            timeline.append((time.perf_counter(), *key))
            last = key
        await asyncio.sleep(0.05)


async def run_phase(browser, name, first, second, report) -> dict:
    """Một lần gián đoạn: hai mốc do người thao tác bấm, rồi chờ client ONLINE trở lại."""
    timeline: list = []
    stop = asyncio.Event()
    watcher = asyncio.create_task(watch(browser, timeline, stop))
    await asyncio.to_thread(input, f"\n[{name}] {first}")
    down = time.perf_counter()
    await asyncio.to_thread(input, f"[{name}] {second}")
    up = time.perf_counter()
    deadline = up + 120
    while time.perf_counter() < deadline:
        snapshot = browser.snapshot()
        if snapshot["state"] == "ONLINE" and not snapshot["reconnecting"]:
            break
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.2)
    stop.set()
    await watcher
    events = [
        {"t": round(at - down, 2), "state": state, "attempt": attempt, "error": error}
        for at, state, attempt, error in timeline
    ]
    left_online = any(item["state"] != "ONLINE" for item in events)
    online_again = [item["t"] for item in events if item["state"] == "ONLINE" and item["t"] > 0]
    result = {
        "interruption_s": round(up - down, 2),
        "session_ended": left_online,
        "online_again_s": online_again[-1] if left_online and online_again else None,
        "online_at_end": browser.snapshot()["state"] == "ONLINE",
        "timeline": events,
    }
    report.line(f"[{name}] interruption {result['interruption_s']} s")
    for item in events:
        report.line(
            f"  t={item['t']:7.2f} s  {item['state']:<13} attempt={item['attempt']} error={item['error']}"
        )
    report.check(result["online_at_end"], f"[{name}] client ONLINE at the end")
    return result


async def main() -> int:
    """Chạy ba lần gián đoạn và ghi evidence/out/interruption_check.*."""
    args = parse_args(__doc__)
    if args.server is None:
        print("This check needs the server on machine A: use --server <IP of A>.")
        return 2
    async with Lab(args) as lab:
        report = Report("interruption_check", lab.mode)
        browser = BrowserClient(lab.settings(4))

        async def drain() -> None:
            """Lấy sự kiện UI để hàng đợi không đầy."""
            while True:
                await browser.events.get()

        drainer = asyncio.create_task(drain())
        await browser.execute(
            UICommand("login", {"username": "client04", "password": lab.password})
        )
        report.check(browser.snapshot()["state"] == "ONLINE", "client04 logged in")
        for name, first, second in PHASES:
            report.data[name] = await run_phase(browser, name, first, second, report)
        await browser.close()
        drainer.cancel()
        await asyncio.gather(drainer, return_exceptions=True)
    return report.save()


if __name__ == "__main__":
    quiet_logs()
    sys.exit(asyncio.run(main()))
