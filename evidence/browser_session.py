"""S1 to S6: three client processes used through their web pages, server on another host.

Run on the client host while the server runs on host A:
    python evidence/browser_session.py --server <IP of A>
The script starts client01, client02 and client03 exactly as a user does
(python main.py client ..., pages on 127.0.0.1:8765 to 8767, logs in logs/), opens the three
pages in a headless Chromium and uses the real interface: login form, chat form, file form
and progress list. client01 sends a 4 MiB and a 32 MiB random file to client03; client03 and
client01 chat while the large file streams; finally client03's process is killed. client01
stays logged in afterwards when --keep-client01 is given (the next scripts expect 20 users).
Needs: python -m pip install playwright && python -m playwright install chromium.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from _common import OUT, ROOT, Report
from playwright.sync_api import Page, sync_playwright

USERS = ("client01", "client02", "client03")


def start_client(index: int, server: str, keys: Path) -> subprocess.Popen:
    """Chạy clientNN bằng đúng lệnh người dùng gõ; output vào logs/clientNN.out."""
    user = USERS[index]
    log = ROOT / "logs" / f"{user}.out"
    log.parent.mkdir(exist_ok=True)
    arguments = [
        sys.executable,
        str(ROOT / "main.py"),
        "client",
        "--server",
        server,
        "--host",
        "0.0.0.0",
        "--username",
        user,
        "--key-id",
        str(index + 1),
        "--keyring",
        str(keys / f"{user}.keys.json"),
        "--http-port",
        str(8765 + index),
        "--receive-dir",
        str(ROOT / "downloads" / user),
        "--log-path",
        str(ROOT / "logs" / f"{user}.log"),
    ]
    return subprocess.Popen(
        arguments,
        cwd=ROOT,
        stdout=log.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def login(page: Page, username: str, password: str) -> None:
    """Đăng nhập qua form của trang."""
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-button")


def send_chat(page: Page, text: str, recipient: str = "") -> None:
    """Gửi tin qua form chat; recipient rỗng là chat chung."""
    page.select_option("#recipient", recipient)
    page.fill("#message", text)
    page.click("#send-message-button")


def wait_own_received(page: Page, text: str, timeout: float = 30000) -> None:
    """Chờ dòng tin của chính mình chuyển sang 'Server received'."""
    page.wait_for_function(
        """(text) => [...document.querySelectorAll('#message-list li.message.own')]
            .some(i => i.textContent.includes(text) && i.textContent.includes('Server received'))""",
        arg=text,
        timeout=timeout,
    )


def send_file(page: Page, path: Path, recipient: str) -> None:
    """Chọn file và gửi qua form file."""
    page.select_option("#file-recipient", recipient)
    page.set_input_files("#file-input", str(path))
    page.click("#send-file-button")


def transfer_status(page: Page, filename: str) -> str:
    """Trạng thái (data-status) của dòng truyền file theo tên."""
    return page.evaluate(
        """(name) => {
            for (const item of document.querySelectorAll('#transfer-list li.transfer')) {
                if (item.textContent.includes(name)) return item.dataset.status || '';
            }
            return '';
        }""",
        filename,
    )


def wait_final(page: Page, filename: str, timeout: float) -> str:
    """Chờ dòng truyền file tới trạng thái cuối."""
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        status = transfer_status(page, filename)
        if status in {"COMPLETED", "FAILED", "CANCELLED"}:
            return status
        page.wait_for_timeout(200)
    return "TIMEOUT"


def sha256(path: Path) -> str:
    """SHA-256 của một file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def user_count(page: Page) -> str:
    """Số người online trên trang."""
    return page.inner_text("#user-count")


def run_session(report: Report, pages: dict[str, Page], processes, password: str) -> None:
    """Các bước S1 đến S6 trên ba trang."""
    one, two, three = (pages[user] for user in USERS)

    # S1: sai mật khẩu, rồi cả ba đăng nhập.
    login(one, "client01", "wrong-password")
    one.wait_for_selector("#error-message:not([hidden])", timeout=20000)
    error = one.inner_text("#error-message")
    report.check("denied" in error.lower(), f"S1 wrong password: {error!r}")
    for user, page in pages.items():
        login(page, user, password)
    for page in pages.values():
        page.wait_for_function(
            "document.querySelector('#user-count').textContent === '3'", timeout=30000
        )
    badge = one.inner_text("#connection-status")
    report.check(True, f"S1 all three online, each list shows 3 users; badge {badge!r}")
    report.data.update(login_error=error, badge=badge)

    # S2: chat chung và riêng.
    send_chat(one, "Hello everyone, the build for the demo is ready.")
    two.wait_for_selector("text=the build for the demo is ready")
    three.wait_for_selector("text=the build for the demo is ready")
    send_chat(two, "Got it. Please send me the test file.", "client01")
    one.wait_for_selector("text=Please send me the test file")
    send_chat(one, "Sending it now (private, client03 cannot see this).", "client02")
    two.wait_for_selector("text=client03 cannot see this")
    send_chat(three, "Xin chào, client03 is online too.")
    one.wait_for_selector("text=client03 is online too")
    two.wait_for_selector("text=client03 is online too")
    one.wait_for_timeout(1000)
    private_on_three = three.locator("text=client03 cannot see this").count()
    private_on_three += three.locator("text=Please send me the test file").count()
    report.check(
        private_on_three == 0, "S2 public lines on all pages, private lines absent on client03"
    )

    # S3: file 4 MiB từ client01 tới client03.
    work = ROOT / "evidence" / "out" / "files"
    work.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, size in (("sample-4MiB.bin", 4), ("dataset-32MiB.bin", 32)):
        source = work / name
        source.write_bytes(os.urandom(size * 1024 * 1024))
        send_file(one, source, "client03")
        if size == 32:
            # S5: chat trong lúc file 32 MiB đang truyền.
            three.wait_for_function(
                """(name) => [...document.querySelectorAll('#transfer-list li.transfer')]
                    .some(i => i.textContent.includes(name) && i.dataset.status === 'TRANSFERRING')""",
                arg=name,
                timeout=60000,
            )
            three.wait_for_timeout(3000)
            send_chat(three, "Chat still arrives while the 32 MB file is streaming.")
            wait_own_received(three, "Chat still arrives while")
            send_chat(one, "Client01 is sending the file and can still chat.")
            wait_own_received(one, "can still chat")
            during = transfer_status(three, name)
            report.check(
                during == "TRANSFERRING", f"S5 both messages acknowledged during S4 ({during})"
            )
        status = wait_final(one, name, 1800)
        received = ROOT / "downloads" / "client03" / name
        same = received.exists() and sha256(received) == sha256(source)
        digest = sha256(source)
        results[name] = {"status": status, "sha256": digest, "same": same}
        report.check(
            status == "COMPLETED" and same,
            f"{'S3' if size == 4 else 'S4'} {size} MiB file: {status}, SHA-256 "
            f"{digest[:8]}...{digest[-8:]} at both ends",
        )
    report.data["files"] = results

    # S6: kill tiến trình client03 từ bên ngoài.
    processes["client03"].kill()
    start = time.perf_counter()
    one.wait_for_function(
        "document.querySelector('#user-count').textContent === '2'", timeout=30000
    )
    seen = time.perf_counter() - start
    send_chat(one, "client03 is gone, are you still there?", "client02")
    two.wait_for_selector("text=are you still there")
    report.check(
        user_count(two) == "2",
        f"S6 client03 killed: the others see 2 users after {seen:.2f} s and still chat",
    )
    report.data["kill_seen_s"] = round(seen, 3)


def main() -> int:
    """Chạy phiên ba client và ghi evidence/out/browser_session.*."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="IP of the server host, or auto")
    parser.add_argument("--keys", type=Path, default=ROOT / "config" / "secrets")
    parser.add_argument("--keep-client01", action="store_true")
    args = parser.parse_args()
    password = os.environ.get("STREAMCOLLAB_PASSWORD") or getpass.getpass(
        "Password of the clientNN accounts: "
    )
    report = Report("browser_session", "two-machine")
    OUT.mkdir(exist_ok=True)
    processes = {user: start_client(i, args.server, args.keys) for i, user in enumerate(USERS)}
    time.sleep(2)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            pages = {}
            for index, user in enumerate(USERS):
                # CSP của trang cấm eval; bypass chỉ để Playwright chạy hàm chờ.
                context = browser.new_context(
                    viewport={"width": 1280, "height": 860}, bypass_csp=True
                )
                page = context.new_page()
                page.goto(f"http://127.0.0.1:{8765 + index}/")
                pages[user] = page
            run_session(report, pages, processes, password)
            browser.close()
    finally:
        for user, process in processes.items():
            if user == "client01" and args.keep_client01:
                report.line(f"client01 left running, pid {process.pid}")
                (OUT / "client01.pid").write_text(str(process.pid), encoding="utf-8")
                continue
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
    return report.save()


if __name__ == "__main__":
    sys.exit(main())
