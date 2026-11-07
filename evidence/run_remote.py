"""Client-host part of the measurements: every script that needs a server on another host.

Before you start: host A runs the server (python main.py server) and client01 is logged in
(for example left running by browser_session.py --keep-client01); no other client of the
browser session is running. Run on host B from the project folder:
    python evidence/run_remote.py --server <IP of A>
The password of the clientNN accounts is asked once. The last script
(interruption_check.py) asks you to take the network of host B down and up and to restart
the server on host A; skip it with --no-interruption and run it later.
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import time

from _common import EVIDENCE, OUT, ROOT

SCRIPTS = [
    ("machine_info.py", ["--role", "B"]),
    ("discovery_check.py", ["--server", "auto"]),
    ("encryption_check.py", None),
    ("hol_check.py", None),
    ("concurrent_login.py", None),
    ("http_bridge_check.py", None),
    ("resilience_check.py", None),
]


def main() -> int:
    """Chạy lần lượt các script đo trên máy B và in bảng tóm tắt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="IP of machine A")
    parser.add_argument("--keys", default=str(ROOT / "config" / "secrets"))
    parser.add_argument("--no-interruption", action="store_true")
    args = parser.parse_args()
    environment = dict(os.environ)
    environment["STREAMCOLLAB_PASSWORD"] = environment.get(
        "STREAMCOLLAB_PASSWORD"
    ) or getpass.getpass("Password of the clientNN accounts: ")
    OUT.mkdir(exist_ok=True)
    scripts = list(SCRIPTS)
    if not args.no_interruption:
        scripts.append(("interruption_check.py", None))
    summary = []
    for script, extra in scripts:
        arguments = [sys.executable, str(EVIDENCE / script)]
        if extra is None:
            extra = ["--server", args.server, "--keys", args.keys]
        elif script != "machine_info.py":
            extra = [*extra, "--keys", args.keys]
        print(f"\n== {script}", flush=True)
        start = time.perf_counter()
        run_env = dict(environment)
        if script == "hol_check.py":
            # Ghi cửa sổ tắc nghẽn của bên gửi cho hình CUBIC của report.
            (ROOT / "logs").mkdir(exist_ok=True)
            run_env["STREAMCOLLAB_CWND_TRACE"] = str(ROOT / "logs" / "cwnd_hol.csv")
        code = subprocess.run([*arguments, *extra], cwd=ROOT, env=run_env).returncode
        summary.append((script, code, time.perf_counter() - start))
        time.sleep(2)  # Để server dọn các phiên của script trước.
    print("\nSummary:")
    for script, code, seconds in summary:
        print(f"  {'PASS' if code == 0 else 'FAIL'}  {script:<24} {seconds:6.1f} s")
    print(f"Results in {OUT}; copy this folder to machine A for tools/collect_metrics.py.")
    return 0 if all(code == 0 for _, code, _ in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
