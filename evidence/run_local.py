"""Machine A part of the measurements: self check, Ruff, comment counts, machine info.

Run on machine A (the server machine) from the project folder, server stopped:
    python evidence/run_local.py
Writes evidence/out/self_check.*, ruff.txt, comment_count.* and machine_A.*.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time

from _common import EVIDENCE, OUT, ROOT, Report

RUFF_FORMAT = "format --isolated --check --line-length 100 --target-version py312 ."
RUFF_CHECK = (
    "check --isolated --line-length 100 --target-version py312 "
    "--select E4,E7,E9,F,I,UP,B,SIM,C4,C90 ."
)


def run(arguments: list[str]) -> tuple[int, str, float]:
    """Chạy một lệnh trong thư mục dự án; trả exit code, output và số giây."""
    start = time.perf_counter()
    result = subprocess.run(
        arguments, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return result.returncode, result.stdout + result.stderr, time.perf_counter() - start


def self_check(runs: int) -> int:
    """Chạy demo.py nhiều lần, ghi số lần PASS và thời gian mỗi lần."""
    report = Report("self_check", "machine-A")
    times, passed, resent, same_seq = [], 0, 0, 0
    for index in range(runs):
        code, output, _ = run([sys.executable, "demo.py"])
        total = re.search(r"Total demo time: ([\d.]+) s", output)
        ok = code == 0 and "DEMO PASS" in output
        passed += ok
        resent += "RETRY: client01 sent FILE_DATA" in output
        dropped = re.search(r"DROP: client01 skipped FILE_DATA seq=(\d+)", output)
        retried = re.search(r"RETRY: client01 sent FILE_DATA seq=(\d+)", output)
        same_seq += bool(dropped and retried and dropped.group(1) == retried.group(1))
        if total:
            times.append(float(total.group(1)))
        report.check(ok, f"demo run {index + 1}: {total.group(1) if total else '?'} s")
    report.data.update(runs=runs, passed=passed, resent=resent, same_seq=same_seq, seconds=times)
    return report.save()


def ruff() -> int:
    """Chạy Ruff với cấu hình của nhóm, ghi evidence/out/ruff.txt."""
    report = Report("ruff", "machine-A")
    # Ruff của venv nằm cạnh python đang chạy, kể cả khi venv chưa được activate.
    scripts = os.path.dirname(sys.executable)
    executable = shutil.which("ruff", path=scripts) or shutil.which("ruff")
    if executable is None:
        report.check(False, "ruff not installed (python -m pip install -r requirements-dev.txt)")
        return report.save()
    files = sorted(
        p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.py") if ".venv" not in p.parts
    )
    results, formatted = {}, None
    for name, command in (("format", RUFF_FORMAT), ("check", RUFF_CHECK)):
        code, output, _ = run([executable, *command.split()])
        results[name] = code
        found = re.search(r"(\d+) files? already formatted", output)
        if name == "format" and found:
            formatted = int(found.group(1))
        report.line(f"$ ruff {command}")
        report.line(output.strip())
        report.check(code == 0, f"ruff {name}")
    code, version, _ = run([executable, "--version"])
    report.data.update(
        version=version.strip(),
        python_files=len(files),
        formatted_files=formatted,
        exit_codes=results,
    )
    return report.save()


def main() -> int:
    """Chạy các bước của máy A và in tóm tắt."""
    OUT.mkdir(exist_ok=True)
    failures = 0
    print("== self check (python demo.py, 5 runs)")
    failures += self_check(5)
    print("== Ruff")
    failures += ruff()
    for script in ("comment_count.py", "machine_info.py"):
        arguments = [sys.executable, str(EVIDENCE / script)]
        if script == "machine_info.py":
            arguments += ["--role", "A"]
        print(f"== {script}")
        code, output, _ = run(arguments)
        print(output.strip())
        failures += code != 0
    print(f"\nMachine A part finished; results in {OUT}. Failures: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
