"""Restart a command each time a Python file of ``src/`` changes (development only).

The controller builds its app at start, so the reload of uvicorn (which needs an import string)
cannot be used: this script runs a console script of the environment in a child process and
restarts it on change. Standard library only (no watchfiles in the environment). Under debugpy
with ``"subProcess": true``, each child is debugged: the script is run as a file, since debugpy
cannot resolve ``python -m <module>`` on Python 3.14 (it relies on the removed
``pkgutil.get_loader``).

    python scripts/dev_reload.py security-review-controller serve --port 8080
"""

import contextlib
import ctypes
import signal
import subprocess
import sys
import time
from pathlib import Path

SOURCES = Path(__file__).resolve().parent.parent / "src"
INTERVAL = 1.0
PR_SET_PDEATHSIG = 1


def snapshot() -> dict[Path, int]:
    """Modification time of every Python file of ``src/``."""
    times = {}
    for path in SOURCES.rglob("*.py"):
        # A file can vanish between the listing and stat (atomic save, branch switch)
        with contextlib.suppress(FileNotFoundError):
            times[path] = path.stat().st_mtime_ns
    return times


def _die_with_parent() -> None:
    """Have Linux send SIGTERM to the child when this script dies, even by SIGKILL (the Stop
    button of the debugger), so that no controller is left running."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)


def start(command: list[str]) -> subprocess.Popen:
    """Start the child, bound to the life of this script on Linux."""
    preexec = _die_with_parent if sys.platform == "linux" else None
    return subprocess.Popen(command, preexec_fn=preexec)


def main(argv: list[str]) -> int:
    """Run the console script ``argv[0]`` and restart it on change, until interrupted."""
    if not argv:
        print("usage: dev_reload.py CONSOLE_SCRIPT [ARGS...]", file=sys.stderr)
        return 2
    script = Path(sys.executable).parent / argv[0]
    if not script.is_file():
        print(f"dev_reload: {script} not found", file=sys.stderr)
        return 2
    command = [sys.executable, str(script), *argv[1:]]
    # Stop the child too when the script is terminated (not only on Ctrl+C)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    state = snapshot()
    child = start(command)
    try:
        while True:
            time.sleep(INTERVAL)
            current = snapshot()
            if current == state:
                continue
            state = current
            print("dev_reload: change detected, restarting", file=sys.stderr)
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child = start(command)
    except KeyboardInterrupt:
        return 0
    finally:
        child.terminate()
        child.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
