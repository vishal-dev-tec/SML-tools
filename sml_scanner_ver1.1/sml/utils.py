"""
SML Scanner - Execution Utilities
===================================
Subprocess wrapper: enforces timeouts, captures stdout/stderr, never uses
shell=True (command injection surface), and detects missing binaries
before attempting execution.
"""

import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class ExecResult:
    tool_key: str
    display_name: str
    command: str
    started_at: float
    duration_sec: float
    returncode: int | None
    stdout: str
    stderr: str
    status: str  # "ok" | "timeout" | "missing_binary" | "error"


def binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_tool(tool_key: str, display_name: str, argv: list[str], timeout_sec: int) -> ExecResult:
    """Execute a single tool's argv list. Never raises on tool failure/timeout;
    failure is encoded in ExecResult.status so the pipeline keeps moving."""
    binary = argv[0]
    cmd_str = " ".join(argv)

    if not binary_available(binary):
        return ExecResult(
            tool_key=tool_key,
            display_name=display_name,
            command=cmd_str,
            started_at=time.time(),
            duration_sec=0.0,
            returncode=None,
            stdout="",
            stderr=f"binary '{binary}' not found on PATH — skipped",
            status="missing_binary",
        )

    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        duration = time.time() - start
        return ExecResult(
            tool_key=tool_key,
            display_name=display_name,
            command=cmd_str,
            started_at=start,
            duration_sec=duration,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            status="ok",
        )
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start
        return ExecResult(
            tool_key=tool_key,
            display_name=display_name,
            command=cmd_str,
            started_at=start,
            duration_sec=duration,
            returncode=None,
            stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
            stderr=f"execution exceeded {timeout_sec}s timeout — process killed",
            status="timeout",
        )
    except Exception as e:  # noqa: BLE001 - must never crash the pipeline
        duration = time.time() - start
        return ExecResult(
            tool_key=tool_key,
            display_name=display_name,
            command=cmd_str,
            started_at=start,
            duration_sec=duration,
            returncode=None,
            stdout="",
            stderr=f"unhandled exception: {e!r}",
            status="error",
        )


def normalize_target(raw_target: str) -> dict:
    """Derive {host, url} pair from a raw user-supplied target.
    Accepts bare host/IP, or a full URL."""
    raw_target = raw_target.strip()
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        url = raw_target.rstrip("/")
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    else:
        host = raw_target.split("/")[0]
        url = f"http://{host}"
    return {"host": host, "url": url}
