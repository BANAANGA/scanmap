"""In-memory job runner for nmap/zmap subprocesses.

Jobs are short lived and not persisted: restarting the container clears the
history. Output is kept in a bounded deque so a runaway scanner cannot eat all
of the container's memory.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

MAX_OUTPUT_LINES = 20_000
KILL_GRACE_SECONDS = 5.0

# zmap's csv output module prints "saddr,dport" and then one "ip,port" line per
# responding host. Anything else on stdout is logging.
ZMAP_RESULT_RE = re.compile(
    r"^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)(?:[,\s]|$)"
)
MAC_ADDRESS_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _default_gateway(interface: str | None) -> tuple[str, str] | None:
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            next(routes, None)
            for line in routes:
                fields = line.split()
                if len(fields) < 4 or (interface and fields[0] != interface):
                    continue
                try:
                    destination, gateway, flags = (
                        int(fields[1], 16),
                        int(fields[2], 16),
                        int(fields[3], 16),
                    )
                except ValueError:
                    continue
                if destination == 0 and gateway and flags & 0x3 == 0x3:
                    return socket.inet_ntoa(struct.pack("<I", gateway)), fields[0]
    except OSError:
        return None
    return None


def _resolve_zmap_gateway_mac(interface: str | None = None) -> tuple[str, str] | None:
    route = _default_gateway(interface)
    if route is None:
        return None
    gateway, device = route

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.sendto(b"\0", (gateway, 9))
    except OSError:
        return None

    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            with open("/proc/net/arp", encoding="ascii") as entries:
                next(entries, None)
                for line in entries:
                    fields = line.split()
                    if (
                        len(fields) >= 6
                        and fields[0] == gateway
                        and fields[2] != "0x0"
                        and fields[5] == device
                        and MAC_ADDRESS_RE.fullmatch(fields[3])
                    ):
                        return gateway, fields[3]
        except OSError:
            return None
        time.sleep(0.05)
    return None


@dataclass
class Job:
    id: str
    scanner: str
    argv: list[str]
    status: str = "queued"  # queued|running|finished|failed|cancelled
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    returncode: int | None = None
    error: str | None = None

    _lines: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_OUTPUT_LINES))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append(self, line: str) -> None:
        with self._lock:
            self._lines.append(line)

    def any_line(self, pattern: re.Pattern[str]) -> bool:
        with self._lock:
            return any(pattern.match(line) for line in self._lines)

    def _duration(self) -> float | None:
        if self.started is None:
            return None
        end = self.finished if self.finished is not None else time.time()
        return round(end - self.started, 2)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            line_count = len(self._lines)
        return {
            "id": self.id,
            "scanner": self.scanner,
            "argv": self.argv,
            "status": self.status,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "duration": self._duration(),
            "returncode": self.returncode,
            "error": self.error,
            "lines": line_count,
        }

    def detail(self, since: int = 0) -> dict[str, Any]:
        payload = self.summary()
        with self._lock:
            total = len(self._lines)
            start = max(0, min(since, total))
            payload["output"] = list(self._lines)[start:]
            payload["next"] = total
            payload["truncated"] = total >= MAX_OUTPUT_LINES
        return payload


def _has_zmap_results(job: Job) -> bool:
    return job.any_line(ZMAP_RESULT_RE)


class JobManager:
    """Serialises scanner execution with a configurable concurrency limit."""

    def __init__(self, max_parallel: int = 2, max_jobs: int = 100, data_dir: str = "/data") -> None:
        self.data_dir = data_dir
        self.max_jobs = max_jobs
        self._jobs: dict[str, Job] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()
        self._sem = threading.BoundedSemaphore(max(1, max_parallel))
        self._procs: dict[str, subprocess.Popen[str]] = {}
        self._cancelled: set[str] = set()

    # -- public API -------------------------------------------------------- #

    def submit(self, scanner: str, argv: list[str]) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], scanner=scanner, argv=argv)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.max_jobs:
                self._evict_locked()
        threading.Thread(target=self._run, args=(job,), daemon=True, name=f"job-{job.id}").start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = [self._jobs[j] for j in self._order if j in self._jobs]
        return [job.summary() for job in reversed(jobs)]

    def delete(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in {"queued", "running"}:
                return False
            del self._jobs[job_id]
            try:
                self._order.remove(job_id)
            except ValueError:
                pass
            return True

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status not in {"queued", "running"}:
                return False
            self._cancelled.add(job_id)
            proc = self._procs.get(job_id)
        if proc is not None:
            self._terminate(proc)
        else:
            job.status = "cancelled"
            job.finished = time.time()
        return True

    # -- internals --------------------------------------------------------- #

    def _evict_locked(self) -> None:
        for job_id in list(self._order):
            job = self._jobs.get(job_id)
            if job is not None and job.status not in {"queued", "running"}:
                self._order.remove(job_id)
                self._jobs.pop(job_id, None)
                return
        oldest = self._order.popleft()
        self._jobs.pop(oldest, None)

    def _terminate(self, proc: subprocess.Popen[str]) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return

        def force_kill() -> None:
            try:
                proc.wait(timeout=KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

        threading.Thread(target=force_kill, daemon=True).start()

    def _run(self, job: Job) -> None:
        with self._sem:
            with self._lock:
                if job.id in self._cancelled:
                    job.status = "cancelled"
                    job.finished = time.time()
                    return
                job.status = "running"
                job.started = time.time()

            try:
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                # zmap buffers heavily without a tty; force line-buffering
                env["ZMAP_STDOUT_FLUSH"] = "1"
                argv = list(job.argv)
                if job.scanner == "zmap" and "-G" not in argv:
                    interface = None
                    if "-i" in argv:
                        interface = argv[argv.index("-i") + 1]
                    resolved = _resolve_zmap_gateway_mac(interface)
                    if resolved:
                        gateway, mac = resolved
                        argv[-1:-1] = ["-G", mac]
                        job.append(f"[scanmap] using gateway {gateway} MAC {mac}")
                if argv and argv[0] == "zmap" and shutil.which("stdbuf"):
                    argv = ["stdbuf", "-oL", "-eL"] + argv
                proc = subprocess.Popen(
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                    cwd=self.data_dir if os.path.isdir(self.data_dir) else None,
                    env=env,
                )
            except FileNotFoundError:
                job.status = "failed"
                job.error = f"{job.argv[0]} is not installed in this container"
                job.finished = time.time()
                return
            except OSError as exc:  # pragma: no cover - environment specific
                job.status = "failed"
                job.error = str(exc)
                job.finished = time.time()
                return

            with self._lock:
                self._procs[job.id] = proc

            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    job.append(line.rstrip("\n"))
                job.returncode = proc.wait()
            finally:
                with self._lock:
                    self._procs.pop(job.id, None)
                job.finished = time.time()
                cancelled = job.id in self._cancelled
                self._cancelled.discard(job.id)

            if cancelled:
                job.status = "cancelled"
            elif job.returncode == 0:
                job.status = "finished"
                if job.scanner == "zmap" and "-d" not in job.argv and not _has_zmap_results(job):
                    job.append(
                        "[scanmap] zmap finished without reporting any hosts. "
                        "The port may be closed or filtered, the target may be "
                        "excluded by the blocklist, or the packets may not reach "
                        "the network (check the container's NET_RAW capability)."
                    )
            else:
                job.status = "failed"
                if not job.error:
                    job.error = f"process exited with code {job.returncode}"
