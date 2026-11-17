"""Isolated, cancellable tasks. No challenge content is executed."""

from __future__ import annotations
import ctypes
import multiprocessing as mp
import os
import time
from .common import Limits


def disable_network():
    """Workers do not resolve hosts, connect sockets, or send datagrams."""
    import socket

    def offline(*args, **kwargs):
        raise OSError("Network access is disabled in this offline application.")

    for name in (
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
    ):
        setattr(socket, name, offline)
    for name in ("connect", "connect_ex", "sendto"):
        setattr(socket.socket, name, offline)


def _run(connection, cancel, kind, values, limits):
    try:
        disable_network()
        from .operations import execute

        result = execute(
            kind,
            values,
            Limits(**limits),
            cancel,
            lambda data: connection.send(("progress", data)),
        )
        connection.send(("result", result))
    except BaseException as exc:
        try:
            connection.send(("error", f"{type(exc).__name__}: {exc}"))
        except (OSError, EOFError):
            pass
    finally:
        connection.close()


def memory_usage(process):
    if os.name != "nt":
        return 0
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (n, ctypes.c_size_t)
            for n in (
                "PeakWorkingSetSize",
                "WorkingSetSize",
                "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage",
                "PagefileUsage",
                "PeakPagefileUsage",
                "PrivateUsage",
            )
        ]

    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    fn = ctypes.windll.psapi.GetProcessMemoryInfo
    fn.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    fn.restype = wintypes.BOOL
    if fn(wintypes.HANDLE(process.sentinel), ctypes.byref(counters), counters.cb):
        return max(counters.WorkingSetSize, counters.PrivateUsage)
    return 0


class Task:
    def __init__(self, kind, values, limits):
        self.limits = limits.validate()
        context = mp.get_context("spawn")
        self.receive, send = context.Pipe(duplex=False)
        self.cancel_event = context.Event()
        self.process = context.Process(
            target=_run,
            args=(send, self.cancel_event, kind, values, limits.__dict__),
            daemon=True,
        )
        self.start = time.monotonic()
        self.finished = False
        self.cancelled_at = None
        self.process.start()
        send.close()

    def cancel(self):
        self.cancel_event.set()
        self.cancelled_at = time.monotonic()

    def stop(self):
        if not self.finished:
            if self.process.is_alive():
                self.process.terminate()
            self.process.join(timeout=0.2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=0.2)
            self.receive.close()
            self.finished = True

    def poll(self):
        if self.finished:
            return []
        messages = []
        try:
            while self.receive.poll():
                item = self.receive.recv()
                messages.append(item)
                if item[0] in ("result", "error"):
                    self.stop()
                    return messages
        except (EOFError, OSError):
            pass
        if self.cancelled_at and time.monotonic() - self.cancelled_at > 0.3:
            self.stop()
            return messages + [("error", "Cancelled by user; worker stopped.")]
        # Import startup is included in a small fixed allowance, then the task deadline is hard.
        if time.monotonic() - self.start > self.limits.seconds + 5:
            self.stop()
            return messages + [
                (
                    "error",
                    "Worker time limit reached; stopped without a complete result.",
                )
            ]
        if memory_usage(self.process) > self.limits.memory_mb * 1024 * 1024:
            self.stop()
            return messages + [
                ("error", "Worker memory limit reached; process stopped.")
            ]
        if not self.process.is_alive():
            self.stop()
            return messages + [("error", "Worker exited without a result.")]
        return messages
