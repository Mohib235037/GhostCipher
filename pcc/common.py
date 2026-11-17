from __future__ import annotations

import base64
import math
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass

FLAG_RE = re.compile(rb"(?:PCCP|PCC|flag|CTF)\{[^{}\r\n]{1,200}\}", re.I)
HARD_INPUT = 2 * 1024 * 1024


@dataclass
class Limits:
    depth: int = 5
    candidates: int = 1800
    input_bytes: int = 262144
    seconds: float = 10.0
    memory_mb: int = 512
    payload_mb: int = 16

    def validate(self):
        for name, low, high in [
            ("depth", 1, 8),
            ("candidates", 10, 5000),
            ("input_bytes", 256, HARD_INPUT),
            ("seconds", 0.01, 60),
            ("memory_mb", 128, 2048),
            ("payload_mb", 1, 64),
        ]:
            if not low <= getattr(self, name) <= high:
                raise ValueError(f"{name} must be between {low} and {high}.")
        return self


class Budget:
    def __init__(self, limits=None, cancel=None):
        self.limits = (limits or Limits()).validate()
        self.cancel = cancel
        self.start = time.monotonic()

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            raise InterruptedError("Cancelled by user.")
        if time.monotonic() - self.start >= self.limits.seconds:
            raise TimeoutError("Time limit reached; results may be incomplete.")


def flags(data: bytes) -> list[str]:
    return list(
        dict.fromkeys(m.decode("utf-8", "replace") for m in FLAG_RE.findall(data))
    )


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum(
        (v / len(data)) * math.log2(v / len(data)) for v in Counter(data).values()
    )


def english_score(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in data) / len(data)
    letters = sum(65 <= c <= 90 or 97 <= c <= 122 or c == 32 for c in data) / len(data)
    common = sum(
        data.lower().count(w)
        for w in (b"the", b"and", b"flag", b"this", b"you", b"ing")
    )
    frequency = sum(" etaoinshrdlu".count(chr(c).lower()) for c in data) / len(data)
    return min(
        1.0,
        printable * 0.35 + letters * 0.25 + frequency * 0.25 + min(common * 0.08, 0.15),
    )


def view(data: bytes, limit=16000) -> str:
    part = data[:limit]
    try:
        out = part.decode("utf-8")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in out):
            raise UnicodeError()
    except UnicodeError:
        out = "Binary data (hex):\n" + part.hex(" ")
    if len(data) > limit:
        out += f"\n… preview truncated; {len(data):,} bytes total"
    return out


def parse_bytes(value: str, encoding="UTF-8") -> bytes:
    if encoding == "Hex":
        return bytes.fromhex(value)
    if encoding == "Base64":
        return base64.b64decode("".join(value.split()), validate=True)
    if encoding == "UTF-8":
        return value.encode("utf-8")
    raise ValueError("Choose UTF-8, Hex, or Base64.")


def integer(value) -> int:
    s = str(value).strip().replace("_", "")
    if len(s) > 2500:
        raise ValueError("Integer exceeds 2500 digits.")
    return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s)


def report(title, output, steps=(), explanation="", **extra):
    data = output if isinstance(output, bytes) else str(output).encode("utf-8")
    return dict(
        title=title,
        output=view(data),
        hex=data[:16000].hex(),
        flags=flags(data),
        steps=list(steps),
        explanation=explanation,
        **extra,
    )
