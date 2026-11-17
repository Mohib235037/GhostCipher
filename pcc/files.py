from __future__ import annotations
import io
import json
import re
import zipfile
from pathlib import Path
from .common import HARD_INPUT, entropy, flags, view
from .engine import detect


def read_limited(path, limit=HARD_INPUT):
    path = Path(path)
    if not path.is_file():
        raise ValueError("Choose a regular file.")
    if path.stat().st_size > limit:
        raise ValueError(f"File exceeds {limit:,} bytes.")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File grew beyond the size limit during reading.")
    return data


def _der_sequence(data):
    if len(data) < 3 or data[0] != 0x30:
        return False
    first = data[1]
    if first < 0x80:
        return first == len(data) - 2
    size = first & 0x7F
    if not 1 <= size <= 4 or len(data) < 2 + size or data[2] == 0:
        return False
    length = int.from_bytes(data[2 : 2 + size], "big")
    return length >= 0x80 and length == len(data) - 2 - size


def signature(data):
    for magic, name in [
        (b"PK\x03\x04", "ZIP archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"%PDF-", "PDF document"),
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows executable"),
        (b"\x1f\x8b", "Gzip stream"),
        (b"Salted__", "OpenSSL salted container"),
        (b"-----BEGIN", "PEM container"),
    ]:
        if data.startswith(magic):
            return name
    if _der_sequence(data):
        return "Possible ASN.1 DER sequence (not sufficient to identify a certificate)"
    try:
        json.loads(data)
        return "JSON data"
    except (ValueError, RecursionError):
        pass
    try:
        data.decode("utf-8")
        return "UTF-8 text / unknown signature"
    except UnicodeError:
        return "Unknown binary signature"


def analyze_file(data, budget, name="input"):
    if len(data) > budget.limits.input_bytes:
        raise ValueError("File exceeds the configured input size limit.")
    budget.check()
    strings = [
        m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{4,2000}", data)[:200]
    ]
    result = {
        "name": Path(name).name,
        "signature": signature(data),
        "bytes": len(data),
        "entropy": round(entropy(data), 3),
        "hex_preview": data[:512].hex(" "),
        "printable_strings": strings,
        "detections": detect(data[:65536]),
        "flags": flags(data),
        "archive": [],
        "note": "Only bytes were inspected. Contents were not executed. Entropy and signatures are clues. Previews and strings are capped.",
    }
    if zipfile.is_zipfile(io.BytesIO(data)):
        total = 0
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            for info in infos[:32]:
                budget.check()
                item = {"name": info.filename[:200], "size": info.file_size}
                if info.is_dir():
                    item["status"] = "Directory"
                elif info.flag_bits & 1:
                    item["status"] = "Encrypted member: password needed; skipped"
                elif (
                    info.file_size > 1048576
                    or info.file_size > max(info.compress_size, 1) * 100
                    or total + info.file_size > 2 * 1048576
                ):
                    item["status"] = "Expansion or compression-ratio limit: skipped"
                else:
                    try:
                        with archive.open(info) as stream:
                            content = stream.read(min(info.file_size + 1, 1048577))
                        if len(content) > info.file_size:
                            raise ValueError("Unexpected expanded size")
                        total += len(content)
                        item.update(
                            status="Inspected in memory",
                            preview=view(content, 2000),
                            flags=flags(content),
                            signature=signature(content),
                        )
                        result["flags"].extend(
                            f for f in flags(content) if f not in result["flags"]
                        )
                    except (
                        ValueError,
                        RuntimeError,
                        zipfile.BadZipFile,
                        NotImplementedError,
                    ) as exc:
                        item["status"] = f"Could not inspect: {exc}"
                result["archive"].append(item)
            if len(infos) > 32:
                result["archive_note"] = (
                    "Only the first 32 archive members were inspected."
                )
    return result
