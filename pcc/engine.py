from __future__ import annotations
import hashlib
import re
from collections import deque
from . import encodings
from .classical import caesar
from .common import Budget, Limits, english_score, entropy, flags, view
from .hashes import identify
from .xor import single_byte


def detect(data: bytes):
    out = []

    def add(name, confidence, reason):
        out.append({"format": name, "confidence": confidence, "reason": reason})

    try:
        text = data.decode("utf-8")
        s = "".join(text.split())
    except UnicodeError:
        text = ""
        s = ""
    if not s:
        if data:
            add(
                "Binary / encrypted / compressed data",
                "Low",
                "Binary bytes have no unique cipher signature. Supply challenge context or key parameters.",
            )
        return out
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        add(
            "Hex",
            "High format fit",
            "Even number of hexadecimal digits; may also be a hash or an integer.",
        )
    if re.fullmatch(r"[01\s]+", text) and len(s) % 8 == 0:
        add("Binary", "High format fit", "Bits form complete eight-bit byte groups.")
    if re.fullmatch(r"(?:[0-7]{3}\s*)+", text) and len(s) % 3 == 0:
        add(
            "Octal",
            "Medium",
            "Three octal digits per byte; decimal input can look similar.",
        )
    if re.fullmatch(r"\d{1,3}(?:\s+\d{1,3})+", text.strip()):
        if all(int(t) <= 255 for t in text.split()):
            add(
                "ASCII decimal",
                "High format fit",
                "Space-separated integers fit in bytes.",
            )
    if len(s) >= 4 and len(s) % 4 != 1 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        add(
            "Base64",
            "Medium" if not s.endswith("=") else "High format fit",
            "Alphabet and length fit; many plain strings also fit.",
        )
    if len(s) >= 4 and len(s) % 4 != 1 and re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", s):
        add(
            "URL-safe Base64",
            "Medium",
            "Uses the URL-safe alphabet; overlaps standard Base64.",
        )
    if (
        len(s) >= 8
        and re.fullmatch(r"[A-Za-z2-7]+={0,6}", s)
        and len(s.rstrip("=")) % 8 in (0, 2, 4, 5, 7)
    ):
        add("Base32", "Medium", "Alphabet and length match Base32.")
    if 4 <= len(s) <= 4096 and all(c in encodings.B58 for c in s):
        add("Base58", "Low", "Alphabet fits Base58, but ordinary letters can match.")
    if 5 <= len(s) <= 8192 and re.fullmatch(r"[0-9A-Za-z!#$%&()*+;\-<=>?@^_`{|}~]+", s):
        add(
            "Base85",
            "Low",
            "Alphabet fits RFC 1924 Base85; not evidence of encryption.",
        )
    if s.startswith("<~") and s.endswith("~>"):
        add("Ascii85", "High format fit", "Adobe Ascii85 delimiters are present.")
    if re.search(r"%[0-9a-fA-F]{2}", text):
        add("URL encoding", "High format fit", "Percent-escaped byte sequences found.")
    if re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z]+);", text):
        add("HTML entities", "High format fit", "HTML character references found.")
    if re.search(r"\\[uUx][0-9a-fA-F]{2,8}", text):
        add(
            "Unicode escapes",
            "High format fit",
            "Explicit Unicode or byte escapes found.",
        )
    if re.fullmatch(r"[.\- /\s]+", text) and "." in text:
        add(
            "Morse",
            "High format fit",
            "Dot/dash groups with spaces or slash word separators.",
        )
    if set(s.upper()) <= set("AB") and len(s) >= 5 and len(s) % 5 == 0:
        add("Bacon", "Medium", "A/B groups of five fit the 26-letter Bacon variant.")
    if len(re.findall("[A-Za-z]", text)) >= 4:
        add(
            "ROT13 / Caesar / Atbash",
            "Low",
            "Letter substitution is possible; only readable results or flags provide supporting evidence.",
        )
        if len(s) >= 20:
            add(
                "Vigenère / Affine / Rail Fence / substitution / transposition",
                "Low",
                "Letters permit these classical ciphers. Use the dedicated key and frequency tools; no unique signature exists.",
            )
    if "-----BEGIN " in text:
        add(
            "PEM key / certificate",
            "Strong signature",
            "PEM header found. A container was recognized, not cracked.",
        )
    if re.search(r"\b[n ec pqd]+\s*[:=]\s*(?:0x[0-9a-fA-F]+|\d+)", text) and re.search(
        r"\bn\s*[:=]", text
    ):
        add(
            "RSA parameters",
            "Possible",
            "Named integer fields resemble an RSA exercise. Use RSA Solver to check conditions.",
        )
    if '"ciphertext"' in text and any(
        k in text for k in ('"iv"', '"nonce"', '"tag"', '"mode"')
    ):
        add(
            "Symmetric cipher parameters",
            "Possible",
            "JSON-like mode or nonce fields found. Need the exact algorithm and key.",
        )
    if data.startswith(b"Salted__") or text.startswith("U2FsdGVkX1"):
        add(
            "OpenSSL salted container",
            "Strong signature",
            "Salted container signature; password and KDF parameters are still needed.",
        )
    out.extend(identify(text))
    if entropy(data) > 7.5 and len(data) > 256:
        add(
            "Compressed / encrypted data",
            "Low",
            "High byte entropy does not identify AES, DES or any specific cipher.",
        )
    return out


def transformations(data, budget, root=False):
    budget.check()
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        text = None
    if text is not None:
        detected = detect(data)
        for candidate in detected:
            name = candidate["format"]
            if name not in encodings.NAMES:
                continue
            budget.check()
            try:
                result = encodings.decode(name, text)
                if result and result != data:
                    yield name, result
            except (ValueError, UnicodeError, KeyError, OverflowError):
                continue
        if len(data) <= 8192 and sum(c.isascii() and c.isalpha() for c in text) >= 3:
            for shift in range(1, 26):
                budget.check()
                yield f"Caesar shift {-shift}", caesar(text, -shift).encode()
            yield "Atbash", encodings.decode("Atbash", text)
            yield "Reverse", encodings.decode("Reverse", text)
    # XOR is intentionally limited to the root. Deeper XOR can be run manually on an intermediate.
    if root and 2 <= len(data) <= 4096:
        for score, key, plain in single_byte(data, budget, 8):
            if english_score(plain) >= 0.65 or flags(plain):
                yield f"Single-byte XOR key 0x{key:02x}", plain


def analyze(data: bytes, limits=None, cancel=None, progress=None):
    limits = (limits or Limits()).validate()
    if len(data) > limits.input_bytes:
        raise ValueError(
            f"Input exceeds the configured {limits.input_bytes:,}-byte limit."
        )
    if not data:
        raise ValueError("Paste text or open a file first.")
    budget = Budget(limits, cancel)
    queue = deque([(data, [])])
    seen = {hashlib.sha256(data).digest()}
    payload = len(data)
    found = []
    examined = 0
    stopped = "Search completed within configured limits."
    flag_depth = 0 if flags(data) else None

    def remember(current, path):
        discovered = flags(current)
        score = english_score(current) + (2 if discovered else 0)
        found.append(
            {
                "path": path or ["Original input"],
                "output": view(current, 4000),
                "hex": current[:4000].hex(),
                "flags": discovered,
                "rank_score": round(score, 3),
                "confidence": (
                    "Flag pattern found; verify with the challenge"
                    if discovered
                    else "Heuristic plaintext candidate"
                ),
                "bytes": len(current),
            }
        )
        found.sort(
            key=lambda x: (
                bool(x["flags"]),
                -len(x["path"]) if x["flags"] else 0,
                x["rank_score"],
            ),
            reverse=True,
        )
        del found[60:]

    try:
        while queue:
            budget.check()
            current, path = queue.popleft()
            examined += 1
            remember(current, path)
            if progress and examined % 20 == 0:
                progress(
                    {
                        "examined": examined,
                        "queued": len(queue),
                        "flags": sum(bool(x["flags"]) for x in found),
                    }
                )
            if (
                len(path) >= limits.depth
                or flags(current)
                or (flag_depth is not None and len(path) >= flag_depth)
            ):
                continue
            for operation, result in transformations(current, budget, not path):
                budget.check()
                if len(result) > limits.input_bytes:
                    continue
                fingerprint = hashlib.sha256(result).digest()
                if fingerprint in seen:
                    continue
                if len(seen) >= limits.candidates:
                    stopped = "Candidate limit reached; results are incomplete."
                    raise StopIteration()
                if payload + len(result) > limits.payload_mb * 1024 * 1024:
                    stopped = (
                        "Stored candidate byte budget reached; results are incomplete."
                    )
                    raise StopIteration()
                seen.add(fingerprint)
                payload += len(result)
                nextpath = path + [operation]
                if flags(result):
                    flag_depth = (
                        len(nextpath)
                        if flag_depth is None
                        else min(flag_depth, len(nextpath))
                    )
                    stopped = "Flag-shaped candidate found; deeper layers were not explored. Verify it before accepting."
                # Record immediately so candidates discovered at a limit are never lost.
                remember(result, nextpath)
                queue.append((result, nextpath))
    except (TimeoutError, InterruptedError) as exc:
        stopped = str(exc)
    except StopIteration:
        pass
    # Same node can be recorded when discovered and visited; show one transformation per byte string.
    unique = []
    outputs = set()
    for item in found:
        marker = (item["hex"], item["bytes"])
        if marker not in outputs:
            outputs.add(marker)
            unique.append(item)
    return {
        "detections": detect(data),
        "entropy": round(entropy(data), 3),
        "bytes": len(data),
        "candidates": unique,
        "flags": list(dict.fromkeys(f for x in unique for f in x["flags"])),
        "examined": examined,
        "generated": len(seen),
        "stored_payload_bytes": payload,
        "status": stopped,
        "explanation": "Each row is an attempted transformation, not proof of a solution. Ranking scores measure readability, not probability. "
        "A flag-shaped string can be a decoy. Secure AES and general RSA are not automatically broken. "
        "Auto mode explores encodings, Caesar, Atbash, reverse and root single-byte XOR. Use dedicated tools for other ciphers.",
    }
