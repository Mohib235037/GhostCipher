import base64
import codecs
import html
import re
import urllib.parse
from .classical import atbash, bacon, caesar, morse

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text):
    n = 0
    for c in text:
        n = n * 58 + B58.index(c)
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + (
        n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    )


def b58encode(data):
    n = int.from_bytes(data, "big")
    result = ""
    while n:
        n, r = divmod(n, 58)
        result = B58[r] + result
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + result


def decode(name, text):
    s = "".join(text.split())
    if name == "Base64":
        return base64.b64decode(s + "=" * ((-len(s)) % 4), validate=True)
    if name == "URL-safe Base64":
        if not re.fullmatch(r"[A-Za-z0-9_\-]*={0,2}", s):
            raise ValueError("Invalid URL-safe Base64 alphabet.")
        return base64.b64decode(
            s + "=" * ((-len(s)) % 4), altchars=b"-_", validate=True
        )
    if name == "Base32":
        return base64.b32decode(s + "=" * ((-len(s)) % 8), casefold=True)
    if name == "Hex":
        return bytes.fromhex(text)
    if name in ("Binary", "Octal", "ASCII decimal"):
        radix = {"Binary": 2, "Octal": 8, "ASCII decimal": 10}[name]
        width = {"Binary": 8, "Octal": 3}.get(name)
        tokens = text.split()
        if len(tokens) == 1 and width:
            if len(s) % width:
                raise ValueError(f"Expected {width}-digit groups.")
            tokens = [s[i : i + width] for i in range(0, len(s), width)]
        return bytes(int(t, radix) for t in tokens)
    if name == "Base58":
        return b58decode(s)
    if name == "Base85":
        return base64.b85decode(s)
    if name == "Ascii85":
        return base64.a85decode(text.encode("ascii"), adobe=s.startswith("<~"))
    if name == "URL encoding":
        return urllib.parse.unquote_to_bytes(text)
    if name == "HTML entities":
        return html.unescape(text).encode("utf-8")
    if name == "Unicode escapes":
        # Decode only explicit escape sequences, preserving existing Unicode characters.
        pattern = r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|[nrt\\])"
        decoded = re.sub(
            pattern, lambda m: codecs.decode(m.group(), "unicode_escape"), text
        )
        # Join surrogate pairs used by JSON-style Unicode escapes. An unmatched
        # surrogate remains invalid and the UTF-16 decoder reports it.
        return (
            decoded.encode("utf-16-le", "surrogatepass")
            .decode("utf-16-le")
            .encode("utf-8")
        )
    if name == "ROT13":
        return codecs.decode(text, "rot_13").encode()
    if name == "Atbash":
        return atbash(text).encode()
    if name == "Morse":
        return morse(text).encode()
    if name == "Bacon":
        return bacon(text).encode()
    if name == "Reverse":
        return text[::-1].encode()
    raise ValueError("Unsupported encoding.")


NAMES = [
    "Base64",
    "URL-safe Base64",
    "Base32",
    "Hex",
    "Binary",
    "Octal",
    "ASCII decimal",
    "Base58",
    "Base85",
    "Ascii85",
    "URL encoding",
    "HTML entities",
    "Unicode escapes",
    "ROT13",
    "Atbash",
    "Morse",
    "Bacon",
    "Reverse",
]


def encode(name, data):
    if name == "Base64":
        return base64.b64encode(data).decode()
    if name == "URL-safe Base64":
        return base64.urlsafe_b64encode(data).decode()
    if name == "Base32":
        return base64.b32encode(data).decode()
    if name == "Hex":
        return data.hex()
    if name == "Binary":
        return " ".join(f"{c:08b}" for c in data)
    if name == "Octal":
        return " ".join(f"{c:03o}" for c in data)
    if name == "ASCII decimal":
        return " ".join(str(c) for c in data)
    if name == "Base58":
        return b58encode(data)
    if name == "Base85":
        return base64.b85encode(data).decode()
    if name == "Ascii85":
        return base64.a85encode(data).decode()
    text = data.decode("utf-8")
    if name == "URL encoding":
        return urllib.parse.quote(text, safe="")
    if name == "HTML entities":
        return "".join(f"&#{ord(c)};" for c in text)
    if name == "Unicode escapes":
        return "".join(
            f"\\u{ord(c):04x}" if ord(c) <= 65535 else f"\\U{ord(c):08x}" for c in text
        )
    if name == "Morse":
        return morse(text, True)
    if name == "Bacon":
        return bacon(text, True)
    return decode(name, text).decode("utf-8")
