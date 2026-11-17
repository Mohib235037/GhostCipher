import base64
import io
import json
import math
import threading
import zipfile
import pytest
from Crypto.PublicKey import RSA, ECC
from pcc import encodings as E
from pcc.classical import (
    caesar,
    atbash,
    vigenere,
    affine,
    rail,
    morse,
    bacon,
    frequency,
    recover_vigenere,
)
from pcc.common import Budget, Limits, flags, parse_bytes, entropy, integer
from pcc.crypto import symmetric, rsa_solve, factor_small, extended_gcd, inspect_key
from pcc.engine import analyze, detect
from pcc.files import analyze_file, read_limited, signature
from pcc.hashes import digest, identify, compare, dictionary_check
from pcc.xor import xor, single_byte, repeating_candidates, key_lengths
from pcc.operations import execute


@pytest.mark.parametrize("name", E.NAMES)
def test_encodings_roundtrip(name):
    data = b"HELLO" if name in ("Morse", "Bacon") else b"PCCP{offline_test}"
    assert E.decode(name, E.encode(name, data)) == data


@pytest.mark.parametrize(
    "name,value,expected",
    [
        ("Base64", "UENDUHt0ZXN0fQ==", b"PCCP{test}"),
        ("Hex", "504343507b746573747d", b"PCCP{test}"),
        ("ROT13", "URYYB", b"HELLO"),
        ("Binary", "01000001 01000010", b"AB"),
        ("Octal", "101 102", b"AB"),
        ("ASCII decimal", "65 66", b"AB"),
        ("Base58", "JxF12TrwUP45BMd", b"Hello World"),
        ("Unicode escapes", r"Pakistan \u0050\x43", b"Pakistan PC"),
        ("HTML entities", "&lt;PCC&gt;", b"<PCC>"),
    ],
)
def test_encoding_vectors(name, value, expected):
    assert E.decode(name, value) == expected


@pytest.mark.parametrize(
    "name,value",
    [
        ("Base64", "%%%%"),
        ("Hex", "zz"),
        ("Binary", "010"),
        ("Octal", "999"),
        ("ASCII decimal", "999 65"),
        ("Bacon", "BBBBB"),
        ("Morse", "---..x"),
        ("URL-safe Base64", "****"),
    ],
)
def test_invalid_encoding(name, value):
    with pytest.raises((ValueError, KeyError)):
        E.decode(name, value)


def test_unicode_preserved():
    assert E.decode("Unicode escapes", r"پاکستان \u0041").decode() == "پاکستان A"


def test_b58_leading_zero():
    assert E.b58decode(E.b58encode(b"\0\0abc")) == b"\0\0abc"


def test_classical_vectors():
    assert caesar("KHOOR, ZRUOG!", -3) == "HELLO, WORLD!"
    assert atbash("Abc XYZ!") == "Zyx CBA!"
    assert vigenere("LXFOPV EF RNHR", "LEMON") == "ATTACK AT DAWN"
    assert vigenere("ATTACK AT DAWN", "LEMON", False) == "LXFOPV EF RNHR"
    assert affine("IHHWVCSWFRCP", 5, 8) == "AFFINECIPHER"
    assert rail("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"
    assert morse("... --- ... / .- -... -.-.") == "SOS ABC"
    assert bacon("AAAAA AAAAB AAABA") == "ABC"
    assert frequency("aab!")["frequencies"] == {"A": 2, "B": 1}
    assert caesar("ABCXYZ", 1, "ABCXYZ") == "BCXYZA"


@pytest.mark.parametrize("rails", [2, 3, 5, 20])
def test_rail_roundtrip(rails):
    msg = "PCCP{spaces and punctuation!}"
    assert rail(rail(msg, rails, False), rails) == msg


def test_classical_invalid():
    for fn in (
        lambda: affine("A", 2, 1),
        lambda: vigenere("A", ""),
        lambda: rail("A", 1),
        lambda: caesar("A", 1, "AAA"),
    ):
        with pytest.raises(ValueError):
            fn()


def test_unused_classical_shift_is_not_parsed():
    assert (
        execute("classical", dict(operation="ROT13", text="URYYB", shift="unused"))[
            "output"
        ]
        == "HELLO"
    )


def test_vigenere_recovery():
    message = (
        "This is a long English message about the history of cryptography and the importance of learning how different ciphers work. "
        "The quick brown fox is running through the garden and the student is reading the hidden message. "
    ) * 20
    result = recover_vigenere(vigenere(message, "LEMON", False), Budget())
    assert any(x["key"] == "LEMON" and x["plaintext"] == message for x in result)


@pytest.mark.parametrize(
    "chain",
    [
        ["Base64"],
        ["Hex"],
        ["ROT13"],
        ["Hex", "Base64"],
        ["Hex", "ROT13", "Base64"],
        ["Base32", "Hex", "Base64"],
    ],
)
def test_multilayer(chain):
    data = b"PCCP{layers_verified}"
    for name in chain:
        data = E.encode(name, data).encode()
    result = analyze(data, Limits(seconds=10, candidates=3000))
    assert "PCCP{layers_verified}" in result["flags"], (chain, result["status"])
    assert any(x["flags"] and len(x["path"]) >= 1 for x in result["candidates"])


def test_detection_is_honest():
    out = detect(b"a" * 64)
    names = {x["format"] for x in out}
    assert {"Hex", "SHA-256", "SHA3-256"} <= names
    assert not any(x["confidence"] == "Certain" for x in out)
    assert "PEM key / certificate" in {
        x["format"] for x in detect(b"-----BEGIN PUBLIC KEY-----")
    }
    assert "RSA parameters" in {x["format"] for x in detect(b"n=3233 e=17 c=2790")}
    assert "Symmetric cipher parameters" in {
        x["format"] for x in detect(b'{"ciphertext":"00","nonce":"00"}')
    }


def test_limits_and_cancellation():
    with pytest.raises(ValueError):
        analyze(b"A" * 300, Limits(input_bytes=256))
    with pytest.raises(ValueError):
        analyze(b"")
    result = analyze(b"UENDUHtiYXNlX2NhbXB9", Limits(candidates=10))
    assert result["generated"] <= 10 and "limit" in result["status"]
    event = threading.Event()
    event.set()
    result = analyze(b"A" * 100, cancel=event)
    assert "Cancelled" in result["status"]
    result = analyze(b"ABCDEF" * 1000, Limits(payload_mb=1, candidates=5000))
    assert result["stored_payload_bytes"] <= 1048576
    assert "budget" in result["status"] or "limit" in result["status"]
    budget = Budget(Limits(seconds=0.01))
    budget.start -= 1
    with pytest.raises(TimeoutError):
        budget.check()
    with pytest.raises(ValueError):
        Limits(depth=100).validate()


def test_flags_and_bytes():
    assert flags(b"PCC{one} PCCP{two} flag{three} CTF{four}") == [
        "PCC{one}",
        "PCCP{two}",
        "flag{three}",
        "CTF{four}",
    ]
    assert flags(b"PCCP{bad\nline}") == []
    assert parse_bytes("4142", "Hex") == b"AB"
    assert entropy(b"AAAA") == 0
    assert integer("0xff") == 255
    with pytest.raises(ValueError):
        parse_bytes("%%%", "Base64")


def test_xor_vectors():
    assert xor(bytes.fromhex("09040d0d0e"), b"A") == b"HELLO"
    plain = b"This is a readable English plaintext message and the flag is PCCP{xor_verified}."
    data = xor(plain, b"\x37")
    assert single_byte(data)[0][1] == 0x37
    assert single_byte(data)[0][2] == plain
    assert xor(xor(plain, b"ICE"), b"ICE") == plain
    assert key_lengths(xor(plain * 10, b"ICE"))
    assert repeating_candidates(xor(plain * 10, b"ICE"), Budget())
    with pytest.raises(ValueError):
        xor(plain, b"")


@pytest.mark.parametrize(
    "algorithm,expected",
    [
        ("MD5", "5d41402abc4b2a76b9719d911017c592"),
        ("SHA-1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        ("SHA-256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        ("NTLM", "066ddfd4ef0e9cd7c256fe77191ef43c"),
    ],
)
def test_hash_vectors(algorithm, expected):
    assert digest("hello", algorithm) == expected


def test_hashes():
    for algorithm in [
        "SHA-224",
        "SHA-384",
        "SHA-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
    ]:
        assert compare("test", digest("test", algorithm), algorithm)
    assert len(identify("0" * 32)) == 2
    assert identify("$2b$12$" + "a" * 53)[0]["format"] == "bcrypt"
    assert identify("pbkdf2_sha256$600000$salt$digest")[0]["format"] == "PBKDF2"
    target = digest("right", "SHA-256")
    assert (
        dictionary_check(target, "SHA-256", ["wrong", "right"], Budget())["candidate"]
        == "right"
    )
    assert not dictionary_check(target, "SHA-256", ["wrong"], Budget())["matched"]
    with pytest.raises(ValueError):
        dictionary_check(target, "SHA-256", ["a"] * 10001, Budget())


def test_rsa_vectors():
    result = rsa_solve("Decrypt", {"p": 61, "q": 53, "e": 17, "c": 2790}, Budget())
    assert result["output"] == "A" and result["integer"] == "65"
    assert (
        rsa_solve("Encrypt", {"n": 3233, "e": 17, "m": 65}, Budget())["output"]
        == "2790"
    )
    assert (
        "2753"
        in rsa_solve("Factor / derive private key", {"n": 3233, "e": 17}, Budget())[
            "output"
        ]
    )
    assert (
        rsa_solve("Small exponent", {"e": 3, "c": 74088}, Budget())["integer"] == "42"
    )
    params = {
        "n": 3233,
        "e1": 7,
        "e2": 11,
        "c1": pow(65, 7, 3233),
        "c2": pow(65, 11, 3233),
    }
    assert rsa_solve("Common modulus", params, Budget())["integer"] == "65"
    assert factor_small(3233, Budget())["factors"] == {53: 1, 61: 1}
    assert extended_gcd(17, 3120)[0] == 1


@pytest.mark.parametrize(
    "op,params",
    [
        ("Decrypt", {"n": 3233, "e": 17, "c": 2790}),
        ("Decrypt", {"p": 5, "q": 5, "e": 3, "c": 2}),
        ("Small exponent", {"e": 3, "c": 42}),
        ("Factor / derive private key", {"n": 2**60, "e": 17}),
        ("Decrypt", {"n": 200, "p": 61, "q": 53, "e": 17, "c": 4}),
        ("Common modulus", {"n": 3233, "e1": 6, "e2": 12, "c1": 2, "c2": 3}),
    ],
)
def test_rsa_rejects_invalid(op, params):
    with pytest.raises(ValueError):
        rsa_solve(op, params, Budget())


def test_key_inspection():
    key = RSA.generate(1024)
    assert inspect_key(key.public_key().export_key())["bits"] == 1024
    assert inspect_key(key.export_key(format="DER"))["type"] == "RSA private key"
    assert (
        inspect_key(ECC.generate(curve="P-256").export_key(format="PEM").encode())[
            "type"
        ]
        == "ECC key"
    )
    with pytest.raises(ValueError):
        inspect_key(b"not a key")


def test_aes_nist_ecb_vector():
    result = symmetric(
        "AES",
        "ECB",
        "Encrypt",
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        padding="None",
    )
    assert result["ciphertext_hex"] == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes_gcm_nist_vector_and_bad_tag():
    encrypted = symmetric("AES", "GCM", "Encrypt", b"\0" * 16, b"\0" * 16, b"\0" * 12)
    assert encrypted["ciphertext_hex"] == "0388dace60b6a392f328c2b971b2fe78"
    assert encrypted["tag_hex"] == "ab6e47d42cec13bdf53a67b21257bddf"
    dec = symmetric(
        "AES",
        "GCM",
        "Decrypt",
        bytes.fromhex(encrypted["ciphertext_hex"]),
        b"\0" * 16,
        b"\0" * 12,
        bytes.fromhex(encrypted["tag_hex"]),
    )
    assert dec["hex"] == "00" * 16 and dec["authenticated"]
    with pytest.raises(ValueError):
        symmetric(
            "AES", "GCM", "Decrypt", b"\0" * 16, b"\0" * 16, b"\0" * 12, b"\0" * 16
        )


@pytest.mark.parametrize(
    "algorithm,key",
    [
        ("AES", bytes(range(16))),
        ("DES", b"12345678"),
        ("3DES", b"12345678ABCDEFGH87654321"),
    ],
)
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR"])
def test_symmetric_roundtrips(algorithm, key, mode):
    iv = (
        b"12345678"
        if algorithm == "AES" and mode == "CTR"
        else b"1234" if mode == "CTR" else bytes(range(16 if algorithm == "AES" else 8))
    )
    source = b"PCCP{symmetric_verified}"
    result = symmetric(algorithm, mode, "Encrypt", source, key, iv)
    decrypted = symmetric(
        algorithm, mode, "Decrypt", bytes.fromhex(result["ciphertext_hex"]), key, iv
    )
    assert decrypted["output"] == source.decode()
    assert not decrypted["authenticated"]


def test_des_known_vector_and_errors():
    assert (
        symmetric(
            "DES",
            "ECB",
            "Encrypt",
            bytes.fromhex("0123456789abcdef"),
            bytes.fromhex("133457799bbcdff1"),
            padding="None",
        )["ciphertext_hex"]
        == "85e813540f0ab405"
    )
    with pytest.raises(ValueError):
        symmetric("AES", "CBC", "Decrypt", b"abc", b"k" * 16, b"bad")
    with pytest.raises(ValueError):
        symmetric("AES", "ECB", "Encrypt", b"abc", b"short")
    with pytest.raises(ValueError):
        symmetric("DES", "GCM", "Encrypt", b"a", b"k" * 8, b"n")
    with pytest.raises(ValueError):
        symmetric("3DES", "ECB", "Encrypt", b"a", b"k" * 24)


def test_safe_file_inspection(tmp_path):
    p = tmp_path / "challenge.bin"
    p.write_bytes(b"\0PCCP{file_flag}\xff")
    data = read_limited(p)
    result = analyze_file(data, Budget(), str(p))
    assert result["flags"] == ["PCCP{file_flag}"] and result["hex_preview"]
    with pytest.raises(ValueError):
        read_limited(p, 3)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../never_execute.py", "raise Exception('PCCP{zip_flag}')")
    result = analyze_file(buf.getvalue(), Budget())
    assert "PCCP{zip_flag}" in result["flags"]
    assert not (tmp_path.parent / "never_execute.py").exists()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.txt", "A" * 200000)
    assert "skipped" in analyze_file(buf.getvalue(), Budget())["archive"][0]["status"]
    assert "JSON" in signature(b'{"n":3233}')


@pytest.mark.parametrize(
    "op,text,expected",
    [
        ("Modular inverse", '{"a":17,"m":3120}', "2753"),
        ("GCD", '{"a":48,"b":18}', "6"),
        ("Extended GCD", '{"a":48,"b":18}', '"gcd": 6'),
        ("Modular power", '{"a":2,"e":10,"m":17}', "4"),
        ("CRT", '{"moduli":[3,5,7],"remainders":[2,3,2]}', "23"),
        ("Prime test", '{"n":65537}', "true"),
        ("Factor small integer", '{"n":3233}', "53"),
        ("LCG generate", '{"a":5,"b":1,"m":16,"seed":0,"count":5}', "13"),
        ("LCG recover", '{"m":16,"outputs":[1,6,15,12,13]}', '"verified": true'),
        ("Entropy", "AAAA", "0.000000"),
        ("Frequency", "AABB", "frequencies"),
    ],
)
def test_advanced_operations(op, text, expected):
    assert (
        expected
        in execute("advanced", dict(operation=op, text=text, encoding="UTF-8"))[
            "output"
        ]
    )


def test_dispatcher_errors():
    with pytest.raises(ValueError):
        execute("advanced", dict(operation="Modular inverse", text='{"a":2,"m":4}'))
    with pytest.raises(json.JSONDecodeError):
        execute("rsa", dict(operation="Decrypt", text="not json"))
    with pytest.raises(ValueError):
        execute(
            "hash",
            dict(
                operation="Local dictionary check",
                text="",
                algorithm="MD5",
                target="",
                wordlist_supplied=False,
            ),
        )
    with pytest.raises(ValueError):
        execute(
            "encoding",
            dict(text="A" * 300, operation="Decode", method="Base64"),
            Limits(input_bytes=256),
        )


def test_worker_network_denial(monkeypatch):
    import socket
    from pcc.worker import disable_network

    for name in (
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
    ):
        monkeypatch.setattr(socket, name, getattr(socket, name))
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, getattr(socket.socket, name))
    disable_network()
    with pytest.raises(OSError, match="disabled"):
        socket.create_connection(("example.com", 443))
    with pytest.raises(OSError, match="disabled"):
        socket.getaddrinfo("example.com", 443)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(OSError, match="disabled"):
            s.sendto(b"test", ("127.0.0.1", 1))


def test_raw_file_limit_does_not_count_display_preview():
    result = execute(
        "xor",
        dict(
            operation="Known key",
            encoding="Raw file",
            raw_bytes=b"A" * 254,
            text="ff" * 254,
            key="00",
            key_encoding="Hex",
        ),
        Limits(input_bytes=256),
    )
    assert result["output"] == "A" * 254
