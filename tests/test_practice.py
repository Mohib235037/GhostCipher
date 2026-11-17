import json
from pcc.content import lessons, practice
from pcc import encodings as E
from pcc.classical import caesar, atbash, vigenere, affine, rail, morse, bacon
from pcc.common import Budget
from pcc.crypto import rsa_solve, symmetric
from pcc.hashes import compare
from pcc.xor import xor, single_byte


def test_all_original_challenges_have_valid_solutions():
    rows = practice()
    assert len(rows) >= 30
    assert len({x["title"] for x in rows}) == len(rows)
    for x in rows:
        kind = x["kind"]
        s = x["input"]
        answer = x["answer"]
        assert x["walkthrough"] and len(x["hints"]) >= 2
        if kind == "Encoding":
            assert E.decode(x["encoding"], s).decode() == answer
        elif kind == "Layers":
            for name in reversed(x["chain"]):
                s = E.decode(name, s).decode()
            assert s == answer
        elif kind == "Caesar":
            assert caesar(s, -x["shift"]) == answer
        elif kind == "Atbash":
            assert atbash(s) == answer
        elif kind == "Vigenère":
            assert vigenere(s, x["key"]) == answer
        elif kind == "Affine":
            assert affine(s, x["a"], x["b"]) == answer
        elif kind == "Rail Fence":
            assert rail(s, x["rails"]) == answer
        elif kind == "Morse":
            assert morse(s) == x["plain"]
        elif kind == "Bacon":
            assert bacon(s) == x["plain"]
        elif "XOR" in kind:
            assert answer in xor(bytes.fromhex(s), bytes.fromhex(x["key_hex"])).decode()
            if kind == "Single-byte XOR":
                assert answer in single_byte(bytes.fromhex(s))[0][2].decode()
        elif kind == "Hash":
            assert compare(answer, s, x["algorithm"])
        elif kind == "Hash identification":
            assert len(s) == 64 and answer == "SHA-256 / SHA3-256"
        elif kind == "RSA":
            assert rsa_solve("Decrypt", x["params"], Budget())["output"] == "A"
        elif kind == "RSA root":
            assert rsa_solve("Small exponent", x["params"], Budget())["integer"] == "42"
        elif kind == "RSA common":
            assert rsa_solve("Common modulus", x["params"], Budget())["output"] == "A"
        elif kind == "AES":
            assert (
                symmetric(
                    "AES",
                    x["mode"],
                    "Decrypt",
                    bytes.fromhex(s),
                    bytes.fromhex(x["key_hex"]),
                    bytes.fromhex(x["iv_hex"]),
                    bytes.fromhex(x["tag_hex"]),
                )["output"]
                == answer
            )
        elif kind == "Inverse":
            assert pow(17, -1, 3120) == 2753
        elif kind == "CRT":
            assert all(23 % m == r for m, r in zip([3, 5, 7], [2, 3, 2]))
        elif kind == "LCG":
            value = 0
            for _ in range(5):
                value = (5 * value + 1) % 16
            assert value == 13
        elif kind == "Reverse":
            assert s[::-1] == answer
        else:
            raise AssertionError(kind)


def test_lessons_cover_every_technique():
    rows = lessons()
    assert len(rows) >= 30
    for row in rows:
        for key in (
            "title",
            "what",
            "recognize",
            "example_input",
            "example_output",
            "tool",
            "why",
            "mistakes",
            "limits",
        ):
            assert row[key]
