import pytest

from pcc.classical import caesar, frequency, recover_vigenere
from pcc.common import Budget
from pcc.crypto import symmetric
from pcc.encodings import decode
from pcc.files import signature
from pcc.hashes import compare, digest


def test_aes_cbc_nist_sp800_38a_f21():
    # NIST SP 800-38A, Appendix F.2.1 (the first two AES-128 blocks).
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    expected = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    encrypted = symmetric("AES", "CBC", "Encrypt", plain, key, iv=iv, padding="None")
    assert encrypted["ciphertext_hex"] == expected
    decrypted = symmetric(
        "AES", "CBC", "Decrypt", bytes.fromhex(expected), key, iv=iv, padding="None"
    )
    assert decrypted["hex"] == plain.hex()
    assert not decrypted["authenticated"]


def test_aes_ctr_increments_from_zero():
    # With an all-zero key and nonce, the first two 128-bit counter blocks are
    # 0 and 1. Their AES encryptions are the expected keystream for zero input.
    result = symmetric("AES", "CTR", "Encrypt", bytes(32), bytes(16), iv=bytes(12))
    assert result["ciphertext_hex"] == (
        "66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a"
    )


def test_aes_gcm_authenticates_associated_data():
    # Published NIST AES-GCM example with 96-bit nonce and nonempty AAD.
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    plain = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72 "
        "1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b39"
    )
    ciphertext = bytes.fromhex(
        "42831ec2217774244b7221b784d0d49c e3aa212f2c02a4e035c17e2329aca12e "
        "21d514b25466931c7d8f6a5aac84aa05 1ba30b396a0aac973d58e091"
    )
    tag = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")
    result = symmetric("AES", "GCM", "Encrypt", plain, key, iv=nonce, aad=aad)
    assert result["ciphertext_hex"] == ciphertext.hex()
    assert result["tag_hex"] == tag.hex()
    result = symmetric("AES", "GCM", "Decrypt", ciphertext, key, nonce, tag, aad)
    assert result["authenticated"] and result["hex"] == plain.hex()
    with pytest.raises(ValueError, match="MAC check failed"):
        symmetric("AES", "GCM", "Decrypt", ciphertext, key, nonce, tag, aad[:-1])


@pytest.mark.parametrize(
    "mode, operation, padding, error",
    [
        ("ECB", "Encryptt", "None", "Encrypt or Decrypt"),
        ("CFB", "Encrypt", "None", "Choose ECB"),
        ("CBC", "Encrypt", "PKCS77", "PKCS7"),
    ],
)
def test_symmetric_rejects_unknown_options(mode, operation, padding, error):
    with pytest.raises(ValueError, match=error):
        symmetric("AES", mode, operation, bytes(16), bytes(16), padding=padding)


@pytest.mark.parametrize("target", ["", "a" * 63, "z" * 64, "é" * 64])
def test_hash_comparison_reports_malformed_hex(target):
    with pytest.raises(ValueError, match="64-digit hexadecimal digest"):
        compare("hello", target, "SHA-256")


def test_hash_comparison_accepts_upper_case_and_outer_whitespace():
    assert compare("hello", " " + digest("hello", "SHA-256").upper() + "\n", "SHA-256")


def test_unicode_escape_pairs_and_lone_surrogates():
    assert decode("Unicode escapes", r"π \ud83d\ude00") == "π 😀".encode()
    with pytest.raises(UnicodeError):
        decode("Unicode escapes", r"\ud83d")


def test_classical_ascii_alphabet_does_not_consume_unicode_case_folds():
    assert caesar("Aſıßz", 1) == "Bſıßa"
    assert frequency("Aſıßz")["letters"] == 2
    with pytest.raises(ValueError, match="ASCII letters"):
        caesar("A", 1, "Aſ")
    with pytest.raises(ValueError, match="at least 20 letters"):
        recover_vigenere("ſıß" * 20, Budget())


def test_asn1_hint_requires_a_matching_sequence_length():
    assert signature(b"0.25") == "JSON data"
    assert "DER" in signature(bytes.fromhex("3003020101"))
    assert "DER" in signature(bytes.fromhex("308180") + bytes(128))
    assert "DER" not in signature(bytes.fromhex("3004020101"))
    assert "DER" not in signature(bytes.fromhex("308103020101"))


def test_file_inspection_handles_json_beyond_the_parser_depth(monkeypatch):
    from pcc import files

    def recursion_limit_reached(_data):
        raise RecursionError("JSON parser depth exceeded")

    monkeypatch.setattr(files.json, "loads", recursion_limit_reached)
    assert signature(b"[[0]]") == "UTF-8 text / unknown signature"
