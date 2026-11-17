# Offline CTF field notes

Start with the story and flag format. Preserve the original bytes. Identify a representation, decode one layer, and inspect the output. Keep a record of each operation. Matching an alphabet is only a guess. If several decodings fit, compare their results.

## Windows PowerShell
Decode Base64 UTF-8: `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('UENDUHt0ZXN0fQ=='))`

View file bytes: `Format-Hex -LiteralPath .\challenge.bin`

Compute a digest: `Get-FileHash -LiteralPath .\challenge.bin -Algorithm SHA256`

## Python (Windows or Kali, when Python is installed)
Base64: `python -c "import base64; print(base64.b64decode('UENDUHt0ZXN0fQ=='))"`

Hex: `python -c "print(bytes.fromhex('504343507b746573747d'))"`

ROT13: `python -c "import codecs; print(codecs.decode('URYYB','rot_13'))"`

Modular inverse: `python -c "print(pow(17,-1,3120))"`

## Kali Linux shell
Decode: `printf '%s' 'UENDUHt0ZXN0fQ==' | base64 -d`

Hex to bytes: `printf '%s' '504343507b746573747d' | xxd -r -p`

Read strings: `strings -a challenge.bin`

Inspect file type: `file challenge.bin`

Digest: `sha256sum challenge.bin`

These commands are examples for your own authorized practice data. The application does not invoke a shell, Kali, or these commands. Its tools run offline using bundled Python libraries.

## Decision guide
Encoding has no secret key. Hashes compare candidates; they do not decrypt. Classical ciphers may have small key spaces. XOR with a short repeated key may leak patterns. Modern AES requires a key and exact parameters. Strong RSA needs a private key or a demonstrated weakness. A format label is never proof that encryption has been cracked.
