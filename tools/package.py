"""Package the verified executable and the source files for a local build."""

import hashlib
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
APP = DIST / "GhostCipher"
GENERATED = ROOT / "build" / "generated"
SOURCE_ROOT_FILES = (
    ".gitattributes",
    ".gitignore",
    "GhostCipher.spec",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "LICENSE",
    "build-windows.ps1",
    "main.py",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "assets/version.txt",
    "docs/WINDOWS-KALI-CHEATSHEET.md",
    "docs/screenshots/GhostCipher-Workspace.png",
    "docs/screenshots/GhostCipher-Encoding.png",
    "docs/screenshots/GhostCipher-Practice.png",
    "examples/README.md",
    "examples/base64.txt",
    "examples/file-inspection.txt",
)


def source_files():
    # Collect project code and named publication materials only. In particular,
    # never walk the repository root for local reports, notes, or credentials.
    paths = [ROOT / name for name in SOURCE_ROOT_FILES]
    for directory in ("pcc", "tests", "tools"):
        paths.extend(sorted((ROOT / directory).glob("*.py")))
    paths.extend(sorted((ROOT / "licenses").rglob("*")))
    for path in paths:
        if (
            path.is_file()
            and not path.is_symlink()
            and path.resolve().is_relative_to(ROOT)
        ):
            yield path


def main():
    executable = APP / "GhostCipher.exe"
    if not executable.is_file():
        raise RuntimeError("Build GhostCipher.exe before packaging.")
    for name in ("README.md", "THIRD_PARTY_NOTICES.md", "LICENSE"):
        path = ROOT / name
        if path.is_file():
            shutil.copy2(path, APP / name)
    shutil.copytree(ROOT / "examples", APP / "examples", dirs_exist_ok=True)
    shutil.copytree(ROOT / "licenses", APP / "licenses", dirs_exist_ok=True)
    for name in ("docs", "samples", "licenses"):
        shutil.copytree(GENERATED / name, APP / name, dirs_exist_ok=True)
    shutil.copytree(
        ROOT / "docs" / "screenshots", APP / "docs" / "screenshots", dirs_exist_ok=True
    )

    portable = DIST / "GhostCipher-Windows-x64.zip"
    with zipfile.ZipFile(portable, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(APP.rglob("*")):
            if path.is_file() and path.name != "user-settings.json":
                archive.write(path, path.relative_to(DIST))

    source = DIST / "GhostCipher-Source.zip"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in source_files():
            archive.write(path, Path("GhostCipher") / path.relative_to(ROOT))

    checksums = []
    for path in (executable, portable, source):
        with path.open("rb") as stream:
            sha = hashlib.file_digest(stream, "sha256").hexdigest()
        checksums.append(f"{sha}  {path.relative_to(DIST).as_posix()}")
    (DIST / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    print("\n".join(checksums))


if __name__ == "__main__":
    main()
