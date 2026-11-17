"""Generate original offline documents, samples, icon and dependency notices."""

import importlib.metadata
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "build" / "generated"
sys.path.insert(0, str(ROOT))
from pcc.content import lessons, practice, CHEATSHEET
from pcc.gui import BACKGROUND, TEXT
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPixmap, QPainter, QColor, QFont
from PySide6.QtCore import Qt


def main():
    for directory in ("docs", "samples", "assets", "licenses"):
        (GENERATED / directory).mkdir(parents=True, exist_ok=True)
    guide = [
        "# GhostCipher Offline Learning Guide",
        "\n35 practical lessons. Each example is local and requires no Internet.\n",
    ]
    headings = {
        "what": "What it is",
        "recognize": "How to recognize it",
        "example_input": "Example input",
        "example_output": "Example output",
        "tool": "Tool to use",
        "why": "Why it works",
        "mistakes": "Common mistakes",
        "limits": "When it will not work",
    }
    for row in lessons():
        guide.append("\n## " + row["title"])
        for key, title in headings.items():
            guide.append("\n### " + title + "\n\n" + row[key])
    (GENERATED / "docs" / "OFFLINE-LEARNING-GUIDE.md").write_text(
        "\n".join(guide), encoding="utf-8"
    )
    (GENERATED / "docs" / "WINDOWS-KALI-CHEATSHEET.md").write_text(
        CHEATSHEET, encoding="utf-8"
    )
    exercises = practice()
    (GENERATED / "docs" / "PRACTICE-CHALLENGES.json").write_text(
        json.dumps(exercises, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    index = [
        "# Original practice arena",
        "\nAnswers are hidden in the GUI. The JSON curriculum contains solutions for offline review.\n",
    ]
    for x in exercises:
        index.append(
            f'{x["id"]}. {x["title"]} — {x["difficulty"]}, {x["points"]} points ({x["kind"]})'
        )
    (GENERATED / "docs" / "PRACTICE-INDEX.md").write_text(
        "\n".join(index), encoding="utf-8"
    )
    for x in exercises:
        if x["id"] in (1, 4, 14, 15, 25, 26, 29, 32, 33):
            (
                GENERATED
                / "samples"
                / f'{x["id"]:02d}-{x["kind"].replace(" ","-")}.txt'
            ).write_text(x["setup"] + "\n\n" + x["input"] + "\n", encoding="utf-8")
    (GENERATED / "samples" / "all-examples.json").write_text(
        json.dumps(
            [
                {k: x[k] for k in ("id", "title", "kind", "input", "setup")}
                for x in exercises
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    (GENERATED / "samples" / "small-wordlist.txt").write_text(
        "PCCP{digest_wrong}\nPCCP{digest_match}\nPCCP{digest_other}\n", encoding="utf-8"
    )
    import zipfile

    with zipfile.ZipFile(GENERATED / "samples" / "safe-archive.zip", "w") as archive:
        archive.writestr(
            "readme.txt",
            "This archive contains the original flag PCCP{archive_strings}. Nothing is executed.",
        )
    (GENERATED / "samples" / "raw-xor.bin").write_bytes(
        bytes(c ^ 0x37 for c in b"PCCP{raw_xor_file}")
    )
    app = QApplication.instance() or QApplication([])
    pix = QPixmap(256, 256)
    pix.fill(QColor(BACKGROUND))
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QColor(TEXT))
    p.setFont(QFont("Segoe UI", 145, QFont.Bold))
    p.drawText(pix.rect(), Qt.AlignCenter, "G")
    p.end()
    if not pix.save(str(GENERATED / "assets" / "app.ico")):
        raise RuntimeError("Could not generate Windows icon")
    pix.save(str(GENERATED / "assets" / "app.png"))
    for name in [
        "PySide6_Essentials",
        "shiboken6",
        "pycryptodome",
        "sympy",
        "mpmath",
        "pyinstaller",
        "altgraph",
    ]:
        dist = importlib.metadata.distribution(name)
        for item in dist.files or []:
            s = str(item).replace("\\", "/")
            if any(
                part.lower()
                in (
                    "licenses",
                    "license",
                    "license.txt",
                    "license.rst",
                    "copying",
                    "copyright",
                    "notice",
                )
                or part.lower().startswith(("license.", "copying."))
                for part in item.parts
            ):
                path = Path(dist.locate_file(item))
                if path.is_file():
                    dest = GENERATED / "licenses" / name / Path(s).name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, dest)
    for file in (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
    ):
        if file.is_file():
            shutil.copy2(file, GENERATED / "licenses" / "PYTHON-LICENSE.txt")
    print(f"Prepared {len(lessons())} lessons and {len(exercises)} challenges.")


if __name__ == "__main__":
    main()
