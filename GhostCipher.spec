from PyInstaller.utils.hooks import collect_dynamic_libs
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / "main.py")],
    pathex=[str(root)],
    binaries=collect_dynamic_libs("Crypto"),
    datas=[],
    hiddenimports=[],
    excludes=[
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick",
        "PySide6.QtNetwork",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "IPython",
        "pytest",
    ],
    noarchive=False,
)
# A build machine can expose a private ICU through PATH with the same DLL name
# as Windows ICU but a different exported API. Qt uses the Windows ICU API.
# Keep OS API-set/UCRT/ICU libraries out of the portable directory so Windows can
# resolve its own compatible libraries (Windows 10 1809+ already provides them).
os_libraries = {"icuuc.dll", "icudt78.dll", "ucrtbase.dll"}
a.binaries = [
    entry
    for entry in a.binaries
    if Path(entry[0]).name.lower() not in os_libraries
    and not Path(entry[0]).name.lower().startswith("api-ms-win-")
]
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="GhostCipher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    version=str(root / "assets" / "version.txt"),
    icon=str(root / "build" / "generated" / "assets" / "app.ico"),
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="GhostCipher")
