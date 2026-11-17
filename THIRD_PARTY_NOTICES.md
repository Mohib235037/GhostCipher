# Third-party notices

The source repository references dependencies through its requirements files. It contains original GhostCipher screenshots captured from the running app with synthetic challenge data and upstream license notices under `licenses/`. Dependency code, wheels, fonts, and compiled libraries are installed separately. The MIT license for GhostCipher applies to original project material. Upstream notices remain under their respective terms.

| Component | Upstream terms |
| --- | --- |
| Python | [Python Software Foundation license](https://www.python.org/psf/license/) |
| PySide6 Essentials, Shiboken6, and Qt | LGPLv3, GPL, or commercial alternatives, as applicable to each component. [Qt for Python licensing](https://doc.qt.io/qtforpython-6/licenses.html) · [Qt licensing](https://doc.qt.io/qt-6/licensing.html) |
| PyCryptodome | The 4.4.0 wheel declares BSD-2-Clause, Unlicense, and MIT for its components. [PyCryptodome license](https://www.pycryptodome.org/src/license) |
| SymPy and mpmath | BSD licenses. [SymPy](https://github.com/sympy/sympy/blob/master/LICENSE) · [mpmath](https://github.com/mpmath/mpmath/blob/master/LICENSE) |
| PyInstaller bootloader | GPL with a distribution exception. [PyInstaller license](https://pyinstaller.org/en/stable/license.html) |

The portable app loads Qt shared libraries from its `_internal` tree. The build configuration keeps the libraries separate from the executable. Matching upstream source locations are the [Qt source archive](https://download.qt.io/archive/qt/) and the [Qt for Python release archive](https://download.qt.io/official_releases/QtForPython/). Build dependencies and their versions are listed in the requirements files.
