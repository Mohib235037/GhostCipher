from __future__ import annotations
import json
import sys
from dataclasses import asdict
from pathlib import Path
from PySide6.QtCore import Qt, QTimer, QSize
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QPlainTextEdit,
    QTextBrowser,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGridLayout,
    QLineEdit,
    QComboBox,
    QSpinBox,
    QDoubleSpinBox,
    QListWidget,
    QStackedWidget,
    QFrame,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractScrollArea,
    QAbstractItemView,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
    QCheckBox,
)
from .common import Limits, HARD_INPUT
from .content import lessons, practice, CHEATSHEET
from .files import read_limited
from .worker import Task
from .encodings import NAMES
from .hashes import ALGORITHMS

APP_NAME = "GhostCipher"
BACKGROUND = "#111315"
PANEL = "#202326"
BORDER = "#383C3E"
TEXT = "#F1F0ED"
MUTED = "#A9B0B4"
ACCENT = "#D99A64"

STYLE = """
QMainWindow { background:palette(window); }
QWidget#sidebar { background:palette(button); border-right:1px solid palette(mid); }
QLabel#brand { font-size:21px; font-weight:700; }
QLabel#heading { font-size:24px; font-weight:650; }
QLabel#section { font-size:13px; font-weight:600; }
QLabel#muted { color:palette(placeholder-text); }
QLabel#stat { font-family:Consolas; font-weight:600; }
QFrame#metrics { background:palette(button); border:1px solid palette(mid); border-radius:3px; }
QFrame#metricDivider { background:palette(mid); }

QListWidget, QTableWidget { background:palette(base); border:1px solid palette(mid); }
QListWidget::item { padding:5px 8px; }
QListWidget::item:hover, QTableWidget::item:hover { background:#272A2D; }
QListWidget::item:selected, QTableWidget::item:selected { background:palette(highlight); color:palette(highlighted-text); }
QListWidget#nav { background:transparent; border:0; outline:0; }
QListWidget#nav::item { border-left:2px solid transparent; padding:4px 8px; color:palette(placeholder-text); }
QListWidget#nav::item:selected { border-left:2px solid #D99A64; color:palette(text); font-weight:600; }
QListWidget#nav::item:focus { border-bottom:1px solid #D99A64; }

QPushButton { background:palette(button); border:1px solid palette(mid); border-radius:3px; padding:6px 12px; font-weight:600; }
QPushButton:hover { background:#2A2D30; border-color:#62676A; }
QPushButton:pressed { background:palette(mid); }
QPushButton:focus { border-color:#D99A64; }
QPushButton:disabled, QPushButton#primary:disabled { color:#858A8D; background:palette(button); border-color:palette(mid); }
QPushButton#primary { background:#D99A64; color:#111315; border-color:#D99A64; }
QPushButton#primary:hover { background:#E9B084; }
QPushButton#primary:pressed { background:#C48450; }
QPushButton#primary:focus { border-color:#F1F0ED; }

QLineEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox, QDoubleSpinBox {
    background:palette(button); border:1px solid palette(mid); border-radius:3px; padding:5px 7px;
}
QPlainTextEdit { font-family:Consolas; font-size:13px; }
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QListWidget:focus, QTableWidget:focus { border-color:#D99A64; }
QComboBox QAbstractItemView { background:palette(button); border:1px solid palette(mid); }
QTabWidget::pane { border:1px solid palette(mid); }
QTabBar::tab { background:palette(window); color:palette(placeholder-text); border-bottom:2px solid transparent; padding:7px 12px; }
QTabBar::tab:hover { background:palette(button); color:palette(text); }
QTabBar::tab:selected { background:palette(button); color:#D99A64; border-bottom-color:#D99A64; }
QTableWidget { alternate-background-color:palette(button); gridline-color:palette(mid); }
QHeaderView::section { background:palette(button); color:palette(text); padding:5px 8px; border:0; border-bottom:1px solid palette(mid); font-weight:600; }
QTableWidget::item { padding:3px 7px; }
QProgressBar { border:0; background:palette(mid); }
QProgressBar::chunk { background:#D99A64; }
QScrollArea { border:0; }
QSplitter::handle { background:palette(mid); }
QSplitter::handle:hover { background:#D99A64; }
QToolTip { background:palette(button); color:palette(text); border:1px solid palette(mid); }
"""


def workbench_palette():
    palette = QPalette()
    for role, color in {
        QPalette.Window: BACKGROUND,
        QPalette.Base: BACKGROUND,
        QPalette.AlternateBase: PANEL,
        QPalette.Button: PANEL,
        QPalette.Mid: BORDER,
        QPalette.WindowText: TEXT,
        QPalette.Text: TEXT,
        QPalette.ButtonText: TEXT,
        QPalette.PlaceholderText: MUTED,
        QPalette.ToolTipBase: PANEL,
        QPalette.ToolTipText: TEXT,
        QPalette.Highlight: BORDER,
        QPalette.HighlightedText: TEXT,
        QPalette.Link: ACCENT,
    }.items():
        palette.setColor(role, QColor(color))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        palette.setColor(QPalette.Disabled, role, QColor("#858A8D"))
    return palette


def label(text, name=None):
    w = QLabel(text)
    w.setWordWrap(name not in ("section", "brand", "heading", "stat"))
    if name:
        w.setObjectName(name)
    return w


def button(text, callback, primary=False):
    w = QPushButton(text)
    w.clicked.connect(callback)
    if primary:
        w.setObjectName("primary")
    return w


def plain(readonly=False):
    w = QPlainTextEdit()
    w.setReadOnly(readonly)
    return w


TOOL_SPECS = {
    "encoding": (
        "Encoding / Decoding",
        "Convert representations one step at a time. Decode before trying more complex ciphers.",
        [
            ("operation", "Operation", ["Decode", "Encode"]),
            ("method", "Method", NAMES),
            (
                "encoding",
                "Input byte encoding (Encode only)",
                ["UTF-8", "Hex", "Base64"],
            ),
        ],
        "UENDUHt0ZXN0fQ==",
    ),
    "classical": (
        "Classical Ciphers",
        "Use a known key, try a bounded key space, or inspect letter patterns.",
        [
            (
                "operation",
                "Operation",
                [
                    "Caesar brute force",
                    "Caesar apply shift",
                    "ROT13",
                    "Atbash",
                    "Vigenère decrypt",
                    "Vigenère encrypt",
                    "Vigenère recover",
                    "Affine decrypt",
                    "Affine encrypt",
                    "Affine brute force",
                    "Rail Fence decrypt",
                    "Rail Fence encrypt",
                    "Morse decode",
                    "Morse encode",
                    "Bacon decode",
                    "Bacon encode",
                    "Frequency analysis",
                    "Reverse",
                ],
            ),
            ("key", "Vigenère key", "LEMON"),
            ("shift", "Caesar shift (signed)", "-3"),
            ("alphabet", "Caesar alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ("a", "Affine a", "5"),
            ("b", "Affine b", "8"),
            ("rails", "Rail count", "3"),
        ],
        "KHOOR ZRUOG",
    ),
    "xor": (
        "XOR Solver",
        "Work with bytes. Readability and key-length estimates are clues, not proof.",
        [
            (
                "operation",
                "Operation",
                [
                    "Known key",
                    "Single-byte brute force",
                    "Repeating-key recovery",
                    "Key-length estimates",
                    "Known-plaintext hint",
                ],
            ),
            ("encoding", "Input encoding", ["Hex", "Base64", "UTF-8", "Raw file"]),
            ("key", "Key", "4b4559"),
            ("key_encoding", "Key encoding", ["Hex", "UTF-8", "Base64"]),
            ("hint", "Known plaintext (UTF-8)", "PCCP{"),
            ("offset", "Hint byte offset", "0"),
        ],
        "1b061a1b3e21243724362a34222b3e",
    ),
    "hash": (
        "Hash Analyzer",
        "Identify possible formats, generate digests, or compare your supplied candidates.",
        [
            (
                "operation",
                "Operation",
                ["Identify", "Generate", "Compare", "Local dictionary check"],
            ),
            ("algorithm", "Algorithm", ALGORITHMS),
            ("target", "Target digest (Compare / Dictionary)", ""),
        ],
        "5d41402abc4b2a76b9719d911017c592",
    ),
    "rsa": (
        "RSA Solver",
        "Educational raw RSA. Supply JSON integers or paste an unencrypted PEM key.",
        [
            (
                "operation",
                "Operation",
                [
                    "Decrypt",
                    "Encrypt",
                    "Factor / derive private key",
                    "Common modulus",
                    "Small exponent",
                    "Inspect PEM / DER",
                ],
            )
        ],
        '{"p":61,"q":53,"e":17,"c":2790}',
    ),
    "symmetric": (
        "AES / DES Tools",
        "Provide exact parameters. GCM verifies the tag before returning plaintext.",
        [
            ("operation", "Operation", ["Decrypt", "Encrypt"]),
            ("algorithm", "Algorithm", ["AES", "DES", "3DES"]),
            ("mode", "Mode", ["CBC", "ECB", "CTR", "GCM"]),
            ("encoding", "Input encoding", ["Hex", "Base64", "UTF-8"]),
            ("key", "Key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "Key encoding", ["Hex", "Base64", "UTF-8"]),
            ("iv", "IV / nonce (Hex)", "000102030405060708090a0b0c0d0e0f"),
            ("tag", "GCM tag (Hex, 16 bytes)", ""),
            ("aad", "GCM associated data (UTF-8)", ""),
            ("padding", "ECB / CBC padding", ["PKCS7", "None"]),
        ],
        "",
    ),
    "advanced": (
        "Advanced Crypto",
        "Exact-integer helpers. Select an operation to see its required JSON fields.",
        [
            (
                "operation",
                "Operation",
                [
                    "Modular inverse",
                    "GCD",
                    "Extended GCD",
                    "Modular power",
                    "CRT",
                    "Prime test",
                    "Factor small integer",
                    "Entropy",
                    "Frequency",
                    "LCG generate",
                    "LCG recover",
                ],
            ),
            ("encoding", "Entropy input encoding", ["UTF-8", "Hex", "Base64"]),
        ],
        '{"a":17,"m":3120}',
    ),
}

MATH_EXAMPLES = {
    "Modular inverse": '{"a":17,"m":3120}',
    "GCD": '{"a":48,"b":18}',
    "Extended GCD": '{"a":48,"b":18}',
    "Modular power": '{"a":2,"e":10,"m":17}',
    "CRT": '{"moduli":[3,5,7],"remainders":[2,3,2]}',
    "Prime test": '{"n":65537}',
    "Factor small integer": '{"n":3233}',
    "Entropy": "AAAA",
    "Frequency": "THE QUICK BROWN FOX",
    "LCG generate": '{"a":5,"b":1,"m":16,"seed":0,"count":5}',
    "LCG recover": '{"m":16,"outputs":[1,6,15,12,13]}',
}
RSA_EXAMPLES = {
    "Decrypt": '{"p":61,"q":53,"e":17,"c":2790}',
    "Encrypt": '{"n":3233,"e":17,"m":65}',
    "Factor / derive private key": '{"n":3233,"e":17}',
    "Small exponent": '{"e":3,"c":74088}',
    "Common modulus": '{"n":3233,"e1":7,"e2":11,"c1":1317,"c2":2811}',
    "Inspect PEM / DER": "Paste a PEM key or open a DER file.",
}


class ToolPage(QWidget):
    def __init__(self, kind, window):
        super().__init__()
        self.kind = kind
        self.window = window
        self.fields = {}
        self.raw = None
        self.wordlist = ""
        self.supplied = False
        title, desc, specs, example = TOOL_SPECS[kind]
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(label(title, "heading"))
        box.addWidget(label(desc, "muted"))
        self.note = label(
            "Select an operation, enter your input, then run. Only relevant key fields are used.",
            "muted",
        )
        box.addWidget(self.note)
        body = QWidget()
        form = QGridLayout(body)
        form.setContentsMargins(2, 4, 8, 4)
        form.setSpacing(6)
        form.setAlignment(Qt.AlignTop)
        columns = 2 if len(specs) >= 5 else 1
        for index, (key, title, value) in enumerate(specs):
            if isinstance(value, list):
                field = QComboBox()
                field.addItems(value)
            else:
                field = QLineEdit(value)
            field.setObjectName(kind + "_" + key)
            column = (index % columns) * 2
            form.addWidget(label(title), index // columns, column)
            form.addWidget(field, index // columns, column + 1)
            form.setColumnStretch(column + 1, 1)
            self.fields[key] = field
        if columns == 1:
            box.addWidget(body)
        else:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
            scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            scroll.setWidget(body)
            scroll.setMaximumHeight(205)
            box.addWidget(scroll)
        row = QHBoxLayout()
        row.addWidget(label("Input", "section"))
        row.addStretch()
        row.addWidget(button("Open input file", self.open_file))
        if kind == "hash":
            row.addWidget(button("Open wordlist", self.open_words))
        if kind in ("rsa", "advanced"):
            row.addWidget(button("Load example", self.load_example))
        box.addLayout(row)
        self.text = plain()
        self.text.setPlaceholderText(
            example or "Paste ciphertext or plaintext. Select its encoding above."
        )
        self.text.setPlainText(example)
        self.text.setMinimumHeight(86)
        box.addWidget(self.text, 1)
        if kind == "rsa":
            self.use_raw = QCheckBox(
                "Use opened binary key file for PEM / DER inspection"
            )
            box.addWidget(self.use_raw)
        row = QHBoxLayout()
        row.addWidget(button("Run operation", self.run, True))
        row.addWidget(button("Clear input", lambda: self.text.clear()))
        row.addStretch()
        box.addLayout(row)
        if kind == "advanced":
            self.fields["operation"].currentTextChanged.connect(
                lambda _: self.note.setText(
                    "Example fields: "
                    + MATH_EXAMPLES[self.fields["operation"].currentText()]
                )
            )
        if kind == "rsa":
            self.fields["operation"].currentTextChanged.connect(
                lambda _: self.note.setText(
                    "Example fields: "
                    + RSA_EXAMPLES[self.fields["operation"].currentText()]
                )
            )

    def load_example(self):
        options = MATH_EXAMPLES if self.kind == "advanced" else RSA_EXAMPLES
        self.text.setPlainText(options[self.fields["operation"].currentText()])

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open challenge input")
        if not path:
            return
        try:
            self.raw = read_limited(path, self.window.limits.input_bytes)
            if self.kind == "xor":
                self.fields["encoding"].setCurrentText("Raw file")
                self.text.setPlainText(self.raw[:2048].hex())
                self.note.setText(
                    f"Raw file: {Path(path).name} · {len(self.raw):,} bytes. Display is a hex preview; the full bounded file is used."
                )
            elif self.kind == "rsa":
                self.fields["operation"].setCurrentText("Inspect PEM / DER")
                self.use_raw.setChecked(True)
                self.text.setPlainText(self.raw.decode("utf-8", "replace")[:4096])
            else:
                try:
                    self.text.setPlainText(self.raw.decode("utf-8"))
                except UnicodeError:
                    self.text.setPlainText(self.raw.hex())
                    if "encoding" in self.fields:
                        self.fields["encoding"].setCurrentText("Hex")
        except (ValueError, OSError) as exc:
            self.window.error(str(exc))

    def open_words(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose an explicitly supplied UTF-8 wordlist"
        )
        if not path:
            return
        try:
            words = read_limited(
                path, min(self.window.limits.input_bytes, 1048576)
            ).decode("utf-8")
            if len(words.splitlines()) > 10000:
                raise ValueError("Maximum 10,000 wordlist lines.")
            self.wordlist = words
            self.supplied = True
            self.note.setText(
                f"Local wordlist: {Path(path).name} · {len(words.splitlines()):,} lines. Used only when Local dictionary check is selected."
            )
        except (ValueError, OSError, UnicodeError) as exc:
            self.window.error(str(exc))

    def run(self):
        values = {
            key: w.currentText() if isinstance(w, QComboBox) else w.text()
            for key, w in self.fields.items()
        }
        values["text"] = self.text.toPlainText()
        if self.kind == "xor":
            values["raw_bytes"] = self.raw if values["encoding"] == "Raw file" else None
        if self.kind == "rsa" and self.use_raw.isChecked():
            values["raw_bytes"] = self.raw
        if self.kind == "hash":
            values.update(wordlist=self.wordlist, wordlist_supplied=self.supplied)
        self.window.run_task(self.kind, values)


class MainWindow(QMainWindow):
    def __init__(self, settings_path=None):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1180, 790)
        self.setMinimumSize(980, 660)
        self.setAcceptDrops(True)
        self.task = None
        self.result = None
        self.opened_data = None
        self.opened_name = ""
        self.limits = Limits()
        self.settings_path = (
            Path(settings_path)
            if settings_path
            else Path(sys.executable if getattr(sys, "frozen", False) else __file__)
            .resolve()
            .parent
            / "user-settings.json"
        )
        try:
            if self.settings_path.exists():
                self.limits = Limits(
                    **json.loads(self.settings_path.read_text())
                ).validate()
        except (OSError, ValueError, TypeError):
            pass
        self.setPalette(workbench_palette())
        self.setStyleSheet(STYLE)
        self.setWindowIcon(self.make_icon())
        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(198)
        sidebox = QVBoxLayout(side)
        sidebox.setContentsMargins(12, 14, 12, 12)
        sidebox.setSpacing(8)
        wordmark = label(APP_NAME, "brand")
        wordmark.setContentsMargins(7, 0, 0, 4)
        sidebox.addWidget(wordmark)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.addItems(
            [
                "Dashboard",
                "Auto Crypto Detector",
                "Encoding / Decoding",
                "Classical Ciphers",
                "XOR Solver",
                "Hash Analyzer",
                "RSA Solver",
                "AES / DES Tools",
                "Advanced Crypto",
                "File Analyzer",
                "Crypto Learning Guide",
                "Settings",
            ]
        )
        for i in range(self.nav.count()):
            self.nav.item(i).setSizeHint(QSize(166, 30))
        sidebox.addWidget(self.nav, 1)
        offline = label("Offline mode", "muted")
        offline.setContentsMargins(7, 0, 0, 0)
        offline.setToolTip("Challenge files and results stay on this PC.")
        sidebox.addWidget(offline)
        layout.addWidget(side)
        area = QWidget()
        outer = QVBoxLayout(area)
        outer.setContentsMargins(18, 14, 18, 10)
        outer.setSpacing(8)
        layout.addWidget(area, 1)
        self.pages = QStackedWidget()
        self.workbench = self.build_workbench()
        self.pages.addWidget(self.workbench)
        self.tools = {}
        for kind in TOOL_SPECS:
            self.tools[kind] = ToolPage(kind, self)
            self.pages.addWidget(self.tools[kind])
        self.file_page = self.build_file()
        self.pages.addWidget(self.file_page)
        self.learning = self.build_learning()
        self.pages.addWidget(self.learning)
        self.settings = self.build_settings()
        self.pages.addWidget(self.settings)
        self.main_split = QSplitter(Qt.Vertical)
        self.main_split.setHandleWidth(2)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.addWidget(self.pages)
        self.output_area = self.build_output()
        self.output_area.setMinimumHeight(238)
        self.main_split.addWidget(self.output_area)
        outer.addWidget(self.main_split, 1)
        status = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedSize(92, 5)
        self.progress.setTextVisible(False)
        self.progress.setAccessibleName("Analysis progress")
        status.addWidget(self.progress)
        self.state = label("Ready · paste a challenge to begin", "muted")
        status.addWidget(self.state, 1)
        self.cancel_button = button("Cancel analysis", self.cancel)
        self.cancel_button.setEnabled(False)
        status.addWidget(self.cancel_button)
        outer.addLayout(status)
        self.timer = QTimer(self)
        self.timer.setInterval(75)
        self.timer.timeout.connect(self.poll)
        self.nav.currentRowChanged.connect(self.navigate)
        self.nav.setCurrentRow(0)

    def make_icon(self):
        pix = QPixmap(64, 64)
        pix.fill(QColor(BACKGROUND))
        painter = QPainter(pix)
        painter.setPen(QColor(TEXT))
        painter.setFont(QFont("Segoe UI", 38, QFont.Bold))
        painter.drawText(pix.rect(), Qt.AlignCenter, "G")
        painter.end()
        return QIcon(pix)

    def build_workbench(self):
        w = QWidget()
        box = QVBoxLayout(w)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(8)
        self.workbench_heading = label("Dashboard", "heading")
        box.addWidget(self.workbench_heading)

        metrics = QFrame()
        metrics.setObjectName("metrics")
        metrics_row = QHBoxLayout(metrics)
        metrics_row.setContentsMargins(10, 5, 10, 5)
        metrics_row.setSpacing(10)
        self.stats = []
        for title, tooltip in [
            ("Input bytes", "Size of the challenge text or local file."),
            ("Transformations", "Number of candidates generated during analysis."),
            ("Possible flags", "Verify each candidate against the challenge."),
        ]:
            if self.stats:
                divider = QFrame()
                divider.setObjectName("metricDivider")
                divider.setFixedWidth(1)
                metrics_row.addWidget(divider)
            caption = label(title, "muted")
            caption.setToolTip(tooltip)
            metrics_row.addWidget(caption)
            stat = label("0", "stat")
            stat.setAccessibleName(title)
            stat.setToolTip(tooltip)
            metrics_row.addWidget(stat)
            self.stats.append(stat)
        metrics_row.addStretch()
        box.addWidget(metrics)
        row = QHBoxLayout()
        row.addWidget(label("Challenge input", "section"))
        row.addStretch()
        self.source_label = label("UTF-8 text", "muted")
        row.addWidget(self.source_label)
        box.addLayout(row)
        self.input = plain()
        self.input.setPlaceholderText(
            "Paste encoded text, ciphertext, or challenge parameters."
        )
        self.input.setMinimumHeight(92)
        self.input.textChanged.connect(self.input_changed)
        box.addWidget(self.input, 1)
        row = QHBoxLayout()
        self.solve_button = button("Auto Detect && Solve", self.auto_solve, True)
        row.addWidget(self.solve_button)
        row.addWidget(button("Clear", self.clear))
        row.addWidget(button("Load demo", self.demo))
        row.addStretch()
        row.addWidget(label("Drop a file here or", "muted"))
        row.addWidget(button("Open file…", self.open_file))
        box.addLayout(row)
        return w

    def build_output(self):
        w = QWidget()
        box = QVBoxLayout(w)
        box.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(label("Results", "section"))
        row.addStretch()
        row.addWidget(button("Copy Result", self.copy_result))
        row.addWidget(button("Save Results", self.save_result))
        box.addLayout(row)
        self.tabs = QTabWidget()
        box.addWidget(self.tabs, 1)
        candidates = QWidget()
        cv = QVBoxLayout(candidates)
        cv.setContentsMargins(8, 8, 8, 8)
        self.result_summary = label(
            "Possible solutions appear here. Select a row to inspect its plaintext and decoding steps.",
            "muted",
        )
        cv.addWidget(self.result_summary)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(
            ["Transformation / result", "Confidence", "Possible flag"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setDefaultAlignment(
            Qt.AlignLeft | Qt.AlignVCenter
        )
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        self.table.setMinimumHeight(82)
        self.table.setMaximumHeight(146)
        self.table.itemSelectionChanged.connect(self.select_candidate)
        cv.addWidget(self.table)
        self.preview = plain(True)
        self.preview.setPlaceholderText("Plaintext, bytes or operation output")
        cv.addWidget(self.preview, 1)
        self.tabs.addTab(candidates, "Possible solutions")
        self.detection = plain(True)
        self.tabs.addTab(self.detection, "Detected formats")
        self.steps = plain(True)
        self.tabs.addTab(self.steps, "Decoding steps")
        self.explanation = QTextBrowser()
        self.explanation.setOpenExternalLinks(False)
        self.explanation.setPlainText(
            "Detection is a clue. Reversible encodings are different from encryption. Use the Learning Guide for examples and limitations."
        )
        self.tabs.addTab(self.explanation, "Beginner explanation")
        return w

    def build_file(self):
        w = QWidget()
        box = QVBoxLayout(w)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(label("File Analyzer", "heading"))
        box.addWidget(
            label(
                "Inspect signatures, hex, printable strings, flags and safe ZIP previews. Files are never executed.",
                "muted",
            )
        )
        box.addWidget(
            label(
                "TXT · BIN · DAT · ZIP · JSON · PEM · DER · ENC · unknown files",
                "muted",
            )
        )
        actions = QHBoxLayout()
        actions.addWidget(
            button(
                "Open && inspect a local file",
                lambda: self.open_file(inspect=True),
                True,
            )
        )
        actions.addWidget(button("Inspect currently opened file", self.inspect_opened))
        actions.addStretch()
        box.addLayout(actions)
        box.addWidget(
            label(
                "ZIP limits: 32 entries, 1 MiB per member, 2 MiB total, expansion ratio at most 100:1. No recursive extraction. Encrypted members are skipped.",
                "muted",
            )
        )
        self.file_label = label(
            "No file selected. You can also drag a file into the window.", "muted"
        )
        box.addWidget(self.file_label)
        box.addStretch()
        return w

    def build_learning(self):
        w = QWidget()
        box = QVBoxLayout(w)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(label("Crypto Learning Guide", "heading"))
        tabs = QTabWidget()
        box.addWidget(tabs, 1)
        learn = QWidget()
        lv = QVBoxLayout(learn)
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search offline lessons: XOR, RSA, Base64, entropy…"
        )
        lv.addWidget(self.search)
        split = QSplitter()
        self.lesson_list = QListWidget()
        split.addWidget(self.lesson_list)
        self.lesson_view = QTextBrowser()
        self.lesson_view.setOpenExternalLinks(False)
        split.addWidget(self.lesson_view)
        split.setSizes([230, 650])
        lv.addWidget(split)
        tabs.addTab(learn, "Technique library")
        self.lesson_rows = lessons()
        self.search.textChanged.connect(self.filter_lessons)
        self.lesson_list.currentRowChanged.connect(self.show_lesson)
        self.filter_lessons("")
        sheet = QTextBrowser()
        sheet.setMarkdown(CHEATSHEET)
        sheet.setOpenExternalLinks(False)
        tabs.addTab(sheet, "Windows && Kali cheat sheet")
        p = QWidget()
        pv = QVBoxLayout(p)
        ps = QSplitter()
        self.challenge_list = QListWidget()
        ps.addWidget(self.challenge_list)
        right = QWidget()
        rv = QVBoxLayout(right)
        self.challenge_view = QTextBrowser()
        self.challenge_view.setOpenExternalLinks(False)
        rv.addWidget(self.challenge_view, 1)
        self.answer_input = QLineEdit()
        self.answer_input.setPlaceholderText("Enter your answer (case-sensitive)")
        rv.addWidget(self.answer_input)
        row = QHBoxLayout()
        row.addWidget(button("Check answer", self.check_answer, True))
        row.addWidget(button("Hint", self.hint))
        row.addWidget(button("Reveal walkthrough", self.reveal))
        rv.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(button("Copy challenge input", self.copy_challenge))
        row.addWidget(button("Send to Auto Detector", self.send_challenge))
        rv.addLayout(row)
        ps.addWidget(right)
        ps.setSizes([286, 620])
        pv.addWidget(ps)
        tabs.addTab(p, "Practice arena")
        self.challenge_rows = practice()
        self.challenge_list.addItems(
            [
                f'{x["id"]:02d}  {x["title"]}  ·  {x["points"]} pt'
                for x in self.challenge_rows
            ]
        )
        self.challenge_list.currentRowChanged.connect(self.show_challenge)
        self.challenge_list.setCurrentRow(0)
        return w

    def filter_lessons(self, text):
        self.filtered = [
            x
            for x in self.lesson_rows
            if text.casefold() in json.dumps(x, ensure_ascii=False).casefold()
        ]
        self.lesson_list.clear()
        self.lesson_list.addItems([x["title"] for x in self.filtered])
        self.lesson_list.setCurrentRow(0)

    def show_lesson(self, row):
        if row < 0 or row >= len(self.filtered):
            self.lesson_view.clear()
            return
        x = self.filtered[row]
        self.lesson_view.setPlainText(
            "\n\n".join(
                f"{title}\n{x[key]}"
                for title, key in [
                    ("TECHNIQUE", "title"),
                    ("WHAT IT IS", "what"),
                    ("HOW TO RECOGNIZE IT", "recognize"),
                    ("EXAMPLE INPUT", "example_input"),
                    ("EXAMPLE OUTPUT", "example_output"),
                    ("TOOL TO USE", "tool"),
                    ("WHY IT WORKS", "why"),
                    ("COMMON MISTAKES", "mistakes"),
                    ("WHEN IT WILL NOT WORK", "limits"),
                ]
            )
        )

    def challenge(self):
        return self.challenge_rows[max(0, self.challenge_list.currentRow())]

    def show_challenge(self, row):
        if row < 0:
            return
        x = self.challenge()
        self.answer_input.clear()
        self.hint_index = 0
        sections = [
            f'{x["title"]}\n{x["difficulty"]} · {x["points"]} points · {x["kind"]}',
            x["description"],
            x["setup"],
            f'CHALLENGE INPUT\n{x["input"]}',
            "Answers remain hidden until you request the walkthrough.",
        ]
        self.challenge_view.setPlainText("\n\n".join(filter(None, sections)))

    def check_answer(self):
        self.challenge_view.append(
            "\n"
            + (
                "Correct — well done. Inspect the walkthrough to understand each step."
                if self.answer_input.text() == self.challenge()["answer"]
                else "That answer does not match. Check case, braces, encoding and the requested format."
            )
        )

    def hint(self):
        hints = self.challenge()["hints"]
        self.challenge_view.append(
            "\nHint: " + hints[min(self.hint_index, len(hints) - 1)]
        )
        self.hint_index += 1

    def reveal(self):
        x = self.challenge()
        self.challenge_view.append(
            "\nSOLUTION\n" + x["answer"] + "\n\nWALKTHROUGH\n" + x["walkthrough"]
        )

    def copy_challenge(self):
        QApplication.clipboard().setText(self.challenge()["input"])

    def send_challenge(self):
        self.input.setPlainText(self.challenge()["input"])
        self.nav.setCurrentRow(1)

    def build_settings(self):
        w = QWidget()
        box = QVBoxLayout(w)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(label("Settings & resource limits", "heading"))
        box.addWidget(
            label(
                "Conservative limits keep analysis bounded. Saved settings apply to the next operation.",
                "muted",
            )
        )
        form = QFormLayout()
        self.limit_fields = {}
        for key, title, low, high in [
            ("depth", "Maximum decoding depth", 1, 8),
            ("candidates", "Maximum generated candidates", 10, 5000),
            ("input_bytes", "Maximum combined input bytes", 256, HARD_INPUT),
            ("seconds", "Analysis time (seconds)", 1, 60),
            ("memory_mb", "Worker memory limit (MiB)", 128, 2048),
            ("payload_mb", "Stored candidate byte budget (MiB)", 1, 64),
        ]:
            spin = QSpinBox()
            spin.setRange(low, high)
            spin.setValue(int(getattr(self.limits, key)))
            form.addRow(title, spin)
            self.limit_fields[key] = spin
        box.addLayout(form)
        box.addWidget(
            button("Save settings", self.save_settings, True), alignment=Qt.AlignLeft
        )
        box.addWidget(
            label(
                "Worker memory is checked every 75 ms on Windows; a short overshoot is possible. The time supervisor allows 5 seconds for process startup and cleanup. Candidate storage has a separate byte budget. The UI shows bounded previews.",
                "muted",
            )
        )
        box.addWidget(
            label(
                "Auto mode covers encodings, Caesar, Atbash, reverse and root single-byte XOR. Other attacks are explicit tools. Vigenère and repeating XOR recovery are heuristic. General substitution, arbitrary columnar transposition, strong RSA and unknown-key AES are not automatically solved.",
                "muted",
            )
        )
        box.addStretch()
        return w

    def save_settings(self):
        try:
            self.limits = Limits(
                **{k: w.value() for k, w in self.limit_fields.items()}
            ).validate()
            self.settings_path.write_text(
                json.dumps(asdict(self.limits), indent=2), encoding="utf-8"
            )
            self.state.setText(
                "Settings saved · portable settings file beside the application"
            )
        except (ValueError, OSError) as exc:
            self.error(str(exc))

    def navigate(self, row):
        self.pages.setCurrentIndex(0 if row <= 1 else row - 1)
        if 0 <= row <= 1:
            self.workbench_heading.setText(self.nav.item(row).text())
        self.output_area.setVisible(row not in (10, 11))
        if row in (10, 11):
            self.main_split.setSizes([800, 0])
        else:
            self.main_split.setSizes([450, 340] if 2 <= row <= 8 else [320, 390])

    def input_changed(self):
        self.opened_data = None
        self.source_label.setText("UTF-8 text")
        self.stats[0].setText(f"{len(self.input.toPlainText().encode()):,}")

    def clear(self):
        self.input.clear()
        self.opened_data = None
        self.result = None
        self.table.setRowCount(0)
        self.preview.clear()
        self.detection.clear()
        self.steps.clear()
        self.explanation.clear()
        self.result_summary.setText("Ready for a new challenge.")
        self.stats[1].setText("0")
        self.stats[2].setText("0")

    def demo(self):
        self.input.setPlainText("UENDUHtiYXNlX2NhbXB9")

    def auto_solve(self):
        self.run_task(
            "auto",
            {
                "data": (
                    self.opened_data
                    if self.opened_data is not None
                    else self.input.toPlainText().encode()
                )
            },
        )

    def open_file(self, checked=False, inspect=False):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open challenge file (never executed)"
        )
        if path:
            self.load_file(path, inspect or self.nav.currentRow() == 9)

    def load_file(self, path, inspect=False):
        try:
            data = read_limited(path, self.limits.input_bytes)
            self.input.blockSignals(True)
            try:
                self.input.setPlainText(data.decode("utf-8"))
            except UnicodeError:
                self.input.setPlainText(
                    "BINARY FILE — hex preview (first 512 bytes)\n"
                    + data[:512].hex(" ")
                )
            self.input.blockSignals(False)
            self.opened_data = data
            self.opened_name = Path(path).name
            self.source_label.setText(f"{self.opened_name} · raw bytes")
            self.stats[0].setText(f"{len(data):,}")
            self.file_label.setText(f"{self.opened_name} · {len(data):,} bytes")
            if inspect:
                self.run_task("file", {"data": data, "name": self.opened_name})
        except (OSError, ValueError) as exc:
            self.error(str(exc))

    def inspect_opened(self):
        if self.opened_data is None:
            self.error("Open or drop a file first.")
            return
        self.run_task("file", {"data": self.opened_data, "name": self.opened_name})

    def run_task(self, kind, values):
        if self.task:
            self.error("An operation is running. Cancel it or wait for the result.")
            return
        try:
            self.task = Task(kind, values, self.limits)
            self.task_kind = kind
            self.result = None
            self.last_error = ""
            self.table.setRowCount(0)
            self.preview.setPlainText("Analyzing…")
            self.steps.clear()
            self.detection.clear()
            self.explanation.clear()
            self.progress.setRange(0, 0)
            self.state.setText("Analyzing locally · worker process is running")
            self.cancel_button.setEnabled(True)
            self.solve_button.setEnabled(False)
            self.timer.start()
        except (OSError, ValueError) as exc:
            self.task = None
            self.error(str(exc))

    def cancel(self):
        if self.task:
            self.task.cancel()
            self.state.setText("Cancelling analysis…")

    def poll(self):
        if not self.task:
            return
        for kind, value in self.task.poll():
            if kind == "progress":
                self.state.setText(
                    f'Analyzing · {value["examined"]} visited · {value["queued"]} queued · {value["flags"]} flag candidates'
                )
            else:
                self.task = None
                self.timer.stop()
                self.progress.setRange(0, 100)
                self.progress.setValue(100 if kind == "result" else 0)
                self.cancel_button.setEnabled(False)
                self.solve_button.setEnabled(True)
                if kind == "result":
                    self.show_result(value)
                    self.state.setText("Finished · results are ready to inspect")
                else:
                    self.last_error = value
                    self.state.setText(value)
                    self.preview.setPlainText(value)
                    self.table.hide()
                    self.result_summary.setText(
                        "Operation stopped or invalid input. No plaintext result was accepted."
                    )
                    self.tabs.setCurrentIndex(0)

    def show_result(self, value):
        self.result = value
        self.table.setRowCount(0)
        self.tabs.setCurrentIndex(0)
        if "candidates" in value:
            self.stats[1].setText(str(value["generated"]))
            self.stats[2].setText(str(len(value["flags"])))
            self.result_summary.setText(
                value["status"]
                + f'  {value["generated"]} generated; ranked previews below.'
            )
            rows = value["candidates"]
            self.table.setRowCount(len(rows))
            self.table.show()
            for i, item in enumerate(rows):
                for j, text in enumerate(
                    [
                        " → ".join(item["path"]),
                        item["confidence"],
                        ", ".join(item["flags"]) or "—",
                    ]
                ):
                    self.table.setItem(i, j, QTableWidgetItem(text))
            self.detection.setPlainText(
                "\n\n".join(
                    f'Detected Format: {x["format"]}\nConfidence: {x["confidence"]}\nWhy: {x["reason"]}'
                    for x in value["detections"]
                )
                + f'\n\nByte entropy: {value["entropy"]} bits/byte. Confidence labels are not measured probabilities.'
            )
            if rows:
                self.table.selectRow(0)
        else:
            self.table.hide()
            self.preview.setPlainText(
                value.get("output", json.dumps(value, indent=2, ensure_ascii=False))
            )
            self.result_summary.setText(
                value.get("title", "File inspection")
                + " · Possible flags: "
                + (", ".join(value.get("flags", [])) or "none found")
            )
            self.steps.setPlainText(
                "\n".join(f"{i+1}. {s}" for i, s in enumerate(value.get("steps", [])))
                or "File bytes, signatures and bounded archive entries were inspected in memory."
            )
            self.explanation.setPlainText(
                value.get("explanation", value.get("note", ""))
                + "\n\nNext Suggested Action\nInspect the output and verify it against the challenge. Use the Learning Guide for examples and limits."
            )
            self.detection.setPlainText(
                json.dumps(value.get("detections", []), indent=2, ensure_ascii=False)
            )

    def select_candidate(self):
        row = self.table.currentRow()
        if not self.result or "candidates" not in self.result or row < 0:
            return
        x = self.result["candidates"][row]
        self.preview.setPlainText(x["output"])
        self.steps.setPlainText(
            "Input\n"
            + "\n".join(f"{i+1}. {s}" for i, s in enumerate(x["path"]))
            + f'\n\nReadability rank score: {x["rank_score"]} (not probability).\nOutput bytes: {x["bytes"]}. Preview capped at 4,000 bytes.'
        )
        self.explanation.setPlainText(
            self.result["explanation"]
            + "\n\nNext Suggested Action\n"
            + (
                "Verify the possible flag against the challenge; a matching shape is not proof."
                if x["flags"]
                else "Inspect intermediate results. Try a dedicated cipher tool with the challenge’s clues or supplied parameters."
            )
        )

    def copy_result(self):
        QApplication.clipboard().setText(self.preview.toPlainText())
        self.state.setText("Current result preview copied")

    def save_result(self):
        if self.result is None:
            self.error("Run an analysis first.")
            return
        path, kind = QFileDialog.getSaveFileName(
            self,
            "Save analysis / extracted printable strings",
            "GhostCipher-analysis.json",
            "JSON report (*.json);;Readable text (*.txt)",
        )
        if not path:
            return
        try:
            text = (
                json.dumps(self.result, indent=2, ensure_ascii=False)
                if path.lower().endswith(".json")
                else self.preview.toPlainText()
                + "\n\nDECODING STEPS\n"
                + self.steps.toPlainText()
                + "\n\nEXPLANATION\n"
                + self.explanation.toPlainText()
            )
            Path(path).write_text(text, encoding="utf-8")
            self.state.setText("Results saved locally")
        except OSError as exc:
            self.error(str(exc))

    def error(self, message):
        QMessageBox.warning(self, APP_NAME, message)

    def dragEnterEvent(self, event):
        if (
            event.mimeData().hasUrls()
            and len(event.mimeData().urls()) == 1
            and event.mimeData().urls()[0].isLocalFile()
        ):
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile():
            self.load_file(urls[0].toLocalFile(), self.nav.currentRow() == 9)
            event.acceptProposedAction()

    def closeEvent(self, event):
        if self.task:
            self.task.stop()
            self.task = None
        super().closeEvent(event)


def launch():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setPalette(workbench_palette())
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    if "--smoke-test" in sys.argv:
        from .selftest import cases

        index = sys.argv.index("--smoke-test")
        target = Path(sys.argv[index + 1])
        ticks = [0]
        started = [False]
        checks = []
        suite = cases()
        position = [0]
        heartbeat = QTimer()
        heartbeat.setInterval(25)
        heartbeat.timeout.connect(lambda: ticks.__setitem__(0, ticks[0] + 1))
        heartbeat.start()

        def smoke():
            if not started[0]:
                name, kind, values, expected = suite[position[0]]
                if name == "Base64":
                    window.demo()
                window.run_task(kind, values)
                started[0] = True
                return
            if window.task:
                return
            name, kind, values, (field, expected) = suite[position[0]]
            if field == "error":
                good = window.result is None and expected in window.last_error
            elif field == "output_contains":
                good = window.result is not None and expected in window.result.get(
                    "output", ""
                )
            elif field == "flags":
                good = window.result is not None and expected in window.result.get(
                    "flags", []
                )
            else:
                good = (
                    window.result is not None and window.result.get(field) == expected
                )
            checks.append(
                {
                    "case": name,
                    "success": good,
                    "error": getattr(window, "last_error", ""),
                }
            )
            position[0] += 1
            started[0] = False
            if position[0] < len(suite):
                return
            target.parent.mkdir(parents=True, exist_ok=True)
            window.grab().save(str(target.with_suffix(".png")))
            good = all(x["success"] for x in checks) and ticks[0] > 5
            target.write_text(
                json.dumps(
                    {
                        "success": good,
                        "checks": checks,
                        "heartbeat_ticks": ticks[0],
                        "flags": (
                            window.result.get("flags", []) if window.result else []
                        ),
                        "qt_version": __import__("PySide6").__version__,
                    },
                    indent=2,
                )
            )
            window.close()
            app.exit(0 if good else 1)

        timer = QTimer()
        timer.setInterval(200)
        timer.timeout.connect(smoke)
        timer.start()
        QTimer.singleShot(120000, lambda: app.exit(2))
    return app.exec()
