import json
import time
import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from pcc.gui import MainWindow
from pcc.common import Limits
from pcc.worker import Task, memory_usage


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait_until(app, predicate, seconds=20):
    start = time.monotonic()
    while not predicate() and time.monotonic() - start < seconds:
        app.processEvents()
        QTest.qWait(20)
    assert predicate()


def test_gui_navigation_and_hidden_practice(app, tmp_path):
    w = MainWindow(tmp_path / "settings.json")
    w.show()
    app.processEvents()
    for row in range(12):
        w.nav.setCurrentRow(row)
        app.processEvents()
        assert w.pages.currentIndex() == (0 if row <= 1 else row - 1)
    w.nav.setCurrentRow(10)
    x = w.challenge()
    assert x["answer"] not in w.challenge_view.toPlainText()
    w.reveal()
    assert x["answer"] in w.challenge_view.toPlainText()
    w.search.setText("Vigenère")
    assert w.lesson_list.count() >= 1
    w.save_settings()
    assert json.loads((tmp_path / "settings.json").read_text())["depth"] == 5
    w.close()


def test_gui_live_worker_responsiveness(app, tmp_path):
    w = MainWindow(tmp_path / "settings.json")
    w.show()
    w.demo()
    heartbeats = []
    timer = QTimer()
    timer.setInterval(10)
    timer.timeout.connect(lambda: heartbeats.append(time.monotonic()))
    timer.start()
    w.auto_solve()
    wait_until(app, lambda: w.task is None)
    assert "PCCP{base_camp}" in w.result["flags"]
    assert len(heartbeats) > 10
    w.tabs.setCurrentIndex(2)
    assert "Base64" in w.steps.toPlainText()
    w.nav.setCurrentRow(2)
    tool = w.tools["encoding"]
    tool.text.setPlainText("504343507b6775697d")
    tool.fields["method"].setCurrentText("Hex")
    tool.run()
    wait_until(app, lambda: w.task is None)
    assert w.result["output"] == "PCCP{gui}"
    timer.stop()
    w.close()


def test_gui_file_and_cancel(app, tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"\0PCCP{local_file}\xff")
    w = MainWindow(tmp_path / "settings.json")
    w.show()
    w.nav.setCurrentRow(9)
    w.load_file(path, True)
    wait_until(app, lambda: w.task is None)
    assert w.result["flags"] == ["PCCP{local_file}"]
    w.nav.setCurrentRow(1)
    w.input.setPlainText("ABCDEF" * 1000)
    w.limits = Limits(seconds=60, candidates=5000)
    w.auto_solve()
    w.cancel()
    wait_until(app, lambda: w.task is None, 5)
    assert "Cancel" in w.state.text() or "cancel" in str(w.result)
    w.close()


def test_process_deadline_and_memory_monitor():
    task = Task(
        "advanced", {"operation": "Prime test", "text": '{"n":65537}'}, Limits()
    )
    if __import__("os").name == "nt":
        assert memory_usage(task.process) > 0
    task.start -= 30
    messages = task.poll()
    assert any("time limit" in str(x) for x in messages)
    assert task.finished and not task.process.is_alive()


def test_process_memory_cap(monkeypatch):
    import pcc.worker as worker

    task = Task(
        "advanced", {"operation": "Prime test", "text": '{"n":65537}'}, Limits()
    )
    monkeypatch.setattr(worker, "memory_usage", lambda _: 3 * 1024**3)
    assert any("memory limit" in str(x) for x in task.poll())
    assert task.finished


def test_gcm_failure_clears_old_result(app, tmp_path):
    from pcc.selftest import cases

    w = MainWindow(tmp_path / "settings.json")
    w.show()
    w.demo()
    w.auto_solve()
    wait_until(app, lambda: w.task is None)
    assert w.result["flags"]
    _, kind, values, _ = next(x for x in cases() if x[0] == "AES GCM rejects bad tag")
    w.run_task(kind, values)
    wait_until(app, lambda: w.task is None)
    assert (
        w.result is None
        and "MAC check failed" in w.preview.toPlainText()
        and w.table.rowCount() == 0
    )
    w.close()
