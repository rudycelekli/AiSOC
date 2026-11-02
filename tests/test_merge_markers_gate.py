"""`scripts/check_merge_markers.py` must read every tracked file it lists.

`tracked_files` ran `git ls-files` without `-z`, so a path with a non-ASCII
byte came back C-quoted (`"docs/r\\303\\251sum\\303\\251.md"`). That string
names no file, `scan` skipped it as unreadable, and a conflict marker in it
passed the gate.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_merge_markers.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_merge_markers", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def test_a_conflict_marker_in_a_non_ascii_path_is_found(tmp_path: Path) -> None:
    rel = "docs/r\u00e9sum\u00e9.md"
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_text("intro\n" + "<" * 7 + " HEAD\nours\n" + "=" * 7 + "\ntheirs\n" + ">" * 7 + " feature\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)

    assert gate.tracked_files(tmp_path) == [rel]
    findings, read, _subject = gate.scan(tmp_path)
    assert read == 1
    assert any(rel in finding for finding in findings), findings
