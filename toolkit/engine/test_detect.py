"""Tests for detect.py stack detection:  python toolkit/engine/test_detect.py"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _detect(files: dict) -> dict:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "proj"
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        out = Path(d) / "profile.json"
        subprocess.run([sys.executable, str(HERE / "detect.py"), str(root), "--out", str(out)], check=True, capture_output=True)
        return json.loads(out.read_text(encoding="utf-8"))


def test_flask_project_with_a_stray_manage_py_is_still_flask():
    """`A and B or C` precedence: any manage.py anywhere used to turn an already detected Flask app into Django."""
    prof = _detect({"app.py": "from flask import Flask\napp = Flask(__name__)\n", "tools/manage.py": "print('x')\n"})
    assert prof["framework"] == "flask", prof["framework"]


def test_real_django_project_is_detected():
    prof = _detect({"manage.py": "print('django')\n", "requirements.txt": "django\n"})
    assert prof["framework"] == "django" and prof["language"] == "python"


def test_fastapi_project_is_fastapi():
    prof = _detect({"main.py": "from fastapi import FastAPI\napp = FastAPI()\n", "requirements.txt": "fastapi\nuvicorn\n"})
    assert prof["framework"] == "fastapi" and "uvicorn" in prof["run_cmd"]


def test_unknown_project_writes_unknown_not_a_guess():
    prof = _detect({"README.md": "nothing here\n"})
    assert prof["run_cmd"] == "unknown" and "run_cmd" in prof["unknown"]


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print("FAIL", name, "-", type(exc).__name__, exc)
    sys.exit(1 if failed else 0)
