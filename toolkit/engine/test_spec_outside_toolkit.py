"""A qa-spec.py copied out of the toolkit folder still loads through run.py (docs/USING.md step 2.3 relies on it): the demo spec's
`from scenarios_lib import ...` resolves because run.py puts the engine folder on sys.path before it loads the spec.

The base URL points at a closed local port, so setup() fails; the point is that the LOAD succeeded first.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parent
DEMO_SPEC = ENGINE.parent / "examples" / "demo-flask-shop" / "qa-spec.py"


def test_demo_spec_loads_from_another_folder(tmp_path):
    spec = tmp_path / "my-api" / "qa-spec.py"
    spec.parent.mkdir()
    shutil.copy(DEMO_SPEC, spec)
    out = tmp_path / "out"
    p = subprocess.run([sys.executable, str(ENGINE / "run.py"), "--base-url", "http://127.0.0.1:1", "--spec", str(spec),
                        "--openapi", str(DEMO_SPEC.parent / "openapi.json"), "--out", str(out)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    rows = json.loads((out / "engines.json").read_text(encoding="utf-8"))
    errors = " ".join(r.get("engine-error", "") for r in rows)
    assert "qa-spec load failed" not in errors, p.stdout[-2000:]
    assert "setup() failed" in errors, "the run must get past loading the spec and fail only at setup() (closed port)"
