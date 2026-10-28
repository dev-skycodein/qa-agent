"""Where things live, with no machine-specific literal.

QA_HOME         the repo root (default: computed from this file)
QA_TARGETS_DIR  the folder that holds the target clones and kits next to the repo (default: the parent of the repo root)
"""
import os
from pathlib import Path


def home() -> Path:
    env = os.environ.get("QA_HOME")
    return Path(env).resolve() if env else Path(__file__).resolve().parent.parent.parent


def targets_root() -> Path:
    env = os.environ.get("QA_TARGETS_DIR")
    return Path(env).resolve() if env else home().parent
