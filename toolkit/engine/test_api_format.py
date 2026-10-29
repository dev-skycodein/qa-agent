"""api.example / api.strategy give values that pass a real validator for each string `format`.

  python -m pytest toolkit/engine/test_api_format.py -q
"""
import datetime
import ipaddress
import re
import sys
import urllib.parse
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402

HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)


def _uri_ok(v):
    u = urllib.parse.urlparse(v)
    return bool(u.scheme and u.netloc)


VALID = {
    "uuid": lambda v: uuid.UUID(v).version == 4 and uuid.UUID(v).variant == uuid.RFC_4122,
    "uri": _uri_ok,
    "date": lambda v: datetime.date.fromisoformat(v).isoformat() == v,
    "date-time": lambda v: datetime.datetime.fromisoformat(v.replace("Z", "+00:00")).tzinfo is not None,
    "email": lambda v: re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v) is not None,
    "ipv4": lambda v: str(ipaddress.IPv4Address(v)) == v,
    "hostname": lambda v: HOSTNAME.match(v) is not None,
}


def _draw(strat):
    from hypothesis import given, settings
    seen = []

    @settings(max_examples=10, database=None)
    @given(strat)
    def run(v):
        seen.append(v)
    run()
    return seen


@pytest.mark.parametrize("fmt", sorted(VALID))
def test_example_gives_valid_value_for_format(fmt):
    v = api.example({"type": "string", "format": fmt}, {})
    assert isinstance(v, str) and VALID[fmt](v), (fmt, v)


@pytest.mark.parametrize("fmt", sorted(VALID))
def test_example_is_deterministic(fmt):
    assert api.example({"type": "string", "format": fmt}, {}) == api.example({"type": "string", "format": fmt}, {})


@pytest.mark.parametrize("fmt", sorted(VALID))
def test_strategy_gives_valid_value_for_format(fmt):
    pytest.importorskip("hypothesis")
    for v in _draw(api.strategy({"type": "string", "format": fmt}, {})):
        assert isinstance(v, str) and VALID[fmt](v), (fmt, v)


def test_format_inside_object_body():
    schema = {"type": "object", "required": ["id", "site"],
              "properties": {"id": {"type": "string", "format": "uuid"}, "site": {"type": "string", "format": "uri"}}}
    body = api.example(schema, {})
    assert VALID["uuid"](body["id"]) and VALID["uri"](body["site"])


def test_example_and_enum_still_win_over_format():
    assert api.example({"type": "string", "format": "uuid", "example": "given"}, {}) == "given"
    assert api.example({"type": "string", "format": "uuid", "enum": ["first", "second"]}, {}) == "first"
    assert api.example({"type": "string", "pattern": "^[A-Z]{3}$", "example": "ABC"}, {}) == "ABC"
    assert api.example({"type": "string", "pattern": "^[A-Z]{3}$", "enum": ["XYZ"]}, {}) == "XYZ"


def test_pattern_only_is_not_honoured_known_limit():
    """Pins the documented limit: a pattern-only string keeps the plain-string value."""
    assert api.example({"type": "string", "pattern": "^[A-Z]{3}$"}, {}) == "qa"


def test_plain_string_length_bounds_unchanged():
    assert api.example({"type": "string"}, {}) == "qa"
    assert api.example({"type": "string", "minLength": 5}, {}) == "qaqaq"
    assert api.example({"type": "string", "maxLength": 1}, {}) == "q"
    assert len(api.example({"type": "string", "minLength": 3, "maxLength": 3}, {})) == 3


def test_unknown_format_falls_back_to_plain_string():
    assert api.example({"type": "string", "format": "binary"}, {}) == "qa"
