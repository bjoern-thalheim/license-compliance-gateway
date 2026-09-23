from __future__ import annotations

import pytest

from lcg import licenses


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("MIT", "MIT"),
        ("Apache 2.0", "Apache-2.0"),
        ("apache2", "Apache-2.0"),
        ("mit license", "MIT"),
        ("MIT OR Apache-2.0", "MIT OR Apache-2.0"),
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert licenses.normalize(raw) == expected


def test_is_choice() -> None:
    assert licenses.is_choice("MIT OR Apache-2.0")
    assert licenses.is_choice("(MIT OR Apache-2.0) AND BSD-3-Clause")
    assert not licenses.is_choice("MIT AND BSD-3-Clause")
    assert not licenses.is_choice("MIT")


def test_license_ids_of_conjunction() -> None:
    assert licenses.conjunctive_ids("MIT AND BSD-3-Clause") == ["MIT", "BSD-3-Clause"]


def test_empty_expression_is_empty() -> None:
    assert licenses.normalize("   ") == ""
