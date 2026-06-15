"""Target type detection."""

from __future__ import annotations

import pytest

from mitiphy.core.target import Target, TargetType, detect_type


@pytest.mark.parametrize(
    "value,expected",
    [
        ("user@example.com", TargetType.EMAIL),
        ("USER+tag@sub.example.co.uk", TargetType.EMAIL),
        ("example.com", TargetType.DOMAIN),
        ("sub.example.co.uk", TargetType.DOMAIN),
        ("1.2.3.4", TargetType.IP),
        ("2001:db8::1", TargetType.IP),
        ("https://example.com/path?q=1", TargetType.URL),
        ("http://x.io", TargetType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", TargetType.HASH_MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", TargetType.HASH_SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            TargetType.HASH_SHA256,
        ),
        ("+1 (555) 234-5678", TargetType.PHONE),
        ("+919876543210", TargetType.PHONE),
        ("akashshrivastava", TargetType.USERNAME),
        ("john_doe-91", TargetType.USERNAME),
        ("Alice Smith", TargetType.PERSON),
        ("", TargetType.UNKNOWN),
        ("    ", TargetType.UNKNOWN),
    ],
)
def test_detect_type(value: str, expected: TargetType) -> None:
    assert detect_type(value) == expected, f"failed for {value!r}"


def test_from_string_strips_and_records_raw() -> None:
    t = Target.from_string("  user@example.com  ")
    assert t.value == "user@example.com"
    assert t.raw == "  user@example.com  "
    assert t.type == TargetType.EMAIL


def test_person_consent_flags() -> None:
    assert Target.from_string("Alice Smith").is_person
    assert Target.from_string("user@example.com").is_person
    assert Target.from_string("+15552345678").is_person
    assert not Target.from_string("example.com").is_person
    assert not Target.from_string("1.2.3.4").is_person


def test_priority_hash_over_username() -> None:
    # 32-hex string is a plausible username but must resolve to MD5.
    assert detect_type("a" * 32) == TargetType.HASH_MD5


def test_url_priority_over_domain() -> None:
    assert detect_type("https://x.io") == TargetType.URL
    assert detect_type("x.io") == TargetType.DOMAIN


def test_target_to_dict_roundtrip() -> None:
    t = Target.from_string("1.2.3.4")
    d = t.to_dict()
    assert d["value"] == "1.2.3.4"
    assert d["type"] == "ip"
