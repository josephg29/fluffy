"""Redaction test suite — written BEFORE redact.py per the FLUF-1 ticket.

Covers:
- raw card 4242 4242 4242 4242
- dashed card
- Luhn-invalid 16 digits (must NOT be redacted)
- sk- / ghp_ / AKIA API keys
- a registered secret appearing raw / URL-encoded / base64 in a log line
- secret in exception traceback text
"""

from __future__ import annotations

import base64
import logging
import urllib.parse

import pytest

from fluffy.redact import RedactionFilter, redact
from fluffy.secrets import MemorySecretStore

SECRET_VALUE = "p@ss w0rd/+with$special=chars"


@pytest.fixture()
def store(registered_store: MemorySecretStore) -> MemorySecretStore:
    registered_store.put("db_password", SECRET_VALUE)
    return registered_store


# ---------------------------------------------------------------- card numbers


def test_raw_card_with_spaces_is_redacted() -> None:
    out = redact("charging card 4242 4242 4242 4242 now")
    assert "4242 4242 4242 4242" not in out
    assert "[REDACTED:card]" in out


def test_dashed_card_is_redacted() -> None:
    out = redact("card: 4242-4242-4242-4242")
    assert "4242-4242-4242-4242" not in out
    assert "[REDACTED:card]" in out


def test_plain_card_no_separators_is_redacted() -> None:
    out = redact("pan=4111111111111111")
    assert "4111111111111111" not in out
    assert "[REDACTED:card]" in out


def test_luhn_invalid_16_digits_not_redacted() -> None:
    # 4242 4242 4242 4243 fails the Luhn check — must survive untouched.
    text = "order id 4242 4242 4242 4243 confirmed"
    assert redact(text) == text


# ------------------------------------------------------------------- API keys


def test_sk_key_redacted() -> None:
    out = redact("key=sk-AbCdEf1234567890AbCdEf1234567890")
    assert "sk-AbCdEf1234567890AbCdEf1234567890" not in out
    assert "[REDACTED:key]" in out


def test_sk_live_key_redacted() -> None:
    # Built at runtime so secret scanners don't flag a literal in the source.
    key = "sk_live_" + "AbCdEf1234567890AbCdEf12"
    out = redact(f"stripe {key}")
    assert key not in out
    assert "[REDACTED:key]" in out


def test_ghp_key_redacted() -> None:
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    out = redact(f"github token {token}")
    assert token not in out
    assert "[REDACTED:key]" in out


def test_akia_key_redacted() -> None:
    out = redact("aws AKIAIOSFODNN7EXAMPLE key")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:key]" in out


def test_high_entropy_token_redacted() -> None:
    token = "zX9kQ2mP7vR4tY8wB3nJ6hL1cF5dG0sA+/eU"
    out = redact(f"bearer {token}")
    assert token not in out


def test_ordinary_prose_untouched() -> None:
    text = "the quick brown fox jumps over the lazy dog 12345"
    assert redact(text) == text


# ---------------------------------------------------- registered secret values


def test_registered_secret_raw_replaced_with_handle(store: MemorySecretStore) -> None:
    out = redact(f"connecting with {SECRET_VALUE} now")
    assert SECRET_VALUE not in out
    assert "{{secret:db_password}}" in out


def test_registered_secret_url_encoded_replaced(store: MemorySecretStore) -> None:
    encoded = urllib.parse.quote(SECRET_VALUE, safe="")
    assert encoded != SECRET_VALUE
    out = redact(f"GET /login?pw={encoded}")
    assert encoded not in out
    assert "{{secret:db_password}}" in out


def test_registered_secret_base64_replaced(store: MemorySecretStore) -> None:
    encoded = base64.b64encode(SECRET_VALUE.encode()).decode()
    out = redact(f"Authorization: Basic {encoded}")
    assert encoded not in out
    assert "{{secret:db_password}}" in out


# ------------------------------------------------------------- logging filter


def test_secret_in_log_line_scrubbed(
    store: MemorySecretStore, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("test.redact.log")
    logger.addFilter(RedactionFilter())
    try:
        with caplog.at_level(logging.INFO, logger="test.redact.log"):
            logger.info("connecting with password %s", SECRET_VALUE)
    finally:
        logger.filters.clear()
    assert SECRET_VALUE not in caplog.text
    assert "{{secret:db_password}}" in caplog.text


def test_card_in_log_line_scrubbed(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.redact.card")
    logger.addFilter(RedactionFilter())
    try:
        with caplog.at_level(logging.INFO, logger="test.redact.card"):
            logger.info("charging 4242 4242 4242 4242")
    finally:
        logger.filters.clear()
    assert "4242 4242 4242 4242" not in caplog.text
    assert "[REDACTED:card]" in caplog.text


def test_secret_in_exception_traceback_scrubbed(
    store: MemorySecretStore, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("test.redact.exc")
    logger.addFilter(RedactionFilter())
    try:
        with caplog.at_level(logging.ERROR, logger="test.redact.exc"):
            try:
                raise RuntimeError(f"auth failed for {SECRET_VALUE}")
            except RuntimeError:
                logger.exception("boom")
    finally:
        logger.filters.clear()
    assert SECRET_VALUE not in caplog.text
    assert "{{secret:db_password}}" in caplog.text
    # the traceback itself is still present, just scrubbed
    assert "RuntimeError" in caplog.text
