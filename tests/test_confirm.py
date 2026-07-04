"""FLUF-3 confirmation gate tests (decision D6)."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from conftest import destructive_meta, events, seed_whitelist
from fluffy import ConfirmationRequired, DestructiveSpec, Guard, GuardConfigError, ToolMeta
from fluffy.confirm import PHRASE_FORMAT
from fluffy.db import connect, default_migrations_dir, migrate


class Spy:
    """A destructive tool that records every real execution."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append((args, kwargs))
        return f"deleted {args[0]}"


@pytest.fixture()
def spy() -> Spy:
    return Spy()


@pytest.fixture()
def delete_project(guard: Guard, spy: Spy) -> Any:
    return guard.wrap(spy, meta=destructive_meta())


def raise_challenge(tool: Any, *args: Any, **kwargs: Any) -> ConfirmationRequired:
    with pytest.raises(ConfirmationRequired) as excinfo:
        tool(*args, **kwargs)
    return excinfo.value


# ------------------------------------------------------------- happy path


def test_first_call_challenges_then_confirmed_retry_runs_exactly_once(
    guard: Guard, spy: Spy, delete_project: Any
) -> None:
    exc = raise_challenge(delete_project, "my-project")
    assert "my-project" in exc.summary
    assert "cannot be undone" in exc.summary
    assert exc.phrase_format == PHRASE_FORMAT
    assert exc.payload == {
        "challenge_id": exc.challenge_id,
        "summary": exc.summary,
        "phrase_format": PHRASE_FORMAT,
    }
    assert spy.calls == []  # blocked before the tool ran

    # The human channel: host reads the phrase and the user types it back.
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert phrase.startswith("DELETE ") and len(phrase) == len("DELETE 00")
    assert guard.confirm(exc.challenge_id, phrase) is True

    result = delete_project("my-project", fluffy_challenge_id=exc.challenge_id)
    assert result == "deleted my-project"
    assert len(spy.calls) == 1
    # The tool never sees the control kwarg.
    assert spy.calls[0] == (("my-project",), {})
    assert ("challenge_created", "blocked") in events(guard)
    assert ("confirm_ok", "ok") in events(guard)


def test_confirm_accepts_surrounding_whitespace_but_is_case_sensitive(
    guard: Guard, delete_project: Any
) -> None:
    exc = raise_challenge(delete_project, "p")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert guard.confirm(exc.challenge_id, phrase.lower()) is False  # case-sensitive
    assert guard.confirm(exc.challenge_id, f"  {phrase}  \n") is True  # stripped


# ------------------------------------------------------- wrong phrase / void


def test_three_wrong_phrases_void_challenge_and_tool_never_runs(
    guard: Guard, spy: Spy, delete_project: Any
) -> None:
    exc = raise_challenge(delete_project, "my-project")
    phrase = guard.challenge_phrase(exc.challenge_id)
    for _ in range(3):
        assert guard.confirm(exc.challenge_id, "DELETE XX") is False
    # Voided: even the correct phrase is now refused.
    assert guard.confirm(exc.challenge_id, phrase) is False
    assert spy.calls == []

    # Retrying with the voided challenge raises a fresh challenge.
    exc2 = raise_challenge(delete_project, "my-project", fluffy_challenge_id=exc.challenge_id)
    assert exc2.challenge_id != exc.challenge_id
    assert spy.calls == []

    evs = events(guard)
    assert evs.count(("confirm_failed", "failed")) == 4  # 3 wrong + 1 against voided
    assert ("challenge_voided", "voided") in evs


def test_unknown_challenge_id_returns_false(guard: Guard) -> None:
    assert guard.confirm("no-such-challenge", "DELETE 00") is False


# ----------------------------------------------------------------- expiry


def test_expired_challenge_confirm_false_and_retry_issues_fresh_nonce(
    guard: Guard, spy: Spy, delete_project: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic nonces: first challenge gets 07, the fresh one gets 42 —
    # no 1-in-100 same-nonce flake.
    nonces = iter([7, 42])
    monkeypatch.setattr("fluffy.confirm.secrets.randbelow", lambda n: next(nonces))

    t0 = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    guard._confirm.now_fn = lambda: t0
    exc = raise_challenge(delete_project, "my-project")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert phrase == "DELETE 07"

    # 6 minutes later: past the 5-minute TTL.
    guard._confirm.now_fn = lambda: t0 + timedelta(minutes=6)
    assert guard.confirm(exc.challenge_id, phrase) is False
    assert ("confirm_failed", "failed") in events(guard)

    exc2 = raise_challenge(delete_project, "my-project", fluffy_challenge_id=exc.challenge_id)
    assert exc2.challenge_id != exc.challenge_id
    assert guard.challenge_phrase(exc2.challenge_id) == "DELETE 42"
    assert spy.calls == []


def test_confirmed_but_expired_challenge_cannot_be_consumed(
    guard: Guard, spy: Spy, delete_project: Any
) -> None:
    t0 = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    guard._confirm.now_fn = lambda: t0
    exc = raise_challenge(delete_project, "p")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert guard.confirm(exc.challenge_id, phrase) is True

    guard._confirm.now_fn = lambda: t0 + timedelta(minutes=6)
    exc2 = raise_challenge(delete_project, "p", fluffy_challenge_id=exc.challenge_id)
    assert exc2.challenge_id != exc.challenge_id
    assert spy.calls == []


# ------------------------------------------------------------- single-use


def test_challenge_is_single_use(guard: Guard, spy: Spy, delete_project: Any) -> None:
    exc = raise_challenge(delete_project, "my-project")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert guard.confirm(exc.challenge_id, phrase) is True
    delete_project("my-project", fluffy_challenge_id=exc.challenge_id)
    assert len(spy.calls) == 1

    # Reuse after success: blocked with a fresh challenge, no second run.
    exc2 = raise_challenge(delete_project, "my-project", fluffy_challenge_id=exc.challenge_id)
    assert exc2.challenge_id != exc.challenge_id
    assert len(spy.calls) == 1
    # confirm() against the used challenge also refuses.
    assert guard.confirm(exc.challenge_id, phrase) is False


def test_challenge_for_one_tool_cannot_confirm_another(guard: Guard) -> None:
    spy_a, spy_b = Spy(), Spy()
    tool_a: Any = guard.wrap(spy_a, meta=destructive_meta(name="delete_project"))
    tool_b: Any = guard.wrap(spy_b, meta=destructive_meta(name="delete_backup"))
    exc = raise_challenge(tool_a, "p")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert guard.confirm(exc.challenge_id, phrase) is True
    # tool_b can't spend tool_a's confirmation.
    raise_challenge(tool_b, "p", fluffy_challenge_id=exc.challenge_id)
    assert spy_b.calls == []
    # tool_a still can.
    tool_a("p", fluffy_challenge_id=exc.challenge_id)
    assert len(spy_a.calls) == 1


# -------------------------------------------------------------- remember


def test_remember_whitelists_same_resource_kind_only(guard: Guard) -> None:
    spy_repo, spy_repo2, spy_db = Spy(), Spy(), Spy()
    del_repo: Any = guard.wrap(spy_repo, meta=destructive_meta(resource_kind="repo"))
    exc = raise_challenge(del_repo, "my-project")
    phrase = guard.challenge_phrase(exc.challenge_id)
    assert guard.confirm(exc.challenge_id, phrase, remember=True) is True

    # Same (tool, resource_kind): gate-free, audited as whitelisted — no
    # challenge id needed, not even for a brand-new wrapped instance.
    assert del_repo("other-project") == "deleted other-project"
    del_repo2: Any = guard.wrap(spy_repo2, meta=destructive_meta(resource_kind="repo"))
    assert del_repo2("third-project") == "deleted third-project"
    assert ("whitelisted", "ok") in events(guard)

    # Same tool name, different resource_kind: still challenges.
    del_db: Any = guard.wrap(spy_db, meta=destructive_meta(resource_kind="database"))
    raise_challenge(del_db, "prod-db")
    assert spy_db.calls == []

    rows = guard.connection.execute("SELECT tool, resource_kind FROM action_whitelist").fetchall()
    assert [(r["tool"], r["resource_kind"]) for r in rows] == [("delete_project", "repo")]


def test_whitelist_persists_across_guard_restart(tmp_path: Any) -> None:
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path) as g1:
        tool: Any = g1.wrap(Spy(), meta=destructive_meta())
        exc = raise_challenge(tool, "p")
        assert (
            g1.confirm(exc.challenge_id, g1.challenge_phrase(exc.challenge_id), remember=True)
            is True
        )
    with Guard(db_path=db_path) as g2:
        tool2: Any = g2.wrap(Spy(), meta=destructive_meta())
        assert tool2("p") == "deleted p"


# ------------------------------------------------------- wrap-time safety net


@pytest.mark.parametrize(
    "name",
    [
        "drop_database",
        "delete_project",
        "destroy-vm",
        "remove_user",
        "truncate_table",
        "db.migrate",
        "fs.remove",
    ],
)
def test_destructive_looking_name_without_spec_fails_at_wrap_time(guard: Guard, name: str) -> None:
    with pytest.raises(GuardConfigError, match="looks destructive"):
        guard.wrap(lambda: "boom", meta=ToolMeta(name=name))


@pytest.mark.parametrize("name", ["list_projects", "dropbox.upload", "undelete", "migrations"])
def test_benign_names_wrap_fine(guard: Guard, name: str) -> None:
    wrapped: Any = guard.wrap(lambda: "ok", meta=ToolMeta(name=name))
    assert wrapped() == "ok"


def test_whitelisted_tool_name_escapes_wrap_time_safety_net(guard: Guard) -> None:
    seed_whitelist(guard.connection, "drop_database", "database")
    wrapped: Any = guard.wrap(lambda: "ok", meta=ToolMeta(name="drop_database"))
    assert wrapped() == "ok"


def test_spec_without_destructive_tag_fails_at_wrap_time(guard: Guard) -> None:
    meta = ToolMeta(
        name="wipe",
        destructive=DestructiveSpec(resource_kind="disk", summary_from=lambda a, k: "wipes"),
    )
    with pytest.raises(GuardConfigError, match="not tagged"):
        guard.wrap(lambda: "boom", meta=meta)


def test_destructive_tag_without_spec_fails_at_wrap_time(guard: Guard) -> None:
    meta = ToolMeta(name="obliterate", tags=frozenset({"destructive"}))
    with pytest.raises(GuardConfigError, match="no DestructiveSpec"):
        guard.wrap(lambda: "boom", meta=meta)


# ------------------------------------------------------------------- audit


def test_all_five_confirm_events_appear(guard: Guard, delete_project: Any) -> None:
    # whitelisted + confirm_ok
    exc = raise_challenge(delete_project, "p1")
    guard.confirm(exc.challenge_id, guard.challenge_phrase(exc.challenge_id), remember=True)
    delete_project("p1")  # whitelisted

    # confirm_failed + challenge_voided on a different resource kind
    other: Any = guard.wrap(Spy(), meta=destructive_meta(resource_kind="database"))
    exc2 = raise_challenge(other, "p2")
    for _ in range(3):
        guard.confirm(exc2.challenge_id, "DELETE XX")

    seen = {event for event, _ in events(guard)}
    assert {
        "challenge_created",
        "confirm_ok",
        "confirm_failed",
        "challenge_voided",
        "whitelisted",
    } <= seen


def test_audit_rows_never_contain_the_phrase(guard: Guard, delete_project: Any) -> None:
    exc = raise_challenge(delete_project, "p")
    phrase = guard.challenge_phrase(exc.challenge_id)
    guard.confirm(exc.challenge_id, phrase)
    for row in guard.audit_tail(50):
        assert phrase not in (row["detail_json"] or "")


# ------------------------------------------------------------------- async


async def test_async_destructive_tool_challenges_and_runs(guard: Guard) -> None:
    ran: list[str] = []

    async def delete_project(project: str) -> str:
        ran.append(project)
        return f"deleted {project}"

    wrapped: Any = guard.wrap(delete_project, meta=destructive_meta())
    with pytest.raises(ConfirmationRequired) as excinfo:
        await wrapped("p")
    exc = excinfo.value
    assert guard.confirm(exc.challenge_id, guard.challenge_phrase(exc.challenge_id))
    assert await wrapped("p", fluffy_challenge_id=exc.challenge_id) == "deleted p"
    assert ran == ["p"]


# --------------------------------------------------------------- migrations


def test_migration_0003_extends_existing_pre_fluf3_database(tmp_path: Any) -> None:
    """A DB created by the *real* 0001+0002 migrations gains 0003 on Guard init."""
    db_path = tmp_path / "state.db"
    pre_fluf3 = tmp_path / "migrations"
    pre_fluf3.mkdir()
    src = default_migrations_dir()
    for name in ("0001_init.sql", "0002_spend_ledger_index.sql"):
        shutil.copy(src / name, pre_fluf3 / name)

    conn = connect(db_path)
    assert migrate(conn, pre_fluf3) == [1, 2]
    conn.close()

    with Guard(db_path=db_path) as g:  # applies 0003
        cols = {row[1] for row in g.connection.execute("PRAGMA table_info(confirmations)")}
        assert {"tool", "resource_kind", "attempts", "state"} <= cols
        versions = [r[0] for r in g.connection.execute("SELECT version FROM schema_version")]
        assert 3 in versions


# ------------------------------------------------------------------ cleanup


def test_expired_unused_challenges_are_swept_on_next_challenge_creation(
    guard: Guard, delete_project: Any
) -> None:
    t0 = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    guard._confirm.now_fn = lambda: t0
    exc = raise_challenge(delete_project, "old")

    # 6 minutes later (past the 5-minute TTL) a new challenge sweeps the
    # expired, never-used row; the fresh row remains.
    guard._confirm.now_fn = lambda: t0 + timedelta(minutes=6)
    exc2 = raise_challenge(delete_project, "new")
    ids = {
        row["challenge_id"]
        for row in guard.connection.execute("SELECT challenge_id FROM confirmations")
    }
    assert exc.challenge_id not in ids
    assert exc2.challenge_id in ids
