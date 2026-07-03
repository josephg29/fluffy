-- 0001_init: full D3 schema. All five tables are owned by FLUF-1 even though
-- later tickets populate most of them.

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    call_id     TEXT,
    ts          TEXT,
    tool        TEXT,
    event       TEXT,
    decision    TEXT,
    detail_json TEXT  -- post-redaction, always
);

CREATE TABLE IF NOT EXISTS spend_ledger (
    id           INTEGER PRIMARY KEY,
    card_id      TEXT,
    ts           TEXT,
    amount_cents INTEGER,
    state        TEXT CHECK (state IN ('reserved', 'settled', 'released')),
    call_id      TEXT
);

CREATE TABLE IF NOT EXISTS confirmations (
    challenge_id TEXT PRIMARY KEY,
    call_id      TEXT,
    phrase       TEXT,
    summary      TEXT,
    created_ts   TEXT,
    expires_ts   TEXT,
    used         INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS action_whitelist (
    tool          TEXT,
    resource_kind TEXT,
    added_ts      TEXT,
    PRIMARY KEY (tool, resource_kind)
);

CREATE TABLE IF NOT EXISTS permissions (
    id         INTEGER PRIMARY KEY,
    kind       TEXT,
    subject    TEXT,
    value_json TEXT,
    granted_ts TEXT,
    expires_ts TEXT,
    decider    TEXT
);
