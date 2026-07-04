-- 0003_confirm_state: FLUF-3 challenge lifecycle columns.
--
-- D6 requires an attempt counter (3 strikes voids), a confirmed/voided state,
-- and "remember" whitelisting keyed by (tool, resource_kind) — but
-- guard.confirm() only receives a challenge_id, so the challenge row must
-- carry the tool name and resource kind it was created for. Additive-only
-- extension of the D3 schema via the D3 migration mechanism.

ALTER TABLE confirmations ADD COLUMN tool TEXT;
ALTER TABLE confirmations ADD COLUMN resource_kind TEXT;
ALTER TABLE confirmations ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
-- state: 'pending' -> 'confirmed' (correct phrase) -> consumed via used=1.
-- "Voided" is not a stored state: it is derived from attempts >= 3, so one
-- fact has one representation.
ALTER TABLE confirmations ADD COLUMN state TEXT NOT NULL DEFAULT 'pending';
