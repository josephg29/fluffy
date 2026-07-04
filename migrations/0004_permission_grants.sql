-- 0004_permission_grants: FLUF-4 columns the permission broker needs on the
-- FLUF-1 permissions table.
--
--   duration    -- 'once' | 'persistent' (D7 request model)
--   consumed_ts -- NULL while the grant is live; set when a 'once' grant is
--                  consumed (inside the same spend transaction that used it,
--                  or by the first allowed call to a restricted tool)
--
-- Active-grant lookups filter on (kind, subject) and always carry the
-- live-grant predicate, so the index is partial on consumed_ts IS NULL:
-- consumed once-rows drop out of it instead of accumulating in the range
-- scan forever.

ALTER TABLE permissions ADD COLUMN duration TEXT DEFAULT 'persistent';
ALTER TABLE permissions ADD COLUMN consumed_ts TEXT;

CREATE INDEX idx_permissions_live_kind_subject ON permissions (kind, subject)
    WHERE consumed_ts IS NULL;
