-- 0002_spend_ledger_index: the daily-sum query runs while SpendInterceptor
-- holds the BEGIN IMMEDIATE write lock; without an index it full-scans the
-- ledger under that lock. (card_id, ts) matches the query's WHERE clause.

CREATE INDEX idx_spend_ledger_card_ts ON spend_ledger (card_id, ts);
