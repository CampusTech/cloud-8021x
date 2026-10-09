-- Original incomplete legacy scan credit floor. Runtime may read it but cannot
-- create, replace, or delete migration evidence. It is not a native spool cursor.
CREATE TABLE ledger.legacy_usage_floor (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  transition text NOT NULL CHECK (transition ~ '^[0-9a-f]{64}$'),
  credit_start text NOT NULL
);
ALTER TABLE ledger.sessions ADD COLUMN native_baseline_required boolean NOT NULL DEFAULT true;
INSERT INTO ledger.schema_version(version) VALUES (4);
