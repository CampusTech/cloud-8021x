-- Optional display metadata; existing raw rows and immutable ledger payloads stay unchanged.
ALTER TABLE ledger.intake ADD COLUMN terminate_cause text,
 ADD COLUMN terminate_cause_count integer NOT NULL DEFAULT 0 CHECK (terminate_cause_count >= 0);
INSERT INTO ledger.schema_version(version) VALUES (3);
