-- Keep the previously allocated schema version without importing accounting history.
INSERT INTO ledger.schema_version(version) VALUES (4);
