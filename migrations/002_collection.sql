-- Public collection payloads remain in the reviewed work/attempt ledger. Scope
-- indexes keep bounded per-host queries independent of accounting/outbox volume.
CREATE INDEX work_collection_recent ON ledger.work ((payload->>'collection_key'),created_at DESC,id)
 WHERE payload ? 'collection_key';
CREATE INDEX work_collection_pending ON ledger.work ((payload->>'collection_key'))
 WHERE payload ? 'collection_key' AND (state!='succeeded' OR receipt->>'pending'='true');
INSERT INTO ledger.schema_version(version) VALUES(2);
