CREATE SCHEMA IF NOT EXISTS ledger;
REVOKE ALL ON SCHEMA ledger FROM PUBLIC;
CREATE TABLE ledger.schema_version(version integer PRIMARY KEY, installed_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE DOMAIN ledger.uint64 AS numeric(20,0) CHECK(VALUE >= 0 AND VALUE <= 18446744073709551615);
CREATE TABLE ledger.sessions (
 session_key text PRIMARY KEY, pending boolean NOT NULL DEFAULT true,
 initialized boolean NOT NULL DEFAULT false, duration ledger.uint64 NOT NULL DEFAULT 0,
 upload ledger.uint64 NOT NULL DEFAULT 0, download ledger.uint64 NOT NULL DEFAULT 0,
 bits integer NOT NULL DEFAULT 64 CHECK(bits IN (32,64)), marked boolean NOT NULL DEFAULT true,
 stopped boolean NOT NULL DEFAULT false, last_seen timestamptz, identity jsonb
);
CREATE INDEX sessions_pending ON ledger.sessions(session_key) WHERE pending;
CREATE FUNCTION ledger.session_key(source_ip text,nas_ip text,nas_count integer,station text,station_count integer,session_id text,session_count integer)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN nas_count=1 AND station_count=1 AND session_count=1 AND a<>'' AND b<>'' AND d<>'' AND pg_input_is_valid(a,'inet') AND pg_input_is_valid(b,'inet') AND strpos(a,'/')=0 AND strpos(b,'/')=0 AND strpos(a,'%')=0 AND strpos(b,'%')=0
 AND (strpos(a,':')>0 OR a ~ '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$')
 AND (strpos(b,':')>0 OR b ~ '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$')
 AND octet_length(a)<=64 AND octet_length(b)<=64 AND octet_length(d)<=253 AND c ~ '^[0-9a-f]{12}$'
 THEN octet_length(a)||':'||a||octet_length(b)||':'||b||octet_length(c)||':'||c||octet_length(d)||':'||d END
 FROM (SELECT lower(btrim(source_ip,E' \t\n\r\013\014')) a,lower(btrim(nas_ip,E' \t\n\r\013\014')) b,lower(translate(btrim(station,E' \t\n\r\013\014'),':.-','')) c,btrim(session_id,E' \t\n\r\013\014') d) v
$$;
CREATE TABLE ledger.intake (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 received_at timestamptz NOT NULL, inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 source_ip text NOT NULL, client_id text NOT NULL, location_id text NOT NULL,
 host text NOT NULL, replay_id text NOT NULL,
 status text, status_count integer NOT NULL DEFAULT 0 CHECK(status_count>=0),
 session_id text, session_count integer NOT NULL DEFAULT 0 CHECK(session_count>=0),
 nas_ip text, nas_count integer NOT NULL DEFAULT 0 CHECK(nas_count>=0),
 station text, station_count integer NOT NULL DEFAULT 0 CHECK(station_count>=0),
 class text, class_count integer NOT NULL DEFAULT 0 CHECK(class_count>=0),
 input_octets text, input_octets_count integer NOT NULL DEFAULT 0 CHECK(input_octets_count>=0),
 output_octets text, output_octets_count integer NOT NULL DEFAULT 0 CHECK(output_octets_count>=0),
 input_gigawords text, input_gigawords_count integer NOT NULL DEFAULT 0 CHECK(input_gigawords_count>=0),
 output_gigawords text, output_gigawords_count integer NOT NULL DEFAULT 0 CHECK(output_gigawords_count>=0),
 session_time text, session_time_count integer NOT NULL DEFAULT 0 CHECK(session_time_count>=0),
 event_timestamp text, delay_time text, packet_id text, request_authenticator text,
 called_station text, nas_port text,
 session_key text GENERATED ALWAYS AS (ledger.session_key(source_ip,nas_ip,nas_count,station,station_count,session_id,session_count)) STORED,
 processed_at timestamptz, observation_id text
);
CREATE INDEX intake_pending_session ON ledger.intake(session_key, (CASE WHEN status_count=1 AND status IN ('Start','1') THEN 0 ELSE 1 END),id) WHERE processed_at IS NULL;
CREATE FUNCTION ledger.queue_session() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM pg_catalog.set_config('synchronous_commit','on',true);
 IF NEW.session_key IS NOT NULL THEN
  INSERT INTO ledger.sessions(session_key) VALUES(NEW.session_key)
  ON CONFLICT(session_key) DO UPDATE SET pending=true;
 END IF;
 RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION ledger.queue_session() FROM PUBLIC;
REVOKE ALL ON FUNCTION ledger.session_key(text,text,integer,text,integer,text,integer) FROM PUBLIC;
CREATE TRIGGER intake_queue AFTER INSERT ON ledger.intake FOR EACH ROW EXECUTE FUNCTION ledger.queue_session();
CREATE TABLE ledger.observations (
 event_id text PRIMARY KEY, intake_id bigint NOT NULL REFERENCES ledger.intake(id), session_key text NOT NULL REFERENCES ledger.sessions(session_key),
 received_at timestamptz NOT NULL, duration ledger.uint64 NOT NULL, upload ledger.uint64 NOT NULL,download ledger.uint64 NOT NULL,
 event jsonb NOT NULL, reason text NOT NULL
);
CREATE TABLE ledger.intervals (
 usage_id text PRIMARY KEY, event_id text NOT NULL REFERENCES ledger.observations(event_id),session_key text NOT NULL REFERENCES ledger.sessions(session_key),
 upload ledger.uint64 NOT NULL, download ledger.uint64 NOT NULL, seconds ledger.uint64 NOT NULL, payload jsonb NOT NULL
);
CREATE TABLE ledger.work (
 id text PRIMARY KEY, kind text NOT NULL, payload jsonb NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','started','succeeded','quarantine')),
 owner text, generation bigint NOT NULL DEFAULT 0, lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),receipt jsonb
);
CREATE INDEX work_pending ON ledger.work(kind,state,created_at);
CREATE TABLE ledger.attempts (
 work_id text NOT NULL REFERENCES ledger.work(id),generation bigint NOT NULL,owner text NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),finished_at timestamptz,outcome text,receipt jsonb,
 PRIMARY KEY(work_id,generation)
);
CREATE TABLE ledger.reconciliations (
 work_id text NOT NULL REFERENCES ledger.work(id),generation bigint NOT NULL,evidence jsonb NOT NULL,
 reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(work_id,generation)
);
CREATE TABLE ledger.quarantine (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, intake_id bigint REFERENCES ledger.intake(id),work_id text REFERENCES ledger.work(id),
 reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), payload jsonb
);
CREATE TABLE ledger.auth_cursors (source text PRIMARY KEY,cursor text NOT NULL,updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE ledger.import_markers (id text PRIMARY KEY,checksum text NOT NULL,imported_at timestamptz NOT NULL DEFAULT clock_timestamp());
INSERT INTO ledger.schema_version(version) VALUES(1);
