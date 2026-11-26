CREATE TABLE IF NOT EXISTS kig_authority (
 id integer PRIMARY KEY CHECK (id = 1),
 audience text NOT NULL,
 audit_key bytea NOT NULL,
 state jsonb NOT NULL,
 schema_version integer NOT NULL DEFAULT 1 CHECK(schema_version=1)
);
CREATE TABLE IF NOT EXISTS kig_events (
 sequence bigint PRIMARY KEY CHECK(sequence>=0),
 payload bytea NOT NULL
);

-- DDL runs under the migration owner, never the restricted runtime role.
ALTER TABLE kig_authority DROP CONSTRAINT IF EXISTS kig_authority_schema_version_check;
ALTER TABLE kig_authority ADD CONSTRAINT kig_authority_schema_version_check CHECK(schema_version IN (1,2));
CREATE OR REPLACE FUNCTION kig_protocol_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'UPDATE' AND OLD.schema_version = 2 AND NEW.schema_version <> 2 THEN
  RAISE EXCEPTION 'protocol downgrade forbidden';
 END IF;
 IF NEW.schema_version = 2 AND (
  current_setting('kig.protocol_version', true) IS DISTINCT FROM '2' OR
  NEW.state->>'protocol_version' IS DISTINCT FROM '2'
 ) THEN
  RAISE EXCEPTION 'v2 compatible writer required';
 END IF;
 IF NEW.schema_version = 1 AND COALESCE(NEW.state->>'protocol_version','0') NOT IN ('0','1') THEN
  RAISE EXCEPTION 'protocol metadata mismatch';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS kig_protocol_guard ON kig_authority;
CREATE TRIGGER kig_protocol_guard BEFORE INSERT OR UPDATE ON kig_authority
 FOR EACH ROW EXECUTE FUNCTION kig_protocol_guard();
