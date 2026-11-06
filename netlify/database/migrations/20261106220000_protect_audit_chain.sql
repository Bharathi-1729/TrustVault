-- Preserve append-only audit records even if a future route attempts to mutate them.
CREATE FUNCTION trustvault_validate_audit_insert() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE last_sequence BIGINT; last_hash TEXT;
BEGIN
  PERFORM pg_advisory_xact_lock(73510422);
  SELECT sequence, current_hash INTO last_sequence, last_hash
    FROM audit_logs ORDER BY sequence DESC LIMIT 1;
  IF NEW.sequence != COALESCE(last_sequence + 1, 1)
    OR NEW.prev_hash != COALESCE(last_hash, repeat('0', 64)) THEN
    RAISE EXCEPTION 'Invalid audit chain append';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION trustvault_reject_audit_mutation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Audit logs are append-only';
END;
$$;
--> statement-breakpoint
CREATE TRIGGER audit_logs_validate_insert BEFORE INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION trustvault_validate_audit_insert();
--> statement-breakpoint
CREATE TRIGGER audit_logs_prevent_update BEFORE UPDATE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation();
--> statement-breakpoint
CREATE TRIGGER audit_logs_prevent_delete BEFORE DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation();
