-- Allow the detector to save non-alerting review states before Telegram alerts fire.
-- Idempotent: safe to run even if 005_signal_triage.sql hasn't been applied yet.

-- 1) triage_status / operator_note / linked_case_id 컬럼이 없을 수도 있으니 보장한다.
ALTER TABLE lumos_hack_signals
  ADD COLUMN IF NOT EXISTS triage_status TEXT,
  ADD COLUMN IF NOT EXISTS operator_note TEXT,
  ADD COLUMN IF NOT EXISTS linked_case_id UUID DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_hack_signals_triage_status
  ON lumos_hack_signals(triage_status);

-- 2) alert_status CHECK 제약을 'ambiguous' / 'quarantined' 까지 허용하도록 갱신.
DO $$
DECLARE
  c record;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'lumos_hack_signals'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ILIKE '%alert_status%'
  LOOP
    EXECUTE format('ALTER TABLE lumos_hack_signals DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

ALTER TABLE lumos_hack_signals
  ADD CONSTRAINT lumos_hack_signals_alert_status_check
  CHECK (alert_status IN ('pending', 'alerted', 'follow_up', 'silent', 'ambiguous', 'quarantined'));

-- 3) triage_status CHECK 제약을 새로운 상태값까지 허용하도록 갱신.
DO $$
DECLARE
  c record;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'lumos_hack_signals'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ILIKE '%triage_status%'
  LOOP
    EXECUTE format('ALTER TABLE lumos_hack_signals DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

ALTER TABLE lumos_hack_signals
  ADD CONSTRAINT lumos_hack_signals_triage_status_check
  CHECK (
    triage_status IS NULL
    OR triage_status IN ('reviewed', 'false_positive', 'escalated', 'ambiguous', 'quarantined')
  );
