ALTER TABLE lumos_hack_signals
  ADD COLUMN IF NOT EXISTS triage_status TEXT
    CHECK (triage_status IN ('reviewed', 'false_positive', 'escalated')),
  ADD COLUMN IF NOT EXISTS operator_note TEXT,
  ADD COLUMN IF NOT EXISTS linked_case_id UUID DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_hack_signals_triage_status
  ON lumos_hack_signals(triage_status);
