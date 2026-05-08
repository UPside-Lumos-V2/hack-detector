-- Hack signal alert-quality fields added by the corroboration/severity sprint.
-- Idempotent: safe to run after migrations 002-006.

ALTER TABLE lumos_hack_signals
  ADD COLUMN IF NOT EXISTS llm_is_new_incident BOOLEAN DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_signals_llm_is_new_incident
  ON lumos_hack_signals(llm_is_new_incident)
  WHERE llm_is_new_incident IS NOT NULL;

ALTER TABLE lumos_incident_groups
  ADD COLUMN IF NOT EXISTS source_authors TEXT[] DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS source_author_count INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tier1_author_count INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tier2_author_count INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS corroboration_score INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS severity_score INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS severity_label TEXT DEFAULT 'low',
  ADD COLUMN IF NOT EXISTS llm_is_new_incident BOOLEAN DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_incident_groups_source_author_count
  ON lumos_incident_groups(source_author_count);

CREATE INDEX IF NOT EXISTS idx_incident_groups_severity_score
  ON lumos_incident_groups(severity_score);
