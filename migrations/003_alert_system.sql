-- T0.3 Alert System 마이그레이션
-- Supabase SQL Editor (https://supabase.com/dashboard/project/jrmreppunqiyrypcipdd/sql/new) 에서 실행

-- 1. lumos_hack_alerts 테이블 (FK: incident_groups + hack_signals)
CREATE TABLE IF NOT EXISTS lumos_hack_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_group_id UUID NOT NULL REFERENCES lumos_incident_groups(id),
  alert_level TEXT NOT NULL CHECK (alert_level IN ('critical', 'follow_up')),
  alert_action TEXT NOT NULL CHECK (alert_action IN ('first_alert', 'follow_up')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  source_count INTEGER NOT NULL DEFAULT 1,
  metadata JSONB DEFAULT '{}',
  trigger_signal_id UUID REFERENCES lumos_hack_signals(id),
  -- 추후 T0.3.3에서 사용 (Telegram 발송 후 채움)
  sent_at TIMESTAMPTZ DEFAULT NULL,
  sent_to TEXT DEFAULT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_group ON lumos_hack_alerts(incident_group_id);
CREATE INDEX IF NOT EXISTS idx_alerts_unsent ON lumos_hack_alerts(sent_at) WHERE sent_at IS NULL;

-- 2. lumos_hack_signals에 alert_status 컬럼 추가
ALTER TABLE lumos_hack_signals
  ADD COLUMN IF NOT EXISTS alert_status TEXT DEFAULT 'pending'
    CHECK (alert_status IN ('pending', 'alerted', 'follow_up', 'silent'));

-- 3. lumos_incident_groups에 best_tier 컬럼 추가 (Critical 1)
ALTER TABLE lumos_incident_groups
  ADD COLUMN IF NOT EXISTS best_tier INTEGER DEFAULT 3
    CHECK (best_tier IN (1, 2, 3));
