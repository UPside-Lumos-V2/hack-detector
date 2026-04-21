-- T0.2.5 Incident Grouping 마이그레이션
-- Supabase SQL Editor (https://supabase.com/dashboard/project/jrmreppunqiyrypcipdd/sql/new) 에서 실행

-- 1. Incident Groups 테이블 생성
CREATE TABLE IF NOT EXISTS lumos_incident_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  protocol_name TEXT,
  chain TEXT,
  loss_usd NUMERIC,
  tx_hash TEXT,
  attacker_address TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signal_count INTEGER DEFAULT 1,
  source_types TEXT[] DEFAULT ARRAY[]::TEXT[],
  confidence_score INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- 2. 인덱스
CREATE INDEX IF NOT EXISTS idx_incident_groups_tx ON lumos_incident_groups(tx_hash);
CREATE INDEX IF NOT EXISTS idx_incident_groups_protocol ON lumos_incident_groups(protocol_name, first_seen_at);

-- 3. hack_signals에 컬럼 추가
ALTER TABLE lumos_hack_signals
ADD COLUMN IF NOT EXISTS incident_group_id UUID REFERENCES lumos_incident_groups(id),
ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 0;

-- 4. FK 인덱스
CREATE INDEX IF NOT EXISTS idx_hack_signals_group ON lumos_hack_signals(incident_group_id);
