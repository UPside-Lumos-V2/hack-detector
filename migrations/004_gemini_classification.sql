-- 004_gemini_classification.sql
-- Gemini LLM 분류 결과 저장용 컬럼 추가
-- Supabase SQL Editor에서 실행: https://supabase.com/dashboard/project/jrmreppunqiyrypcipdd/sql/new

ALTER TABLE lumos_hack_signals
  ADD COLUMN IF NOT EXISTS llm_is_hack BOOLEAN DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS llm_confidence REAL DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS llm_category TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS llm_summary TEXT DEFAULT NULL;

-- llm_is_hack 인덱스 (HACK 필터 빠르게)
CREATE INDEX IF NOT EXISTS idx_signals_llm_is_hack
  ON lumos_hack_signals(llm_is_hack)
  WHERE llm_is_hack = true;
