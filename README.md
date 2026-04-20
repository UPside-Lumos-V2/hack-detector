# Hack Detector

DeFi 해킹 사건 자동 감지 & 알림 파이프라인.

## Overview

SNS(X/Twitter, Telegram) 보안 채널을 실시간 모니터링하여 해킹 사건을 자동 감지하고, 교차 검증 후 팀에 알림을 발송합니다.

## Quick Start

```bash
# 1. 가상환경 생성 + 활성화
python -m venv .venv
source .venv/bin/activate

# 2. 의존성 설치
pip install -e .

# 3. 실행 (API 크레덴셜은 터미널에서 직접 입력)
python -m src.main
```

## Architecture

```
Telegram 채널 리스닝 (Telethon) ──→ Field Extractor ──→ HackSignal
X/Twitter 폴링 (twscrape)      ──→ Field Extractor ──→ HackSignal
                                                          ↓
                                                    Incident Grouper
                                                          ↓
                                                    Alert Rule Engine
                                                          ↓
                                                    Telegram Bot 알림
```

## Security

- API 크레덴셜은 `.env`에 저장하지 않음 — 터미널 직접 입력 방식
- 세션 파일(`sessions/`)은 `.gitignore`에 등록
