# Hack Detector — 모니터링 소스 관리

> **관리 파일**: 이 파일을 수정하면 `config/channels.yaml`, `config/accounts.yaml`에도 동기화 필요
> **최종 업데이트**: 2026-04-27

---

## Telegram 채널

| 상태 | 이름 | chat_id | Tier | 비고 |
|------|------|---------|------|------|
| ON | Defimon Alerts | -1002360854548 | T1 | |
| ON | DefiHackLabs Security News | -1003089530830 | T1 | |
| ON | EthSecurity | -1001794535570 | T1 | |
| TEST | Testing Channel | -1003872533937 | T1 | 테스트용 |

### 추가 후보

| 이름 | chat_id | Tier | X/링크 | 메모 |
|------|---------|------|--------|------|
| BlockSec Alerts | ? | T1 | | 확인 필요 |
| SlowMist Zone | ? | T1 | | 확인 필요 |

---

## Twitter/X 계정

### Tier 1 — 보안업체 / Alert 봇

| 상태 | 계정 | X 프로필 | 비고 |
|------|------|----------|------|
| ON | PeckShieldAlert | [x.com/PeckShieldAlert](https://x.com/PeckShieldAlert) | 해킹 실시간 알림 |
| ON | CertiKAlert | [x.com/CertiKAlert](https://x.com/CertiKAlert) | 해킹/러그 알림 |
| ON | BlockSecTeam | [x.com/BlockSecTeam](https://x.com/BlockSecTeam) | 온체인 분석 |
| ON | SlowMist_Team | [x.com/SlowMist_Team](https://x.com/SlowMist_Team) | 중국계 보안업체 |
| ON | TenArmorAlert | [x.com/TenArmorAlert](https://x.com/TenArmorAlert) | 실시간 탐지 |
| ON | peckshield | [x.com/peckshield](https://x.com/peckshield) | PeckShield 메인 |
| ON | BeosinAlert | [x.com/BeosinAlert](https://x.com/BeosinAlert) | Beosin 알림 |
| ON | Beosin_com | [x.com/Beosin_com](https://x.com/Beosin_com) | Beosin 메인 |
| ON | CyversAlerts | [x.com/CyversAlerts](https://x.com/CyversAlerts) | 실시간 위협 탐지 |
| ON | ScamSniffers | [x.com/ScamSniffers](https://x.com/ScamSniffers) | 피싱/스캠 탐지 |
| ON | Phalcon_xyz | [x.com/Phalcon_xyz](https://x.com/Phalcon_xyz) | BlockSec Phalcon |
| ON | HypernativeLabs | [x.com/HypernativeLabs](https://x.com/HypernativeLabs) | 실시간 보안 |
| ON | QuillAudits_AI | [x.com/QuillAudits_AI](https://x.com/QuillAudits_AI) | AI 감사 |
| ON | Wi11y010 | [x.com/Wi11y010](https://x.com/Wi11y010) | |
| ON | wiiwhdhqo | [x.com/wiiwhdhqo](https://x.com/wiiwhdhqo) | |

### Tier 2 — 보안 연구자 / 분석가

| 상태 | 계정 | X 프로필 | 비고 |
|------|------|----------|------|
| ON | samczsun | [x.com/samczsun](https://x.com/samczsun) | Paradigm 보안 리서처 |
| ON | zachxbt | [x.com/zachxbt](https://x.com/zachxbt) | 온체인 탐정 |
| ON | Mudit__Gupta | [x.com/Mudit__Gupta](https://x.com/Mudit__Gupta) | Polygon CISO |
| ON | pashov | [x.com/pashov](https://x.com/pashov) | 독립 감사자 |
| ON | cmichelio | [x.com/cmichelio](https://x.com/cmichelio) | 스마트컨트랙트 보안 |
| ON | lopp | [x.com/lopp](https://x.com/lopp) | BTC 보안 전문가 |
| ON | lookonchain | [x.com/lookonchain](https://x.com/lookonchain) | 온체인 분석 |
| ON | bubblemaps | [x.com/bubblemaps](https://x.com/bubblemaps) | 토큰 분석 시각화 |

### 추가 후보

| 계정 | X 프로필 | Tier | 메모 |
|------|----------|------|------|
| taaboris | [x.com/taaboris](https://x.com/taaboris) | T2 | Igor Igamberdiev |
| 0xfoobar | [x.com/0xfoobar](https://x.com/0xfoobar) | T2 | Delegate |
| pcaversaccio | [x.com/pcaversaccio](https://x.com/pcaversaccio) | T2 | Snekmate |

---

## 관리 규칙

- **상태**: `ON` = 활성, `OFF` = 비활성, `TEST` = 테스트용
- **Tier 기준**:
  - **T1**: 보안업체 공식 계정 — 사건 발생 시 5분 내 트윗, 구조화된 알림
  - **T2**: 개인 보안 연구자 — 사건 분석/의견, 반응 빠르지만 구조화 안 됨
  - **T3**: 커뮤니티/일반 — 소문/재게시 위주
- **추가 방법**: 이 파일에 "추가 후보"에 먼저 기록 → 검토 후 위 테이블로 이동 + yaml 동기화
- **비활성화**: 상태를 `OFF`로 변경 + yaml에서 `enabled: false` 추가

---

## 통계

| 구분 | T1 | T2 | T3 | 합계 |
|------|----|----|-----|------|
| Telegram | 3 (+1 test) | 0 | 0 | 4 |
| Twitter | 15 | 8 | 0 | 23 |
| **합계** | **18** | **8** | **0** | **27** |
