# 🛡️ Mini-SIEM 팀 협업 가이드 & 역할별 AI 마스터 프롬프트

> 버전 v3 (2026-11-24). 변경 요약: 공격 시나리오를 확정 6종(sqli/xss/bruteforce/portscan/c2_beacon/ssrf, SID 1000001~1000006)으로 확대. portscan 목적지 22·80 제외(sample은 8080 사용, 룰 ![22,80] 유지, 2026-11-24 A안). ssrf는 HTTP 200이면 SEV1로 자동 격상, c2_beacon은 threshold 기반(HTTP 200 격상 없음). MITRE 기법 ID는 가안(c2_beacon T1071.001 SEV2 가안, ssrf T1190). 역할별 프롬프트는 개별 마크다운 파일(01~06)로 분리 관리.

본 문서는 **Suricata 기반 자체 웹 Mini-SIEM(4일 단기 프로젝트)**을 팀원들이 병렬로 개발할 때, 데이터 규격 충돌을 방지하고 보안 기본기를 유지하기 위한 팀 공용 협업 가이드입니다.  
각 팀원이 AI 도구(ChatGPT, Gemini, Claude 등)를 활용할 때 **새 채팅창 첫 메시지로 본인 역할의 프롬프트 파일(01~06 마크다운)을 복사·붙여넣기**하여 일관된 결과물을 유지하세요.

---

## 📁 0. 팀 공용 폴더 구조 (작업 영역 분리)

Git 충돌을 방지하기 위해 각 담당자는 지정된 폴더의 파일만 수정·커밋합니다.

아래 트리는 **경로 제안**이다. 실습망·pcap 공식 경로와 백엔드/Suricata 실행 위치는 **PM 합의 필요**. README 초안은 `scenarios/pcaps/`와 루트 `AI_COLLABORATION_GUIDE.md`를 가리키지만, 현재 저장소에는 실습망이 `scenarios/lab/`에 있고 가이드는 `ai-guides/`에 있다.

~~~~text
mini-siem/
├── backend/                # [백엔드] FastAPI, SQLite, Suricata 파서
├── frontend/               # [프론트엔드] 단일 HTML + Tailwind + Vanilla JS 대시보드
├── rules/                  # [룰 담당] custom.rules, rule_catalog.json
├── scenarios/              # [시나리오 담당]
│   ├── lab/                # 실습망 compose·컨테이너 (PM 합의 필요, 현재 저장소 위치)
│   │   └── pcaps/          # 녹화 pcap (PM 합의 필요)
│   ├── sample_eve.json
│   └── playbooks.json
├── policies/               # [PM] sev_sla_policy.json, PROJECT_SPEC_QA.md
├── docs/                   # ARCHITECTURE.md, playbooks_guide.md, sample_eve_guide.md
├── ai-guides/              # 본 가이드 및 역할별 마크다운 프롬프트 (01~06)
└── README.md
~~~~

---

## 📌 1. 팀원 전원 필수 준수 가이드 (AI 협업 시 절대 규칙)

1. **공용 규격(Contract) 임의 변경 금지**
   * 공격 시나리오는 확정 6종을 사용합니다.
     * 카테고리 키: `sqli`, `xss`, `bruteforce`, `portscan`, `c2_beacon`, `ssrf`
     * SID 매핑: `sqli` 1000001, `xss` 1000002, `bruteforce` 1000003, `portscan` 1000004, `c2_beacon` 1000005, `ssrf` 1000006
     * 커스텀 룰 SID 대역(`1000001~1000999`), 동적 치환 변수(`{{SRC_IP}}`, `{{DEST_IP}}`, `{{DEST_PORT}}`), 심각도(`SEV1~SEV4`)는 백엔드·PM 합의 없이 AI가 임의로 바꾼 이름으로 커밋하지 않습니다.
2. **기술 스택 이탈 및 과잉 설계 금지 (초급~중급 수준 유지)**
   * 백엔드는 `Python FastAPI + SQLite`, 프론트엔드는 `단일 HTML + Tailwind CDN + Vanilla JS`를 유지합니다. AI가 PostgreSQL, Redis, TypeScript, 과도한 아키텍처 패턴을 제안해도 거절하고 4일 내 디버깅 가능한 단순한 구조를 유지합니다.
3. **보안 기본기(Secure-by-Default) 강제 적용**
   * 비밀번호·API 키·시크릿은 코드에 하드코딩하지 않고 환경변수로 분리합니다.
   * SQL 문자열 결합 대신 파라미터 바인딩(`?`)만 사용하며, 로그 속 민감정보는 자동 마스킹(`[MASKED]`)합니다.
4. **탐지·대응·문서화 실무 원칙 준수**
   * 모든 탐지 룰은 MITRE ATT&CK 매핑, 필요 로그 소스(`data_sources`), 예상 오탐 시나리오, 검증 테스트 케이스를 함께 작성합니다.
   * 모든 네트워크/방화벽 차단 명령어는 반드시 **검증(`verify`)과 롤백(`rollback`) 절차**를 세트로 포함합니다. 차단은 명령어 안내만 하며 시스템이 실행하지 않습니다. playbooks는 linux iptables/ufw를 필수로 하고, 다른 벤더는 선택입니다.
   * 관제 메모와 보고서는 **관찰된 사실(`observation`/Fact)**과 **분석가 추정(`assessment`) 및 신뢰도**를 명확히 분리합니다.
5. **AI 생성 코드·룰 무검증 커밋 금지**
   * AI가 생성한 코드나 Suricata 룰은 반드시 본인 로컬 환경에서 1회 이상 실행·테스트한 뒤 지정 폴더에만 커밋합니다.
6. **실습망 격리**
   * 공격 재현과 패킷 수집은 팀 Docker 실습망(`mini-siem-net` `172.28.0.0/24`, 브리지 `br-minisiem`, `internal: true`)의 `victim-web`(`172.28.0.10`)과 `victim-pc`(`172.28.0.11`)만 대상으로 합니다. 학교·회사·가정 네트워크나 공인 IP, 다른 PC는 쓰지 않습니다.

---

## 🎯 2. 확정 6종 공격 시나리오 규격

| 카테고리 키 | SID | 시나리오 | 대상 | 탐지 방식 | MITRE (가안) | 기본 심각도 | 격상 조건 |
|---|---|---|---|---|---|---|---|
| `sqli` | 1000001 | SQL 인젝션 | `victim-web` (`172.28.0.10`) | HTTP URI·바디 SQL 삽입 패턴 | T1190 | SEV3 | 해당 요청 응답이 200이면 SEV1 |
| `xss` | 1000002 | XSS | `victim-web` (`172.28.0.10`) | HTTP URI·바디 스크립트 삽입 패턴 | T1189 | SEV3 | 해당 요청 응답이 200이면 SEV1 |
| `bruteforce` | 1000003 | SSH 무차별 대입 | `victim-pc` (`172.28.0.11`, 22/tcp) | 단시간 동일 출발지 22/tcp 반복 연결 횟수(암호화 페이로드 내용 확인 불가) | T1110.001 | SEV2 | HTTP 200 격상 없음 |
| `portscan` | 1000004 | 포트 스캔 | `victim-web` / `victim-pc` | 단시간 동일 출발지 다수 목적지 포트 SYN 전송 (목적지 22, 80 미사용, sample은 8080 사용, 룰 `![22,80]` 유지, 2026-11-24 A안) | T1046 | SEV3 | HTTP 200 격상 없음 |
| `c2_beacon` | 1000005 | C2 비콘 | 실습망 내부 (`172.28.0.0/24`) | 반복 연결 횟수 임계치(threshold 기반). 방향·횟수·시간창·포트는 TBD (PM 확인 필요) | T1071.001 (가안) | SEV2 (가안) | HTTP 200 격상 없음 |
| `ssrf` | 1000006 | SSRF | `victim-web` (`172.28.0.10`) | 내부 자원 조회 유도 HTTP 요청 패턴. URI 경로는 TBD (PM 확인 필요) | T1190 (가안) | TBD (PM 확인 필요) | 해당 요청 응답이 200이면 SEV1 |

---

## 🤖 3. 역할별 복사·붙여넣기용 AI 시스템 프롬프트 (6개 파일 안내)

각 역할별 상세 프롬프트와 지침은 `ai-guides/` 디렉터리의 개별 마크다운 파일에 정의되어 있습니다. 본인 역할에 맞는 마크다운 파일을 열어 AI 시스템 프롬프트로 활용하세요.

| 파일명 | 역할 | 담당 범위 | 소유 폴더·파일 |
|---|---|---|---|
| [`01_백엔드_AI룰.md`](01_백엔드_AI룰.md) | 백엔드 | FastAPI, SQLite, eve.json 파싱, 상관분석, API | `backend/` (`rules/`, `scenarios/`는 읽기 전용 참조) |
| [`02_프론트엔드_AI룰.md`](02_프론트엔드_AI룰.md) | 프론트엔드 | 단일 HTML SOC 대시보드 | `frontend/` |
| [`03_시나리오_AI룰.md`](03_시나리오_AI룰.md) | 시나리오 | 실습 트래픽·pcap, 샘플 eve 로그, 대응 플레이북 | `scenarios/lab/pcaps/`, `scenarios/sample_eve.json`, `scenarios/playbooks.json`, `docs/playbooks_guide.md`, `docs/sample_eve_guide.md` |
| [`04_룰_AI룰.md`](04_룰_AI룰.md) | 룰 | Suricata 커스텀 룰과 메타데이터 카탈로그 | `rules/custom.rules`, `rules/rule_catalog.json` |
| [`05_PM_AI룰.md`](05_PM_AI룰.md) | PM | 심각도·SLA 정책, 통합 스펙, QA, 머지 순서 및 일정 관리 | `policies/sev_sla_policy.json`, `policies/PROJECT_SPEC_QA.md` |
| [`06_문서_PPT_AI룰.md`](06_문서_PPT_AI룰.md) | 문서·PPT | 전체 아키텍처 문서화, README, 슬라이드 발표 자료 | `README.md`, `docs/ARCHITECTURE.md`, `ai-guides/*` |

---

## 🚀 4. 팀원 사용 방법 (3단계)

1. 각자 사용하는 AI 도구(ChatGPT, Gemini, Claude 등)에서 새 채팅창을 열고 **본인 역할의 프롬프트 파일(`01`~`06_*.md`) 전체 내용을 맨 첫 메시지로 복사·붙여넣기**합니다.
2. AI가 가이드 적용 완료를 확인하면, 본인 담당 폴더의 작업 파일 내용을 붙여넣고 요구사항을 요청합니다.
3. 아직 비어 있는 값(C2 방향·횟수·시간창·포트, SSRF 경로, 공식 샘플·pcap 건수 등)은 임의로 지어내지 않고 **PM 확인 후 확정**합니다.
