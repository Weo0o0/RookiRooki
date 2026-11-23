# Mini-SIEM

SK쉴더스 루키즈 07기 미니프로젝트 04조가, 팀 전용 Docker 실습망에서 녹화한 패킷을 Suricata로 분석하고 웹 대시보드에서 경보를 확인하는 경량 SIEM입니다.

이 문서는 GitHub 저장소 [Weo0o0/RookiRooki](https://github.com/Weo0o0/RookiRooki)의 설계·계약 문서입니다. **애플리케이션 코드는 아직 구현 전**이며, 아래 실행 명령은 구현 후 사용할 표준 절차입니다. 시스템 배치와 탐지 흐름의 상세는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를, 팀 협업 규칙과 역할별 AI 프롬프트는 [AI_COLLABORATION_GUIDE.md](AI_COLLABORATION_GUIDE.md)를 참고하세요.

## 팀 구성과 역할

| 역할 | 담당 범위 | 소유 폴더·파일 |
|---|---|---|
| 백엔드 | FastAPI, SQLite, eve.json 파싱, 상관분석, API | `backend/` (`rules/`, `scenarios/` 파일은 읽기 전용으로 참조) |
| 프론트엔드 | 단일 HTML SOC 대시보드 | `frontend/` |
| 룰 | Suricata 커스텀 룰과 메타데이터 카탈로그 | `rules/custom.rules`, `rules/rule_catalog.json` |
| 시나리오 | 실습 트래픽·pcap, 샘플 eve 로그, 대응 플레이북 | `scenarios/pcaps/`, `scenarios/sample_eve.json`, `scenarios/playbooks.json` |
| PM | 심각도·SLA 정책, 통합 스펙, QA, 발표 | `policies/sev_sla_policy.json`, `policies/PROJECT_SPEC_QA.md` |

기술 스택은 고정입니다. 백엔드는 Python FastAPI + 내장 SQLite(`sqlite3`) + Pydantic v2이며, ORM이나 외부 DB로 바꾸지 않습니다. 프론트엔드는 단일 HTML + Tailwind CSS CDN + Vanilla JS(+ 필요 시 Chart.js CDN)이며, React/TypeScript/Webpack으로 바꾸지 않습니다. 백엔드 API는 `http://localhost:8000`에서 제공하고, 대시보드는 5초 주기 폴링(`GET /api/alerts`)과 Mock/Live 토글을 사용합니다.

## 핵심 기능

4일 범위에서 구현·시연하는 차별화는 다음 네 가지입니다.

1. **같은 요청의 HTTP 200 응답이면 SEV1로 격상**  
   Suricata `eve.json`의 `alert`와 `http`를 연결해, SQL 인젝션·XSS **해당 공격 요청의 응답 코드가 200**이면 `is_confirmed_risk=1`, 심각도 SEV1로 올립니다. 같은 연결에 섞인 다른 요청의 200으로는 격상하지 않습니다. 포트 스캔과 SSH 무차별 대입은 HTTP 응답이 없으므로 이 규칙을 적용하지 않고, 카탈로그의 기본 심각도를 유지합니다.
2. **평문 패스워드·토큰 자동 마스킹**  
   URL이나 로그에 보이는 `password`, `token`, `secret` 등 민감 값은 저장·표시 전에 `[MASKED]`로 바꿉니다. 실습 데이터에도 실제 비밀번호를 넣지 않습니다.
3. **경보 클릭 시 OSI 흐름과 검증·차단·원복 CLI 안내**  
   `playbooks.json`을 `category`로 매칭해 공격 경로를 보여 주고, `{{SRC_IP}}`, `{{DEST_IP}}`, `{{DEST_PORT}}`를 실제 값으로 치환한 검증(`verify`)·차단(`block`)·원복(`rollback`) 명령어를 복사할 수 있게 합니다. **차단 명령은 화면에 안내만 하며, 시스템이 iptables 등을 실행하지 않습니다.**
4. **업로드한 PCAP을 커스텀 룰로 검사하고 MITRE 커버리지를 보여 줌**  
   웹에서 pcap을 올리면 백엔드가 `suricata -r`과 `rules/custom.rules`로 오프라인 분석합니다. 대시보드는 `GET /api/stats`로 심각도 집계와 MITRE ATT&CK 커버리지를 표시합니다.

## 공격 시나리오

Stage 1에서 다루는 시나리오는 **아래 4종뿐입니다.** MITRE 기법 ID는 초안이며, **룰 담당자가 카탈로그를 확정할 때 검증**합니다.

| 카테고리 키 | SID | 시나리오 | 대상 | Suricata가 보는 것 | MITRE (검증 필요) | 기본 심각도 | 격상 |
|---|---|---|---|---|---|---|---|
| `sqli` | 1000001 | SQL 인젝션 | `victim-web` (`172.28.0.10`, HTTP) | HTTP URI·바디의 SQL 삽입 패턴 | T1190 (Initial Access) | SEV3 | 해당 요청 응답이 200이면 SEV1 |
| `xss` | 1000002 | XSS | `victim-web` (`172.28.0.10`, HTTP) | HTTP URI·바디의 스크립트 삽입 패턴 | T1189 (Initial Access) | SEV3 | 해당 요청 응답이 200이면 SEV1 |
| `bruteforce` | 1000003 | SSH 무차별 대입 | `victim-pc` (`172.28.0.11`, 22/tcp) | 짧은 시간 동안 동일 출발지가 22/tcp로 반복 연결하는 횟수. SSH는 암호화되어 패스워드 문자열을 볼 수 없음 | T1110.001 (Credential Access) | SEV2 | HTTP 200 격상 없음 |
| `portscan` | 1000004 | 포트 스캔 | `victim-web` / `victim-pc` | 짧은 시간 동안 동일 출발지가 서로 다른 목적 포트로 SYN을 다수 전송 | T1046 (Discovery) | SEV3 | HTTP 200 격상 없음 |

실습망 주소는 팀이 쓰는 격리 Docker 네트워크만 사용합니다. `mini-siem-net`는 `172.28.0.0/24`, 공격자 `172.28.0.100`, 웹 타깃 `172.28.0.10`, SSH 타깃 `172.28.0.11`입니다. 백엔드와 프론트엔드는 호스트에서 실행하고, API는 8000 포트를 사용합니다.

### 계약 변경 안내

기존 팀 가이드와 역할 프롬프트의 카테고리 키는 `sqli`, `ssrf`, `c2_beacon`(SID 1000001–1000003)이었습니다. **지금부터는 위 4키·4 SID로 교체**하며, `ssrf`와 `c2_beacon`은 사용하지 않습니다. 아래 문서는 배포 전에 같은 키로 고쳐야 합니다.

| 문서 | 고쳐야 할 항목 |
|---|---|
| `AI_COLLABORATION_GUIDE.md` | 전원 필수 규칙의 카테고리 키 목록 |
| 백엔드 역할 프롬프트 | 고정 규격의 `category` 키 (`sqli`, `ssrf`, `c2_beacon`) |
| 룰 역할 프롬프트 | 작업 규격의 카테고리 키 |
| 시나리오 역할 프롬프트 | 카테고리 키와 SID 매핑 (`ssrf` 1000002, `c2_beacon` 1000003) |
| 프론트엔드 역할 프롬프트 | 키 목록은 없지만, Mock 데이터와 플레이북 매칭은 새 4키를 따름 |
| `policies/PROJECT_SPEC_QA.md` (PM) | 「카테고리 키 통일」항목. PM 프롬프트 본문에는 구 키가 직접 적혀 있지 않음 |

플레이북 최상위 키, `rule_catalog.json`의 `category`·`sid`, `sample_eve.json`의 `signature_id`는 서로 철자까지 같아야 합니다. SID 대역 `1000001`–`1000999`, 치환 변수, 심각도 `SEV1`–`SEV4`는 그대로입니다.

## 동작 흐름 (Stage 1)

공격과 패킷 녹화는 **팀 격리 Docker 실습망 안에서만** 합니다. 브리지에서 tcpdump로 `victim-web`과 `victim-pc` 트래픽을 함께 남기고, 그 pcap을 웹에 올려 Suricata가 오프라인으로 읽습니다. 라이브 탐지는 Stage 2(Backlog)입니다.

```mermaid
flowchart LR
  Attacker["공격자 172.28.0.100"] --> LabNet["실습망 mini-siem-net"]
  LabNet --> Web["victim-web 172.28.0.10"]
  LabNet --> HostPc["victim-pc 172.28.0.11"]
  LabNet --> Dump["브리지 tcpdump"]
  Dump --> Upload["POST /api/pcap/upload"]
  Sample["sample_eve.json"] --> Ingest["POST /api/ingest/sample"]
  Upload --> Suricata["suricata -r 커스텀 룰"]
  Suricata --> Eve["eve.json"]
  Eve --> Parse["파싱 마스킹 격상"]
  Ingest --> Parse
  Parse --> Db["SQLite"]
  Db --> Api["FastAPI :8000"]
  Api --> Ui["대시보드"]
```

## API

Stage 1에서 프론트·백엔드가 맞출 인터페이스입니다. 앞의 네 개는 기존 계약이고, `POST /api/pcap/upload`는 Stage 1에서 추가합니다. `GET /api/stats`는 원래 백엔드 프롬프트에 있던 집계 API로, 차별화 ④(MITRE 커버리지)를 위해 Stage 1에 포함합니다. 가이드에 있던 `POST /api/sandbox/test`(업로드 pcap + 임의 룰 텍스트)는 Stage 1에서 `POST /api/pcap/upload`(고정 `custom.rules`로 `suricata -r`)로 대체하며, 웹에서 룰 문구를 바꿔 시험하는 기능은 Backlog로 둡니다.

| 메서드 | 경로 | 용도 | 입력 | 응답 요지 |
|---|---|---|---|---|
| `POST` | `/api/ingest/sample` | 데모용 `scenarios/sample_eve.json` 적재 | 없음 | 적재된 경보 건수 |
| `GET` | `/api/alerts` | 경보 목록 | `severity`, `limit`, `offset` | `items`, 페이지 건수 |
| `GET` | `/api/alerts/{id}` | 경보 상세 + 플레이북 | 경로 `id` | 경보 필드 + `playbook` |
| `PATCH` | `/api/alerts/{id}/triage` | 분석가 판정 저장 | `verdict`(`TP`/`FP`/`UNREVIEWED`), `observation`, `assessment`, `confidence`(`HIGH`/`MEDIUM`/`LOW`) | 갱신 결과 |
| `POST` | `/api/pcap/upload` | pcap 업로드 후 `suricata -r` | `multipart/form-data`, `.pcap` 또는 `.pcapng`, 최대 20MB | 분석 요약(적재 건수 등) |
| `GET` | `/api/stats` | 심각도 집계, MITRE 커버리지, 로그 단절(Blind) 룰 | 없음 | `severity_counts`, `mitre_coverage`, `blind_rules` 등 |

경보 JSON의 핵심 키는 `id`, `timestamp`, `sid`, `category`, `signature`, `mitre_id`, `src_ip`, `dest_ip`, `dest_port`, `http_status`, `severity`, `is_confirmed_risk`, `pii_masked`, `raw_url`, `verdict`, `observation`, `assessment`, `confidence`, `playbook`입니다. 스키마 상세는 [ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하세요.

## 저장소 구조

```text
mini-siem/
├── backend/                      # 백엔드
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   └── index.html
├── rules/
│   ├── custom.rules
│   └── rule_catalog.json
├── scenarios/
│   ├── pcaps/
│   ├── sample_eve.json
│   └── playbooks.json
├── policies/
│   ├── sev_sla_policy.json
│   └── PROJECT_SPEC_QA.md
├── docs/
│   └── ARCHITECTURE.md
├── AI_COLLABORATION_GUIDE.md
└── README.md
```

## 실행 방법 (구현 후 예정)

아래는 코드가 준비된 뒤에 쓰는 표준 절차입니다. 지금은 설계만 확정된 상태이므로, 명령을 그대로 실행해도 서버가 뜨지 않을 수 있습니다.

1. **실습망과 녹화 (시나리오 담당, 격리망 전용)**  
   팀 Docker 실습망(`mini-siem-net`)을 띄운 뒤, **Docker 브리지 인터페이스**에서 `victim-web`과 `victim-pc` 트래픽이 모두 보이도록 tcpdump로 pcap을 남깁니다. 브리지 이름은 환경마다 다르므로 `docker network inspect`로 확인합니다.
   ```bash
   sudo tcpdump -i <브리지_인터페이스> -w scenarios/pcaps/lab_capture.pcap
   ```
2. **오프라인 룰 검사 (룰·백엔드 점검용)**  
   ```bash
   mkdir -p /tmp/suricata_out
   suricata -r scenarios/pcaps/lab_capture.pcap -S rules/custom.rules -l /tmp/suricata_out
   ```
3. **백엔드**  
   ```bash
   pip install -r backend/requirements.txt
   uvicorn backend.main:app --reload --port 8000
   ```
   API 문서는 구현 후 `http://localhost:8000/docs`에서 확인합니다. 샘플 로그는 `POST /api/ingest/sample`, 녹화 파일은 `POST /api/pcap/upload`로 넣습니다.
4. **대시보드**  
   `frontend/index.html`을 열고, 백엔드가 준비되면 Mock 모드를 끄고 Live API(`http://localhost:8000`)에 연결합니다.

## 4일 일정

Day 3 **오후 6시 Feature Freeze** 이후에는 새 기능을 넣지 않고, 버그 수정과 시연 준비만 합니다.

| 일정 | 목표 | 역할별 작업 |
|---|---|---|
| Day 1 | 계약 고정과 뼈대 | 전원이 카테고리 키·SID·API를 확인. 백엔드: 프로젝트 뼈대와 샘플 적재. 프론트: Mock으로 경보 목록·상세 레이아웃. 룰: 4종 1차 룰과 카탈로그. 시나리오: 실습망·1차 pcap과 플레이북 초안. PM: SLA 정책과 QA 목록 |
| Day 2 | 탐지와 화면 연동 | 백엔드: pcap 업로드, 마스킹, SQL/XSS 200 격상. 프론트: Live API, 플레이북 치환, 트리아지(사실/추정 분리). 룰: pcap으로 튜닝. 시나리오: 정상·공격 트래픽 분리 녹화. PM: 키 일치 점검 |
| Day 3 | 통합과 동결 | 4시나리오가 업로드부터 대시보드까지 이어지는지 확인. MITRE 요약과 QA PASS/FAIL. **18:00 Feature Freeze** |
| Day 4 | 시연 | 리허설, README·스크린샷, 발표. 실습망이 안 되면 저장해 둔 pcap과 `sample_eve.json`으로 재현 |

## 심각도 SLA

PM이 `policies/sev_sla_policy.json`으로 관리합니다. 초안 기준은 다음과 같습니다.

| 등급 | 의미 (초안) | 초기 대응 목표 | 상황 공유 |
|---|---|---|---|
| SEV1 | 해당 웹 공격 요청이 200을 받은 침투 성공 의심, 민감정보 유출 등 | 5분 이내 | 15분마다 |
| SEV2 | SSH 무차별 대입 등 고위험 시도, 확인 필요 | 15분 이내 | 30분마다 |
| SEV3 | 포트 스캔, 응답이 200이 아닌 웹 공격 시도 | 1시간 이내 | 2시간마다 |
| SEV4 | 정보성·오탐 튜닝 대상 | 다음 영업일 이내 | 일일 요약 |

자동 격상: SQL 인젝션·XSS에서 **그 요청의 응답이 200**이면 즉시 SEV1. 평문 패스워드·토큰이 보이면 마스킹하고, 정책상 최소 SEV2 이상을 검토합니다. SEV1 선언 후 30분 안에 원인을 못 찾으면 상위 보고를 검토합니다.

## 보안 기본기

- 비밀번호, API 키, 웹훅 주소는 코드에 직접 적지 않고 환경변수로 분리합니다.
- SQLite는 파라미터 바인딩(`?`)만 쓰고, 문자열을 이어 붙여 쿼리하지 않습니다.
- CORS는 `*`가 아니라 로컬 주소 목록만 허용합니다. 요청 본문은 Pydantic으로 검증하고, 에러 응답에 스택 트레이스를 넣지 않습니다.
- 프론트엔드는 서버에서 받은 문자열을 `innerHTML`에 넣기 전에 이스케이프합니다.
- 차단 CLI는 반드시 검증·원복 명령과 세트로 적습니다. 관제 메모는 사실(`observation`)과 추정(`assessment`), 신뢰도를 나눕니다.

## 안전과 윤리

- 공격 재현과 패킷 수집은 **이 팀의 격리된 Docker 실습망에서만** 합니다. 학교·회사·가정 네트워크나 허가 없는 대상을 쓰지 않습니다.
- 샘플 로그와 pcap에는 실제 계정, 실제 비밀번호, 실제 개인정보를 넣지 않습니다. 마스킹 시험에는 가짜 `password=` / `token=`만 사용합니다.
- 문서에 적힌 차단 명령은 안내입니다. 실습망 밖 장비에 적용하지 않습니다.
- 샘플 출발지·문서 예시가 필요하면 RFC 5737 문서용 대역(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)만 쓰고, 실공인 IP는 사용하지 않습니다.

## Backlog (4일 범위 밖)

- **Stage 2:** 브리지에서 Suricata를 상시 실행하고 `eve.json`을 실시간으로 읽기
- 시스템이 방화벽 명령을 직접 실행하는 임시 차단(지금은 화면 안내만)
- 공격 스토리 묶기, 오탐 학습 점수, 외부 메신저 알림
- 웹에서 룰 텍스트를 바꿔 시험하는 샌드박스(`POST /api/sandbox/test`)
- 호스트 로그(`auth.log` 등)와의 추가 상관분석, 로그인·다중 권한, 상용 DB 전환
