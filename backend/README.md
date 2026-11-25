# Backend

WSL에서 `uvicorn backend.main:app --port 8000`으로 실행합니다. 테스트는 `python -m pytest backend/tests -q`입니다.

## 엔드포인트 목록

- `POST /api/pcap/upload`: PCAP/PCAPNG 파일 업로드 및 Suricata 분석 실행, 파싱 결과 DB 저장 (중복 건너뛰기 지원).
- `POST /api/ingest/sample`: 기본 샘플 데이터(`scenarios/sample_eve.json`) 수동 인제스트.
- `GET /api/alerts`: 탐지된 경보 목록 조회 (최신순 정렬, `severity` 필터, `limit`, `offset` 페이징).
- `GET /api/alerts/{id}`: 특정 경보 상세 조회 (카테고리별 대응 플레이북 매칭 포함).
- `PATCH /api/alerts/{id}/triage`: 경보 트리아지 정보 갱신 (`verdict`: TP/FP/UNREVIEWED, `confidence`: HIGH/MEDIUM/LOW, `observation`, `assessment`). 관찰 및 평가 입력 시 민감정보 마스킹 처리.
- `GET /api/live/status`: (선택 기능, 기본 꺼짐) 라이브 캡처 상태와 Suricata 시작/중지 안내 문자열 조회. 읽기 전용이며 꺼져 있어도 `enabled: false`로 응답.
- `GET /api/stats`: 전체 통계(전체 건수, 심각도별/카테고리별 건수, MITRE ATT&CK 커버리지) 및 로그 결측 탐지 사각지대 규칙(`blind_rules`) 목록 조회.

## 환경 변수 (기본값)

- `DB_PATH`: `backend/data/alerts.db`
- `UPLOAD_DIR`: `backend/data/uploads`
- `SURICATA_OUT_ROOT`: `backend/data/suricata`
- `RULES_PATH`: `rules/custom.rules` (규칙 추가 전 테스트 시 `backend/tests/fixtures/test_custom.rules` 사용 가능)
- `SURICATA_BIN`: `suricata`
- `SURICATA_TIMEOUT`: `120`
- `ALLOWED_ORIGINS`: `http://localhost:5500,http://127.0.0.1:5500`
- `SAMPLE_EVE_PATH`: `scenarios/sample_eve.json`
- `PLAYBOOKS_PATH`: `scenarios/playbooks.json`
- `RULE_CATALOG_PATH`: `rules/rule_catalog.json`
- `LIVE_CAPTURE_ENABLED`: 없음(꺼짐). `1`일 때만 라이브 캡처 폴링 스레드 시작. 그 외 값은 모두 꺼짐 (팀 합의 후 사용, [docs/live_capture_guide.md](../docs/live_capture_guide.md))
- `LIVE_EVE_PATH`: `backend/data/live/eve.json`
- `LIVE_POLL_SECONDS`: `2`

## 데이터 파일 및 중복 제거 동작

- `scenarios/sample_eve.json`, `scenarios/playbooks.json`, `rules/rule_catalog.json` 파일은 타 역할(시나리오/규칙 담당자)이 관리하는 파일입니다.
  - 해당 파일이 아직 없거나 유효하지 않은 경우:
    - `/api/ingest/sample` 호출 시 404 (`scenarios/sample_eve.json not found`) 반환
    - 경보 상세/목록의 `playbook` 필드는 `null` 반환
    - 통계의 `blind_rules`는 `[]` 반환 (서버 500 에러 발생 안 함)
- **재업로드/중복 방지 (Deduplication)**:
  - 1차 방어 (파일 해시 중복 방지): 동일한 PCAP 파일(동일 SHA-256 해시)이 재업로드되면 Suricata를 다시 실행하지 않고 즉시 이전 업로드의 저장 건수를 `duplicates_skipped`로, `alerts_stored=0`, `duplicate_of=<이전 upload_id>`를 반환합니다.
  - 2차 방어 (경보 식별 고유 인덱스): Suricata 실행 시마다 `flow_id` 해시 시드가 무작위로 변경되므로 고유 인덱스(`ux_alert_identity_v2`)에서는 `flow_id`를 제외하고 `(timestamp, sid, IFNULL(src_ip,''), IFNULL(dest_ip,''), IFNULL(dest_port,-1), IFNULL(raw_url,''))`를 기준으로 `INSERT OR IGNORE` 처리하여 중복 경보가 저장되지 않도록 방지합니다.
  - 기존 구버전 DB에 이미 중복 데이터가 들어가 고유 인덱스 생성이 실패할 경우 로그 경고가 남을 수 있으며, 이 경우 `backend/data/alerts.db`를 한 번 삭제하고 다시 실행하면 인덱스가 정상 생성됩니다.
