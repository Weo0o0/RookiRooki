# Backend

WSL에서 `uvicorn backend.main:app --port 8000`으로 실행합니다. 테스트는 `python -m pytest backend/tests -q`입니다.

## 엔드포인트 목록

- `POST /api/pcap/upload`: PCAP/PCAPNG 파일 업로드 및 Suricata 분석 실행, 파싱 결과 DB 저장 (중복 건너뛰기 지원).
- `POST /api/ingest/sample`: 기본 샘플 데이터(`scenarios/sample_eve.json`) 수동 인제스트.
- `GET /api/alerts`: 탐지된 경보 목록 조회 (최신순 정렬, `severity` 필터, `limit`, `offset` 페이징, `include_fp`: `0`/`1`, 기본 `0`은 `verdict=FP` 제외, `total`도 같은 기준).
- `GET /api/alerts/{id}`: 특정 경보 상세 조회 (카테고리별 대응 플레이북 매칭 포함).
- `PATCH /api/alerts/{id}/triage`: 경보 트리아지 정보 갱신 (`verdict`: TP/FP/UNREVIEWED, `confidence`: HIGH/MEDIUM/LOW, `observation`, `assessment`, `analyst`: 최대 50자, `action_status`: ISOLATED/GUIDE_ONLY/NONE). 관찰 및 평가 입력 시 민감정보 마스킹 처리.
- `GET /api/live/status`: (선택 기능, 기본 꺼짐) 라이브 캡처 상태와 Suricata 시작/중지 안내 문자열 조회. 읽기 전용이며 꺼져 있어도 `enabled: false`로 응답.
- `POST /api/isolate`: (선택 기능, 기본 꺼짐) 본문 `alert_id`와 1회용 `token`으로 승인된 격리 실행. 대상은 `172.28.0.100`의 `attacker` 컨테이너뿐.
- `POST /api/unisolate`: (선택 기능, 기본 꺼짐) 본문 `alert_id` 또는 `ip` 중 하나로 격리 해제. 해제 뒤 IP `172.28.0.100` 유지를 확인.
- `GET /api/isolation/status`: 격리 상태와 최근 이력 조회. 읽기 전용이며 꺼져 있으면 docker를 호출하지 않고 `enabled: false`로 응답.
- `GET /api/stats`: 전체 통계(전체 건수, 심각도별/카테고리별 건수, MITRE ATT&CK 커버리지, `include_fp`: `0`/`1`, 기본 `0`은 FP 제외) 및 로그 결측 탐지 사각지대 규칙(`blind_rules`) 목록 조회.

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
- `ISOLATION_ENABLED`: 없음(꺼짐). `1`일 때만 격리·해제 API와 `isolation_token` 발급이 동작. 그 외 값은 모두 꺼짐
- `DOCKER_BIN`: `docker` (테스트용 대체 이름. 운영자가 정하는 값이며 요청 값이 아님)

## 격리 사용 조건 (선택 기능)

- 격리를 켜려면 `ISOLATION_ENABLED=1`을 직접 지정합니다. 기본(꺼짐)에서는 docker를 호출하지 않으며 경보의 `isolation_token`은 항상 `null`입니다.
- `--reload`·`--workers` 없이 프로세스 1개로 실행합니다. 토큰이 서버 메모리에 있어 여러 프로세스에서는 맞지 않고, 서버를 다시 켜면 토큰이 사라집니다.
- 격리를 켠 서버는 `--host 0.0.0.0`으로 열지 않고 기본 `127.0.0.1` 바인딩을 유지합니다. 토큰이 경보 조회 응답에 들어 있기 때문입니다.
- 백엔드는 `docker` 명령만 호출하며 `sudo`를 쓰지 않습니다. 사용자 계정이 `docker` 그룹이어야 합니다(권한이 없으면 API가 503 `Docker permission denied`를 돌려줌). `docker` 그룹은 사실상 root 권한이므로 실습 PC에서만 사용합니다. 이 안내는 문서로만 두며 코드·compose는 바꾸지 않습니다.
- 대상은 실습망 `mini-siem-net`의 `attacker`(`172.28.0.100`) 한 대뿐입니다. 토큰은 SEV1 경보, 허용 IP, 경보 시각 5분 이내일 때만 발급되고, 1회용이며 10분 뒤 만료됩니다. docker가 실패하면 토큰은 소모되지 않습니다.
- 자동 해제는 없습니다. 해제는 `POST /api/unisolate`로 합니다. 해제 뒤에는 서버가 IP를 확인하지만, 실제 컨테이너가 `172.28.0.100`을 유지하는지 사람이 한 번 더 확인합니다.

```bash
docker inspect -f '{{(index .NetworkSettings.Networks "mini-siem-net").IPAddress}}' attacker   # 172.28.0.100이어야 함
```

- 격리된 채 남았을 때 수동 복구(실습 PC의 터미널에서 직접 실행):

```bash
docker network connect --ip 172.28.0.100 mini-siem-net attacker
# 그래도 안 되면 컨테이너 재생성
cd ~/RookiRooki/scenarios/lab && docker compose up -d --force-recreate attacker
```

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
- `analyst`/`action_status` 컬럼은 서버가 시작할 때 자동으로 추가되므로 DB를 삭제할 필요가 없습니다.
