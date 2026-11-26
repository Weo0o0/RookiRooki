# 라이브 캡처 ingest 가이드 (선택 기능, 기본 꺼짐, 팀 합의 후 사용)

> 이 기능은 README Backlog의 Stage 2 항목이며 **팀 합의 전까지 기본 꺼짐**입니다. `LIVE_CAPTURE_ENABLED=1`을 직접 지정한 경우에만 동작하고, 지정하지 않으면 기존 pcap 업로드·샘플 적재 흐름과 코드 경로가 완전히 같습니다(스레드 없음, 새 테이블 쓰기 없음).
> 공격 트래픽과 캡처는 **팀 격리 Docker 실습망(`172.28.0.0/24`) 안에서만** 합니다.
> 컨테이너 격리는 이 기능과 별개이며 `ISOLATION_ENABLED=1`로 따로 켭니다.

## 1. 동작 구조

```text
Suricata(라이브, br-minisiem) → backend/data/live/eve.json → 백엔드 폴링 스레드 → parse_eve → SQLite alerts
```

- 백엔드는 **Suricata를 시작하거나 멈추지 않으며 `sudo`를 호출하지 않습니다.** 브리지에서 라이브 캡처하려면 root 권한이 필요한데 백엔드가 `sudo` 권한을 갖게 하지 않기 위해, 시작·중지는 **사용자가 자기 Ubuntu 터미널에서 직접** 실행하는 안내 방식으로 정했습니다.
- 격리 기능은 `docker` 명령만 호출하며(`sudo` 없음, 사용자 계정이 `docker` 그룹이어야 함), Suricata는 여전히 건드리지 않습니다. 격리를 켠 서버는 `127.0.0.1` 바인딩, `--reload`·`--workers` 없는 단일 프로세스로 실행합니다.
- 백엔드는 `eve.json`만 읽습니다. `LIVE_POLL_SECONDS`(기본 2초)마다 저장해 둔 offset 이후의 **줄바꿈으로 끝난 완전한 줄만** 읽어 임시 파일에 쓰고, 기존 `parse_eve`로 파싱합니다(파싱·마스킹·SEV1 격상 규칙은 pcap 업로드와 동일).
- 저장은 `ingest_eve`와 같은 `INSERT OR IGNORE` SQL을 씁니다. `ingest_sources`, `ingest_meta`는 건드리지 않으므로 `/api/stats`의 `blind_rules` 계산은 바뀌지 않습니다.

## 2. 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `LIVE_CAPTURE_ENABLED` | (없음 = 꺼짐) | `1`일 때만 켜짐. `true`, `yes`, `0`, 빈 값 등 그 외는 모두 꺼짐 |
| `LIVE_EVE_PATH` | `backend/data/live/eve.json` | 읽을 eve 파일 경로 |
| `LIVE_POLL_SECONDS` | `2` | 폴링 간격(초). 잘못된 값이면 2 |

## 3. 켜는 방법 (터미널별 역할)

터미널 번호는 [설치_테스트_가이드](설치_테스트_가이드.md)의 표를 따르며, 이 기능에서만 `라이브_터미널.8`(Ubuntu)을 새로 씁니다.

| 번호 | 이름 | 역할 | `.venv` 필요 여부 |
|---:|---|---|---|
| 1 | `서버_터미널.1` | 백엔드 `uvicorn`(`:8000`) 실행 | 필요 |
| 3 | `요청_터미널.3` | `curl`로 상태·경보 확인 | 불필요 |
| 4 | `attacker_터미널.4` | 실습망 `docker compose`, `lab-traffic.sh` 실행 | 불필요 |
| 8 | `라이브_터미널.8` | Suricata 라이브 캡처 (`sudo`) | 불필요 |

새 Ubuntu 창은 Windows에서 **PowerShell 새 창 → `wsl -d Ubuntu` → `cd ~/RookiRooki`** 순서로 엽니다.

```powershell
wsl -d Ubuntu
```
```bash
cd ~/RookiRooki
```

1. `(attacker_터미널.4)` 실습망을 띄우고 브리지를 확인합니다.
   ```bash
   cd ~/RookiRooki/scenarios/lab
   docker compose up -d --build
   ip link show br-minisiem
   ```
   `br-minisiem`은 `docker-compose.yml`의 `com.docker.network.bridge.name`으로 고정한 브리지 이름입니다.
2. `(서버_터미널.1, .venv 필요)` 라이브 로그 폴더를 **일반 사용자 권한으로** 만들고, 플래그를 켜서 백엔드를 실행합니다. **uvicorn은 `--reload`와 `--workers` 없이 프로세스 1개로 실행합니다**(폴링 스레드가 중복으로 생기지 않게 하기 위함).
   ```bash
   cd ~/RookiRooki
   source .venv/bin/activate
   mkdir -p backend/data/live
   LIVE_CAPTURE_ENABLED=1 uvicorn backend.main:app --port 8000
   ```
3. `(라이브_터미널.8, .venv 불필요)` Suricata를 라이브로 시작합니다. 아래 명령은 `GET /api/live/status`의 `start_command`와 같습니다.
   ```bash
   cd ~/RookiRooki
   sudo suricata -i br-minisiem -S rules/custom.rules -l backend/data/live -k none --user $(id -un) --group $(id -gn) 'net 172.28.0.0/24'
   ```
   | 옵션 | 의미 |
   |---|---|
   | `-i br-minisiem` | 해당 인터페이스를 라이브로 캡처 |
   | `-S rules/custom.rules` | 커스텀 룰만 단독으로 로드 (pcap 업로드와 동일) |
   | `-l backend/data/live` | 로그(`eve.json`) 저장 폴더. `LIVE_EVE_PATH`의 폴더와 같아야 함 |
   | `-k none` | 체크섬 검사 끔 (pcap 업로드와 동일) |
   | `--user`, `--group` | 초기화 후 현재 사용자 권한으로 전환해 `eve.json`을 백엔드가 읽을 수 있게 함 |
   | `'net 172.28.0.0/24'` | BPF 필터. 실습망 트래픽만 캡처 |
4. `(attacker_터미널.4)` 트래픽을 발생시킵니다.
   ```bash
   docker exec attacker /lab/lab-traffic.sh
   ```
5. `(요청_터미널.3)` 상태와 경보를 확인합니다.
   ```bash
   curl -sS http://localhost:8000/api/live/status | python3 -m json.tool
   curl -sS "http://localhost:8000/api/alerts?limit=50" | python3 -m json.tool
   ```

`GET /api/live/status` 응답: `enabled`, `eve_path`, `offset`, `last_poll_at`, `rows_stored`(이번 백엔드 실행 중 저장 건수), `rows_skipped_out_of_scope`, `last_error`(예외 종류만), `start_command`, `stop_command`. 읽기 전용이며 꺼져 있어도 `enabled: false`로 응답합니다.

## 4. 끄는 방법

- Suricata 중지: `(라이브_터미널.8)`에서 `Ctrl+C`. 다른 창에서 멈춰야 하면 이 Suricata만 지정해서 종료합니다.
  ```bash
  sudo pkill -f '^suricata -i br-minisiem'
  ```
  `^`로 시작하는 패턴이라 `sudo` 명령줄 자체나 다른 프로세스는 종료 대상이 아닙니다.
- 백엔드의 읽기 중지: `(서버_터미널.1)`에서 `Ctrl+C` 후 `LIVE_CAPTURE_ENABLED` 없이 다시 실행합니다. 이미 저장된 경보와 offset은 그대로 남습니다.
- 실습 종료: `(attacker_터미널.4)`에서 `docker compose down`.

## 5. offset과 중복 방지 규칙

- offset은 eve 파일 경로별로 SQLite 새 테이블 `live_capture_state`에 저장합니다(이 테이블은 기능을 켰을 때만 만들어집니다). 백엔드를 재시작해도 이미 읽은 줄은 다시 읽지 않습니다.
- 마지막 줄이 줄바꿈 없이 끝나 있으면(쓰는 중) 그 줄은 읽지 않고 다음 폴링을 기다립니다.
- 파일 크기가 저장된 offset보다 작으면(로테이션·삭제 후 재생성·truncate) offset을 0으로 되돌립니다.
- 2차 방어는 기존 고유 인덱스 `ux_alert_identity_v2`입니다. offset이 어긋나 같은 줄을 다시 읽어도 `INSERT OR IGNORE`로 중복 저장되지 않습니다.
- 한 번에 최대 8MiB까지만 읽고 나머지는 다음 폴링에서 이어 읽습니다.

## 6. 172.28.0.0/24 필터

- Suricata 쪽 BPF 필터(`net 172.28.0.0/24`)로 1차로 거르고, 백엔드는 `ipaddress` 모듈로 **`src_ip`와 `dest_ip`가 둘 다 `172.28.0.0/24` 안인 경보만** 저장합니다.
- 범위 밖이거나 IP가 없거나 형식이 잘못된 경보는 저장하지 않고 `rows_skipped_out_of_scope`에 개수만 더합니다.

## 7. 한계

- **다른 배치에 걸친 http 매칭**: `parse_eve`는 한 파일 안에서 `alert`와 `http`를 flow로 맞춥니다. 라이브에서는 배치마다 파싱하므로, 이전 배치에 있던 `http` 이벤트는 최근 200줄까지만 앞에 붙여서 맞춥니다. 반대로 `alert`가 먼저 저장되고 해당 요청의 `http` 이벤트가 나중 배치에 도착하면, 그 배치를 저장할 때 `flow_id`가 같고 `http_status`가 비어 있는 `sqli`·`xss`·`ssrf` 행의 `http_status`, `severity`, `is_confirmed_risk`만 갱신합니다(상태 200이면 SEV1·`is_confirmed_risk=1`, 그 외 상태는 SEV3 유지하고 `http_status`만 기록). 두 이벤트에 URL이 모두 있으면 마스킹한 URL이 같을 때만 갱신하며, 행을 새로 만들지 않으므로 중복이 생기지 않습니다. 남은 한계: 이미 `http_status`가 채워진 행은 다시 바꾸지 않고, 백엔드 재시작 등으로 그 `http` 이벤트를 읽기 전에 offset이 지나갔다면 갱신되지 않으며, Suricata가 `alert`를 `http`보다 먼저 기록하는 빈도는 이 저장소에서 실측하지 않았으니 실습망에서 확인이 필요합니다.
- `http` 문맥은 메모리에만 있어 백엔드를 재시작하면 비워집니다.
- 로테이션 후 새 파일이 이미 저장된 offset보다 커져 있으면 감지하지 못합니다(크기 비교만 사용).
- 읽는 파일은 `LIVE_EVE_PATH` 하나이며, Suricata가 살아 있는지는 확인하지 않습니다(`offset`과 `last_poll_at`으로만 추정).
- 폴링 스레드는 프로세스마다 하나씩 생기므로 백엔드는 프로세스 1개로 실행합니다.
- `eve.json`은 계속 커집니다. 로그 폴더(`backend/data/`)는 `.gitignore` 대상이며 커밋하지 않습니다.
