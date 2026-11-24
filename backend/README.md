# 백엔드 (Stage 1 뼈대)

FastAPI + sqlite3 + Pydantic v2. 지금 들어 있는 API는 `POST /api/pcap/upload`와 `GET /api/stats`입니다. 나머지 API(`/api/ingest/sample`, `/api/alerts` 등)는 아직 없습니다.

## 실행 (호스트 WSL2 Ubuntu)

FastAPI와 Suricata는 호스트 WSL2 Ubuntu에서 실행하고, Docker 컨테이너는 실습망만 맡습니다.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --port 8000   # 저장소 루트에서 실행
```

- Suricata는 `/etc/suricata/suricata.yaml`을 읽어야 합니다. 읽기 권한이 없으면 업로드가 502로 실패하니, 실행 전에 직접 한 번 `sudo chmod 644 /etc/suricata/suricata.yaml`로 열어 두세요. 코드에는 sudo가 없습니다.
- 분석 명령은 고정입니다: `suricata -r <업로드파일> -S rules/custom.rules -l <출력폴더> -k none`
- `rules/custom.rules`가 없으면 업로드는 500을 돌려줍니다. 룰 담당자가 파일을 올리기 전에는 `RULES_PATH=backend/tests/fixtures/test_custom.rules`로 임시 테스트 룰을 쓸 수 있습니다.

## 환경 변수 (모두 선택)

| 이름 | 기본값 |
|---|---|
| `DB_PATH` | `backend/data/alerts.db` |
| `UPLOAD_DIR` | `backend/data/uploads` |
| `SURICATA_OUT_ROOT` | `backend/data/suricata_out` |
| `RULES_PATH` | `rules/custom.rules` |
| `SURICATA_BIN` | `suricata` |
| `SURICATA_TIMEOUT` | `120` (초) |
| `ALLOWED_ORIGINS` | `http://localhost:5500,http://127.0.0.1:5500` (와일드카드 `*`는 무시) |

## 테스트

```bash
python -m pytest backend/tests -q
```

Suricata 호출은 테스트에서 가짜로 바꿔 실행하므로 Suricata 없이도 돌아갑니다.
