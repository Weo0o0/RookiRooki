# Backend

WSL에서 `uvicorn backend.main:app --port 8000`으로 실행합니다. `DB_PATH`, `UPLOAD_DIR`, `SURICATA_OUT_ROOT`, `RULES_PATH`, `SURICATA_BIN`, `SURICATA_TIMEOUT`, `ALLOWED_ORIGINS` 환경 변수를 설정할 수 있습니다. 테스트는 `python -m pytest backend/tests -q`입니다.

현재 엔드포인트는 `POST /api/pcap/upload`과 `GET /api/stats`만 있습니다. 기본값은 `DB_PATH=backend/data/alerts.db`, `UPLOAD_DIR=backend/data/uploads`, `SURICATA_OUT_ROOT=backend/data/suricata`, `RULES_PATH=rules/custom.rules`, `SURICATA_BIN=suricata`, `SURICATA_TIMEOUT=120`, `ALLOWED_ORIGINS=http://localhost:5500,http://127.0.0.1:5500`입니다. 규칙 소유자가 `rules/custom.rules`를 추가하기 전에는 `RULES_PATH=backend/tests/fixtures/test_custom.rules`를 사용할 수 있습니다.

Suricata가 `/etc/suricata/suricata.yaml`을 읽을 수 있어야 하며, 한 번 `sudo chmod 644 /etc/suricata/suricata.yaml`을 실행합니다.
