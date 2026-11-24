# Backend

WSL에서 `uvicorn backend.main:app --port 8000`으로 실행합니다. `DB_PATH`, `UPLOAD_DIR`, `SURICATA_OUT_ROOT`, `RULES_PATH`, `SURICATA_BIN`, `SURICATA_TIMEOUT`, `ALLOWED_ORIGINS` 환경 변수를 설정할 수 있습니다. 테스트는 `python -m pytest backend/tests -q`입니다.

Suricata가 `/etc/suricata/suricata.yaml`을 읽을 수 있어야 하며, 한 번 `sudo chmod 644 /etc/suricata/suricata.yaml`을 실행합니다. 임시 테스트 규칙은 `backend/tests/fixtures/test_custom.rules`에 있습니다.
