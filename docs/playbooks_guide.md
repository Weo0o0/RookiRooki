# scenarios/playbooks.json v2 기술 명세서 및 1줄 1주석 해설

> **작업 위치 제안 (PM 합의 필요)**: 실습망 `scenarios/lab/`, pcap `scenarios/lab/pcaps/`, 플레이북 `scenarios/playbooks.json`

팀 규격 v2(2026-11-24)에 맞춰 **6종 공격 카테고리(`sqli`, `xss`, `bruteforce`, `portscan`, `c2_beacon`, `ssrf`)** 및 실습망 격리 환경(172.28.0.0/24)에 맞춘 관제 플레이북 기술 명세서입니다.

---

## 1. 플레이북 v2 요약표

| 공격 카테고리 | SID | 타깃 자산 및 포트 | 심각도 | Linux 방화벽 대응 (iptables / ufw) |
| :--- | :--- | :--- | :--- | :--- |
| **`sqli`** | 1000001 | victim-web (172.28.0.10:80) | HIGH | 웹 소켓/웹로그 검증 ➔ 포트 80 차단 ➔ 원복 |
| **`xss`** | 1000002 | victim-web (172.28.0.10:80) | MEDIUM | 스크립트 문자열 검증 ➔ 포트 80 차단 ➔ 원복 |
| **`bruteforce`** | 1000003 | victim-pc (172.28.0.11:22) | HIGH | SSH 실패 로그(`/var/log/auth.log`) 검증 ➔ 22 차단 ➔ 원복 |
| **`portscan`** | 1000004 | web/pc (172.28.0.10, 11) | MEDIUM | SYN-RECV 소켓 검증 ➔ IP 전면 차단 ➔ 원복 |
| **`c2_beacon`** | 1000005 | victim-web (172.28.0.10:8443) | MEDIUM | 소켓/최근 로그 검증 ➔ 대상 포트 차단 ➔ 원복 |
| **`ssrf`** | 1000006 | victim-web (172.28.0.10:80) | HIGH | 소켓/웹로그 검증 ➔ 포트 80 차단 ➔ 원복 |

---

## 2. 플레이북별 1줄 1주석 상세 해설

---

### [플레이북 1] SQL Injection (`sqli`, SID: 1000001)

```javascript
{
  "category": "sqli",                                   // [카테고리] SQL 인젝션 공격 분류 키 (rule_catalog와 일치)
  "sid": 1000001,                                       // [SID 매핑] Suricata EVE 로그의 signature_id: 1000001과 1:1 매칭
  "name": "SQL 인젝션(SQLi) 관제 및 침해대응 플레이북",     // [제목] 관제 대시보드 모달에 표시되는 공식 대응 절차 명칭
  "severity": "HIGH",                                   // [심각도] 데이터베이스 내부 정보 유출 위험으로 High 지정
  "description": "웹 애플리케이션 입력값 검증 부재를 악용한 SQL 인젝션 공격 시도 및 데이터베이스 정보 유출 탐지 시 대응 절차", // [개요] 위협 요약 설명
  "preserve_evidence_first": "서버 재부팅, 웹 서비스 재기동, 방화벽 차단 전 반드시 비정상 세션 현황(`ss -tanp`), 웹서버 접근/에러 로그 사본(`/var/log/nginx/` 또는 `/var/log/apache2/`), DB 쿼리 감사 로그 사본을 먼저 안전한 격리 스토리지로 백업 및 보존할 것.", // [증거보존] 재부팅 금지 및 소켓/웹/DB 감사 로그 선 백업 지침
  "actions": {
    "linux": {
      "verify": "ss -tanp '( sport = :{{DEST_PORT}} and src {{SRC_IP}} )' && tail -n 50 /var/log/nginx/access.log | grep '{{SRC_IP}}'", // [검증] 공격자 IP와 웹서버 간 활성 소켓 및 웹로그 교차 확인 (오탐 방지)
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP",                                                  // [차단] 방화벽 INPUT 1번 최우선 순위로 공격자 IP의 웹 포트 접근 즉시 드롭
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP"                                                  // [원복] 오탐 차단 발생 시 해당 차단 룰만 지정 삭제하여 정상 서비스 복구
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",                                                                                 // [검증] Ubuntu UFW 방화벽 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp",                                                    // [차단] UFW 최상단 1번에 해당 웹 포트 차단 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp"                                                    // [원복] UFW에 등록된 차단 정책 즉시 회수
    }
  }
}
```

---

### [플레이북 2] Reflected XSS (`xss`, SID: 1000002)

```javascript
{
  "category": "xss",                                    // [카테고리] 반사형 크로스 사이트 스크립팅 공격 분류 키
  "sid": 1000002,                                       // [SID 매핑] Suricata EVE 로그의 signature_id: 1000002와 매칭
  "name": "반사형 크로스 사이트 스크립팅(Reflected XSS) 관제 및 대응 플레이북", // [제목] 대시보드 표출용 플레이북 명칭
  "severity": "MEDIUM",                                 // [심각도] 사용자 세션 쿠키 탈취 및 악성 스크립트 실행 위험
  "description": "웹 파라미터(예: /search?q=)를 통한 악성 스크립트 삽입 및 세션 쿠키 탈취 시도 탐지 시 대응 절차", // [개요] 위협 요약 설명
  "preserve_evidence_first": "웹 데몬을 즉시 재시작하지 말고, 웹서버 액세스 로그에서 공격자가 주입한 악성 스크립트 문자열 및 Referer 헤더 사본을 먼저 확보할 것.", // [증거보존] 데몬 종료 금지 및 웹서버 파라미터 주입 로그 사본 선 확보
  "actions": {
    "linux": {
      "verify": "ss -tanp '( sport = :{{DEST_PORT}} and src {{SRC_IP}} )' && tail -n 50 /var/log/nginx/access.log | grep -E '(script|alert|onerror)'", // [검증] 소켓 상태 및 웹로그에서 XSS 인젝션 패턴 교차 확인
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP",                                                  // [차단] 공격자 IP에 대한 웹 서비스 접근 즉시 드롭
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP"                                                  // [원복] 오탐 시 해당 차단 룰 삭제
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",                                                                                 // [검증] UFW 방화벽 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp",                                                    // [차단] UFW 최상단 1번에 웹 포트 접근 거부 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp"                                                    // [원복] 등록된 차단 룰 삭제
    }
  }
}
```

---

### [플레이북 3] SSH Brute Force (`bruteforce`, SID: 1000003)

```javascript
{
  "category": "bruteforce",                             // [카테고리] SSH 무차별 대입 공격 분류 키
  "sid": 1000003,                                       // [SID 매핑] Suricata EVE 로그의 signature_id: 1000003과 매칭
  "name": "SSH 무차별 대입(Brute Force) 관제 및 침해대응 플레이북", // [제목] 대시보드 표출용 플레이북 명칭
  "severity": "HIGH",                                   // [심각도] 서버 계정 탈취 및 원격 셸 장악 위험으로 High 지정
  "description": "victim-pc(172.28.0.11:22)를 대상으로 다수의 패스워드 대입을 통한 비인가 원격 셸 탈취 시도 탐지 시 대응 절차", // [개요] 위협 요약 설명
  "preserve_evidence_first": "서버 재부팅 금지. 현재 SSH 로그인 세션(`who`, `w`)과 실패 인증 감사 로그 사본(`/var/log/auth.log` 또는 `/var/log/secure`)을 우선 채증할 것.", // [증거보존] 재부팅 금지 및 SSH 활성 사용자 세션/인증 감사 로그 선 확보
  "actions": {
    "linux": {
      "verify": "ss -tanp '( sport = :{{DEST_PORT}} and src {{SRC_IP}} )' && tail -n 50 /var/log/auth.log | grep 'Failed password'",     // [검증] SSH 22번 포트 활성 소켓 및 인증 실패(Failed password) 다발 로그 확인
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP",                                                  // [차단] 방화벽 INPUT 1번에 공격자 IP의 SSH(22) 포트 접속 즉각 차단
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP"                                                  // [원복] 관리자 오탐 차단 발생 시 SSH 차단 룰 즉시 해제
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",                                                                                 // [검증] UFW 방화벽 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp",                                                    // [차단] UFW 최상단 1번에 SSH 포트 거부 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp"                                                    // [원복] 등록된 SSH 차단 룰 삭제
    }
  }
}
```

---

### [플레이북 4] Port Scan (`portscan`, SID: 1000004)

```javascript
{
  "category": "portscan",                               // [카테고리] 포트 스캔 및 SYN 정찰 분류 키
  "sid": 1000004,                                       // [SID 매핑] Suricata EVE 로그의 signature_id: 1000004와 매칭
  "name": "포트 스캔(Port Scan / SYN Sweep) 관제 및 사전 차단 플레이북", // [제목] 대시보드 표출용 플레이북 명칭
  "severity": "MEDIUM",                                 // [심각도] 공격 사전 단계(Reconnaissance)이므로 Medium 지정
  "description": "실습망 자산(172.28.0.10, 172.28.0.11)의 오픈 포트 및 서비스 식별을 위한 무차별 SYN 정찰 패킷 탐지 시 대응 절차", // [개요] 위협 요약 설명
  "preserve_evidence_first": "방화벽 차단 전 실시간 비정상 SYN-RECV 소켓 상태 사본을 추출하고 패킷 덤프 사본을 우선 보존할 것.", // [증거보존] 미완결 반가상(SYN-RECV) 소켓 덤프 선 채증
  "actions": {
    "linux": {
      "verify": "ss -tan state syn-recv '( src {{SRC_IP}} )' && iptables -L INPUT -n -v | grep '{{SRC_IP}}'",                           // [검증] 공격자 IP로부터 들어온 비정상 SYN 대기 소켓 및 기존 방화벽 차단 이력 조회
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -j DROP",                                                                               // [차단] 특정 포트가 아닌 공격자 IP로부터 들어오는 모든 L4 패킷 전면 드롭
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -j DROP"                                                                               // [원복] IP 전면 차단 룰 삭제 복구
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",                                                                                 // [검증] UFW 방화벽 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any",                                                                                 // [차단] UFW 최상단에 해당 IP 발 모든 인바운드 거부 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any"                                                                                 // [원복] 등록된 IP 차단 룰 삭제
    }
  }
}
```

---

### [플레이북 5] C2 Beacon (`c2_beacon`, SID: 1000005)

```javascript
{
  "category": "c2_beacon",  // [카테고리] C2 비콘 분류 키
  "sid": 1000005,  // [SID 매핑] EVE 로그의 signature_id: 1000005와 매칭
  "name": "C2 beacon repeated connection",  // [제목] 대시보드 표출용 플레이북 명칭
  "severity": "MEDIUM",  // [심각도] Medium 지정
  "description": "Repeated TCP connections from attacker 172.28.0.100 to victim-web 172.28.0.10:8443 within the agreed 30-second window.",  // [개요] 공격자 172.28.0.100 → victim-web 172.28.0.10:8443 반복 TCP 연결 요약
  "preserve_evidence_first": "Preserve the pcap and connection timestamps first; collect the relevant service and network logs before blocking the source.",  // [증거보존] 차단 전 pcap, 연결 시각, 서비스/네트워크 로그 선 확보
  "actions": {
    "linux": {
      "verify": "ss -tanp '( sport = :{{DEST_PORT}} and src {{SRC_IP}} )' && journalctl --since '-5 min' | tail -n 50",  // [검증] 활성 소켓 및 로그 교차 확인
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP",  // [차단] INPUT 1번에 공격자 IP의 대상 포트 접근 드롭
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP"  // [원복] 오탐 시 해당 차단 룰만 삭제
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",  // [검증] UFW 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp",  // [차단] UFW 최상단에 대상 포트 거부 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp"  // [원복] 등록된 차단 룰 삭제
    }
  }
}
```

---

### [플레이북 6] SSRF (`ssrf`, SID: 1000006)

```javascript
{
  "category": "ssrf",  // [카테고리] SSRF 분류 키
  "sid": 1000006,  // [SID 매핑] EVE 로그의 signature_id: 1000006과 매칭
  "name": "SSRF internal resource access",  // [제목] 대시보드 표출용 플레이북 명칭
  "severity": "HIGH",  // [심각도] High 지정
  "description": "The /fetch?url= endpoint receives an internal URL; access to http://172.28.0.10/health returns HTTP 200, while the failed case is mapped to HTTP 403.",  // [개요] /fetch?url= 내부 URL 요청 요약 (성공 200, 실패 403 매핑)
  "preserve_evidence_first": "Preserve the request URL, HTTP status, application logs, and pcap first; collect evidence before blocking the source.",  // [증거보존] 차단 전 요청 URL, HTTP 상태, 앱 로그, pcap 선 확보
  "actions": {
    "linux": {
      "verify": "ss -tanp '( sport = :{{DEST_PORT}} and src {{SRC_IP}} )' && tail -n 50 /var/log/nginx/access.log | grep '{{SRC_IP}}'",  // [검증] 활성 소켓 및 로그 교차 확인
      "block": "iptables -I INPUT 1 -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP",  // [차단] INPUT 1번에 공격자 IP의 대상 포트 접근 드롭
      "rollback": "iptables -D INPUT -s {{SRC_IP}} -p tcp --dport {{DEST_PORT}} -j DROP"  // [원복] 오탐 시 해당 차단 룰만 삭제
    },
    "ufw": {
      "verify": "ufw status numbered | grep '{{SRC_IP}}'",  // [검증] UFW 룰 번호 및 정책 상태 확인
      "block": "ufw insert 1 deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp",  // [차단] UFW 최상단에 대상 포트 거부 룰 삽입
      "rollback": "ufw delete deny from {{SRC_IP}} to any port {{DEST_PORT}} proto tcp"  // [원복] 등록된 차단 룰 삭제
    }
  }
}
```
