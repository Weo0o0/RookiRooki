# scenarios/sample_eve.json v2 기술 명세서 및 세션별 주석 해설

> **작업 위치 제안 (PM 합의 필요)**: 실습망 `scenarios/lab/`, pcap `scenarios/lab/pcaps/`, EVE 샘플 `scenarios/sample_eve.json`

팀 규격 v2(2026-11-24)에 맞춰 `ssrf`와 `c2_beacon`을 완전히 배제하고, **4대 공격 카테고리(`sqli`, `xss`, `bruteforce`, `portscan`)** 및 실습망(attacker `172.28.0.100`, victim-web `172.28.0.10`, victim-pc `172.28.0.11`)에 맞춘 명세서입니다.

---

## 1. 4대 공격 카테고리 매핑 요약 (총 8개 세션 / 16개 이벤트)

| Flow ID | 공격 카테고리 | SID | 대상 IP:포트 | 상태 / L4 상태 | 설명 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **2001001** | `sqli` | 1000001 | `172.28.0.10:80` | **200 OK** | `/login` SQLi 우회 성공 (PII: `password=`) |
| **2001002** | `sqli` | 1000001 | `172.28.0.10:80` | **403 Forbidden** | `/login` 실패 및 인라인 차단 (PII: `password=`) |
| **2001003** | `xss` | 1000002 | `172.28.0.10:80` | **200 OK** | `/search?q=` 반사형 XSS 성공 위험 |
| **2001004** | `xss` | 1000002 | `172.28.0.10:80` | **403 Forbidden** | WAF/보안필터 차단 가상 케이스 (EVE 전용) |
| **2001005** | `bruteforce`| 1000003 | `172.28.0.11:22` | TCP Established | SSH 무차별 대입 시도 허용 (암호화 페이로드 제외) |
| **2001006** | `bruteforce`| 1000003 | `172.28.0.11:22` | TCP Closed | SSH 무차별 대입 인라인 차단 |
| **2001007** | `portscan` | 1000004 | `172.28.0.10:80` | SYN Sweep / Reset | 단일 포트 정찰 시도 허용 |
| **2001008** | `portscan` | 1000004 | `172.28.0.11:8080`| SYN Sweep / Drop | 비인가 포트 정찰 방화벽 드롭(차단) |

---

## 2. 세션별 1줄 1주석 상세 해설

### [세션 1] SQL Injection (`sqli`) - 200 OK 성공 위험 (1~2행)
```javascript
// 1행: [HTTP 트랜잭션] victim-web(172.28.0.10)의 실제 app.py /login 엔드포인트 SQLi 로그인 시도
{"flow_id":2001001,"event_type":"http","src_ip":"172.28.0.100","src_port":52101,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","http":{"hostname":"lab-web.local","url":"/login?username=admin'%20OR%20'1'='1'%20--&password=DummyTestPass01","http_method":"GET","status":200}}
// 2행: [보안 탐지 알람] SQLi 룰(SID: 1000001) 실시간 탐지 알람 (Allowed)
{"flow_id":2001001,"event_type":"alert","src_ip":"172.28.0.100","src_port":52101,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"MINI-SIEM SQLi Injection Probe Detected","category":"sqli","severity":2}}
```

### [세션 2] SQL Injection (`sqli`) - 403 Forbidden 실패/차단 (3~4행)
```javascript
// 3행: [HTTP 트랜잭션] app.py 명세에 따른 로그인 실패 403 Forbidden 응답 트래픽
{"flow_id":2001002,"event_type":"http","src_ip":"172.28.0.100","src_port":52102,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","http":{"hostname":"lab-web.local","url":"/login?username=admin'/*comment*/--&password=DummyTestPass02","http_method":"GET","status":403}}
// 4행: [보안 탐지 알람] 인라인 보안장비에 의해 패킷이 차단된 알람 (Blocked)
{"flow_id":2001002,"event_type":"alert","src_ip":"172.28.0.100","src_port":52102,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":1000001,"rev":1,"signature":"MINI-SIEM SQLi Injection Probe Detected","category":"sqli","severity":2}}
```

### [세션 3] XSS (`xss`) - 200 OK 반사형 XSS 침투 위험 (5~6행)
```javascript
// 5행: [HTTP 트랜잭션] victim-web의 /search?q= 엔드포인트 반사형 XSS (실습 앱 기본 200 OK)
{"flow_id":2001003,"event_type":"http","src_ip":"172.28.0.100","src_port":52103,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","http":{"hostname":"lab-web.local","url":"/search?q=%3Cscript%3Ealert(1)%3C/script%3E","http_method":"GET","status":200}}
// 6행: [보안 탐지 알람] XSS 룰(SID: 1000002) 실시간 탐지 알람 (Allowed)
{"flow_id":2001003,"event_type":"alert","src_ip":"172.28.0.100","src_port":52103,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000002,"rev":1,"signature":"MINI-SIEM Reflected XSS Attempt","category":"xss","severity":2}}
```

### [세션 4] XSS (`xss`) - 403 Forbidden 가상 차단 케이스 (7~8행)
```javascript
// 7행: [HTTP 트랜잭션] XSS 차단 시나리오 검증용 가상 403 Forbidden 응답 트래픽 (EVE 전용)
{"flow_id":2001004,"event_type":"http","src_ip":"172.28.0.100","src_port":52104,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","http":{"hostname":"lab-web.local","url":"/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E","http_method":"GET","status":403}}
// 8행: [보안 탐지 알람] XSS 공격이 WAF에서 차단된 경보 (Blocked)
{"flow_id":2001004,"event_type":"alert","src_ip":"172.28.0.100","src_port":52104,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":1000002,"rev":1,"signature":"MINI-SIEM Reflected XSS Attempt","category":"xss","severity":2}}
```

### [세션 5] SSH Brute Force (`bruteforce`) - 세션 연결 시도 허용 (9~10행)
```javascript
// 9행: [L4 Flow 트랜잭션] victim-pc(172.28.0.11:22) 대상 SSH 무차별 대입 패킷 통계 (암호화로 비밀번호 페이로드 미포함)
{"flow_id":2001005,"event_type":"flow","src_ip":"172.28.0.100","src_port":52105,"dest_ip":"172.28.0.11","dest_port":22,"proto":"TCP","flow":{"pkts_toserver":28,"pkts_toclient":24,"bytes_toserver":2480,"bytes_toclient":2120,"state":"established"}}
// 10행: [보안 탐지 알람] SSH Brute Force 임계치 초과 탐지 알람 (SID: 1000003, Allowed)
{"flow_id":2001005,"event_type":"alert","src_ip":"172.28.0.100","src_port":52105,"dest_ip":"172.28.0.11","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000003,"rev":1,"signature":"MINI-SIEM SSH Brute Force Guessing Attempt","category":"bruteforce","severity":2}}
```

### [세션 6] SSH Brute Force (`bruteforce`) - 차단 성공 케이스 (11~12행)
```javascript
// 11행: [L4 Flow 트랜잭션] Fail2ban/방화벽에 의해 세션이 강제 종료된 통계
{"flow_id":2001006,"event_type":"flow","src_ip":"172.28.0.100","src_port":52106,"dest_ip":"172.28.0.11","dest_port":22,"proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":10,"bytes_toserver":1100,"bytes_toclient":920,"state":"closed"}}
// 12행: [보안 탐지 알람] 방화벽 정책에 의한 SSH 대입 공격 차단 기록 (Blocked)
{"flow_id":2001006,"event_type":"alert","src_ip":"172.28.0.100","src_port":52106,"dest_ip":"172.28.0.11","dest_port":22,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":1000003,"rev":1,"signature":"MINI-SIEM SSH Brute Force Guessing Attempt","category":"bruteforce","severity":2}}
```

### [세션 7] Port Scan (`portscan`) - 포트 스캔 허용/탐지 (13~14행)
```javascript
// 13행: [L4 Flow 트랜잭션] victim-web(172.28.0.10:80) SYN 스캔 패킷
{"flow_id":2001007,"event_type":"flow","src_ip":"172.28.0.100","src_port":52107,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":60,"bytes_toclient":40,"state":"closed","reason":"reset"}}
// 14행: [보안 탐지 알람] SYN Sweep 포트 스캐닝 탐지 알람 (SID: 1000004, Allowed)
{"flow_id":2001007,"event_type":"alert","src_ip":"172.28.0.100","src_port":52107,"dest_ip":"172.28.0.10","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000004,"rev":1,"signature":"MINI-SIEM Port Scan SYN Sweep Detected","category":"portscan","severity":3}}
```

### [세션 8] Port Scan (`portscan`) - 비인가 포트 스캔 드롭/차단 (15~16행)
```javascript
// 15행: [L4 Flow 트랜잭션] victim-pc(172.28.0.11:8080) 비인가 포트 탐색 패킷 드롭 통계
{"flow_id":2001008,"event_type":"flow","src_ip":"172.28.0.100","src_port":52108,"dest_ip":"172.28.0.11","dest_port":8080,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":60,"bytes_toclient":0,"state":"closed","reason":"drop"}}
// 16행: [보안 탐지 알람] 방화벽 정책에 의한 비인가 포트 스캔 차단 경보 (Blocked)
{"flow_id":2001008,"event_type":"alert","src_ip":"172.28.0.100","src_port":52108,"dest_ip":"172.28.0.11","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":1000004,"rev":1,"signature":"MINI-SIEM Port Scan SYN Sweep Detected","category":"portscan","severity":3}}
```
