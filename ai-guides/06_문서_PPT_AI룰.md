# 문서·PPT 담당 AI 룰

> 사용법: 아래 「AI 룰」 전체를 AI 대화창 맨 앞에 붙여 넣고, 그 다음에 질문과 고칠 문서·슬라이드 초안을 붙여 넣으세요.
> 기준: 최신 main `0a70475` (PR #10 머지 후). 담당 파일은 `README.md`, `docs/ARCHITECTURE.md`, `ai-guides/*` 입니다. 숫자는 팀이 알려 준 것만 씁니다.

## 꼭 기억할 5가지
1. 시나리오는 6종입니다. 저장소와 가이드에 남아 있는 “4종만”, “ssrf·c2_beacon은 사용하지 않음” 문구를 고칩니다. SID 철자를 바꾸지 마세요.
2. 공식 샘플·pcap 건수, 테스트 개수, C2 횟수·경로처럼 **아직 확정되지 않은 숫자는 지어내지 마세요.** 슬라이드에는 「확인 후 기입」 또는 팀이 준 값만 넣습니다.
3. 차별화 4개는 그대로입니다: 200 OK 격상, `[MASKED]`, OSI 흐름·CLI 안내, PCAP 룰 테스트·MITRE 커버리지.
4. 화면 캡처는 **프론트 수정 PR이 머지된 뒤**에 찍습니다. Live 목록이 비는 버그가 있는 지금 화면을 최종 자료로 쓰지 마세요.
5. `docs/playbooks_guide.md`와 `docs/sample_eve_guide.md`는 시나리오 담당입니다. README, ARCHITECTURE, ai-guides만 이 역할이 고칩니다.

## 이번에 할 일

| 우선 | 위치 | 할 일 |
|---|---|---|
| 필수 | `README.md:34-47`, `:52-55`, `:157`, `:262` | 4종·“ssrf와 c2_beacon은 사용하지 않습니다”·스토리 MVP 4종 문구를 6종 표로 바꿉니다. 옛 매핑(ssrf=1000002, c2_beacon=1000003)과 지금 SID가 섞이지 않게 하세요. |
| 필수 | `docs/ARCHITECTURE.md:44`, `:112-120`, `:155`, `:166`, `:182-183`, `:215` | 4종 표와 category 설명을 6종으로 갱신합니다. 215행의 ssrf·c2_beacon Backlog 표기는 본선 범위로 올립니다. ssrf 200 격상을 명시하세요. |
| 필수 | `ai-guides/*` | “4종만, ssrf·c2_beacon은 사용하지 않음”을 6종 확정값으로 교체합니다. |
| 필수 | 아키텍처 그림 | 실습망 → 녹화 → 업로드 → suricata -r → 파싱·격상·마스킹 → SQLite → 웹. 실시간 캡처처럼 그리지 마세요. |
| 필수 | PPT | 6종 표, 차별화 4개, 시연 순서, Backlog 슬라이드. MITRE 가안은 “가안”이라고 적습니다. |
| 필수 | 화면 캡처 | 프론트(Live 버그 3개 + 6종 UI) 머지 후. Mock과 Live를 구분해 찍습니다. |
| 하지 말 것 | 미확정 건수를 표에 기입 | 현재 확정된 참고값만 쓸 수 있습니다: 공식 샘플 경보 12건(SEV1 3 / SEV2 4 / SEV3 5, PR #13 기준), pcap(c2_ssrf.pcap)에 룰을 적용하면 7건, lab_capture.pcap은 4종 각 1건(PR #10). 테스트 개수처럼 아직 비어 있는 값은 공란. |
| 하지 말 것 | `backend/`, `frontend/index.html`, `rules/`, `scenarios/` , 시나리오 가이드 2개 | 다른 역할 파일입니다. 바꿔야 하면 「PM 합의 필요」만 적으세요. |

머지 순서에서 문서 PR은 **마지막**입니다. 기능 PR이 올라온 뒤 한 번에 맞추는 것이 충돌이 적습니다. `main`에 직접 푸시하지 마세요.

## 셀프 테스트 명령어

Windows에서 Ubuntu를 연 다음 확인하세요.

(PowerShell) — `.venv` 불필요
```powershell
wsl -d Ubuntu
```

(요청) — `.venv` 불필요
```bash
cd ~/RookiRooki
git checkout main
git pull origin main
# 문서 전용 기능 브랜치에서 작업하세요.

# 4종 잔여 문구가 남았는지 살펴봅니다. 맞아 없어야 할 표현이 있으면 고칩니다.
# (확정 전 건수를 새로 써 넣지는 마세요.)
grep -n '4종만\|사용하지 않음\|c2_beacon은 사용하지\|아래 4종뿐' README.md docs/ARCHITECTURE.md ai-guides/* || true

# SID 표가 서로 다른지 빠르게 봅니다.
grep -n '1000005\|1000006\|c2_beacon\|ssrf' README.md docs/ARCHITECTURE.md | head
```

화면 캡처는 (프론트)에서 `python3 -m http.server 5500`, (서버)에서 백엔드를 띄운 뒤 `http://localhost:5500`에서 찍습니다. 프론트 수정이 머지되기 전 Live 빈 목록 화면은 최종 슬라이드에 넣지 마세요.

## 문제 보고 양식

```
1. 어떤 문서·슬라이드인가요?
2. 어떤 문구·숫자가 의심되나요?
3. 그 숫자를 누가, 언제 알려 줬나요? (없으면 「확인 전」)
4. 관련 파일 경로와 브랜치
```

---

## AI 룰 (여기부터 끝까지 복사)

```text
당신은 Mini-SIEM(저장소 Weo0o0/RookiRooki)의 문서·발표 자료 담당을 돕는 안내자입니다. 팀이 알려 준 숫자만 쓰고, 없는 값을 지어내지 마세요. 고칠 파일은 README.md, docs/ARCHITECTURE.md, ai-guides/ 뿐입니다.

docs/playbooks_guide.md 와 docs/sample_eve_guide.md 는 시나리오 담당입니다. backend/, frontend/, rules/, scenarios/ 는 PM 합의 없이 변경하지 말 것.

## 프로젝트 맥락
기준은 origin/main 0a70475 (PR #10 머지 후)입니다.
실습망 172.28.0.0/24, attacker 172.28.0.100, victim-web 172.28.0.10, victim-pc 172.28.0.11.
Stage 1 흐름: 실습망 공격 → 브리지 녹화 → POST /api/pcap/upload → suricata -r → 파싱·마스킹·격상 → SQLite → 웹(Mock/Live).
작업은 기능 브랜치에서 하고 PR로만 올립니다. main에 직접 푸시하지 마세요.
머지 순서: PM 결정 기록 → 시나리오 8080 선행 → 룰 → 시나리오(pcap·샘플·플레이북·SSRF 페이지) → 백엔드 → 프론트 → 문서(마지막).
Day3 18:00 Feature Freeze, Day4 시연.

## 고정 규칙 (6종 표) — 철자와 SID를 바꾸지 말 것
- sqli 1000001. 기본 SEV3. 해당 요청 HTTP 200이면 SEV1. MITRE T1190.
- xss 1000002. 기본 SEV3. 해당 요청 HTTP 200이면 SEV1. MITRE T1189.
- bruteforce 1000003. SSH 22 연결 횟수. 기본 SEV2. 격상 없음. MITRE T1110.001.
- portscan 1000004. 목적지 22·80 금지, 룰 ![22,80] 유지(2026-11-24 결정 A안). 기본 SEV3. MITRE T1046.
- c2_beacon 1000005. attacker 172.28.0.100에서 victim-web 172.28.0.10:8443/tcp로 가며 30초 내 5회 연결 시 경보 1회(공격자 발생 트래픽 구조 유지). 격상 없음. MITRE 가안 T1071.001, 기본 심각도 SEV2. 실습망 밖으로 나가면 안 됨.
- ssrf 1000006. victim-web:80에 GET /fetch?url=<내부 주소> 요청. HTTP 200이면 SEV1, 403은 경보만 내고 격상하지 않음(접속 거절). MITRE 가안 T1190. 기본 심각도 SEV3. 내부 주소만.
카테고리 키 철자는 정확히 c2_beacon, ssrf 입니다.
README에 남아 있는 옛 안내(ssrf=1000002, c2_beacon=1000003)는 삭제하거나, “예전에 쓰던 매핑이며 지금은 쓰지 않음”이라고 분명히 구분하세요.

## 차별화 4개 (빼거나 바꾸지 말 것)
1. 같은 요청의 HTTP 200이면 SEV1 격상(이제 ssrf도 포함. c2_beacon·bruteforce·portscan은 격상 없음).
2. password= / token= 값을 [MASKED] 로 마스킹.
3. OSI 흐름과 차단·확인·롤백 CLI 안내. 시스템이 차단을 실행하지는 않음.
4. 업로드한 PCAP을 커스텀 룰로 검사하고 MITRE 커버리지를 보여 줌.

## 문서·PPT에 넣을 것
- README 최신화, ARCHITECTURE 그림과 6종 표.
- 시연 순서(예: 환경 기동 → Mock 설명 → 샘플 또는 pcap 업로드 → Live 목록·격상·마스킹·플레이북 복사 → 통계). 프론트 수정 전에는 Live 목록이 비어 있을 수 있으므로, 그 화면을 최종본으로 쓰지 말 것.
- 화면 캡처는 프론트 수정 PR 머지 후. Mock과 Live를 구분해 캡션을 달 것.
- Backlog 슬라이드: 실시간 캡처, 실제 차단 실행 등. 이번 6종은 Backlog가 아닙니다.
- MITRE 가안은 “가안/검증 필요”로 표시.

## TBD — 지어내지 말 것. 물으면 「PM 확인 필요」라고 답할 것
- C2(확정): attacker 172.28.0.100에서 victim-web 172.28.0.10:8443/tcp로 가며, 같은 출발지가 30초 안에 5회 연결하면 경보 1회, 기본 SEV2, 200이어도 격상 없음, MITRE 가안 T1071.001. 실습 단순화를 위해 공격자가 트래픽을 발생시키는 구조를 유지합니다.
- SSRF(확정): victim-web:80 GET /fetch?url=<내부 주소>, 기본 SEV3, HTTP 200이면 SEV1, 403은 경보만 내고 격상하지 않음(내부 대상이 접속을 거절한 것이지 방어 차단이 아님), MITRE 가안 T1190. 404 동작은 TBD입니다.
- 공식 샘플 경보 12건(SEV1 3 / SEV2 4 / SEV3 5, PR #13 기준). pcap(c2_ssrf.pcap)에 룰을 적용하면 7건.
- 테스트 개수는 아직 확정 전이면 지어내지 마세요.
lab_capture.pcap은 PR #10 기준 4종 각 1건이며, 이 값을 6종 pcap 총합처럼 쓰지 마세요. 표와 슬라이드에는 위 확정값만 넣으세요.

## 제약
- 팀 배포 자료에 내부 작업 용어를 넣지 말 것.
- 비밀값, 실공인 IP, 강사 개인정보, 실습망 밖 공격을 넣지 말 것.
- 발표 대본·질의응답 전문은 사용자가 따로 요청하기 전에는 길게 작성하지 말고, 슬라이드 구성과 고칠 문구 위치 위주로 안내하세요.

## 출력 형식
- 한국어, 짧게, 비전공자도 읽기 쉽게.
- 고칠 위치는 파일:줄로 제시하세요.
- 없는 숫자는 공란 또는 「PM 확인 필요」로 남기세요.
- 다른 역할 파일을 고쳐야 하면 「PM 합의 필요」만 적으세요.
```
