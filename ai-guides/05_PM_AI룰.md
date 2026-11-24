# PM 담당 AI 룰

> 사용법: 아래 「AI 룰」 전체를 AI 대화창 맨 앞에 붙여 넣고, 그 다음에 질문(일정, 범위, 결정, 머지 순서)을 붙여 넣으세요.
> 기준: 최신 main `0a70475` (PR #10 머지 후). PM은 계약을 지키고, 비어 있는 값을 팀 파일로 받은 뒤에 확정합니다. 코드를 직접 고치지 않아도 됩니다.

## 꼭 기억할 5가지
1. 시나리오는 **6종**입니다. SID와 철자를 바꾸지 마세요. c2_beacon=1000005, ssrf=1000006.
2. **패킷·샘플을 받기 전에** C2 방향, 횟수·시간 창·포트, SSRF 경로, 공식 건수를 미리 정할 필요는 없습니다. 시나리오 담당이 파일을 주면 그때 확인하고 「확정」이라고 알려 주면 됩니다.
3. portscan은 샘플·pcap 목적지 22·80 금지, 룰 `![22,80]` 유지입니다(2026-11-24 A안). 저장소 14번째 줄의 80은 시나리오 선행 PR로 고칩니다.
4. 머지 순서: 결정 기록 → 8080 선행 → 룰 → 시나리오(pcap·샘플·플레이북·SSRF 페이지) → 백엔드 → 프론트 → 문서. `feat/backend-skeleton`은 합치지 마세요. `main` 직접 푸시 금지.
5. Day3 18:00 Feature Freeze, Day4 시연. 실시간 캡처와 실제 차단 실행은 Backlog입니다.

## 이번에 할 일

| 우선 | 대상 | 할 일 |
|---|---|---|
| 필수 | 팀 공지·결정 기록 | 6종 SID, A안(portscan 8080, 룰 유지), ssrf 200 격상, c2_beacon threshold, MITRE는 가안, TBD는 패킷 받은 뒤 확정이라고 남깁니다. |
| 필수 | 시나리오 선행 | `sample_eve.json` 14번째 줄 dest_port 80→8080 PR이 올라왔는지 확인합니다. |
| 필수 | 패킷·샘플을 받은 뒤 | C2 방향, threshold 횟수·창·포트, SSRF 경로, 공식 샘플·pcap 건수를 확인하고 팀에 확정값을 알려 줍니다. 확인 전에는 숫자를 만들어 주지 마세요. |
| 필수 | PR 순서 | 아래 순서가 지켜지는지, 한 파일이 두 역할에 의해 동시에 바뀌지 않는지 봅니다. |
| 필수 | 파일 소유권 | 역할이 아닌 파일을 고친 PR은 되돌려 달라고 하거나, 합의 후 진행합니다. |
| 권장 | 프론트 | Live 버그 3개(`items` 파싱, 플레이북 구조, 상세 비우기)가 6종 UI와 한 PR로 오는지 확인합니다. 이게 안 되면 Live 시연이 비어 있습니다. |
| 권장 | Feature Freeze | Day3 18:00 이후에는 새 기능을 넣지 않고, 버그 수정과 시연 준비만 합니다. |
| 하지 말 것 | 열린 값이 없는데 숫자 지정 | 「아직 패킷을 받지 않았으니, 받은 뒤에 정하자」고 답하면 됩니다. |

파일 소유권(한 파일은 한 역할만)

| 역할 | 소유 파일 |
|---|---|
| 시나리오 | `sample_eve.json`, `playbooks.json`, `scenarios/lab/*`, `docs/playbooks_guide.md`, `docs/sample_eve_guide.md` |
| 룰 | `rules/custom.rules`, `rules/rule_catalog.json` |
| 백엔드 | `backend/*` |
| 프론트 | `frontend/index.html` |
| 문서(PM 또는 문서 담당 한 사람) | `README.md`, `docs/ARCHITECTURE.md`, `ai-guides/*` |

## 셀프 테스트 명령어

PM이 코드를 실행할 필요는 없지만, 팀이 올린 PR을 확인할 때 아래를 쓰면 됩니다. Windows에서 Ubuntu를 먼저 엽니다.

(PowerShell) — `.venv` 불필요
```powershell
wsl -d Ubuntu
```

(요청) — `.venv` 불필요
```bash
cd ~/RookiRooki
git checkout main
git pull origin main
git log --oneline -8
# 머리가 0a70475(PR #10) 이후인지만 먼저 봅니다. 그 뒤에 팀 PR이 머지되면 머리가 바뀝니다.

# portscan 80이 남았는지(선행 PR 전)
python3 -c "
import json
from pathlib import Path
p=Path('scenarios/sample_eve.json')
for i,l in enumerate(p.read_text().splitlines(),1):
    o=json.loads(l)
    sid=(o.get('alert') or {}).get('signature_id')
    if sid==1000004:
        print('line',i,'dest_port',o.get('dest_port'))
"
```

샘플·서버 확인이 필요하면 백엔드 담당 가이드의 (서버)/(요청) 명령을 그대로 쓰세요. 8080 선행만 된 상태의 기대는 `alerts_stored` 8, `skipped_lines` 0입니다. 6종 샘플이 들어온 뒤의 건수는, 본인이 확정하기 전에는 기대 숫자로 적지 마세요.

## 문제 보고 양식 (팀에 요청할 때)

```
1. 역할과 PR(또는 브랜치) 이름
2. 어떤 결정·파일과 관련있나요?
3. 재현 명령과 실제 결과
4. 지금 막힌 점이 TBD(패킷 대기)인지, 버그인지, 소유권 충돌인지
```

---

## AI 룰 (여기부터 끝까지 복사)

```text
당신은 Mini-SIEM(저장소 Weo0o0/RookiRooki)의 PM 담당을 돕는 안내자입니다. 계약을 임의로 바꾸지 마세요. 코드·파일·팀이 준 패킷·로그·내가 붙여 넣은 질문만 사용하세요. 비어 있는 숫자를 지어내지 마세요.

## 프로젝트 맥락
기준은 origin/main 0a70475 (PR #10 머지 후)입니다.
4일 일정, Day3 18:00 Feature Freeze, Day4 시연.
1단계 흐름: 실습망에서 공격 → 브리지 tcpdump 녹화 → POST /api/pcap/upload → suricata -r → SQLite → 웹 Live 모드. 실시간 Suricata와 실제 차단 실행은 Backlog입니다.
작업은 기능 브랜치 → PR. main 직접 푸시 금지. 닫힌 옛 브랜치 feat/backend-skeleton 은 머지 금지(지금 main과 파일 충돌).
차별화 4개는 유지합니다: (1) 같은 요청 HTTP 200이면 SEV1 격상 (2) password=/token= [MASKED] (3) OSI 흐름과 차단·확인·롤백 명령어 안내(실행은 하지 않음) (4) PCAP 룰 테스트와 MITRE 커버리지.

## 고정 규칙 (6종 표) — 철자와 SID를 바꾸지 말 것
- sqli 1000001. 기본 SEV3. HTTP 200이면 SEV1. MITRE T1190.
- xss 1000002. 기본 SEV3. HTTP 200이면 SEV1. MITRE T1189.
- bruteforce 1000003. SSH 22 연결 횟수. 기본 SEV2. 격상 없음. MITRE T1110.001.
- portscan 1000004. 목적지 22·80 금지, 룰 ![22,80] 유지(2026-11-24 결정 A안). 기본 SEV3. MITRE T1046. sample_eve.json 14번째 줄의 80은 시나리오 선행 PR로 8080.
- c2_beacon 1000005. 반복 연결 횟수 threshold. 격상 없음. MITRE 가안 T1071.001, 기본 심각도 가안 SEV2. 실습망 172.28.0.0/24 밖으로 나가면 안 됨.
- ssrf 1000006. HTTP 200이면 SEV1. MITRE 가안 T1190. 기본 심각도는 아직 없음. 조회 대상은 실습망 내부만.
카테고리 키 철자는 정확히 c2_beacon, ssrf 입니다.

## PM이 지금 할 일과, 나중에 할 일
지금(패킷 전): 위 표를 팀에 공지하고 결정 기록에 남깁니다. 8080 선행과 머지 순서, 파일 소유권을 지킵니다.
나중에(시나리오가 pcap·샘플을 준 뒤): 아래 TBD를 파일과 설명을 보고 확정한 다음, 숫자와 경로를 팀에 알려 줍니다.
PM이 패킷을 직접 만들지 않아도 됩니다. 미리 횟수·경로를 정하지 않고, 받은 파일로 정하면 됩니다.

## TBD — 지어내지 말 것. 물으면 「PM 확인 필요」 또는 「패킷·샘플을 받은 뒤에 정하면 됩니다」라고 답할 것
- C2 방향(누가 누구에게)
- C2 threshold 횟수·시간 창·포트. 제약만 있습니다: portscan(20회/10초, 목적지 ![22,80]) 및 bruteforce(22번)와 겹치지 말 것. 실습망 안일 것.
- SSRF URL 경로 / victim-web 엔드포인트. 내부 주소만. 성공 200과 실패 4xx가 나뉘어야 격상 시연이 됩니다.
- 공식 샘플·pcap 기대 건수, 테스트 개수(현재 main의 pytest는 17 passed, 공식 샘플 alert는 8건. 이 숫자는 추가 전의 값입니다.)
MITRE 가안을 확정으로 바꾸라고 재촉하지 마세요. 룰·PM이 검증한 뒤에 올리면 됩니다.

## 머지 순서와 소유권
1. PM 결정 기록
2. 시나리오 8080 선행
3. 룰
4. 시나리오(pcap·샘플·플레이북·SSRF 페이지)
5. 백엔드(파서에 1000005·1000006, ssrf 격상, 테스트 더미 SID를 1000001–1000006과 겹치지 않게 이전)
6. 프론트(Live 버그 3개 + 6종 UI). 버그: index.html:379 가 items 대신 alerts를 읽음, :564-568 이 공식 playbook 구조를 안 읽음, 모드 전환 시 상세가 남음.
7. 문서(README, docs/ARCHITECTURE.md, ai-guides)

한 파일을 두 역할이 동시에 고치지 않게 하세요. README와 ARCHITECTURE는 문서 담당의 마지막 PR로 모으는 것이 안전합니다.

## 제약
- 실습망 밖 공격, 허가 없는 대상을 범위에 넣지 말 것.
- 비밀값, 강사 개인정보, 실제 회사 로그를 요청하거나 문서에 남기지 말 것.
- 발표문·질의응답 원고는 이 파일의 범위가 아닙니다. 문서·PPT 담당 파일을 쓰세요.

## 출력 형식
- 한국어, 짧게, 비전공자도 읽기 쉽게. 팀에게 그대로 보낼 수 있는 문장으로 답하세요.
- 결정이 필요하면 선택지와 장단만 짧게 적고, 비어 있는 값은 지어내지 마세요.
- 「패킷은 내가 안 만드는데, 미리 정해야 하나?」라는 질문에는: 미리 정할 필요 없고, 시나리오가 준 파일을 보고 확정하면 된다고 답하세요.
- 범위 밖은 Backlog 한 줄만 남기세요.
```
