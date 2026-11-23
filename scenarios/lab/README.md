# Mini-SIEM Docker 실습망 초안

팀원 전원 Windows PC에서 테스트해 볼 실습망 예시입니다.

- **이 폴더는 초안입니다.** GitHub 저장소(`Weo0o0/RookiRooki`)를 수정·커밋·PR하지 않았습니다.
- 공식 폴더 규격(`README.md` 저장소 구조)에는 `docker-compose.yml` 자리가 없습니다. 실습망·pcap은 시나리오 담당 영역(`scenarios/`)이므로, 넣을 위치는 **PM·시나리오 담당과 합의**가 필요합니다. 합의안: `scenarios/lab/`.
- 공격은 **이 실습망 안에서만** 하세요. 학교·회사·가정 네트워크나 허가 없는 대상을 쓰지 마세요.
- 계정 `labuser` / `labpass` 는 **가짜 실습 값**입니다. 실제 비밀번호를 넣지 마세요.

근거: `DECISIONS.md` 3번, GitHub `README.md`, `docs/ARCHITECTURE.md`.

## 1. 브리지는 별도 이미지가 필요 없습니다

`docker-compose.yml`의 `networks:` 에 `mini-siem-net`를 선언하면 Docker가 리눅스 브리지(소프트웨어 스위치)를 만듭니다. 브리지 전용 컨테이너 이미지는 만들지 않습니다.

브리지 이름은 환경마다 `br-` + 해시로 달라질 수 있어서, 이 초안은 공식 옵션으로 이름을 `br-minisiem`으로 고정합니다.

- Compose 네트워크: https://docs.docker.com/reference/compose-file/networks/
- 브리지 이름 옵션 `com.docker.network.bridge.name`: https://docs.docker.com/engine/network/drivers/bridge/#options

## 2. 구성

| 구성 | 주소 | 역할 |
|---|---|---|
| 네트워크 `mini-siem-net` | `172.28.0.0/24` | 팀 격리 브리지 (`internal: true`, 밖으로 나가지 않음) |
| attacker | `172.28.0.100` | curl, nmap, hydra로 4종 트래픽 발생 |
| victim-web | `172.28.0.10` | HTTP. SQLi·XSS 타깃. SQLi 성공 시 **200** (SEV1 격상용) |
| victim-pc | `172.28.0.11` | SSH 22/tcp. 무차별 대입·포트스캔 타깃. 계정 `labuser`/`labpass` |
| 브리지 tcpdump | `br-minisiem` | 웹과 SSH 트래픽을 한 pcap으로 녹화 |
| 백엔드 8000, `suricata -r` | 호스트 | **Docker 실습망 밖**. 이 compose에 넣지 않음 |

공식 자료는 공격 도구 이름을 정하지 않았습니다. 이 초안은 시나리오에 맞춰 `curl`(HTTP), `nmap`(포트스캔)을 넣었고, SSH 무차별 대입 도구 `hydra`는 비공식 제미나이 기록에만 등장합니다.

## 3. Windows 팀원 준비

1. Windows에서 **WSL2**를 켭니다.
2. [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)을 설치하고, Settings에서 WSL2 엔진을 사용하게 합니다.
3. PowerShell에서 `docker version` 과 `docker compose version` 이 보이면 준비된 것입니다.
4. 이 폴더(`rooki-docker-draft`)를 팀원 PC로 복사합니다. (저장소 위치는 PM 합의 전)

> 공식 README의 `sudo tcpdump -i <브리지>` 와 `suricata -r` 은 **리눅스 호스트**를 가정한 명령입니다. Windows PowerShell에서는 브리지 인터페이스가 보이지 않습니다. 이유는 5절을 보세요.

## 4. 실행 순서 (PowerShell)

아래는 이 폴더를 연 뒤 입력하는 명령입니다.

```powershell
cd C:\경로\rooki-docker-draft

# 문법 확인
docker compose config

# 피해 호스트 + 공격자 이미지 빌드 후 기동
docker compose up -d --build

docker compose ps
docker network inspect mini-siem-net
```

공격자에서 타깃이 보이는지 확인합니다.

```powershell
docker exec attacker ping -c 2 172.28.0.10
docker exec attacker ping -c 2 172.28.0.11

# SQLi 성공 → 응답 코드 200 이어야 함
docker exec attacker curl -sS -D - -o - "http://172.28.0.10/login?username=admin'%20OR%20'1'='1'--&password=test"

# 4종 실습 트래픽을 한 번에 (실습망 주소만 대상)
docker exec attacker /lab/lab-traffic.sh
```

개별 명령 예:

```powershell
# 정상 로그인 200, 실패 403
docker exec attacker curl -sS -o /dev/null -w "%{http_code}\n" "http://172.28.0.10/login?username=labuser&password=labpass"
docker exec attacker curl -sS -o /dev/null -w "%{http_code}\n" "http://172.28.0.10/login?username=labuser&password=wrongpass"

# XSS (응답 200, 검색어가 그대로 반사)
docker exec attacker curl -sS "http://172.28.0.10/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# 포트스캔 (웹·PC, README 범위)
docker exec attacker nmap -sS -Pn -T4 -p 1-100 172.28.0.10 172.28.0.11

# SSH 무차별 대입 (가짜 비밀번호 목록)
docker exec attacker hydra -l labuser -P /lab/passwords.txt -t 4 ssh://172.28.0.11/
```

끝낸 뒤:

```powershell
docker compose --profile linux-capture --profile desktop-capture down
```

컨테이너 HTTP/SSH 포트는 기본으로 호스트에 열지 않습니다. 브라우저로 victim-web만 보고 싶다면 `docker-compose.yml`의 `127.0.0.1:8080:80` 주석을 해제하세요. **22번 포트는 호스트에 열지 마세요.**

## 5. 브리지에서 pcap 녹화

ARCHITECTURE.md가 브리지에서 녹화하는 이유: 컨테이너 하나만 보면 웹 또는 SSH 한쪽만 남을 수 있습니다. 브리지를 보면 `172.28.0.10`과 `172.28.0.11`로 가는 패킷을 같은 파일에 담습니다.

저장 위치는 합의 전이면 이 초안의 `pcaps/`, 합의 후면 `scenarios/pcaps/` 입니다. 업로드 한도는 `.pcap`/`.pcapng`, 20MB.

### 5-1. 리눅스 Docker Engine (가장 README와 같음)

브리지가 **그 컴퓨터의 네트워크 인터페이스 목록에 보입니다.**

```bash
ip -o link | grep br-minisiem
sudo tcpdump -i br-minisiem -n -U -w scenarios/pcaps/lab_capture.pcap
```

또는 Compose 프로필:

```bash
docker compose --profile linux-capture up -d
# 다른 터미널에서 트래픽 생성
docker compose --profile linux-capture down
```

같은 방법을 **WSL2 Ubuntu 안에 Docker Engine을 직접 설치**한 경우에도 쓸 수 있습니다. 이 경우 Docker Desktop 엔진과 동시에 켜면 충돌할 수 있으니, Desktop을 끈 상태에서 쓰는 편이 안전합니다.

### 5-2. Windows Docker Desktop에서는 호스트 tcpdump가 바로 안 됩니다

공식 문서 그대로입니다.

> There is no `docker0` bridge on the host. Because of the way networking is implemented in Docker Desktop, you cannot see a `docker0` interface on the host. This interface is actually within the virtual machine.
>
> 출처: https://docs.docker.com/desktop/features/networking/networking-how-tos/#there-is-no-docker0-bridge-on-the-host

또, 브리지 네트워크는 호스트에서 컨테이너 IP로 직접 갈 수 없습니다. PowerShell의 `tcpdump -i br-minisiem` 이나 `ping 172.28.0.10` 은 실패하는 것이 정상입니다.

**주의: `network_mode: host` + netshoot로 브리지를 잡는다**는 방법은, **리눅스 Docker Engine에서는 맞지만 Docker Desktop에서는 공식 동작이 아닙니다.**

Docker Desktop 4.34+ 의 host networking은 설정에서 켜야 하고, **L4(TCP/UDP)만** 지원합니다. 공식 문서는 컨테이너가 **호스트 인터페이스에 직접 접근하지 못한다**고 적습니다. tcpdump로 `br-minisiem`을 집는 일은 그 아래에 해당하므로, Desktop에서 이 방법을 검증된 기본값으로 권하지 않습니다.

- https://docs.docker.com/engine/network/drivers/host/

### 5-3. Docker Desktop을 쓸 때의 현실적인 녹화

**권장.** 트래픽이 지나가는 각 타깃 네임스페이스에서 녹화한 뒤, 파일 두 개를 하나로 합칩니다. `network_mode: service:victim-web` / `service:victim-pc` 는 Compose 공식 문법입니다.

```powershell
docker compose --profile desktop-capture up -d
docker exec attacker /lab/lab-traffic.sh
docker compose --profile desktop-capture stop capture-web capture-pc
```

그러면 `pcaps/web.pcap` 과 `pcaps/ssh.pcap` 이 생깁니다. 하나로 합치는 방법:

- Windows에 [Wireshark](https://www.wireshark.org/)를 설치했다면, GUI에서 두 파일을 열어 하나로 저장합니다.
- WSL2 Ubuntu라면: `sudo apt install -y wireshark-common` 후
  `mergecap -w pcaps/lab_capture.pcap pcaps/web.pcap pcaps/ssh.pcap`

**다른 선택.** WSL2 Ubuntu에 Docker Engine을 직접 설치하면 5-1처럼 `br-minisiem`이 그 리눅스 안에 보이므로, README의 `tcpdump -i br-minisiem`을 그대로 쓸 수 있습니다.

커뮤니티에서 가끔 쓰는 `docker run --privileged --pid=host` 로 Docker Desktop VM 안에 들어가는 방법은 **공식 지원 절차가 아니고**, Desktop 버전에 따라 막힐 수 있어 팀 기본 방법으로 적지 않았습니다.

## 6. Windows에서 `suricata -r` 리스크 (짧게)

공식 설계는 백엔드가 **호스트에서** `suricata -r` 로 pcap을 분석합니다. 이 명령은 리눅스에서 흔하고, Windows 기본 PowerShell에는 보통 없습니다.

팀 현실 선택:

1. **WSL2 Ubuntu에 Suricata 설치** 후, 그 안에서 README와 같은 명령 실행. 백엔드도 WSL에서 돌리면 가장 자료와 가깝습니다.
2. Suricata를 분석용 컨테이너로 돌리기. 동작은 하지만 “호스트에서 실행”이라는 문서와는 다릅니다. 나중에 FastAPI가 `suricata` 실행 파일을 찾을 때도 경로를 다시 정해야 합니다.

Windows에만 백엔드를 두면 Day 2 pcap 업로드 연동이 막힐 수 있으니, 백엔드·룰 담당과 미리 실행 위치(WSL vs Windows)를 맞추세요.

## 7. 자료와의 차이 · 미정 사항

| 항목 | 상태 |
|---|---|
| `docker-compose.yml` / Dockerfile | 공식 저장소·확정 문서에 **없음**. 제미나이 기록에도 미작성. 이 폴더는 초안. |
| compose 파일 위치 | **미정**. PM 합의 필요. |
| victim-web 이미지 | 자료에 지정된 이미지 없음. 최소 Python 앱을 새로 작성. SQLi 성공 시 200이 나오도록 함. |
| 공격 도구 | 공식 문서에 도구명 없음. curl·nmap은 시나리오에 맞춰 선택. hydra는 `gemini_v2_changes.md`에만 등장. |
| `internal: true` | 공식 README에는 없지만, “격리망에서만 공격” 규칙에 맞춰 초안에 넣음. |
| 제미나이 “방식 A” (Suricata를 `network_mode: service:victim-web`에 붙이기, 출발지 위장 등) | **채택하지 않음.** 확정 설계는 브리지 tcpdump + 호스트 `suricata -r`. 방식 A는 SSH 트래픽을 못 보는 문제가 로컬 검토 기록에 이미 있음. |
| 베이스라인 프롬프트 `04_scenarios.txt` | 카테고리가 옛 값(`sqli`/`ssrf`/`c2_beacon`). **DECISIONS.md와 GitHub README의 4종(sqli/xss/bruteforce/portscan)이 우선.** |

GitHub `main`(2026-11-23 확인)에는 `README.md`, `docs/`, `ai-guides/`만 있고 애플리케이션 코드는 없습니다. 로컬 `minisiem-notes/repo/README.md` 및 `ARCHITECTURE.md`는 GitHub raw와 같았습니다.

## 8. 문제가 생길 때 (Linux Engine)

컨테이너끼리 ping/curl이 타임아웃이면, 브리지 트래픽이 `br_netfilter`를 거쳐 iptables FORWARD로 들어갈 수 있습니다. 이 초안을 검증할 때, 남아 있던 `iptables-legacy`의 `FORWARD` 정책이 DROP이라 SYN이 브리지에는 보이지만 상대 컨테이너에는 도착하지 않았습니다. Docker 규칙은 nft 쪽에만 있었습니다.

깨끗한 Docker Desktop/Engine에서는 보통 이 문제가 없습니다. Linux에서 같은 증상이면 아래를 **임시로** 확인하세요.

```bash
sudo iptables-legacy -S FORWARD
# 정책이 DROP이고 br-minisiem 허용이 없으면:
sudo iptables-legacy -I FORWARD -i br-minisiem -o br-minisiem -j ACCEPT
```

## 9. 검증 (이 초안을 만든 환경)

Linux Docker Engine 26.1.5 + Compose 2.26.1 에서 확인했습니다 (Asia/Seoul, 2026-11-23 22:26).

- `docker compose config` 문법 OK (linux-capture, desktop-capture 프로필 포함)
- 네트워크 이름 `mini-siem-net`, 브리지 인터페이스 `br-minisiem`, 주소 `.10` / `.11` / `.100` 일치
- SQLi 성공 응답 **200**, 정상 로그인 200, 실패 로그인 **403**, XSS **200**
- nmap `-sS`: `.10`은 80 open·22 closed, `.11`은 22 open·80 closed
- hydra가 실습 계정 `labuser`/`labpass`를 찾음
- 호스트 `tcpdump -i br-minisiem` 한 파일에 HTTP(.10)와 SSH(.11)와 포트스캔이 함께 기록됨 (`pcaps/lab_capture.pcap`, 약 62KB)
- `linux-capture` 프로필(netshoot, `network_mode: host`)도 같은 브리지에서 웹+SSH를 한 파일에 담는 것을 확인
- `desktop-capture` 프로필: `web.pcap`에는 HTTP만, `ssh.pcap`에는 해당 호스트 트래픽만 담김 (그래서 합치기가 필요)

**Windows Docker Desktop에서는 이 초안을 실행해 보지 않았습니다.** 브리지가 호스트에 안 보이는 점은 공식 문서에 근거하고, host networking으로 브리지를 잡는 방법은 Desktop에서 공식 지원이 아니라서 기본 권장에서 뺐습니다.
