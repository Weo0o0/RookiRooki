# WSL2 Ubuntu Docker 환경 구축 종합 명령어 (04조 미니 SIEM)

> 모든 공격은 팀 실습망 `172.28.0.0/24` 안에서만 합니다. 학교망, 다른 사람 PC, 허가 없는 대상에는 절대 하지 않습니다.
> 설치 명령은 Microsoft / Docker / Suricata 공식 설치 방식을 바탕으로 정리했습니다. 실습망 구성은 README·ARCHITECTURE와 초안을 따릅니다.

## 전체 순서 한눈에

```
0. 준비 확인 → 1. systemd 켜기 → 2. Docker Engine 설치 → 3. 설치 확인
→ 4. 실습 파일 옮기기 → 5. 실습망 켜기 → 6. 녹화 + 공격
→ 7. Suricata 설치(처음 한 번) → 8. pcap 분석 → 9. 결과 확인
```

---

## 0. 준비 확인 (Windows PowerShell)

```powershell
wsl -l -v
```
- Ubuntu의 VERSION이 **2**인지 확인합니다.
- 1이면: `wsl --set-version Ubuntu 2`
- Ubuntu가 없으면: `wsl --install -d Ubuntu`
- **Docker Desktop이 설치돼 있으면 꺼 둡니다.** 같이 켜면 `docker` 명령이 어느 쪽으로 갈지 꼬일 수 있습니다.

## 0-1. Ubuntu로 들어가기 (Windows → Ubuntu)

여기부터는 **리눅스(Ubuntu) 명령**입니다. PowerShell에서 아래를 입력하면 Ubuntu로 들어갑니다. (시작 메뉴에서 **Ubuntu** 앱을 열어도 됩니다.)
```powershell
wsl -d Ubuntu
```
- 프롬프트가 `PS C:\...>` 에서 `user@DESKTOP-xxxx:~$` 처럼 바뀌면 Ubuntu 안에 들어온 것입니다.
- 이 상태에서 입력하는 `sudo`, `apt`, `docker`, `tcpdump`, `suricata`는 모두 Ubuntu 명령입니다.
- `wsl ...` 로 시작하는 명령만 PowerShell에서 입력합니다.

## 1. systemd 켜기 (Ubuntu) ← Docker 설치보다 먼저

`/etc/wsl.conf`는 Docker가 아니라 **Ubuntu 자체의 설정 파일**입니다. Docker가 없어도 Ubuntu에 들어가면 바로 수정할 수 있습니다.

systemd는 Docker 같은 프로그램을 서비스로 등록하고 자동으로 켜 주는 관리자입니다. Docker 설치 전에 켜 둬야 Docker 서비스가 자동으로 실행됩니다.

```bash
sudo nano /etc/wsl.conf
```
아래 두 줄을 넣고 `Ctrl+O` → `Enter`로 저장, `Ctrl+X`로 나옵니다.
```ini
[boot]
systemd=true
```
Ubuntu에서 `exit`로 나와 PowerShell로 돌아간 뒤 재시작하고, 다시 Ubuntu로 들어갑니다.
```bash
exit
```
```powershell
wsl --shutdown
wsl -d Ubuntu
```
Ubuntu에서 켜졌는지 확인합니다. `systemd`가 나오면 성공입니다.
```bash
ps -p 1 -o comm=
```

## 2. Docker Engine 설치 (Ubuntu)

Docker 공식 저장소를 등록하고 설치합니다. 한 줄씩 붙여 넣습니다.
```bash
sudo apt update && sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin tcpdump unzip
sudo usermod -aG docker $USER
```
- 마지막 줄은 `sudo` 없이 `docker`를 쓰게 해 줍니다. **Ubuntu 창을 닫고 다시 열어야 적용됩니다.**

## 3. 설치 확인 (Ubuntu)

```bash
docker --version
docker compose version
docker run --rm hello-world
```
- `Hello from Docker!`가 보이면 설치 완료입니다.

## 4. 실습 파일 옮기기 (Ubuntu)

```bash
cp /mnt/c/Users/<윈도우사용자이름>/Downloads/rooki-docker-draft.zip ~/
cd ~ && unzip rooki-docker-draft.zip && cd rooki-docker-draft
```
- `/mnt/c`는 윈도우 C드라이브입니다.
- 파일은 Ubuntu 홈(`~/`)에 둡니다. 윈도우 경로에서 작업하면 느리고 권한 문제가 잘 생깁니다.

## 5. 실습망 켜기와 연결 확인 (Ubuntu, `~/rooki-docker-draft` 안에서)

| 명령어 | 쉬운 설명 |
|---|---|
| `cd ~/rooki-docker-draft` | 실습 폴더로 들어가요 (모든 명령의 출발점) |
| `docker compose up -d --build` | 컨테이너 3개 + 실습망을 만들고 켜요. `-d`는 뒤에서 조용히 실행 |
| `docker compose ps` | 켜진 컨테이너 목록. attacker, victim-web, victim-pc 3개 모두 Up이면 정상 |
| `docker network inspect mini-siem-net` | 실습망에 누가 어떤 IP로 붙어 있는지 봐요 |
| `ip link show br-minisiem` | 브리지(가상 스위치)가 있는지 확인해요 |
| `docker exec attacker ping -c 2 172.28.0.10` | 공격자 안에서 웹 서버로 신호 2번. `docker exec 컨테이너 명령` = 그 컨테이너 안에서 실행 |

| 컨테이너 | IP | 역할 |
|---|---|---|
| attacker | 172.28.0.100 | 공격 트래픽 발생 |
| victim-web | 172.28.0.10 | HTTP 타깃 (sqli, xss) |
| victim-pc | 172.28.0.11 | SSH 22/tcp 타깃 (bruteforce, portscan) |

## 6. 녹화하고 공격하기 (터미널 2개)

| 순서 | 명령어 | 쉬운 설명 |
|---|---|---|
| 터미널 1 | `sudo tcpdump -i br-minisiem -n -U -w pcaps/lab_capture.pcap` | 브리지를 지나는 패킷을 파일로 녹화 (CCTV 녹화 시작) |
| 터미널 2 | `docker exec attacker /lab/lab-traffic.sh` | 공격 4종(sqli, xss, bruteforce, portscan)을 순서대로 보내요 |
| 터미널 1 | `Ctrl+C` | 녹화를 멈추고 저장해요 |
| 확인 | `ls -lh pcaps/` | 파일이 생겼고 크기가 0이 아닌지 봐요 |

tcpdump 옵션: `-i` 어디서 녹화할지, `-n` IP를 이름으로 바꾸지 않기, `-U` 바로바로 저장, `-w` 파일로 쓰기.

## 7. Suricata 설치 (Ubuntu, 처음 한 번만)

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata jq
suricata -V
```
- `suricata -V`에서 버전이 나오면 설치 완료입니다. `jq`는 JSON 로그를 보기 좋게 보여 주는 도구입니다.

## 8. pcap 분석하기

### 준비: 룰 파일
- `rules/custom.rules`는 **룰 담당이 전달하는 파일**입니다 (SID 1000001~1000004). `~/rooki-docker-draft/rules/`에 넣습니다.
```bash
mkdir -p rules
ls -l rules/custom.rules
```

### 실행
```bash
mkdir -p /tmp/suricata_out
rm -rf /tmp/suricata_out/*
sudo suricata -r pcaps/lab_capture.pcap -S rules/custom.rules -l /tmp/suricata_out -k none
sudo chown -R $USER:$USER /tmp/suricata_out
```

| 옵션 | 쉬운 설명 |
|---|---|
| `-r` | 실시간이 아니라 녹화된 파일을 읽어요 |
| `-S` | 우리 팀 룰 파일만 써요 |
| `-l` | 결과를 저장할 폴더 |
| `-k none` | 체크섬 검사를 끕니다. 컨테이너 녹화본은 체크섬이 틀려 보이는 경우가 많아, 안 끄면 패킷이 버려져 탐지가 안 될 수 있어요 |

## 9. 결과 확인

| 명령어 | 쉬운 설명 |
|---|---|
| `ls /tmp/suricata_out` | `eve.json`, `fast.log`, `stats.log`, `suricata.log`가 생겼는지 봐요 |
| `cat /tmp/suricata_out/fast.log` | 경보를 한 줄씩 간단히 봐요 |
| `jq 'select(.event_type=="alert") \| {sid: .alert.signature_id, msg: .alert.signature, src: .src_ip, dst: .dest_ip}' /tmp/suricata_out/eve.json` | 경보만 골라 SID, 이름, 출발지, 목적지 보기 |
| `jq -r 'select(.event_type=="alert") \| .alert.signature_id' /tmp/suricata_out/eve.json \| sort \| uniq -c` | SID별 경보 개수. 1000001~1000004가 다 보이면 4종 탐지 성공 |

> 표 안의 `\|`는 표 때문에 붙인 표시입니다. 터미널에 칠 때는 `|`만 입력하세요.

## 10. 끄기와 문제 해결

| 명령어 | 쉬운 설명 |
|---|---|
| `docker compose down` | 실습 끝나면 전부 꺼요 (이미지는 남아서 다음엔 빨리 켜져요) |
| `docker compose logs victim-web` | 웹 서버 기록 보기 (이름 바꾸면 다른 컨테이너) |
| `docker compose restart` | 전부 껐다 다시 켜요 |
| `docker compose down` 후 `docker compose up -d --build` | 완전히 새로 만들어요 |

---

## 자주 나오는 오류

| 오류 메시지 | 원인 | 해결 |
|---|---|---|
| `Cannot connect to the Docker daemon` | systemd가 꺼져 있거나 Docker 서비스가 안 켜짐 | 1단계 확인 → `wsl --shutdown` 후 재시작 → `sudo systemctl start docker` |
| `permission denied ... docker.sock` | docker 그룹 적용 전 | Ubuntu 창을 닫고 다시 열기 (`sudo usermod -aG docker $USER` 이후) |
| `conf-yaml-loader: failed to open file: /etc/suricata//suricata.yaml: Permission denied` | Suricata 설정 파일을 관리자(root)만 읽을 수 있게 설치됨 | `sudo suricata ...`로 실행하고, 끝나면 `sudo chown -R $USER:$USER /tmp/suricata_out` |
| `No rule files match the pattern rules/custom.rules` / `no rules were loaded!` | 룰 파일이 없음 | 룰 담당에게 `custom.rules`를 받아 `rules/`에 넣기 |
| `1/3th of packets have an invalid checksum` | 컨테이너 패킷 체크섬 오프로드 | 분석할 때 `-k none` 붙이기 |
| `tcpdump: br-minisiem: No such device` | 실습망이 안 켜짐 | `docker compose up -d --build` 먼저 |

## 참고 (팀 합의 필요)

- 나중에 백엔드가 `suricata -r`을 자동 실행할 때는 코드에 `sudo`를 넣지 않는 편이 좋습니다. 대신 `sudo chmod 644 /etc/suricata/suricata.yaml`로 설정 파일 읽기 권한을 여는 방법을 검토합니다. 백엔드 호출에도 `-k none`을 넣습니다.
- compose 파일의 저장소 위치(제안: `scenarios/lab/`)와 백엔드·Suricata 실행 위치(WSL2 Ubuntu 권장)는 PM과 합의합니다.
