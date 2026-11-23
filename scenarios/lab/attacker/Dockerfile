# 실습망 안에서만 쓰는 공격자 이미지.
# 공식 README/ARCHITECTURE는 도구 이름을 정하지 않았습니다.
# curl = HTTP(SQLi/XSS), nmap = 포트스캔, hydra = SSH 무차별 대입(비공식 제미나이 기록에만 등장).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        nmap \
        hydra \
        openssh-client \
        iproute2 \
        iputils-ping \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY passwords.txt /lab/passwords.txt
COPY lab-traffic.sh /lab/lab-traffic.sh
RUN chmod +x /lab/lab-traffic.sh

# 컨테이너를 띄워 두고 docker exec 로 명령을 실행합니다.
CMD ["sleep", "infinity"]
