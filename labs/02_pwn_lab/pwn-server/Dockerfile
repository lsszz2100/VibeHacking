FROM ubuntu:22.04

LABEL maintainer="vibe-hacking-lab"
LABEL description="취약한 C 바이너리 5종 서비스 — 교육 목적 전용"

# 비대화형 설치
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

# 기본 도구 설치
RUN apt-get update && apt-get install -y \
    gcc \
    gcc-multilib \
    g++ \
    gdb \
    python3 \
    python3-pip \
    xinetd \
    socat \
    libssl-dev \
    libc6-dev \
    libc6-dbg \
    make \
    ncat \
    wget \
    curl \
    vim \
    file \
    && rm -rf /var/lib/apt/lists/*

# pwntools 설치
RUN pip3 install --no-cache-dir pwntools

# CTF 사용자 생성
RUN useradd -m -s /bin/bash ctf && \
    echo 'ctf:ctf' | chpasswd

WORKDIR /challenges

# -------------------------------------------------------
# 챌린지 소스 코드 복사 및 컴파일
# -------------------------------------------------------
COPY src/ /challenges/src/
COPY compile.sh /challenges/compile.sh
RUN chmod +x /challenges/compile.sh && \
    bash /challenges/compile.sh

# -------------------------------------------------------
# xinetd 서비스 설정
# -------------------------------------------------------
COPY xinetd/ /etc/xinetd.d/
RUN chmod 644 /etc/xinetd.d/*

# 플래그 파일 배치
RUN echo "FLAG{st4ck_0v3rfl0w_no_nx_pwned}"     > /challenges/flag01.txt && \
    echo "FLAG{r3t2l1bc_byp4ss_nx}"              > /challenges/flag02.txt && \
    echo "FLAG{r0p_ch41n_m4st3r}"                > /challenges/flag03.txt && \
    echo "FLAG{f0rm4t_str1ng_4rb1tr4ry_wr1t3}"  > /challenges/flag04.txt && \
    echo "FLAG{tc4ch3_p01s0n1ng_h34p_pwn}"       > /challenges/flag05.txt && \
    chmod 644 /challenges/flag*.txt

EXPOSE 10001 10002 10003 10004 10005

CMD ["/usr/sbin/xinetd", "-dontfork", "-stayalive", "-inetd_compat"]
