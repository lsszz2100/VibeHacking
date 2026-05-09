FROM ubuntu:22.04

LABEL description="pwntools + GDB 디버거 공격 컨테이너 — 교육 목적 전용"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

# 기본 도구
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    gdb \
    git \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    vim \
    tmux \
    ltrace \
    strace \
    binutils \
    elfutils \
    file \
    xxd \
    hexdump \
    ROPgadget \
    && rm -rf /var/lib/apt/lists/*

# pwntools 설치
RUN pip3 install --no-cache-dir \
    pwntools \
    ropper \
    one_gadget \
    angr \
    z3-solver

# GDB 플러그인 설치 (pwndbg 권장)
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && \
    ./setup.sh || true

# GEF (GDB Enhanced Features) — 대안
RUN wget -q -O /opt/gef.py \
    https://gef.blah.cat/py || \
    curl -sL https://gef.blah.cat/py -o /opt/gef.py || true

# CTF 사용자
RUN useradd -m -s /bin/bash ctf && \
    mkdir -p /home/ctf/exploits /home/ctf/tools

# .gdbinit 설정
RUN echo "source /opt/pwndbg/gdbinit.py" > /home/ctf/.gdbinit 2>/dev/null || \
    echo "# pwndbg not available" > /home/ctf/.gdbinit

WORKDIR /home/ctf

# 환경변수 (타겟 서버 IP)
ENV TARGET_HOST=172.17.0.10

# 예제 익스플로잇 스크립트 복사
COPY --chown=ctf:ctf exploit_templates/ /home/ctf/exploits/

USER ctf

CMD ["/bin/bash"]
