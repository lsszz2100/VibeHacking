#!/bin/bash
# 취약한 바이너리 컴파일 스크립트
# 각 챌린지에 맞는 보안 플래그 조정

set -e

SRC=/challenges/src
OUT=/challenges/bin

mkdir -p "$OUT"

echo "[*] 챌린지 01: BOF 기초 (NX 없음, 스택 실행 가능)"
gcc -o "$OUT/chal01" "$SRC/chal01_bof_basic.c" \
    -fno-stack-protector \
    -z execstack \
    -no-pie \
    -m32 \
    2>/dev/null || \
gcc -o "$OUT/chal01" "$SRC/chal01_bof_basic.c" \
    -fno-stack-protector \
    -z execstack \
    -no-pie
chmod +x "$OUT/chal01"
echo "    → $OUT/chal01 생성 완료"

echo "[*] 챌린지 02: ret2libc (NX 있음, ASLR 없음)"
gcc -o "$OUT/chal02" "$SRC/chal02_ret2libc.c" \
    -fno-stack-protector \
    -no-pie \
    -z noexecstack
chmod +x "$OUT/chal02"
echo "    → $OUT/chal02 생성 완료"

echo "[*] 챌린지 03: ROP 체인 (Full RELRO, NX, PIE 없음)"
gcc -o "$OUT/chal03" "$SRC/chal03_rop.c" \
    -fno-stack-protector \
    -Wl,-z,relro,-z,now \
    -no-pie \
    -z noexecstack
chmod +x "$OUT/chal03"
echo "    → $OUT/chal03 생성 완료"

echo "[*] 챌린지 04: 포맷 스트링"
gcc -o "$OUT/chal04" "$SRC/chal04_fmtstr.c" \
    -fno-stack-protector \
    -no-pie \
    -z noexecstack
chmod +x "$OUT/chal04"
echo "    → $OUT/chal04 생성 완료"

echo "[*] 챌린지 05: 힙 익스플로잇 (tcache poisoning)"
gcc -o "$OUT/chal05" "$SRC/chal05_heap.c" \
    -fno-stack-protector \
    -no-pie \
    -z noexecstack
chmod +x "$OUT/chal05"
echo "    → $OUT/chal05 생성 완료"

echo ""
echo "[+] 모든 바이너리 컴파일 완료"
ls -la "$OUT/"
