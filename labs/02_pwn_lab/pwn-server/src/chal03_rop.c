/*
 * chal03_rop.c — ROP 체인 (Return-Oriented Programming)
 * 보호: Full RELRO, NX, PIE 없음
 * 목표: ROP 가젯을 체이닝하여 execve("/bin/sh", NULL, NULL) 호출
 * 힌트: ROPgadget, ropper 등의 도구로 가젯 탐색
 *       syscall 번호: execve = 59 (x86_64)
 *       레지스터 설정: rax=59, rdi="/bin/sh", rsi=0, rdx=0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 가젯 탐색에 도움이 되는 함수들
void gadget_helper() {
    // pop rdi; ret
    // pop rsi; ret
    // pop rdx; ret
    // syscall; ret
    // 이 함수는 직접 호출되지 않지만 바이너리에 가젯을 포함시킵니다
    __asm__ volatile(
        "pop %rdi\n\t"
        "ret\n\t"
        "pop %rsi\n\t"
        "ret\n\t"
        "pop %rdx\n\t"
        "ret\n\t"
        "syscall\n\t"
        "ret\n\t"
    );
}

void vuln() {
    char buf[64];
    printf("ROP challenge: ");
    fflush(stdout);
    read(0, buf, 256);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Challenge 03: ROP Chain ===\n");
    printf("Binary base: %p\n", main);
    vuln();
    return 0;
}
