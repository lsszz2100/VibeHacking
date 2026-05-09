/*
 * chal02_ret2libc.c — ret2libc
 * 보호: NX 있음 (스택 실행 불가), 스택 카나리 없음, PIE 없음, ASLR 없음
 * 목표: ret 주소를 system("/bin/sh")로 덮어 쉘 획득
 * 힌트: system(), /bin/sh 문자열, pop rdi; ret 가젯 주소 필요
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// libc 주소 힌트 제공
void hint() {
    printf("[힌트] system() @ %p\n", system);
    printf("[힌트] /bin/sh 찾기: strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh\n");
}

void vuln() {
    char buf[128];
    printf("Input: ");
    fflush(stdout);
    // 취약 포인트: read()로 512바이트 읽음 → 128바이트 버퍼 오버플로우
    read(0, buf, 512);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    hint();
    vuln();
    return 0;
}
