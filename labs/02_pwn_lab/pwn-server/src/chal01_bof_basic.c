/*
 * chal01_bof_basic.c — 스택 오버플로우 기초
 * 보호: NX 없음 (스택 실행 가능), 스택 카나리 없음, ASLR 없음
 * 목표: 셸코드를 스택에 올리고 ret 주소를 덮어 실행
 * 플래그: /challenges/flag01.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win() {
    // 힌트: 이 함수를 직접 호출해도 됩니다
    system("/bin/cat /challenges/flag01.txt");
}

void vuln() {
    char buf[64];
    printf("Enter your input: ");
    fflush(stdout);
    // 취약 포인트: gets()는 경계 검사 없음
    gets(buf);
    printf("You entered: %s\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("=== Challenge 01: Basic Buffer Overflow ===\n");
    printf("win() address: %p\n", win);
    vuln();
    return 0;
}
