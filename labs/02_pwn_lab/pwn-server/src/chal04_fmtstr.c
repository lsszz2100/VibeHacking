/*
 * chal04_fmtstr.c — 포맷 스트링 취약점
 * 보호: 스택 카나리 없음, PIE 없음
 * 목표:
 *   1단계: 포맷 스트링으로 스택 값 읽기 (%x, %p)
 *   2단계: 임의 주소 읽기 (%s)
 *   3단계: GOT 오버라이트로 임의 코드 실행 (%n)
 * 플래그: secret_flag 전역 변수를 읽거나
 *         win() 함수를 호출하면 획득
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 스택에 올라가는 비밀 값
int secret = 0xdeadbeef;
char secret_flag[] = "FLAG{f0rm4t_str1ng_4rb1tr4ry_wr1t3}";

void win() {
    printf("축하합니다! 플래그: %s\n", secret_flag);
    system("/bin/cat /challenges/flag04.txt");
}

void vuln() {
    char buf[256];
    printf("포맷 스트링 챌린지\n");
    printf("secret 주소: %p\n", &secret);
    printf("win() 주소: %p\n", win);
    printf("입력: ");
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);
    // 취약 포인트: printf(buf) — 포맷 스트링을 사용자가 제어
    printf(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    while (1) {
        vuln();
    }
    return 0;
}
