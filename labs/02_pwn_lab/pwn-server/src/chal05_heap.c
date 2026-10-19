/*
 * chal05_heap.c — 힙 익스플로잇 (tcache poisoning)
 * 보호: PIE 없음, NX 있음
 * 목표: tcache 청크 포인터를 오염시켜 임의 주소에 malloc() 할당
 *       → __free_hook 또는 __malloc_hook 덮어쓰기
 * glibc 버전: Ubuntu 22.04 (glibc 2.35) — tcache key 우회 필요
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 10
#define CHUNK_SIZE 64

void *chunks[MAX_CHUNKS];
int chunk_count = 0;

void win() {
    system("/bin/cat /challenges/flag05.txt");
}

void menu() {
    printf("\n=== 힙 관리자 ===\n");
    printf("1. malloc (할당)\n");
    printf("2. free (해제)\n");
    printf("3. 쓰기 (write)\n");
    printf("4. 읽기 (read)\n");
    printf("5. 종료\n");
    printf("선택: ");
    fflush(stdout);
}

int read_int() {
    int v;
    char buf[32];
    fgets(buf, sizeof(buf), stdin);
    sscanf(buf, "%d", &v);
    return v;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== Challenge 05: Heap Exploit (tcache poisoning) ===\n");
    printf("[힌트] win() @ %p\n", win);
    printf("[힌트] chunks 배열 @ %p\n", chunks);

    while (1) {
        menu();
        int choice = read_int();

        if (choice == 1) {
            if (chunk_count >= MAX_CHUNKS) {
                printf("최대 개수 초과\n");
                continue;
            }
            chunks[chunk_count] = malloc(CHUNK_SIZE);
            printf("chunks[%d] = %p\n", chunk_count, chunks[chunk_count]);
            chunk_count++;

        } else if (choice == 2) {
            printf("인덱스: ");
            int idx = read_int();
            if (idx < 0 || idx >= chunk_count || !chunks[idx]) {
                printf("잘못된 인덱스\n");
                continue;
            }
            free(chunks[idx]);
            // 취약 포인트: free 후 포인터를 NULL로 초기화하지 않음 (dangling pointer)
            // chunks[idx] = NULL; // 이 줄이 없어서 UAF/double-free 가능

        } else if (choice == 3) {
            printf("인덱스: ");
            int idx = read_int();
            if (idx < 0 || idx >= chunk_count || !chunks[idx]) {
                printf("잘못된 인덱스\n");
                continue;
            }
            printf("데이터 (최대 %d바이트): ", CHUNK_SIZE);
            fgets(chunks[idx], CHUNK_SIZE, stdin);

        } else if (choice == 4) {
            printf("인덱스: ");
            int idx = read_int();
            if (idx < 0 || idx >= chunk_count) {
                printf("잘못된 인덱스\n");
                continue;
            }
            printf("chunks[%d]: %s\n", idx, (char*)chunks[idx]);

        } else if (choice == 5) {
            break;
        }
    }
    return 0;
}
