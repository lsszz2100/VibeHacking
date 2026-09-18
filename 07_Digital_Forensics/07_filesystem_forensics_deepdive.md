> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 파일 시스템 포렌식 심화 — FAT32, NTFS, EXT2/3/4 구조와 복구 실무

## 0. 초보자를 위한 개념 이해

### 파일 시스템 포렌식이란?

파일 시스템 포렌식(File System Forensics)은 디스크 스토리지의 파티션 구조와 파일 시스템 메타데이터를 분석하여 파일의 생성, 수정, 접근, 삭제 이력을 재구성하고 삭제된 데이터를 복원하는 기술입니다. 운영체제가 "파일이 삭제되었다"고 표시하더라도 실제 디스크 블록에는 메타데이터 포인터와 데이터 클러스터가 고스란히 남아 있습니다.

```
파일 시스템 계층 구조와 포렌식 분석 대상:

  ┌────────────────────────────────────────────────────────┐
  │ [파티션 테이블] MBR (0x55AA) / GPT (GUID Partition)   │
  ├────────────────────────────────────────────────────────┤
  │ [볼륨 부트 레코드] VBR / Superblock (클러스터 크기 등) │
  ├────────────────────────────────────────────────────────┤
  │ [메타데이터 영역] FAT / $MFT / Inode Table            │
  │  → 파일명, 권한, MACB 타임스탬프, 데이터 할당 포인터     │
  ├────────────────────────────────────────────────────────┤
  │ [데이터 클러스터] 실제 파일 내용 / 비할당 영역(Slack)   │
  └────────────────────────────────────────────────────────┘
```

---

## 1. FAT32 파일 시스템 상세 구조 및 삭제 파일 복구

### 1.1 FAT32 볼륨 레이아웃
FAT32는 단순성과 호환성으로 인해 USB 드라이브, SD 카드, 임베디드 장비에서 광범위하게 사용됩니다.

```
┌─────────────────┬───────────┬───────────┬──────────────────────┐
│  Reserved Area  │   FAT 1   │   FAT 2   │      Data Area       │
│ (VBR + FSInfo)  │ (할당 테이블)│ (백업용)  │ (Cluster 2 .. N)     │
└─────────────────┴───────────┴───────────┴──────────────────────┘
 0x0000            오프셋은 VBR의 Reserved Sector Count로 결정됨
```

### 1.2 32바이트 디렉터리 엔트리(Directory Entry) 구조

| 오프셋 (Offset) | 크기 (Bytes) | 필드 설명 |
|-----------------|--------------|-----------|
| `0x00 - 0x07` | 8 | 파일 이름 (Short File Name, 8자 공백 패딩) |
| `0x08 - 0x0A` | 3 | 파일 확장자 (Extension, 3자) |
| `0x0B` | 1 | 속성 플래그 (0x01: ReadOnly, 0x02: Hidden, 0x10: Directory, 0x0F: LFN) |
| `0x14 - 0x15` | 2 | 시작 클러스터 상위 16비트 (High Cluster) |
| `0x16 - 0x17` | 2 | 파일 수정 시간 (Time: Hours 5b, Min 6b, Sec/2 5b) |
| `0x18 - 0x19` | 2 | 파일 수정 날짜 (Date: Year-1980 7b, Month 4b, Day 5b) |
| `0x1A - 0x1B` | 2 | 시작 클러스터 하위 16비트 (Low Cluster) |
| `0x1C - 0x1F` | 4 | 파일 크기 (File Size, 바이트 단위 리틀엔디안) |

### 1.3 삭제 메커니즘과 복원 기법
- **삭제 마킹**: 파일 삭제 시 디렉터리 엔트리의 첫 번째 바이트(`0x00`)가 `0xE5`로 변경됩니다.
- **FAT 체인 초기화**: 해당 파일이 점유하던 FAT1/FAT2의 클러스터 엔트리가 `0x00000000`(미할당)으로 초기화됩니다.
- **복원 방법**: 파일이 단편화(Fragmentation)되지 않았다면, 디렉터리 엔트리의 시작 클러스터(`High << 16 | Low`)와 파일 크기를 확인하여 해당 클러스터 번호부터 순차적으로 데이터를 덤프하면 100% 복구 가능합니다.

---

## 2. NTFS 파일 시스템 및 $MFT 메타데이터 심층 해부

Windows 표준 파일 시스템인 NTFS는 모든 파일과 디렉터리를 메타데이터 파일 `$MFT`(Master File Table)의 1024바이트 크기 레코드로 관리합니다.

### 2.1 $MFT 레코드 및 주요 속성(Attribute)

```
$MFT Record (1024 Bytes):
  ┌────────────────────────────────────────────────────────┐
  │ Header: "FILE" 매직 바이트, LSN, Sequence Number 등      │
  ├────────────────────────────────────────────────────────┤
  │ $STANDARD_INFORMATION (0x10): 생성/수정/MFT수정/접근 시간 │
  ├────────────────────────────────────────────────────────┤
  │ $FILE_NAME (0x30): 부모 디렉터리 참조, 파일명, 시간정보 │
  ├────────────────────────────────────────────────────────┤
  │ $DATA (0x80): 실제 파일 데이터 (Resident or Non-Resident)│
  └────────────────────────────────────────────────────────┘
```

### 2.2 Timestomping 탐지 기법 ($0x10 vs $0x30)
- **$STANDARD_INFORMATION (0x10)**: 일반적인 Windows API(`SetFileTime`)를 통해 사용자가 수정 가능.
- **$FILE_NAME (0x30)**: 커널(NTFS 드라이버)만 수정 가능하며, 파일 이름 변경 등의 이벤트 발생 시에만 갱신됨.
- **탐지 규칙**: `$0x10`의 수정 시간(M)이 `$0x30`의 수정 시간보다 현저히 이전(과거)으로 조작되어 있다면 공격자의 **Timestomping(안티포렌식 타임스탬프 조작)** 행위로 확정할 수 있습니다.

### 2.3 Non-Resident Data Run 디코딩 알고리즘
대용량 파일은 MFT 레코드 내부에 데이터를 직접 저장하지 않고(Non-Resident), 클러스터 할당 정보인 Data Run을 기록합니다.

```
Data Run 예시: 0x32 0x01 0x20 0x05 0x10 0x00
  Header: 0x32 -> [상위 4비트 3: Offset 크기 (3바이트)] [하위 4비트 2: Length 크기 (2바이트)]
  Length: 0x0120 (288 클러스터 할당)
  Offset: 0x001005 (시작 클러스터 LCN = 4101)
```

---

## 3. Linux EXT2/EXT3/EXT4 파일 시스템 구조

리눅스 파일 시스템은 블록 그룹(Block Group) 단위로 디스크를 분할하여 관리합니다.

```
┌──────────────────┬──────────────┬──────────────┬─────────────────┐
│ Boot Record (1K) │ Block Group 0│ Block Group 1│ Block Group N.. │
└──────────────────┴──────────────┴──────────────┴─────────────────┘
Block Group Layout:
┌────────────┬──────────────────┬──────────────┬──────────────┬─────────────┬────────────┐
│ Superblock │ Group Descriptors│ Block Bitmap │ Inode Bitmap │ Inode Table │ Data Blocks│
└────────────┴──────────────────┴──────────────┴──────────────┴─────────────┴────────────┘
```

### 3.1 Inode 구조와 블록 포인터
- **Direct Block Pointers (0~11)**: 데이터 블록 번호를 직접 가리킴 (블록 크기 4KB 기준 최대 48KB).
- **Indirect Pointers**:
  - `12`: 단일 간접 블록 (Single Indirect Pointer) -> 1024개 블록 포인터 참조.
  - `13`: 이중 간접 블록 (Double Indirect Pointer) -> $1024 \times 1024$ 블록 포인터.
  - `14`: 삼중 간접 블록 (Triple Indirect Pointer).
- **EXT4 Extents 트리**: EXT4는 Inode에 블록 포인터 대신 `(시작 논리 블록, 블록 개수, 시작 물리 블록)` 형태의 Extents 구조를 도입하여 대용량 파일 할당 속도를 비약적으로 향상시켰습니다.

---

## 4. 슬랙 공간(Slack Space) 포렌식 분석

클러스터 크기(예: 4096 바이트)보다 작은 파일(예: 1500 바이트)을 저장할 때 클러스터의 남는 공간을 **슬랙 공간(Slack Space)**이라 부르며, 공격자가 은닉한 셸코드나 과거 삭제된 민감 데이터가 잔존합니다.

```
┌────────────────────────────────────── 4096 Bytes Cluster ─────────────────────────────────────┐
│ 1500 Bytes File Content │ 548 B (RAM Slack: 0패딩) │ 2048 B (Drive/File Slack: 이전 데이터 잔존) │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
 Sector 1 (512B)           Sector 2 (512B)            Sector 3 (512B)            Sector 4 (512B)
```

### 4.1 Python 기반 MFT & Slack Data Carving 실습

```python
#!/usr/bin/env python3
"""디스크 이미지 내 슬랙 공간 및 삭제된 파일 시그니처 검색 도구."""
from __future__ import annotations
import os

SIG_JPEG = b"\xFF\xD8\xFF\xE0"
SIG_PNG  = b"\x89PNG\r\n\x1a\n"
SIG_PDF  = b"%PDF-"
SIG_ZIP  = b"PK\x03\x04"

def carve_unallocated_slack(image_path: str, output_dir: str = "carved_output", block_size: int = 4096) -> None:
    os.makedirs(output_dir, exist_ok=True)
    signatures = [("jpg", SIG_JPEG), ("png", SIG_PNG), ("pdf", SIG_PDF), ("zip", SIG_ZIP)]
    
    with open(image_path, "rb") as f:
        offset = 0
        file_count = 0
        while True:
            chunk = f.read(block_size * 16)
            if not chunk:
                break
            for ext, sig in signatures:
                idx = chunk.find(sig)
                if idx != -1:
                    abs_offset = offset + idx
                    f.seek(abs_offset)
                    header_data = f.read(65536) # 샘플 덤프
                    out_name = os.path.join(output_dir, f"carved_{abs_offset:#x}.{ext}")
                    with open(out_name, "wb") as out_f:
                        out_f.write(header_data)
                    print(f"[+] 시그니처 발견: {ext.upper()} at offset {abs_offset:#x} -> {out_name}")
                    file_count += 1
                    f.seek(abs_offset + block_size)
            offset += len(chunk)
    print(f"[*] Carving 완료: 총 {file_count}개 파일 조각 복구됨.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        carve_unallocated_slack(sys.argv[1])
    else:
        print("사용법: python3 carve_slack.py <disk_image.raw>")
```

---

<a name="english"></a>

# File System Forensics Deep Dive — FAT32, NTFS, EXT Architecture & Data Carving

## 0. Conceptual Foundation

### What is File System Forensics?

File System Forensics is the rigorous technical reconstruction of storage layout structures and metadata records. When an operating system reports a file as "deleted", the low-level data clusters and metadata pointers often remain intact until overwritten by subsequent operations, providing irreplaceable evidentiary artifacts.

---

## 1. FAT32 Internal Structures & Deleted File Recovery

### 1.1 FAT32 Volume Organization
- **Reserved Area**: Houses Volume Boot Record (VBR) and FSInfo sector.
- **File Allocation Tables (FAT1 & FAT2)**: Cluster allocation chains.
- **Data Area**: Contiguous storage units (clusters 2 through N).

### 1.2 Directory Entry & Deletion Marker
In FAT32, deleting a file executes two primary actions:
1. Replaces the first character of the 32-byte directory entry with byte `0xE5`.
2. Marks the associated cluster entries in the FAT table as `0x00000000` (Free).
If the target file was contiguous (non-fragmented), full recovery is accomplished by parsing the starting cluster (`High << 16 | Low`) and reading the byte size specified in offset `0x1C`.

---

## 2. NTFS Architecture & $MFT Dissection

### 2.1 MFT Record Layout
Every file in NTFS is mapped to a 1024-byte record inside `$MFT`:
- `$STANDARD_INFORMATION (0x10)`: User-accessible MACB timestamps.
- `$FILE_NAME (0x30)`: Kernel-managed timestamps linked to parent directories.
- `$DATA (0x80)`: Payload storage, configured as either Resident ($\le 700$ bytes) or Non-Resident (Data Runs).

### 2.2 Timestomping Detection Matrix
If an adversary leverages user-mode API primitives (`SetFileTime`) to forge `$STANDARD_INFORMATION` timestamps, the underlying `$FILE_NAME` attributes within the same MFT record typically retain authentic creation and modification times, revealing anti-forensic tampering.

---

## 3. Linux EXT2/EXT3/EXT4 Architecture

- **Block Groups**: Division of storage into self-contained operational blocks.
- **Superblock**: Master volume parameters replicated across backup groups.
- **Inode Table**: Tracks ownership (UID/GID), permissions, file size, deletion time (`dtime`), and block allocation pointers.
- **EXT4 Extents**: Replaces multi-tiered indirect pointers with extent descriptors `(ee_block, ee_len, ee_start)` for high-throughput contiguous allocation.

---

## 4. Slack Space Exploitation & Carving

- **RAM Slack**: Unused space between the end of a file's logical end and the sector boundary (padded with zeros in modern kernels).
- **Drive / File Slack**: The remaining sectors in an allocated cluster past the file's logical end, frequently harboring residual data from previously deleted documents.
