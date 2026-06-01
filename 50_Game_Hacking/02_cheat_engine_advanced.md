> 🌐 **Language / 언어**: [🇰🇷 한국어](#한국어) | [🇺🇸 English](#english)

---

<a name="한국어"></a>

# 02. Cheat Engine 고급 활용 (Advanced Cheat Engine)

Cheat Engine의 Lua 스크립팅, 자동 어셈블러, 구조체 분석 기능을 활용한 고급 치트 제작 방법을 다룬다. CTF 게임 해킹 챌린지 및 보안 연구 목적으로 활용한다.

---

## 1. Cheat Engine Lua 스크립팅

Cheat Engine은 내장 Lua 5.3 인터프리터를 제공한다. `Lua Engine` (Ctrl+Alt+L) 창에서 실행한다.

### 1.1 기본 Lua API

```lua
-- 프로세스 및 메모리 기본 조작

-- 현재 열린 프로세스의 모듈 베이스 주소
local base = getAddress("game.exe")
print(string.format("베이스: 0x%X", base))

-- 메모리 읽기
local hp_addr = base + 0xA1B2C3
local hp_value = readFloat(hp_addr)
print(string.format("현재 체력: %.1f", hp_value))

-- 메모리 쓰기
writeFloat(hp_addr, 9999.0)
print("체력 무한 적용")

-- 정수 읽기/쓰기
local gold = readInteger(base + 0xB2C3D4)
writeInteger(base + 0xB2C3D4, 999999)

-- 포인터 체인 역참조
local ptr1 = readPointer(base + 0xA1B2C3)
local ptr2 = readPointer(ptr1 + 0x10)
local final = ptr2 + 0x5C
writeFloat(final, 9999.0)
```

### 1.2 메모리 레코드 조작

```lua
-- Cheat Table의 메모리 레코드 접근
local mr = getAddressList()

-- 이름으로 레코드 찾기
local hp_record = mr.getMemoryRecordByDescription("체력")
if hp_record then
    hp_record.Active = true   -- 활성화 (고정)
    hp_record.Value = "9999"  -- 값 설정
end

-- 인덱스로 접근
local record = mr[0]  -- 첫 번째 레코드
print(record.Description, record.Address, record.Value)

-- 레코드 순회
for i = 0, mr.Count - 1 do
    local r = mr[i]
    print(i, r.Description, r.Address, r.Type)
end
```

### 1.3 타이머를 이용한 주기적 패치

```lua
-- 100ms마다 체력 유지 (무한 체력)
local base = getAddress("game.exe")
local hp_ptr_chain = {0xA1B2C3, 0x10, 0x5C, 0x08}

local function resolve_chain(b, chain)
    local addr = b
    for i = 1, #chain - 1 do
        addr = readPointer(addr + chain[i])
        if addr == 0 then return nil end
    end
    return addr + chain[#chain]
end

local timer = createTimer(nil, false)
timer.Interval = 100  -- 100ms

timer.OnTimer = function(sender)
    local hp_addr = resolve_chain(base, hp_ptr_chain)
    if hp_addr and hp_addr ~= 0 then
        writeFloat(hp_addr, 9999.0)
    end
end

timer.Enabled = true
print("[+] 무한 체력 타이머 시작")

-- 중지: timer.Enabled = false
```

### 1.4 핫키 등록

```lua
-- F1 키로 무적 토글
local god_mode = false
local god_timer = nil

registerHotkey(VK_F1, function()
    god_mode = not god_mode
    if god_mode then
        if not god_timer then
            god_timer = createTimer(nil, false)
            god_timer.Interval = 50
            god_timer.OnTimer = function()
                local base = getAddress("game.exe")
                local addr = resolve_chain(base, {0xA1B2C3, 0x10, 0x08})
                if addr then writeFloat(addr, 9999.0) end
            end
        end
        god_timer.Enabled = true
        print("[+] 무적 ON")
    else
        if god_timer then god_timer.Enabled = false end
        print("[-] 무적 OFF")
    end
end)

-- F2 키로 골드 증가
registerHotkey(VK_F2, function()
    local base = getAddress("game.exe")
    local gold_addr = base + 0xB2C3D4
    local current = readInteger(gold_addr)
    writeInteger(gold_addr, current + 100000)
    print(string.format("[+] 골드 추가: %d -> %d", current, current + 100000))
end)
```

---

## 2. 자동 어셈블러 (Auto Assembler)

CE의 자동 어셈블러는 x86/x64 어셈블리 코드를 직접 주입하는 강력한 도구다. `Ctrl+A` 로 열거나 메모리 뷰어에서 `Ctrl+A`.

### 2.1 기본 템플릿

```asm
[ENABLE]
; 코드 인젝션 템플릿
aobscanmodule(INJECT_HOOK, game.exe, 89 87 A8 00 00 00)  // AOB 스캔으로 주소 탐색
alloc(newmem, 128, INJECT_HOOK)                            // 코드 동굴 할당

label(code)
label(return)

newmem:
code:
  ; 원본 코드 실행 (필요 시)
  mov [edi+000000A8], eax
  ; 추가 로직: 체력을 항상 최대로
  mov eax, 461C4000    // float 9999.0 의 16진수 표현
  jmp return

INJECT_HOOK:
  jmp newmem
  nop
return:

[DISABLE]
INJECT_HOOK:
  db 89 87 A8 00 00 00  // 원본 바이트 복원
dealloc(newmem)
```

### 2.2 값 가로채기 (Code Injection)

데미지 처리 함수를 후킹하여 받는 데미지를 0으로 만드는 예제.

```asm
[ENABLE]
; 데미지 수신 함수 후킹 (x86 예시)
; 원본: mov [eax+08], ecx  — ECX에 새 체력값 저장
aobscanmodule(DMG_HOOK, game.exe, 89 48 08 8B 55 FC)
alloc(dmg_cave, 64, DMG_HOOK)

label(dmg_code)
label(dmg_ret)

dmg_cave:
dmg_code:
  ; ECX에서 체력 감소를 막는다
  ; 현재 체력이 100 이하면 9999로 복구
  cmp ecx, 00000064    ; 100 과 비교
  jg dmg_original      ; 100 초과면 정상 처리
  mov ecx, 0000270F    ; 9999 로 강제 설정 (정수)
dmg_original:
  mov [eax+08], ecx    ; 원본 명령어 실행
  jmp dmg_ret

DMG_HOOK:
  jmp dmg_cave
  nop
  nop
dmg_ret:

[DISABLE]
DMG_HOOK:
  db 89 48 08 8B 55 FC
dealloc(dmg_cave)
```

### 2.3 x64 코드 인젝션

```asm
[ENABLE]
; 64비트 게임용 JMP 후킹 (14바이트 절대 점프)
aobscanmodule(HOOK64, game.exe, 89 87 A8 00 00 00 48 8B 5C 24 30)
alloc(cave64, 128, HOOK64)

label(cave_code)
label(cave_ret)

cave64:
cave_code:
  ; 레지스터 보존
  push rax
  push rcx

  ; 커스텀 로직: RDI+A8 주소에 최대 체력 쓰기
  mov eax, 461C4000        ; float 9999.0
  mov [rdi+000000A8], eax

  pop rcx
  pop rax

  ; 원본 코드 재실행
  mov [rdi+000000A8], eax  ; 사실 위에서 이미 쓴 것과 동일
  jmp cave_ret

HOOK64:
  jmp cave64
  nop
  nop
cave_ret:

[DISABLE]
HOOK64:
  db 89 87 A8 00 00 00
dealloc(cave64)
```

### 2.4 NOP 패치

```asm
[ENABLE]
; 특정 코드 무력화
aobscanmodule(NOP_TARGET, game.exe, FF 50 14 83 C4 04 85 C0)
NOP_TARGET:
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop

[DISABLE]
NOP_TARGET:
  db FF 50 14 83 C4 04 85 C0
```

---

## 3. 구조체 역분석 (Structure Dissect)

### 3.1 구조체 뷰어 사용법

```
1. 대상 오브젝트의 베이스 주소 탐색 (예: 플레이어 구조체 시작 주소)
2. Memory View → Tools → Dissect data/structures
3. "Add extra address" 로 오브젝트 주소 입력
4. 자동으로 각 오프셋의 값을 표시

오프셋   크기  값           추정 의미
+0x00    4     1            플레이어 ID
+0x04    4     0.0          미사용/패딩
+0x08    4     9999.0       체력 (float)
+0x0C    4     9999.0       최대 체력
+0x10    4     500.0        마나 (float)
+0x14    4     500.0        최대 마나
+0x18    8     (포인터)     인벤토리 구조체 포인터
+0x20    4     100          레벨
+0x24    4     987654       경험치
```

### 3.2 구조체 정의 예시 (C 형식 역분석)

```c
// CE Structure Dissect 결과를 C 구조체로 표현
#pragma pack(push, 1)

typedef struct {
    int32_t  player_id;          // +0x00
    int32_t  padding;            // +0x04
    float    health;             // +0x08
    float    max_health;         // +0x0C
    float    mana;               // +0x10
    float    max_mana;           // +0x14
    void*    inventory_ptr;      // +0x18
    int32_t  level;              // +0x20
    int32_t  experience;         // +0x24
    float    pos_x;              // +0x28
    float    pos_y;              // +0x2C
    float    pos_z;              // +0x30
    uint8_t  is_alive;           // +0x34
    uint8_t  is_invincible;      // +0x35
    uint8_t  team_id;            // +0x36
    uint8_t  flags;              // +0x37
} PlayerStruct;

#pragma pack(pop)
```

---

## 4. CE Trainer 제작

### 4.1 Lua 기반 GUI 트레이너

```lua
-- CE 내장 GUI 라이브러리를 이용한 트레이너 창 제작

local base = getAddress("game.exe")

-- 메인 폼 생성
local form = createForm()
form.Caption = "Game Trainer v1.0 (CTF)"
form.Width = 300
form.Height = 400
form.Position = poScreenCenter

-- 무적 체크박스
local chk_godmode = createCheckBox(form)
chk_godmode.Caption = "무적 모드 (F1)"
chk_godmode.Left = 20
chk_godmode.Top = 20

local godmode_timer = createTimer(nil, false)
godmode_timer.Interval = 100

chk_godmode.OnChange = function(sender)
    godmode_timer.Enabled = sender.Checked
    if sender.Checked then
        godmode_timer.OnTimer = function()
            local addr = readPointer(base + 0xA1B2C3)
            if addr ~= 0 then
                writeFloat(addr + 0x08, 9999.0)
            end
        end
    end
end

-- 골드 설정 버튼
local lbl_gold = createLabel(form)
lbl_gold.Caption = "골드 설정:"
lbl_gold.Left = 20
lbl_gold.Top = 60

local edit_gold = createEdit(form)
edit_gold.Text = "999999"
edit_gold.Left = 20
edit_gold.Top = 80
edit_gold.Width = 150

local btn_gold = createButton(form)
btn_gold.Caption = "적용"
btn_gold.Left = 180
btn_gold.Top = 78
btn_gold.Width = 80
btn_gold.OnClick = function(sender)
    local gold_addr = base + 0xB2C3D4
    local amount = tonumber(edit_gold.Text)
    if amount then
        writeInteger(gold_addr, amount)
        showMessage(string.format("골드 %d 설정 완료", amount))
    end
end

-- 스피드 설정
local lbl_speed = createLabel(form)
lbl_speed.Caption = "이동속도 배율:"
lbl_speed.Left = 20
lbl_speed.Top = 120

local track_speed = createTrackBar(form)
track_speed.Min = 10
track_speed.Max = 500
track_speed.Position = 100
track_speed.Left = 20
track_speed.Top = 140
track_speed.Width = 240

local lbl_speed_val = createLabel(form)
lbl_speed_val.Caption = "1.0x"
lbl_speed_val.Left = 20
lbl_speed_val.Top = 170

track_speed.OnChange = function(sender)
    local multiplier = sender.Position / 100.0
    lbl_speed_val.Caption = string.format("%.1fx", multiplier)
    local speed_addr = base + 0xC3D4E5
    writeFloat(speed_addr, multiplier * 5.0)  -- 기본 속도 5.0 가정
end

-- 핫키
registerHotkey(VK_F1, function()
    chk_godmode.Checked = not chk_godmode.Checked
end)

form.show()
```

---

## 5. 스피드핵 구현 원리

### 5.1 타이머/틱 기반 조작

게임 속도는 보통 게임 내부 타이머 또는 고정 틱레이트로 제어된다.

```
게임 루프의 DeltaTime 변수를 조작하면 게임 전체 속도 변경 가능
DeltaTime 주소 탐색: "Unknown initial value" → 시간 경과 후 "Increased value"
```

```lua
-- DeltaTime 스피드핵 (Lua)
local delta_addr = nil  -- 스캔으로 탐색한 DeltaTime 주소
local speed_multiplier = 2.0  -- 2배속

local spdhack_timer = createTimer(nil, false)
spdhack_timer.Interval = 16  -- 약 60fps

spdhack_timer.OnTimer = function()
    if delta_addr and delta_addr ~= 0 then
        local dt = readFloat(delta_addr)
        -- DeltaTime에 배율 적용 (단, 한 프레임당 한 번만)
        if dt > 0 and dt < 0.1 then  -- 정상 범위 체크
            writeFloat(delta_addr, dt * speed_multiplier)
        end
    end
end
```

### 5.2 게임 클럭 함수 후킹

```asm
[ENABLE]
; GetTickCount 래퍼 후킹으로 게임 시간 가속
; 원본 GetTickCount 반환값에 배율 적용
aobscanmodule(TICK_HOOK, game.exe, FF 15 ?? ?? ?? ?? 89 45 F8)
alloc(tick_cave, 64, TICK_HOOK)

label(tick_code)
label(tick_ret)

tick_cave:
tick_code:
  ; 원본 GetTickCount 호출 (이미 EAX에 결과가 있음)
  ; EAX *= 2 (2배속)
  shl eax, 1
  jmp tick_ret

TICK_HOOK:
  jmp tick_cave
  nop
tick_ret:

[DISABLE]
TICK_HOOK:
  db FF 15
  db ?? ?? ?? ??
  db 89 45 F8
dealloc(tick_cave)
```

---

## 6. Python으로 Cheat Engine 테이블(.CT) 파서

### 6.1 CT 파일 구조

`.CT` 파일은 XML 기반이며 메모리 레코드, 설명, 핫키, Lua 스크립트를 포함한다.

```python
#!/usr/bin/env python3
"""
Cheat Engine 테이블 (.CT) 파서 및 분석 도구
CE 테이블에서 주소, 오프셋, 핫키 정보를 추출한다.
"""

import xml.etree.ElementTree as ET
import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class MemoryRecord:
    description: str
    address: str
    variable_type: str
    offsets: list[str] = field(default_factory=list)
    hotkeys: list[dict] = field(default_factory=list)
    value: Optional[str] = None
    group: Optional[str] = None


@dataclass
class CheatTable:
    process_name: str = ""
    records: list[MemoryRecord] = field(default_factory=list)
    lua_script: str = ""


def parse_offsets(entry_elem: ET.Element) -> list[str]:
    """OffsetList 요소에서 오프셋 목록 추출"""
    offsets: list[str] = []
    offset_list = entry_elem.find("OffsetList")
    if offset_list is None:
        return offsets

    for offset_elem in offset_list.findall("Offset"):
        if offset_elem.text:
            offsets.append(offset_elem.text.strip())

    return offsets


def parse_hotkeys(entry_elem: ET.Element) -> list[dict]:
    """Hotkeys 요소에서 핫키 정보 추출"""
    hotkeys: list[dict] = []
    hk_list = entry_elem.find("Hotkeys")
    if hk_list is None:
        return hotkeys

    for hk in hk_list.findall("Hotkey"):
        hk_info: dict = {}

        action_elem = hk.find("Action")
        if action_elem is not None:
            hk_info["action"] = action_elem.text or ""

        key_elem = hk.find("Keys")
        if key_elem is not None:
            hk_info["keys"] = key_elem.text or ""

        value_elem = hk.find("Value")
        if value_elem is not None:
            hk_info["value"] = value_elem.text or ""

        hotkeys.append(hk_info)

    return hotkeys


def parse_entry(
    entry_elem: ET.Element,
    group_name: Optional[str] = None
) -> Optional[MemoryRecord]:
    """단일 메모리 레코드 파싱"""
    desc_elem = entry_elem.find("Description")
    if desc_elem is None:
        return None

    description = desc_elem.text or "(unnamed)"

    # 변수 타입
    vtype_elem = entry_elem.find("VariableType")
    variable_type = vtype_elem.text if vtype_elem is not None else "4 Bytes"

    # 주소
    addr_elem = entry_elem.find("Address")
    address = addr_elem.text if addr_elem is not None else ""

    # 오프셋 (포인터 체인)
    offsets = parse_offsets(entry_elem)

    # 핫키
    hotkeys = parse_hotkeys(entry_elem)

    # 고정값
    value_elem = entry_elem.find("Value")
    value = value_elem.text if value_elem is not None else None

    return MemoryRecord(
        description=description.strip(),
        address=address.strip() if address else "",
        variable_type=variable_type.strip() if variable_type else "4 Bytes",
        offsets=offsets,
        hotkeys=hotkeys,
        value=value,
        group=group_name,
    )


def parse_entries_recursive(
    parent: ET.Element,
    records: list[MemoryRecord],
    group_name: Optional[str] = None
) -> None:
    """CheatEntries를 재귀적으로 순회하며 레코드 수집"""
    entries_elem = parent.find("CheatEntries")
    if entries_elem is None:
        return

    for entry in entries_elem.findall("CheatEntry"):
        # 그룹 여부 확인 (하위 CheatEntries 가 있으면 그룹)
        sub_entries = entry.find("CheatEntries")
        desc_elem = entry.find("Description")
        current_desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

        if sub_entries is not None:
            # 그룹 — 재귀 처리
            parse_entries_recursive(entry, records, group_name=current_desc)
        else:
            record = parse_entry(entry, group_name=group_name)
            if record:
                records.append(record)


def parse_ct_file(filepath: str) -> CheatTable:
    """CT 파일 전체 파싱"""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"CT 파일 미발견: {filepath}")

    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        raise ValueError(f"XML 파싱 오류: {e}") from e

    root = tree.getroot()
    table = CheatTable()

    # 프로세스 이름
    proc_elem = root.find("ProcessName") or root.find("TargetProcessName")
    if proc_elem is not None and proc_elem.text:
        table.process_name = proc_elem.text.strip()

    # Lua 스크립트
    lua_elem = root.find("LuaScript")
    if lua_elem is not None and lua_elem.text:
        table.lua_script = lua_elem.text

    # 메모리 레코드 파싱
    parse_entries_recursive(root, table.records)

    return table


def format_pointer_chain(record: MemoryRecord) -> str:
    """포인터 체인을 가독성 있는 문자열로 변환"""
    if not record.offsets:
        return record.address

    parts = [f"[{record.address}]"]
    for offset in record.offsets:
        parts.append(f"+{offset}")

    return " -> ".join(parts)


def print_summary(table: CheatTable) -> None:
    """테이블 요약 출력"""
    print(f"[*] 프로세스: {table.process_name or '(미설정)'}")
    print(f"[*] 메모리 레코드 수: {len(table.records)}")

    if table.lua_script:
        lines = len(table.lua_script.splitlines())
        print(f"[*] Lua 스크립트: {lines}줄")
    print()

    # 그룹별 정리
    groups: dict[str, list[MemoryRecord]] = {}
    for r in table.records:
        key = r.group or "(ungrouped)"
        groups.setdefault(key, []).append(r)

    for group, records in groups.items():
        print(f"  [{group}]")
        for r in records:
            chain = format_pointer_chain(r)
            hk_str = ""
            if r.hotkeys:
                keys = [h.get("keys", "") for h in r.hotkeys]
                hk_str = f" [핫키: {', '.join(keys)}]"
            print(f"    {r.description:<30} {r.variable_type:<12} {chain}{hk_str}")
        print()


def export_json(table: CheatTable, output_path: str) -> None:
    """파싱 결과를 JSON으로 내보내기"""
    data = {
        "process_name": table.process_name,
        "record_count": len(table.records),
        "has_lua": bool(table.lua_script),
        "records": [asdict(r) for r in table.records],
        "lua_script": table.lua_script,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON 내보내기 완료: {output_path}")


def extract_lua(table: CheatTable, output_path: str) -> None:
    """Lua 스크립트만 추출"""
    if not table.lua_script:
        print("[!] Lua 스크립트 없음")
        return
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(table.lua_script)
    print(f"[+] Lua 스크립트 추출: {output_path}")


def search_records(table: CheatTable, keyword: str) -> None:
    """키워드로 레코드 검색"""
    keyword_lower = keyword.lower()
    matches = [
        r for r in table.records
        if keyword_lower in r.description.lower()
        or keyword_lower in r.address.lower()
    ]
    print(f"[*] '{keyword}' 검색 결과: {len(matches)}개")
    for r in matches:
        chain = format_pointer_chain(r)
        print(f"  {r.description:<30} {r.variable_type:<12} {chain}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cheat Engine 테이블 (.CT) 파서")
    parser.add_argument("ct_file", help="분석할 .CT 파일 경로")

    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser("summary", help="테이블 요약 출력")

    p_export = sub.add_parser("export", help="JSON으로 내보내기")
    p_export.add_argument("output", help="출력 JSON 파일 경로")

    p_lua = sub.add_parser("lua", help="Lua 스크립트 추출")
    p_lua.add_argument("output", help="출력 .lua 파일 경로")

    p_search = sub.add_parser("search", help="레코드 검색")
    p_search.add_argument("keyword", help="검색 키워드")

    args = parser.parse_args()

    try:
        table = parse_ct_file(args.ct_file)
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] 오류: {e}", file=sys.stderr)
        sys.exit(1)

    command = args.command or "summary"

    if command == "summary":
        print_summary(table)
    elif command == "export":
        export_json(table, args.output)
    elif command == "lua":
        extract_lua(table, args.output)
    elif command == "search":
        search_records(table, args.keyword)


if __name__ == "__main__":
    main()
```

---

## 7. 실전 AOB 패턴 탐색 및 Lua 자동화

### 7.1 AOB 스캔 + 자동 후킹 Lua 스크립트

```lua
-- AOB 스캔으로 대상 주소 탐색 후 자동 후킹
local pattern = "89 87 A8 00 00 00 8B 4D FC"
local result = AOBScan(pattern, "+X")  -- 실행 가능 영역만 스캔

if result == nil then
    print("[!] 패턴 미발견: " .. pattern)
else
    print(string.format("[+] 패턴 발견: 0x%X", result))
    
    -- 자동 어셈블러 스크립트 생성 및 실행
    local script = [[
    [ENABLE]
    ]] .. string.format("0x%X", result) .. [[:
      mov eax, 461C4000
      mov [edi+000000A8], eax
      jmp ]] .. string.format("0x%X", result + 6) .. [[
    
    [DISABLE]
    ]] .. string.format("0x%X", result) .. [[:
      db 89 87 A8 00 00 00
    ]]
    
    local aa = createAutoAssembler()
    aa.execute(script)
    print("[+] 자동 어셈블러 실행 완료")
end
```

### 7.2 실전 팁 — CT 파일 재활용

```
# CTF 환경에서 CT 파일을 커맨드라인으로 분석
python ct_parser.py chall.ct summary
python ct_parser.py chall.ct search "health"
python ct_parser.py chall.ct lua extracted.lua
python ct_parser.py chall.ct export records.json
```

---

## 8. 주요 Cheat Engine 단축키

| 단축키     | 기능                       |
|-----------|----------------------------|
| Ctrl+A    | 자동 어셈블러 열기           |
| Ctrl+B    | 바이트 배열 스캔             |
| Ctrl+L    | Lua 엔진 열기               |
| Ctrl+D    | 구조체 분석 (Dissect)        |
| F5        | 현재 선택 주소로 메모리 뷰    |
| Ctrl+G    | 주소로 이동                  |
| Space     | 디스어셈블리 팝업            |
| F7        | 스텝 인 (디버거)             |
| F8        | 스텝 오버 (디버거)           |
| Ctrl+F2   | 프로세스 재시작              |

---

<a name="english"></a>

# 02. Advanced Cheat Engine Usage

This document covers advanced cheat creation techniques using Cheat Engine's Lua scripting, Auto Assembler, and structure analysis features. All content is intended for CTF game hacking challenges and security research purposes.

---

## 1. Cheat Engine Lua Scripting

Cheat Engine provides a built-in Lua 5.3 interpreter. Run scripts from the `Lua Engine` window (Ctrl+Alt+L).

### 1.1 Basic Lua API

```lua
-- Basic process and memory manipulation

-- Get the module base address of the currently opened process
local base = getAddress("game.exe")
print(string.format("Base: 0x%X", base))

-- Read memory
local hp_addr = base + 0xA1B2C3
local hp_value = readFloat(hp_addr)
print(string.format("Current HP: %.1f", hp_value))

-- Write memory
writeFloat(hp_addr, 9999.0)
print("Infinite HP applied")

-- Read/write integers
local gold = readInteger(base + 0xB2C3D4)
writeInteger(base + 0xB2C3D4, 999999)

-- Dereference a pointer chain
local ptr1 = readPointer(base + 0xA1B2C3)
local ptr2 = readPointer(ptr1 + 0x10)
local final = ptr2 + 0x5C
writeFloat(final, 9999.0)
```

### 1.2 Memory Record Manipulation

```lua
-- Access memory records in the Cheat Table
local mr = getAddressList()

-- Find a record by description
local hp_record = mr.getMemoryRecordByDescription("Health")
if hp_record then
    hp_record.Active = true   -- Activate (freeze)
    hp_record.Value = "9999"  -- Set value
end

-- Access by index
local record = mr[0]  -- First record
print(record.Description, record.Address, record.Value)

-- Iterate records
for i = 0, mr.Count - 1 do
    local r = mr[i]
    print(i, r.Description, r.Address, r.Type)
end
```

### 1.3 Periodic Patching with a Timer

```lua
-- Maintain HP every 100ms (infinite health)
local base = getAddress("game.exe")
local hp_ptr_chain = {0xA1B2C3, 0x10, 0x5C, 0x08}

local function resolve_chain(b, chain)
    local addr = b
    for i = 1, #chain - 1 do
        addr = readPointer(addr + chain[i])
        if addr == 0 then return nil end
    end
    return addr + chain[#chain]
end

local timer = createTimer(nil, false)
timer.Interval = 100  -- 100ms

timer.OnTimer = function(sender)
    local hp_addr = resolve_chain(base, hp_ptr_chain)
    if hp_addr and hp_addr ~= 0 then
        writeFloat(hp_addr, 9999.0)
    end
end

timer.Enabled = true
print("[+] Infinite HP timer started")

-- To stop: timer.Enabled = false
```

### 1.4 Registering Hotkeys

```lua
-- Toggle god mode with F1
local god_mode = false
local god_timer = nil

registerHotkey(VK_F1, function()
    god_mode = not god_mode
    if god_mode then
        if not god_timer then
            god_timer = createTimer(nil, false)
            god_timer.Interval = 50
            god_timer.OnTimer = function()
                local base = getAddress("game.exe")
                local addr = resolve_chain(base, {0xA1B2C3, 0x10, 0x08})
                if addr then writeFloat(addr, 9999.0) end
            end
        end
        god_timer.Enabled = true
        print("[+] God mode ON")
    else
        if god_timer then god_timer.Enabled = false end
        print("[-] God mode OFF")
    end
end)

-- Add gold with F2
registerHotkey(VK_F2, function()
    local base = getAddress("game.exe")
    local gold_addr = base + 0xB2C3D4
    local current = readInteger(gold_addr)
    writeInteger(gold_addr, current + 100000)
    print(string.format("[+] Gold added: %d -> %d", current, current + 100000))
end)
```

---

## 2. Auto Assembler

CE's Auto Assembler is a powerful tool that directly injects x86/x64 assembly code. Open it with `Ctrl+A` or from the Memory Viewer with `Ctrl+A`.

### 2.1 Basic Template

```asm
[ENABLE]
; Code injection template
aobscanmodule(INJECT_HOOK, game.exe, 89 87 A8 00 00 00)  // AOB scan to find address
alloc(newmem, 128, INJECT_HOOK)                            // Allocate code cave

label(code)
label(return)

newmem:
code:
  ; Execute original code (if needed)
  mov [edi+000000A8], eax
  ; Additional logic: always set health to maximum
  mov eax, 461C4000    // Hex representation of float 9999.0
  jmp return

INJECT_HOOK:
  jmp newmem
  nop
return:

[DISABLE]
INJECT_HOOK:
  db 89 87 A8 00 00 00  // Restore original bytes
dealloc(newmem)
```

### 2.2 Value Interception (Code Injection)

Example that hooks a damage handler function to set incoming damage to zero.

```asm
[ENABLE]
; Hook damage receive function (x86 example)
; Original: mov [eax+08], ecx  — stores new HP in ECX
aobscanmodule(DMG_HOOK, game.exe, 89 48 08 8B 55 FC)
alloc(dmg_cave, 64, DMG_HOOK)

label(dmg_code)
label(dmg_ret)

dmg_cave:
dmg_code:
  ; Prevent HP decrease from ECX
  ; If HP drops to 100 or below, restore to 9999
  cmp ecx, 00000064    ; Compare with 100
  jg dmg_original      ; If above 100, normal processing
  mov ecx, 0000270F    ; Force set to 9999 (integer)
dmg_original:
  mov [eax+08], ecx    ; Execute original instruction
  jmp dmg_ret

DMG_HOOK:
  jmp dmg_cave
  nop
  nop
dmg_ret:

[DISABLE]
DMG_HOOK:
  db 89 48 08 8B 55 FC
dealloc(dmg_cave)
```

### 2.3 x64 Code Injection

```asm
[ENABLE]
; JMP hook for 64-bit games (14-byte absolute jump)
aobscanmodule(HOOK64, game.exe, 89 87 A8 00 00 00 48 8B 5C 24 30)
alloc(cave64, 128, HOOK64)

label(cave_code)
label(cave_ret)

cave64:
cave_code:
  ; Preserve registers
  push rax
  push rcx

  ; Custom logic: write max health to RDI+A8
  mov eax, 461C4000        ; float 9999.0
  mov [rdi+000000A8], eax

  pop rcx
  pop rax

  ; Re-execute original code
  mov [rdi+000000A8], eax  ; Same as what was written above
  jmp cave_ret

HOOK64:
  jmp cave64
  nop
  nop
cave_ret:

[DISABLE]
HOOK64:
  db 89 87 A8 00 00 00
dealloc(cave64)
```

### 2.4 NOP Patch

```asm
[ENABLE]
; Neutralize specific code
aobscanmodule(NOP_TARGET, game.exe, FF 50 14 83 C4 04 85 C0)
NOP_TARGET:
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop

[DISABLE]
NOP_TARGET:
  db FF 50 14 83 C4 04 85 C0
```

---

## 3. Structure Reverse Engineering (Structure Dissect)

### 3.1 Using the Structure Viewer

```
1. Find the base address of the target object (e.g., player struct start address)
2. Memory View → Tools → Dissect data/structures
3. Add object address via "Add extra address"
4. Automatically displays values at each offset

Offset   Size  Value        Estimated Meaning
+0x00    4     1            Player ID
+0x04    4     0.0          Unused/padding
+0x08    4     9999.0       Health (float)
+0x0C    4     9999.0       Max Health
+0x10    4     500.0        Mana (float)
+0x14    4     500.0        Max Mana
+0x18    8     (pointer)    Inventory struct pointer
+0x20    4     100          Level
+0x24    4     987654       Experience
```

### 3.2 Structure Definition Example (C-style Reverse Engineering)

```c
// Representing CE Structure Dissect results as a C struct
#pragma pack(push, 1)

typedef struct {
    int32_t  player_id;          // +0x00
    int32_t  padding;            // +0x04
    float    health;             // +0x08
    float    max_health;         // +0x0C
    float    mana;               // +0x10
    float    max_mana;           // +0x14
    void*    inventory_ptr;      // +0x18
    int32_t  level;              // +0x20
    int32_t  experience;         // +0x24
    float    pos_x;              // +0x28
    float    pos_y;              // +0x2C
    float    pos_z;              // +0x30
    uint8_t  is_alive;           // +0x34
    uint8_t  is_invincible;      // +0x35
    uint8_t  team_id;            // +0x36
    uint8_t  flags;              // +0x37
} PlayerStruct;

#pragma pack(pop)
```

---

## 4. Building a CE Trainer

### 4.1 Lua-based GUI Trainer

```lua
-- Creating a trainer window using CE's built-in GUI library

local base = getAddress("game.exe")

-- Create main form
local form = createForm()
form.Caption = "Game Trainer v1.0 (CTF)"
form.Width = 300
form.Height = 400
form.Position = poScreenCenter

-- God mode checkbox
local chk_godmode = createCheckBox(form)
chk_godmode.Caption = "God Mode (F1)"
chk_godmode.Left = 20
chk_godmode.Top = 20

local godmode_timer = createTimer(nil, false)
godmode_timer.Interval = 100

chk_godmode.OnChange = function(sender)
    godmode_timer.Enabled = sender.Checked
    if sender.Checked then
        godmode_timer.OnTimer = function()
            local addr = readPointer(base + 0xA1B2C3)
            if addr ~= 0 then
                writeFloat(addr + 0x08, 9999.0)
            end
        end
    end
end

-- Gold setting button
local lbl_gold = createLabel(form)
lbl_gold.Caption = "Set Gold:"
lbl_gold.Left = 20
lbl_gold.Top = 60

local edit_gold = createEdit(form)
edit_gold.Text = "999999"
edit_gold.Left = 20
edit_gold.Top = 80
edit_gold.Width = 150

local btn_gold = createButton(form)
btn_gold.Caption = "Apply"
btn_gold.Left = 180
btn_gold.Top = 78
btn_gold.Width = 80
btn_gold.OnClick = function(sender)
    local gold_addr = base + 0xB2C3D4
    local amount = tonumber(edit_gold.Text)
    if amount then
        writeInteger(gold_addr, amount)
        showMessage(string.format("Gold set to %d", amount))
    end
end

-- Speed setting
local lbl_speed = createLabel(form)
lbl_speed.Caption = "Movement Speed Multiplier:"
lbl_speed.Left = 20
lbl_speed.Top = 120

local track_speed = createTrackBar(form)
track_speed.Min = 10
track_speed.Max = 500
track_speed.Position = 100
track_speed.Left = 20
track_speed.Top = 140
track_speed.Width = 240

local lbl_speed_val = createLabel(form)
lbl_speed_val.Caption = "1.0x"
lbl_speed_val.Left = 20
lbl_speed_val.Top = 170

track_speed.OnChange = function(sender)
    local multiplier = sender.Position / 100.0
    lbl_speed_val.Caption = string.format("%.1fx", multiplier)
    local speed_addr = base + 0xC3D4E5
    writeFloat(speed_addr, multiplier * 5.0)  -- Assume base speed is 5.0
end

-- Hotkey
registerHotkey(VK_F1, function()
    chk_godmode.Checked = not chk_godmode.Checked
end)

form.show()
```

---

## 5. Speed Hack Implementation Principles

### 5.1 Timer/Tick-based Manipulation

Game speed is usually controlled by an internal timer or a fixed tick rate.

```
Manipulating the DeltaTime variable in the game loop can change the overall game speed
Searching for DeltaTime: "Unknown initial value" → "Increased value" after time passes
```

```lua
-- DeltaTime speed hack (Lua)
local delta_addr = nil  -- DeltaTime address found by scanning
local speed_multiplier = 2.0  -- 2x speed

local spdhack_timer = createTimer(nil, false)
spdhack_timer.Interval = 16  -- ~60fps

spdhack_timer.OnTimer = function()
    if delta_addr and delta_addr ~= 0 then
        local dt = readFloat(delta_addr)
        -- Apply multiplier to DeltaTime (only once per frame)
        if dt > 0 and dt < 0.1 then  -- Sanity check for normal range
            writeFloat(delta_addr, dt * speed_multiplier)
        end
    end
end
```

### 5.2 Hooking the Game Clock Function

```asm
[ENABLE]
; Accelerate game time by hooking a GetTickCount wrapper
; Apply a multiplier to the original GetTickCount return value
aobscanmodule(TICK_HOOK, game.exe, FF 15 ?? ?? ?? ?? 89 45 F8)
alloc(tick_cave, 64, TICK_HOOK)

label(tick_code)
label(tick_ret)

tick_cave:
tick_code:
  ; Original GetTickCount has been called (result already in EAX)
  ; EAX *= 2 (2x speed)
  shl eax, 1
  jmp tick_ret

TICK_HOOK:
  jmp tick_cave
  nop
tick_ret:

[DISABLE]
TICK_HOOK:
  db FF 15
  db ?? ?? ?? ??
  db 89 45 F8
dealloc(tick_cave)
```

---

## 6. Python Cheat Engine Table (.CT) Parser

### 6.1 CT File Structure

`.CT` files are XML-based and contain memory records, descriptions, hotkeys, and Lua scripts.

```python
#!/usr/bin/env python3
"""
Cheat Engine Table (.CT) parser and analysis tool
Extracts addresses, offsets, and hotkey information from CE tables.
"""
# (same code as Korean section above)
```

---

## 7. Real-World AOB Pattern Search and Lua Automation

### 7.1 AOB Scan + Auto-Hooking Lua Script

```lua
-- Find target address via AOB scan and auto-hook
local pattern = "89 87 A8 00 00 00 8B 4D FC"
local result = AOBScan(pattern, "+X")  -- Scan only executable regions

if result == nil then
    print("[!] Pattern not found: " .. pattern)
else
    print(string.format("[+] Pattern found: 0x%X", result))
    -- Generate and execute Auto Assembler script
    -- (same structure as above)
    print("[+] Auto Assembler executed successfully")
end
```

### 7.2 Practical Tips — Reusing CT Files

```
# Analyze CT files from the command line in a CTF environment
python ct_parser.py chall.ct summary
python ct_parser.py chall.ct search "health"
python ct_parser.py chall.ct lua extracted.lua
python ct_parser.py chall.ct export records.json
```

---

## 8. Key Cheat Engine Shortcuts

| Shortcut   | Function                          |
|-----------|-----------------------------------|
| Ctrl+A    | Open Auto Assembler               |
| Ctrl+B    | Byte Array Scan                   |
| Ctrl+L    | Open Lua Engine                   |
| Ctrl+D    | Structure Dissect                 |
| F5        | Memory view at selected address   |
| Ctrl+G    | Go to address                     |
| Space     | Disassembly popup                 |
| F7        | Step Into (debugger)              |
| F8        | Step Over (debugger)              |
| Ctrl+F2   | Restart process                   |
