# Write-up: inner-engine (hiCTF – Reverse Engineering)

*Thể loại: Reverse Engineering · Nền tảng: Linux x86-64 ELF (Nim, stripped) · Flag format: `hiCTF{}`*

## 1. Đề bài

File README trong bộ cài LATHE-CAD r4 mô tả cơ chế kích hoạt node-locked: chạy `inner-engine <key>`, key đúng thì "unseal" bản ghi kích hoạt, sai thì vẫn bị khóa. Nhiệm vụ là tìm key hợp lệ để lấy flag.

**Kết quả:**

- Key: `L1c#N0d3_7mQ9f3a2b8c6d1e` (24 ký tự)
- Flag: `hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}`

```
$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

## 2. Khảo sát ban đầu

```
$ file inner-engine
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
$ sha256sum inner-engine
df7e8c38accd119e1feeee401e06d0e41abeab156747e757150e36b4dc42e38c
$ ./inner-engine test
license sealed
```

Những điểm nhận ra từ `strings`, `readelf` và `.rodata`:

- Các chuỗi `syncio.nim`, `cmdline.nim`, `IndexDefect`... cho thấy đây là chương trình **Nim**. Những hàm như `NimMain` và quản lý `string`/`seq` của Nim làm disassembly rối hơn bình thường.
- Chuỗi `@TracerPid:` và `@/proc/self/status` → có **kiểm tra anti-debug**.
- Thấy các chuỗi nhìn như rác (`PU_YROY`, `OY]PYX6`...) → dữ liệu bị mã hóa.
- Thư viện liên kết `libm`, `libc`; không có symbol nào hữu ích.

Trong sandbox không có `gdb`, `ltrace`, `strace`, `capstone` hay `z3`, nên mình chỉ dùng `objdump -d -M intel` và Python.

## 3. Tìm hàm chính

`_start` (`0x400560`) gọi `__libc_start_main` với `main = 0x400530`, hàm này gọi `NimMain` (`0x4048eb`) → `0x403814` (khởi tạo) → `0x404871` → module chính tại **`0x4047ad`**.

Từ `0x4047ad` có ba điều quan trọng:

1. `call 0x404588` khởi tạo **bảng 24 con trỏ hàm** ghi vào vùng `0x40a240 + opcode*8`.
2. `cmp [rdx+8], 0x18`: độ dài `argv[1]` phải đúng **24 byte**, nếu khác thì nhảy thẳng sang nhánh in lỗi.
3. `call 0x404709`: vòng lặp chính, thực chất là **một máy ảo bytecode**.

Nhánh thất bại (`0x404691`) lấy 15 byte từ `0x406298`, XOR từng byte với `0x3c`, rồi in ra. Kết quả là `license sealed\n`, đây là lý do `strings` không thấy.

## 4. Phân tích máy ảo

### 4.1. Vòng lặp fetch/decode (`0x404709`)

- Bytecode nằm tại `0x405e00`, dài `0x492` byte (234 lệnh), **mỗi lệnh 5 byte**: 1 byte opcode + 4 byte operand little-endian. Operand được lưu vào biến toàn cục `imm` (`0x40aa50`).
- `pc` ở `0x40aa58`, tăng 5 sau mỗi lệnh; cờ dừng ở `0x40aa48`; giới hạn 1.000.001 lệnh.
- Handler được gọi qua `table[opcode]`. Nếu ô bảng rỗng thì máy dừng.
- Ngn xếp là `seq` của Nim (độ dài tại `0x40aa80`, dữ liệu tại `+8`), phần tử 32-bit. Có 4 thanh ghi 32-bit tại `0x40aa60`. Key nằm trong một Nim `string` tại `0x40aa70` (len) và `0x40aa78` (con trỏ, dữ liệu tại `+8`).

### 4.2. Bảng opcode

Mình đọc từng handler và đặt tên như sau ("top" là phần tử đỉnh ngn xếp, "second" là phần tử dưới nó):

| Opcode | Tên | Handler | Hành động |
| --- | --- | --- | --- |
| 23 | PUSH | `0x403c14` | push `imm` |
| 76 | KEY | `0x403c1c` | push `key[imm]` (1 byte) |
| 149 | LOAD | `0x403c30` | push `reg[imm]` |
| 56 | STORE | `0x403c9c` | pop vào `reg[imm]` |
| 163 | DUP | `0x403c64` | nhân đôi đỉnh ngn xếp |
| 110 | SWAP | `0x403c78` | hoán đổi hai phần tử trên cùng |
| 43 | POP | `0x403c9a` | bỏ đỉnh |
| 125 | ADD | `0x403cb1` | `second + top` |
| 193 | SUB | `0x403cc7` | `second - top` |
| 138 | MUL | `0x403cf5` | `second * top` (32-bit) |
| 82 | XOR | `0x403cde` | `second ^ top` |
| 51 | AND | `0x403d0d` | `second & top` |
| 191 | OR | `0x403d24` | `second \| top` |
| 100 | ROL | `0x403d3b` | xoay trái top theo `imm` |
| 204 | SHL | `0x403d8c` | dịch trái top theo `imm` |
| 113 / 174 | NEG / NOT | `0x403d6c` / `0x403d7c` | phủ định số học / bit |
| 30 | EQ | `0x403d51` | push `1` nếu `second == top`, ngược lại push `0` |
| 73 | JZ | `0x403db7` | pop; nếu bằng 0 thì `pc = imm` |
| 215 | JMP | `0x403be2` | `pc = imm` |
| 229 / 90 | HALT(1) / HALT(2) | `0x403bf0` / `0x403bfc` | đặt cờ dừng |
| 242 | NODBG | `0x403fe3` | gọi hàm đọc `/proc/self/status`; push `1` nếu **không** bị trace, `0` nếu có `TracerPid` |
| 11 | UNSEAL | `0x404416` | giải mã và in flag (mục 5) |

Một lưu ý dễ nhầm: `JZ 0x6e` trong bytecode nhảy tới lệnh `HALT` ở offset `0x6e`. Ý có vẻ "thành công" của tên `OK` chỉ là do mình đặt tạm. Cho nên **mỗi `EQ` sai đều dẫn tới HALT**, còn thành công chỉ có khi chạy tới lệnh `UNSEAL` cuối cùng ở offset `0x48d`.

### 4.3. Chương trình bytecode

Mã bảo đảm bằng vòng lặp disassembly 5 byte/lệnh (xem script ở mục 7). Cấu trúc:

1. `NODBG; JZ 0x6e`: nếu đang bị debug thì dừng ngay.
2. Khởi tạo 4 thanh ghi: `r0 = k0`, `r1 = k1`, `r2 = k2`, `r3 = k3` (qua các lệnh "nhiễu" như `DUP; POP`, `OR 0`, `SWAP`, `ROL 8; ROL 24`. Hai lệnh xoay cộng lại đúng 32 bit nên không đổi gì).
3. `JMP 0x73`: nhảy qua lệnh `HALT`.
4. 23 khối kiểm tra, mỗi khối kết thúc bằng `PUSH c; EQ; JZ 0x6e`.
5. Lệnh cuối cùng `UNSEAL`.

## 5. Các ràng buộc trên key

Gọi `k[i]` là byte thứ `i` của key (0..23). Tất cả phép `ADD` và `MUL` đều được `AND 0xff` nên làm việc mod 256.

| # | Ràng buộc |
| --- | --- |
| 1 | `k5 ^ k6 = 0x54` |
| 2–12 | Tổng cặp liền kề: `k9+k10=0xa4`, `k10+k11=0xbe`, `k12+k13=0x9f`, `k13+k14=0x99`, `k14+k15=0x94`, `k16+k17=0x94`, `k17+k18=0x9a`, `k18+k19=0x9b`, `k19+k20=0x99`, `k20+k21=0x9a`, `k22+k23=0x96` |
| 13 | `k23 + k0 = 0xb1` |
| 14 | `k3 * k15 = 0x43` |
| 15 | `k7 * k21 = 0xec` |
| 16 | `k11 * k19 = 0x53` |
| 17 | `k0 ^ k8 ^ k16 = 0x21` |
| 18 | `k4 ^ k12 ^ k20 = 0x41` |
| 19 | `k2 ^ k10 ^ k18 = 0x36` |
| 20 | `k0 + k4 + k8 + k12 + k16 + k20 = 0x9a` |
| 21 | `k1 ^ k5 ^ k9 ^ k13 ^ k17 ^ k21 = 0x56` |
| 22 | `k2 + k7 + k10 + k15 + k18 + k23 = 0x01` |
| 23 | `k3 ^ k6 ^ k11 ^ k14 ^ k19 ^ k22 = 0x77` |

Các ràng buộc dạng cột (20–23) là các hàm "parity" trên bốn cột `i mod 4`, gồm XOR hoặc tổng của `k[i], k[i+4], k[i+8], ...`.

## 6. Giải ràng buộc

Có 23 phương trình cho 24 ẩn, nhưng ràng buộc có cấu trúc chuỗi nên mình chỉ cần **4 tham số tự do**: `k9`, `k12`, `k16`, `k22`. Từ đó suy ra:

- `k10, k11` từ chuỗi `k9`; `k13, k14, k15` từ `k12`; `k17..k21` từ `k16`; `k23` từ `k22`.
- `k0 = 0xb1 - k23`.
- `k8 = k0 ^ k16 ^ 0x21`, `k4 = k12 ^ k20 ^ 0x41`, `k2 = k10 ^ k18 ^ 0x36`.
- `k7` từ ràng buộc 22, `k3` từ ràng buộc 14 (cần `k15` lẻ để có nghịch đảo mod 256).
- `k6` từ ràng buộc 23, `k5 = k6 ^ 0x54`, `k1` từ ràng buộc 21.
- Các ràng buộc còn lại (15, 16, 20) dùng để lọc.

Vì sandbox không có `z3`, mình viết solver vét cạn có cắt tỉa với miền ký tự in được (0x20–0x7e). Không gian tìm kiếm chỉ là đầu vào của 4 vòng lặp lồng nhau, được rút gọn mạnh nhờ kiểm tra sớm.

```python
P = range(32, 127)
ok = lambda v: 32 <= v <= 126
sols = []
for a in P:                                   # k9
    k9 = a; k10 = (0xa4 - k9) & 255; k11 = (0xbe - k10) & 255
    if not (ok(k10) and ok(k11)): continue
    for c in P:                               # k16
        k16 = c; k17 = (0x94 - k16) & 255; k18 = (0x9a - k17) & 255
        k19 = (0x9b - k18) & 255; k20 = (0x99 - k19) & 255; k21 = (0x9a - k20) & 255
        if not all(ok(x) for x in (k17, k18, k19, k20, k21)): continue
        if (k11 * k19) & 255 != 0x53: continue
        for b in P:                           # k12
            k12 = b; k13 = (0x9f - k12) & 255; k14 = (0x99 - k13) & 255; k15 = (0x94 - k14) & 255
            if not all(ok(x) for x in (k13, k14, k15)): continue
            k3s = [x for x in P if (x * k15) & 255 == 0x43]
            for d in P:                       # k22
                k22 = d; k23 = (0x96 - k22) & 255; k0 = (0xb1 - k23) & 255
                if not (ok(k23) and ok(k0)): continue
                k8 = k0 ^ k16 ^ 0x21; k4 = k12 ^ k20 ^ 0x41
                if not (ok(k8) and ok(k4)): continue
                if (k0 + k4 + k8 + k12 + k16 + k20) & 255 != 0x9a: continue
                k2 = k10 ^ k18 ^ 0x36
                if not ok(k2): continue
                k7 = (1 - (k2 + k10 + k15 + k18 + k23)) & 255
                if not ok(k7) or (k7 * k21) & 255 != 0xec: continue
                for k3 in k3s:
                    k6 = k3 ^ k11 ^ k14 ^ k19 ^ k22 ^ 0x77
                    k5 = k6 ^ 0x54
                    k1 = k5 ^ k9 ^ k13 ^ k17 ^ k21 ^ 0x56
                    if not (ok(k5) and ok(k6) and ok(k1)): continue
                    sols.append(bytes([k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11,
                                       k12, k13, k14, k15, k16, k17, k18, k19, k20, k21, k22, k23]))
print(sols)
```

Kết quả có **hai nghiệm in được**:

```
L1c#N0d3_7mQ9f3a2b8c6d1e
FS##F*~}]OUi9f3a:Z@[>\+k
```

Nghiệm đầu rõ ràng là key do tác giả đặt (`L1c#N0d3_` = "license node" dạng leet, kết thúc bằng `f3a2b8c6d1e`). Nghiệm thứ hai chỉ là nghiệm ngẫu nhiên của hệ ràng buộc.

## 7. Unseal và flag

Handler `UNSEAL` (`0x404416`) làm các việc sau:

1. Tính **SHA-256** của key. Nhận biết qua hằng số khởi tạo tại `0x406420`, `0x406430`, phần padding (`idiv 0x40`, dừng tại 56 byte) và ghi độ dài bit dạng big-endian.
2. Chạy một bước suy dẫn (`0x404336`) để tạo 40 byte khóa từ digest.
3. XOR 40 byte đó với ciphertext tại `0x4062e0`.
4. Tính SHA-256 của kết quả và so với digest lưu sẵn tại `0x4062c0`.
5. Nếu khớp thì in ra bản rõ (flag), nếu không thì chỉ hiện `license sealed`.

Bước 2 mình **không phân tích sâu** vì không cần: với hai ứng viên, mình chạy trực tiếp binary làm "oracle":

```
$ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}

$ ./inner-engine 'FS##F*~}]OUi9f3a:Z@[>\+k'
license sealed
```

Nghiệm thứ hai vượt qua cả 23 ràng buộc của VM nhưng vẫn bị từ chối ở bước 4 (khóa SHA-256 sai nên giải mã ra rác). Điều này cho thấy VM chỉ lọc ứng viên, còn **chính key mới là khóa giải mã**.

## 8. Disassembler cho bytecode

Đoạn script dùng để đọc bytecode (offset file = `0x5e00`, vì segment chứa `.rodata` map `0x405000` ↔ `0x5000`):

```python
d = open('inner-engine', 'rb').read()
code = d[0x5e00:0x5e00 + 0x492]
ops = {23:'PUSH', 76:'KEY', 149:'LOAD', 163:'DUP', 110:'SWAP', 43:'POP', 56:'STORE',
       125:'ADD', 193:'SUB', 82:'XOR', 138:'MUL', 51:'AND', 191:'OR', 100:'ROL',
       30:'EQ', 113:'NEG', 174:'NOT', 204:'SHL', 73:'JZ', 215:'JMP',
       229:'HALT1', 90:'HALT2', 242:'NODBG', 11:'UNSEAL'}
for pc in range(0, len(code), 5):
    op = code[pc]
    imm = int.from_bytes(code[pc + 1:pc + 5], 'little')
    print(f'{pc:4d} {ops.get(op, op)} {imm}')
```

## 9. Lưu ý và hạn chế

- Mình không debug động mà chỉ đọc tĩnh rồi chạy binary với các ứng viên, nên **không vướng anti-debug**. Nếu bạn dùng `gdb`, lệnh `NODBG` sẽ thấy `TracerPid` khác 0 và VM dừng ngay. Cách lách: patch hàm `0x403dd0` hoặc cho `gdb` attach sau khi đã qua lệnh đó (hoặc `set` thanh ghi trả về).
- Mình không đảo hết hàm suy dẫn khóa tại `0x404336` và không tái hiện flag bằng Python thuần. Nếu muốn biết chắc nghiệm là duy nhất trong cả không gian không in được (byte 0x00–0xff), cần mở rộng domain và giải lại. Với miền ký tự in được, nghiệm đúng là `L1c#N0d3_7mQ9f3a2b8c6d1e`.

## 10. Bài học

- **VM bytecode là một lớp che đậy, không phải bảo mật.** Khi đã biết cấu trúc `opcode + imm` và bảng handler, toàn bộ logic kiểm tra là một hệ phương trình tuyến tính/XOR/nhân mod 256 giải được bằng solver hoặc script ngắn.
- **Kiểm tra key rồi mới giải mã flag bằng chính key** là thiết kế đúng hơn so với nhúng sẵn flag vào binary, nhưng vẫn yếu nếu không gian key nhỏ và có oracle tự kiểm tra (digest). Trong bài này các ràng buộc VM đã thu hẹp key xuống còn 2 ứng viên.
- **Chuỗi bị mã hóa XOR 1 byte** (`0x3c`) tránh được `strings` nhưng lộ ngay khi đọc vòng lặp giải mã. Nên tìm các đoạn `xor reg, imm8` lặp qua một mảng hằng.
- **Khi không có công cụ**, `objdump` + Python (phân tích handler từng cái, dựng disassembler riêng cho bytecode) là đủ để giải một bài VM-crackme.
