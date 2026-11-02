# Write-up: snaptool — Giải mã định dạng Snapfile (.snap)

Oct 31, 2026

## 1. Đề bài

Challenge cung cấp đúng một file duy nhất: `snaptool` — binary Crystal đã strip, Linux x86-64, không phụ thuộc runtime ngoài glibc thường. Theo mô tả:

- Một nhóm research-tooling tự chế định dạng container nhị phân nén gọn, gọi là **snapfile** (`.snap`), và viết công cụ dòng lệnh Crystal `snaptool` để kiểm tra (validate) và giải nén các file này.
- Định dạng chưa từng được tài liệu hóa ra bên ngoài; thứ duy nhất lộ ra là chính binary — không có source, không có spec, không có file `.snap` mẫu.
- Cách dùng: `./snaptool somefile.snap`. Nếu file hợp lệ, tool in ra **label** đã giải nén (đó chính là flag); nếu không, in `invalid snapfile`. Không có option nào khác, không có log debug.

Mục tiêu: tự suy ngược định dạng `.snap` từ chính binary, tự tay dựng một file `.snap` mà `snaptool` chấp nhận là "genuine", để nó in ra flag.

## 2. Khảo sát ban đầu

```
file snaptool
→ ELF 64-bit LSB executable, x86-64, dynamically linked, stripped, GNU/Linux
```

`strings` lộ ra ngay hàng loạt chuỗi `Crystal::...`, `/usr/share/crystal/src/...` → binary được build bằng **ngôn ngữ Crystal** (tự biên dịch native, không có bytecode/VM, nhưng mang theo runtime GC + exception + backtrace rất đặc trưng — giải thích vì sao file nặng gần 600KB dù logic chính rất ít).

Một chuỗi quan trọng xuất hiện đúng một lần:

```
invalid snapfile
```

Đây chính là thông điệp lỗi duy nhất của tool, nên **mọi logic kiểm tra hợp lệ đều hội tụ về một hàm fail() dùng chung** — chỉ cần tìm tất cả nơi gọi đến hàm in ra chuỗi này là sẽ lần ra toàn bộ các điều kiện validate.

Thử chạy nhanh với file rác (toàn byte 0x00, nhiều kích thước khác nhau) — tool luôn trả lời `invalid snapfile`, không có thông tin rò rỉ nào qua stdout/stderr. Cần quan sát sâu hơn ở tầng syscall.

## 3. Truy vết syscall đọc file

Môi trường không có `strace`, nhưng có `gcc` → tự viết một shim `LD_PRELOAD` nhỏ để hook `openat`, `read`, `pread64`, `lseek` và log lại tham số + nội dung buffer vào file log.

Chạy thử với file 1000 byte chứa dữ liệu tuần tự `00 01 02 ... FF ...`:

```
read(fd=3, count=1700) = 721 : 63 70 75 20 20 32 30 37 ...   # /proc/cpuinfo (runtime Crystal tự đọc)
read(fd=9, count=32768) = 1000 : 00 01 02 03 04 ...
read(fd=9, count=0) : (EOF)
```

Kết luận: `snaptool` đọc **toàn bộ file vào bộ nhớ trong một lần** (kiểu `File.read`/`IO#gets_to_end` của Crystal — gọi `read()` với buffer lớn tới khi EOF), không hề dùng `lseek`/`pread64` để nhảy offset. Điều này nghĩa là toàn bộ thao tác parse diễn ra trên buffer trong RAM, không có cấu trúc kiểu "đọc dần theo stream" — thuận lợi cho việc đọc ngược bằng disassembly vì mọi offset trong file tương ứng trực tiếp với offset trong buffer.

## 4. Đọc ngược định dạng header

Dùng `objdump -d` toàn bộ binary rồi tìm các điểm gọi tới hàm `fail()` (nơi in `invalid snapfile`, địa chỉ `0x436710`). Hai lệnh gọi (`0x4035e4` và `0x403bc2`) dẫn ngược về đúng một khối logic validate chính trong `main`, bắt đầu từ `0x402c26`.

**Kiểm tra kích thước file** — so sánh trực tiếp với hằng số:

```asm
cmp ebp, 0x68      ; filesize phải đúng bằng 0x68 = 104 byte
jne fail
```

→ `.snap` hợp lệ có kích thước **cố định 104 byte**, không có phần dữ liệu biến đổi độ dài.

**Magic 4 byte đầu + version + flags** — so từng byte:

```asm
cmp byte[rbx+0], 0x53   ; 'S'
cmp byte[rbx+1], 0x4e   ; 'N'
cmp byte[rbx+2], 0x41   ; 'A'
cmp byte[rbx+3], 0x50   ; 'P'
; word tại offset 4-5, đọc big-endian (rol ax,8 rồi so == 0x0002)
cmp byte[rbx+6], 0x03
cmp byte[rbx+7], 0x00
```

→ offset 0–3 = `"SNAP"`, offset 4–5 = version **2** (big-endian uint16), offset 6 = `0x03`, offset 7 = `0x00`.

**Tag 8 byte tiếp theo** — 8 byte tại offset 8–15 được build thành một số 64-bit theo kiểu big-endian (byte đầu → bit cao nhất) rồi so với hằng số `0x534e41502d4c4e47`:

```
0x53 0x4e 0x41 0x50 0x2d 0x4c 0x4e 0x47  =  "SNAP-LNG"
```

→ offset 8–15 = chuỗi ASCII `"SNAP-LNG"` (có lẽ viết tắt cho *snap-lang* hoặc tên định dạng).

**Bảng offset/length 24 byte tiếp theo (offset 0x10–0x27)** — đọc qua một hàm phụ `sub_438800(buf, flag, ptr, field_offset)` trả về giá trị 4 byte big-endian tại `field_offset`, rồi so khớp với các hằng số cố định:

| offset field | giá trị bắt buộc | ý nghĩa |
| --- | --- | --- |
| 0x10 | `0x28` (40) | offset vùng #1 |
| 0x14 | `0x10` (16) | length vùng #1 |
| 0x18 | `0x38` (56) | offset vùng #2 |
| 0x1c | `0x20` (32) | length vùng #2 |
| 0x20 | `0x58` (88) | offset vùng #3 |
| 0x24 | `0x08` (8) | length vùng #3 |

Code còn ràng buộc tính liên tục: `offset2 == offset1+length1`, `offset3 == offset2+length2`, `offset3+length3 == 0x60`. Ba vùng này khớp hoàn hảo, liền kề nhau: **\[0x28,0x38) = 16 byte "label"**, **\[0x38,0x58) = 32 byte** (đúng kích thước một digest **SHA-256** — khớp với chuỗi `"SHA256"` và các lời gọi `EVP_DigestInit_ex`/`EVP_DigestFinal_ex` (OpenSSL) thấy trong binary), **\[0x58,0x60) = 8 byte** còn lại chưa rõ, tạm gọi là vùng dự trữ/entry phụ.

Cộng với 8 byte checksum cuối file (0x60–0x68, xem mục 6), tổng vừa khít 104 byte.

## 5. Trường SHA-256 ở offset 0x38

Sau khi bảng offset/length khớp, code gọi hàm `0x438890(length=edi, dataptr=rdx)` — đây là một wrapper gọi thẳng OpenSSL (`EVP_get_digestbyname("SHA256")` → `EVP_DigestInit_ex` → `EVP_DigestUpdate` → `EVP_DigestFinal_ex`), tức hàm tổng quát "tính SHA-256 của `length` byte bắt đầu từ `dataptr`".

Điểm mấu chốt: lệnh gọi dùng

```asm
mov edi, 0x28      ; length = 0x28 = 40
mov rdx, rbx        ; dataptr = đầu buffer file
call 0x438890
```

Nghĩa là **digest không phải của label**, mà là **SHA-256 của đúng 40 byte đầu file** — tức toàn bộ header cố định (magic + version + flags + tag `"SNAP-LNG"` + bảng offset/length). Vì 40 byte này hoàn toàn xác định sẵn (không phụ thuộc nội dung do người tạo file chọn), giá trị digest mong đợi tại offset 0x38 cũng **tính được ngay bằng Python**, không cần đoán hay brute-force:

```python
import hashlib, struct
header = b"SNAP" + struct.pack(">H", 2) + bytes([3, 0]) + b"SNAP-LNG"
table  = struct.pack(">IIIIII", 0x28,0x10, 0x38,0x20, 0x58,0x08)
hdr    = header + table          # đúng 40 byte
digest = hashlib.sha256(hdr).digest()
# 602ad961723691750a666930a6d68399af7a4b8e20210122beb7817c64412b74  (32 byte)
```

Đây chính là nội dung bắt buộc cho vùng \[0x38, 0x58).

## 6. Checksum 8 byte cuối cùng (offset 0x60–0x68)

Ngay sau khi qua được check SHA-256, có một vòng lặp 88 vòng (`rcx` chạy từ `-0x58` đến `0`) trông giống thuật toán băm kiểu FNV, thao tác trên byte tại `[rbx + rcx + 0x60]` — tức duyệt đúng **88 byte từ offset 0x08 đến 0x60** (toàn bộ: tag + bảng offset + label + digest + vùng dự trữ):

```asm
movabs rax, 0x1357bdf02468ace1      ; seed ban đầu
movabs rdx, 0xd1b54a32d192ed03      ; hằng số nhân
loop:
  movzx esi, byte[rbx+rcx+0x60]
  add   rsi, rax
  imul  rsi, rdx
  mov   rax, rsi
  shr   rax, 0x1d
  xor   rax, rsi
  inc   rcx
  jne   loop
```

Dịch sang Python (số học mod 2⁶⁴):

```python
MASK64 = (1 << 64) - 1
def hasher(data):
    a = 0x1357bdf02468ace1
    mul = 0xd1b54a32d192ed03
    for byte in data:
        a = (byte + a) & MASK64
        a = (a * mul) & MASK64
        a = (a >> 0x1d) ^ a
        a &= MASK64
    return a
```

(Hai hằng số `0x1357bdf02468ace1` / `0xd1b54a32d192ed03` khá giống seed/constant dùng trong `Crystal::Hasher` của thư viện chuẩn Crystal — hợp lý vì toàn bộ binary được Crystal sinh ra.)

Sau vòng lặp, 8 byte cuối file (offset 0x60–0x68) được đọc thành một số 64-bit big-endian, XOR với kết quả hash, và so với hằng số cố định:

```asm
xor rdx, rax      ; rdx = BE(bytes[0x60:0x68]) XOR hash
cmp rdx, 0x58
jne fail
```

→ điều kiện cuối cùng: `BE(file[0x60:0x68]) == hasher(file[0x08:0x60]) XOR 0x58`.

Vì ta tự chọn toàn bộ 88 byte đầu vào (label tùy ý + digest đã tính sẵn ở mục 5 + 8 byte vùng dự trữ tùy ý), checksum này **tự tính được**, không phải một bí mật ẩn — nó chỉ đảm bảo tính toàn vẹn nội bộ của file, không ràng buộc nội dung label phải là một giá trị bí mật cụ thể.

## 7. Dựng file .snap hợp lệ

Gộp tất cả các ràng buộc đã suy ra từ mục 4–6 thành một script dựng file:

```python
import hashlib, struct

MASK64 = (1 << 64) - 1

def hasher(data):
    a = 0x1357bdf02468ace1
    mul = 0xd1b54a32d192ed03
    for byte in data:
        a = (byte + a) & MASK64
        a = (a * mul) & MASK64
        a = (a >> 0x1d) ^ a
        a &= MASK64
    return a

# --- header cố định, 40 byte ---
header = b"SNAP" + struct.pack(">H", 2) + bytes([3, 0]) + b"SNAP-LNG"
table  = struct.pack(">IIIIII", 0x28, 0x10, 0x38, 0x20, 0x58, 0x08)
hdr    = header + table
assert len(hdr) == 0x28

# --- digest của header (bắt buộc, tự tính) ---
digest = hashlib.sha256(hdr).digest()

# --- label: 16 byte, nội dung không bị ràng buộc gì khác ---
label  = b"hiCTF{????????}"[:16].ljust(16, b"\x00")

# --- 8 byte vùng dự trữ cuối: cũng không bị ràng buộc ---
entry3 = b"\x00" * 8

body = hdr + label + digest + entry3
assert len(body) == 0x60

# --- checksum 8 byte cuối ---
h = hasher(body[8:0x60])          # 88 byte, offset 0x08..0x60
checksum = (h ^ 0x58).to_bytes(8, "big")

full = body + checksum
assert len(full) == 0x68           # đúng 104 byte
open("test1.snap", "wb").write(full)
```

Chạy thử:

```
$ ./snaptool test1.snap
hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}
```

File được chấp nhận ngay ở lần thử đầu tiên — mọi suy luận ở mục 4–6 là đủ và chính xác.

## 8. Kết quả

Điều bất ngờ: dù label ta nhét vào chỉ là chuỗi giả `"hiCTF{????????}"` (16 byte, padding `\x00`), `snaptool` vẫn in ra **một chuỗi dài hơn hẳn 16 byte**, không liên quan gì tới nội dung ta đưa vào:

```
hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}
```

Nghĩa là trường "label" 16 byte trong file **không phải** là nguồn thật của chuỗi được in ra — nó chỉ là một phần dữ liệu cần đúng định dạng/đúng checksum để vượt qua validate. Một khi file được coi là "genuine" (đúng magic, đúng version, đúng bảng offset/length, đúng SHA-256 header, đúng checksum FNV cuối), nhánh thành công của chương trình in ra một **chuỗi được nhúng sẵn, cố định trong chính binary** — đó chính là flag thật, độc lập với nội dung label ta tự chọn.

### Tổng kết định dạng Snapfile (104 byte, mọi số nguyên big-endian)

| Offset | Length | Nội dung |
| --- | --- | --- |
| 0x00 | 4 | Magic `"SNAP"` |
| 0x04 | 2 | Version = `2` |
| 0x06 | 1 | `0x03` |
| 0x07 | 1 | `0x00` |
| 0x08 | 8 | Tag `"SNAP-LNG"` |
| 0x10 | 4 | Offset vùng #1 = `0x28` |
| 0x14 | 4 | Length vùng #1 = `0x10` |
| 0x18 | 4 | Offset vùng #2 = `0x38` |
| 0x1c | 4 | Length vùng #2 = `0x20` |
| 0x20 | 4 | Offset vùng #3 = `0x58` |
| 0x24 | 4 | Length vùng #3 = `0x08` |
| 0x28 | 16 | "Label" (không ràng buộc nội dung thật) |
| 0x38 | 32 | SHA-256(byte 0x00–0x28) |
| 0x58 | 8 | Vùng dự trữ (không ràng buộc) |
| 0x60 | 8 | Checksum = hasher(byte 0x08–0x60) XOR `0x58` |

### Flag

```
hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}
```

### Công cụ/kỹ thuật đã dùng

- `file`, `strings`, `objdump -d -M intel` để đọc ngược binary Crystal đã strip.
- Truy ngược từ chuỗi lỗi duy nhất `"invalid snapfile"` để tìm toàn bộ các điểm kiểm tra hợp lệ.
- Tự viết shim `LD_PRELOAD` (biên dịch bằng `gcc -shared -fPIC`) để quan sát hành vi đọc file khi không có `strace`.
- Dịch tay từng đoạn assembly dựng số 64-bit big-endian từ các byte rời rạc, nhận diện các hằng số OpenSSL (`EVP_*`) và chuỗi `SHA256`.
- Dịch thuật toán băm kiểu FNV sang Python để tái tạo checksum cuối file.
- Viết script Python dựng file `.snap` thỏa mọi ràng buộc đã suy ra, kiểm chứng bằng cách chạy trực tiếp `snaptool`.
