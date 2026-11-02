# Write-up: Forgotten Secrets --- Binary Forensics & XOR Obfuscation

## 1. Thông tin thử thách

-   **Tên file:** `forgotten_secrets.bin`
-   **Kích thước:** 262.144 bytes (256 KiB)
-   **Định dạng flag:** `hiCTF{...}`
-   **Chủ đề:** Binary Forensics, Memory Dump Analysis, XOR Obfuscation

## 2. Mục tiêu

Một bản dump nhị phân được khôi phục từ máy chủ bị xâm nhập. Flag không
xuất hiện khi tìm kiếm chuỗi thông thường, vì vậy cần kiểm tra dữ liệu ở
mức byte và xem xét các phép biến đổi đơn giản có thể được dùng để che
giấu nội dung.

## 3. Phân tích ban đầu

### 3.1. Kiểm tra file

Có thể dùng các lệnh cơ bản trên Linux:

``` bash
file forgotten_secrets.bin
ls -lh forgotten_secrets.bin
xxd -l 32 forgotten_secrets.bin
```

Kết quả kiểm tra trực tiếp:

-   Kích thước file: `262144` bytes.
-   4 byte đầu: `7f 45 4c 46` --- ELF magic (`\x7fELF`).

Điều này cho thấy dữ liệu có phần đầu mang chữ ký ELF. Tuy nhiên, chỉ
dựa vào magic bytes chưa đủ để kết luận toàn bộ file là một ELF
executable hợp lệ.

### 3.2. Tìm flag bằng strings

Thử tìm chuỗi có thể đọc được:

``` bash
strings -a forgotten_secrets.bin | grep -i 'hiCTF{'
```

Không tìm thấy flag theo cách tìm kiếm trực tiếp. Đây là dấu hiệu cho
thấy nội dung có thể đã được mã hóa hoặc biến đổi trước khi ghi vào
file.

> Lưu ý: `strings` chỉ trích xuất các chuỗi ký tự in được. Không tìm
> thấy flag bằng `strings` không có nghĩa là flag không tồn tại trong dữ
> liệu.

## 4. Giả thuyết: XOR một byte

Một phép biến đổi thường gặp trong các bài CTF là XOR toàn bộ dữ liệu
hoặc một vùng dữ liệu với một byte khóa cố định.

Công thức:

\[ C_i = P_i `\oplus `{=tex}K \]

Trong đó:

-   (P_i): byte dữ liệu gốc.
-   (C_i): byte sau khi XOR.
-   (K): khóa XOR một byte, có giá trị từ `0x00` đến `0xFF`.

XOR có tính chất tự nghịch đảo:

\[ P_i = C_i `\oplus `{=tex}K \]

Vì khóa chỉ có 256 giá trị khả dĩ, có thể brute-force toàn bộ không gian
khóa một byte. Sau mỗi lần giải mã, chương trình kiểm tra sự xuất hiện
của tiền tố flag `hiCTF{`.

## 5. Khai thác: Brute-force XOR key

### 5.1. Script Python

``` python
from pathlib import Path

file_path = Path("forgotten_secrets.bin")
data = file_path.read_bytes()

for key in range(256):
    decoded = bytes(byte ^ key for byte in data)

    start = decoded.find(b"hiCTF{")
    if start == -1:
        continue

    end = decoded.find(b"}", start)
    if end == -1:
        continue

    flag = decoded[start:end + 1]

    print(f"[+] XOR key : 0x{key:02x}")
    print(f"[+] Offset  : {start} (decimal)")
    print(f"[+] Flag    : {flag.decode('ascii')}")
```

### 5.2. Kết quả

Chương trình tìm được kết quả:

``` text
[+] XOR key : 0x42
[+] Offset  : 143838 (decimal)
[+] Flag    : hiCTF{m3m0ry_dump_d1g_d33p}
```

-   **XOR key:** `0x42` (decimal `66`).
-   **Offset:** `143838` (decimal).
-   **Flag:** `hiCTF{m3m0ry_dump_d1g_d33p}`.

## 6. Xác minh kết quả

Có thể xác minh bằng cách giải mã lại file với khóa `0x42`, sau đó trích
xuất vùng chứa flag:

``` python
from pathlib import Path

data = Path("forgotten_secrets.bin").read_bytes()
key = 0x42

decoded = bytes(byte ^ key for byte in data)

offset = 143838
expected = b"hiCTF{m3m0ry_dump_d1g_d33p}"

assert decoded[offset:offset + len(expected)] == expected
print("Flag verified:", decoded[offset:offset + len(expected)].decode())
```

Phép XOR được áp dụng lại với cùng khóa sẽ khôi phục đúng byte ban đầu
vì:

\[ (P_i `\oplus `{=tex}K) `\oplus `{=tex}K = P_i \]

Việc kiểm tra cả tiền tố, dấu ngoặc đóng `}` và nội dung tại offset tìm
được giúp giảm khả năng nhận nhầm một chuỗi ngẫu nhiên thành flag.

## 7. Kết luận

Flag được che giấu bằng phép XOR với khóa một byte `0x42`. Tìm kiếm
chuỗi trực tiếp không phát hiện được flag vì các byte đã bị biến đổi.
Brute-force toàn bộ 256 khóa, kết hợp kiểm tra định dạng `hiCTF{...}`,
cho phép khôi phục nội dung.

**Flag cuối cùng:**

``` text
hiCTF{m3m0ry_dump_d1g_d33p}
```

## 8. Bài học rút ra

1.  Không nên phụ thuộc duy nhất vào `strings` hoặc tìm kiếm chuỗi thuần
    túy khi phân tích memory dump.
2.  Cần kiểm tra file ở cả mức cấu trúc (`file`, magic bytes, hex dump)
    và mức byte thô.
3.  XOR một byte là phép obfuscation yếu vì không gian khóa chỉ có 256
    khả năng.
4.  Khi brute-force, nên xác thực kết quả bằng định dạng flag, offset và
    nội dung giải mã thay vì chỉ dựa vào một chuỗi trùng khớp.
5.  Trong điều tra thực tế, cần xác định phạm vi dữ liệu bị biến đổi:
    toàn bộ file hay chỉ một vùng. Không nên mặc định mọi memory dump
    đều được XOR theo cùng một cách.

------------------------------------------------------------------------

*Ghi chú:* Write-up này mô tả phép XOR một byte đã được xác minh trên
file `forgotten_secrets.bin` được cung cấp. Việc file có ELF magic ở đầu
không tự chứng minh rằng toàn bộ cấu trúc ELF hợp lệ; phân tích cấu trúc
ELF chuyên sâu nằm ngoài phạm vi lời giải này.
