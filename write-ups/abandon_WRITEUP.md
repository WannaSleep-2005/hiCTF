# Write-up: tìm địa điểm quay lại nhiều nhất

## 1. Xác định quy tắc từ các file

Các ghi chú mô tả cách chấm điểm:

- Chỉ xét các access point có trong `aps.conf`; các mạng khác trong bản export bị bỏ qua.
- Chỉ tính những lần điện thoại đang di chuyển, dựa trên `step_delta`.
- Tín hiệu mạnh hơn đóng góp nhiều điểm hơn, và access point có trọng số tin cậy cao hơn cũng được nhân thêm điểm.

Log ghi lại các hàng được nhận hoặc loại trong lần chạy thử:

- `CafeDelMundo`: `step_delta=40` bị loại, còn `41`, `58`, `77` được giữ.
- `HomePlex_5G`: `step_delta=44` được giữ; các giá trị thấp như `5` và `11` bị loại.

Do đó, điều kiện di chuyển là **`step_delta > 40`**. Mỗi hàng hợp lệ đóng góp:

```text
điểm hàng = signal × trọng số của access point
```

Điểm của một access point là tổng điểm hàng hợp lệ của nó.

## 2. Trọng số được cấu hình

| Access point | Trọng số |
|---|---:|
| FoxgloveCoffee_Guest | 3 |
| HomePlex_5G | 2 |
| CafeDelMundo | 2 |
| NETGEAR-8841 | 1 |

## 3. Tính điểm trên toàn bộ `scan_export.csv`

Chỉ lấy các hàng có `step_delta > 40` và tên AP nằm trong cấu hình:

- **FoxgloveCoffee_Guest**: các tín hiệu hợp lệ là `68, 71, 66, 73, 70`.  
  `(68 + 71 + 66 + 73 + 70) × 3 = 348 × 3 = 1,044`
- **CafeDelMundo**: các tín hiệu hợp lệ là `60, 64, 58`. Hàng có `step_delta=40` bị loại.  
  `(60 + 64 + 58) × 2 = 182 × 2 = 364`
- **NETGEAR-8841**: các tín hiệu hợp lệ là `80, 78, 82`. Hàng có `step_delta=30` bị loại.  
  `(80 + 78 + 82) × 1 = 240`
- **HomePlex_5G**: chỉ hàng có `signal=87` và `step_delta=44` hợp lệ.  
  `87 × 2 = 174`

Các AP không có trong `aps.conf` không được tính, dù tín hiệu mạnh hoặc xuất hiện trong export.

## 4. Kết luận

| Xếp hạng | Access point | Điểm |
|---:|---|---:|
| 1 | FoxgloveCoffee_Guest | 1,044 |
| 2 | CafeDelMundo | 364 |
| 3 | NETGEAR-8841 | 240 |
| 4 | HomePlex_5G | 174 |

Địa điểm thắng cuộc là access point đứng đầu. Flag:

```text
hiCTF{FoxgloveCoffee_Guest}
```
