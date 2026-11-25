import csv
import statistics
import struct
import subprocess
from collections import Counter, defaultdict
import serial

COM_PORT = 'COM5'        # Cổng COM của ESP32
BAUD_RATE = 921600
WIRESHARK_PATH = r"G:\Wireshark\Wireshark.exe"

# Magic Number của file PCAP (0xa1b2c3d4)
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
GLOBAL_HDR_SIZE = 24
PACKET_HDR_SIZE = 16


def read_exact(ser, rx_buf, n, proc=None):
    """Đọc chính xác n byte từ bộ đệm/Serial và đẩy sang Wireshark"""
    out = bytearray()
    if rx_buf:
        take = min(n, len(rx_buf))
        out.extend(rx_buf[:take])
        del rx_buf[:take]

    while len(out) < n:
        chunk = ser.read(n - len(out))
        if not chunk:
            continue
        out.extend(chunk)

    data = bytes(out)
    if proc and proc.poll() is None:
        try:
            proc.stdin.write(data)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
    return data


def detect_protocol(payload):
    """Nhận diện giao thức từ khung Ethernet Layer 2"""
    if len(payload) < 14:
        return "UNKNOWN"
    eth_type = struct.unpack(">H", payload[12:14])[0]
    if eth_type == 0x0806:
        return "ARP"
    if eth_type == 0x86DD:
        return "IPv6"
    if eth_type == 0x0800 and len(payload) >= 24:
        proto = payload[23]
        if proto == 1:
            return "ICMP"
        if proto == 6:
            return "TCP"
        if proto == 17:
            return "UDP"
        return f"IPv4({proto})"
    return f"0x{eth_type:04X}"


def export_reports(records):
    """Phân loại chiều TX/RX, in bảng tổng hợp và xuất 2 file CSV"""
    if not records:
        print("[-] Chưa thu thập đủ cặp gói tin hợp lệ.")
        return

    # Tự động xác định địa chỉ MAC của ESP32 (MAC xuất hiện nhiều nhất trong luồng)
    mac_counter = Counter()
    for r in records:
        mac_counter[r["src_mac"]] += 1
        if r["dst_mac"] != "ff:ff:ff:ff:ff:ff":
            mac_counter[r["dst_mac"]] += 1
    esp_mac = mac_counter.most_common(1)[0][0]

    for r in records:
        r["direction"] = "TX" if r["src_mac"] == esp_mac else "RX"

    # 1. Xuất bảng chi tiết từng gói tin (Raw CSV)
    raw_file = "esp32_latency_raw.csv"
    with open(raw_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "STT", "Chieu", "Giao_Thuc", "Kich_Thuoc_Bytes",
            "Thoi_Gian_Hook_us", "Tong_Thoi_Gian_UART_us", "Tong_Thoi_Gian_UART_ms"
        ])
        for idx, r in enumerate(records, start=1):
            writer.writerow([
                idx,
                r["direction"],
                r["protocol"],
                r["orig_len"],
                r["hook_us"],
                r["total_us"],
                round(r["total_us"] / 1000.0, 3)
            ])

    # 2. Gom nhóm thống kê theo (Chiều, Giao thức, Kích thước)
    groups = defaultdict(list)
    for r in records:
        groups[(r["direction"], r["protocol"], r["orig_len"])].append(r)

    summary_file = "esp32_latency_summary.csv"
    summary_rows = []
    for (direction, proto, size), items in sorted(groups.items()):
        hooks = [x["hook_us"] for x in items]
        totals = [x["total_us"] for x in items]
        summary_rows.append([
            direction,
            proto,
            size,
            len(items),
            round(statistics.mean(hooks), 2),
            min(totals),
            round(statistics.mean(totals), 2),
            max(totals),
            round(statistics.mean(totals) / 1000.0, 3)
        ])

    with open(summary_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Chieu", "Giao_Thuc", "Kich_Thuoc_Bytes", "So_Goi",
            "Hook_TB_us", "UART_Min_us", "UART_TB_us", "UART_Max_us", "UART_TB_ms"
        ])
        writer.writerows(summary_rows)

    # In bảng tóm tắt ra màn hình Console
    print("\n" + "=" * 92)
    print(f" BẢNG THỐNG KÊ THỜI GIAN BẮT & GỬI UART THỰC TẾ (MAC ESP32: {esp_mac} | Tổng: {len(records)} gói)")
    print("=" * 92)
    header = f"{'Chiều':<6} {'Proto':<7} {'Size(B)':<8} {'Số gói':<7} {'Hook TB(us)':<12} {'UART Min(us)':<13} {'UART TB(us)':<12} {'UART Max(us)':<13} {'UART TB(ms)':<11}"
    print(header)
    print("-" * 92)
    for row in summary_rows:
        print(f"{row[0]:<6} {row[1]:<7} {row[2]:<8} {row[3]:<7} {row[4]:<12} {row[5]:<13} {row[6]:<12} {row[7]:<13} {row[8]:<11}")
    print("=" * 92)
    print(f"[✓] Đã lưu chi tiết từng gói vào : {raw_file}")
    print(f"[✓] Đã lưu bảng tổng hợp vào    : {summary_file}\n")


def main():
    print(f"Đang mở cổng {COM_PORT} ({BAUD_RATE} baud)...")
    try:
        ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
    except Exception as e:
        print(f"Lỗi mở cổng Serial: {e}")
        return

    print("Đang chờ PCAP Magic Header từ ESP32...")
    rx_buf = bytearray()

    # Lọc rác bootlog ban đầu cho đến khi gặp đủ 24 byte Global Header
    while True:
        data = ser.read(1)
        if not data:
            continue
        rx_buf.extend(data)
        idx = rx_buf.find(PCAP_MAGIC)
        if idx != -1:
            del rx_buf[:idx]
            while len(rx_buf) < GLOBAL_HDR_SIZE:
                more = ser.read(GLOBAL_HDR_SIZE - len(rx_buf))
                if more:
                    rx_buf.extend(more)
            global_hdr = bytes(rx_buf[:GLOBAL_HDR_SIZE])
            del rx_buf[:GLOBAL_HDR_SIZE]
            print("Đã tìm thấy PCAP Header chuẩn! Đang mở Wireshark...")
            break
        if len(rx_buf) > 4096:
            del rx_buf[:-4]

    cmd = [WIRESHARK_PATH, "-k", "-i", "-"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.stdin.write(global_hdr)
    proc.stdin.flush()

    records = []
    print("Đang bắt gói & đo độ trễ phần cứng... Nhấn Ctrl+C trên cửa sổ này để dừng và xuất CSV.")

    try:
        while True:
            pkt_hdr_raw = read_exact(ser, rx_buf, PACKET_HDR_SIZE, proc)
            hook_us, prev_total_us, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr_raw)
            payload = read_exact(ser, rx_buf, incl_len, proc)

            # Gán thời gian đo thực tế (t2 - t0) vừa nhận được vào đúng gói liền trước đó
            if records:
                records[-1]["total_us"] = prev_total_us

            if len(payload) >= 14:
                dst_mac = ":".join(f"{b:02x}" for b in payload[0:6])
                src_mac = ":".join(f"{b:02x}" for b in payload[6:12])
                records.append({
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "protocol": detect_protocol(payload),
                    "orig_len": orig_len,
                    "hook_us": hook_us,
                    "total_us": None,
                })
    except KeyboardInterrupt:
        print("\nĐã dừng thu thập dữ liệu.")
    finally:
        ser.close()
        if proc.poll() is None:
            proc.terminate()
        valid_records = [r for r in records if r["total_us"] is not None]
        export_reports(valid_records)


if __name__ == '__main__':
    main()
