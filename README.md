# Multi-Protocol IoT Packet-Capture & Latency Testbed

An embedded hardware testbed built on **ESP32** and **ESP-IDF** to extract raw datalink-layer frames across wireless IoT protocols (**Wi-Fi, Zigbee, Matter**), stream captured packets over **UART** to a Python host pipeline for live **Wireshark** inspection, and benchmark end-to-end transmission latency.

## System Architecture

```text
+-----------------------+      +-------------------------+      +-----------------------+      +-------------------+
|   Wireless Medium     | ---> |   ESP32 Target Node     | ---> |  UART Serial Link     | ---> |   Host PC (WSL)   |
| (Wi-Fi/Zigbee/Matter) |      | (Promiscuous / L2 TAP)  |      | (High-Speed Framing)  |      | Python -> Wireshark|
+-----------------------+      +-------------------------+      +-----------------------+      +-------------------+
