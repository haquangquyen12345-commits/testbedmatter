#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/uart.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#define WIFI_SSID "quyendeptraivl"
#define WIFI_PASS "cccccccc"

#define MAX_FRAME 2000
#define QUEUE_DEPTH 64

#define PCAP_UART_NUM UART_NUM_0
#define PCAP_BAUD_RATE 921600

typedef struct
{
    uint16_t len;
    uint32_t hook_us; // t1 - t0: Thời gian thực thi hàm capture() (us)
    int64_t t0_us;    // Mốc t0: Thời điểm bắt đầu lấy gói tin (us)
    uint8_t data[];
} pkt_t;

static QueueHandle_t pkt_q;

// --- CẤU TRÚC HEADER PCAP ---
typedef struct __attribute__((packed))
{
    uint32_t magic_number;  /* 0xa1b2c3d4 */
    uint16_t version_major; /* 2 */
    uint16_t version_minor; /* 4 */
    int32_t thiszone;       /* GMT = 0 */
    uint32_t sigfigs;       /* 0 */
    uint32_t snaplen;       /* Max len = 65535 */
    uint32_t network;       /* Ethernet = 1 */
} pcap_global_header_t;

typedef struct __attribute__((packed))
{
    uint32_t ts_sec;   /* Chứa hook_us (t1 - t0) của gói hiện tại */
    uint32_t ts_usec;  /* Chứa total_us thực tế (t2 - t0) của gói liền trước */
    uint32_t incl_len; /* Độ dài trong PCAP */
    uint32_t orig_len; /* Độ dài thực tế */
} pcap_packet_header_t;

static void send_pcap_global_header(void)
{
    pcap_global_header_t gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1};
    uart_write_bytes(PCAP_UART_NUM, (const char *)&gh, sizeof(gh));
}

// Hàm capture đo thời gian xử lý bộ nhớ (t1 - t0) và lưu mốc bắt đầu (t0)
static inline void capture(uint8_t dir, const void *buf, size_t len)
{
    int64_t t0 = esp_timer_get_time();

    if (buf == NULL || len < 14 || len > MAX_FRAME || pkt_q == NULL)
        return;

    pkt_t *p = malloc(sizeof(pkt_t) + len);
    if (p == NULL)
        return;

    p->len = (uint16_t)len;
    p->t0_us = t0;
    memcpy(p->data, buf, len);

    int64_t t1 = esp_timer_get_time();
    p->hook_us = (uint32_t)(t1 - t0);

    // Nếu đẩy vào queue thất bại (queue đầy), giải phóng bộ nhớ để tránh tràn RAM
    if (xQueueSend(pkt_q, &p, 0) != pdTRUE)
        free(p);
}

// --- CÁC HÀM HOOK ---
extern esp_err_t __real_esp_netif_receive(esp_netif_t *n, void *buffer, size_t len, void *eb);
esp_err_t __wrap_esp_netif_receive(esp_netif_t *n, void *buffer, size_t len, void *eb)
{
    capture(0, buffer, len);
    return __real_esp_netif_receive(n, buffer, len, eb);
}

extern esp_err_t __real_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len);
esp_err_t __wrap_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len)
{
    capture(1, buffer, len);
    return __real_esp_wifi_internal_tx(ifx, buffer, len);
}

extern esp_err_t __real_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf);
esp_err_t __wrap_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf)
{
    capture(1, buffer, len);
    return __real_esp_wifi_internal_tx_by_ref(ifx, buffer, len, netstack_buf);
}

// --- TASK ĐẨY DỮ LIỆU RA UART & ĐO MỐC t2 THỰC TẾ ---
static void pkt_task(void *pv)
{
    pkt_t *p;
    uint32_t prev_real_total_us = 0; // Lưu tổng thời gian thực tế (t2 - t0) của gói liền trước

    // Gửi Global Header ngay khi task chạy
    send_pcap_global_header();

    while (1)
    {
        if (xQueueReceive(pkt_q, &p, portMAX_DELAY) == pdTRUE)
        {
            pcap_packet_header_t ph;
            ph.ts_sec = p->hook_us;
            ph.ts_usec = prev_real_total_us; // Đính kèm kết quả đo thực tế của gói trước đó
            ph.incl_len = p->len;
            ph.orig_len = p->len;

            uart_write_bytes(PCAP_UART_NUM, (const char *)&ph, sizeof(ph));
            uart_write_bytes(PCAP_UART_NUM, (const char *)p->data, p->len);
            // Chờ phần cứng đẩy xong byte cuối cùng ra chân TX
            uart_wait_tx_done(PCAP_UART_NUM, portMAX_DELAY);

            // Chốt mốc t2 thực tế từ bộ đếm phần cứng cho gói tiếp theo mang về
            int64_t t2 = esp_timer_get_time();
            prev_real_total_us = (uint32_t)(t2 - p->t0_us);

            free(p);
        }
    }
}

static void event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED)
    {
        esp_wifi_connect();
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP)
    {
        esp_wifi_set_ps(WIFI_PS_NONE);
    }
}

static void wifi_init_sta(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    (void)netif;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wc = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void app_main(void)
{
    // Tắt toàn bộ Log ASCII ra UART để không làm bẩn stream PCAP
    esp_log_level_set("*", ESP_LOG_NONE);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    uart_config_t uart_config = {
        .baud_rate = PCAP_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};
    uart_param_config(PCAP_UART_NUM, &uart_config);
    uart_driver_install(PCAP_UART_NUM, 4096, 0, 0, NULL, 0);

    pkt_q = xQueueCreate(QUEUE_DEPTH, sizeof(pkt_t *));
    xTaskCreate(pkt_task, "pkt_task", 4096, NULL, 4, NULL);

    wifi_init_sta();
}
