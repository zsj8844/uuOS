/**
 * @file    main.c
 * @brief   SecuFerry-OS 工控网关工具 (Agent.exe)
 *
 *          通信接口: CH340 串口 (虚拟 COM 口, 9600 8N1)
 *          握手方向: STM32 主动发起 → 网关被动响应
 *
 *          时序 (设计文档3 阶段1):
 *            1. STM32 发 Hello(nonce_s) → 网关识别为工控侧
 *            2. 网关回复 Handshake(nonce_g, HMAC(MK_DATA, nonce_s||nonce_g))
 *            3. STM32 验证通过 → ACK → 派生 SK2
 *            4. STM32 发数据请求 (CMD 0x11)
 *            5. 网关采集 PLC 数据 → 双层加密 → 回传 (CMD 0x12)
 *            6. STM32 ACK → 完成
 *
 *          编译 (MinGW-w64):
 *            gcc -o Agent.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
 */

#include "protocol.h"
#include "crypto_win.h"
#include "serial_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/*══════════════════════════════════════════════════════════
 * MK_DATA 密钥 (与固件 sec_core.c 一致)
 *══════════════════════════════════════════════════════════*/
static const uint8_t MK_DATA[32] = {
    0x8B, 0x1C, 0x56, 0xEA, 0x3F, 0x70, 0xD2, 0x94,
    0x09, 0x4E, 0x17, 0xA6, 0xFD, 0x85, 0x23, 0x61,
    0xCC, 0x39, 0x7B, 0x0A, 0xE1, 0x58, 0x2D, 0x9F,
    0x46, 0x13, 0x80, 0xDC, 0x67, 0xB4, 0x35, 0xAA,
};

static HANDLE g_hDev = INVALID_HANDLE_VALUE;

static void sig_handler(int sig)
{
    (void)sig;
    printf("\n\n  Ctrl+C - cleaning up...\n");
    if (g_hDev != INVALID_HANDLE_VALUE) Serial_CloseDevice(g_hDev);
    Crypto_Cleanup();
    exit(0);
}

static void console_init(void)
{
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

/*══════════════════════════════════════════════════════════
 * 等待 Hello → Handshake → ACK
 *══════════════════════════════════════════════════════════*/
static int do_handshake(HANDLE hDev, SessionCtx *sess)
{
    uint8_t cmd, data[FRAME_PAYLOAD_MAX];
    uint8_t len;
    int     ret;

    printf("\n  [HS] Waiting for STM32 Hello...\n");
    ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS * 2);
    if (ret <= 0) { fprintf(stderr, "  [HS] Hello timeout\n"); return -1; }
    Proto_DumpFrame("Recv", cmd, data, len);
    if (cmd != FRAME_CMD_HELLO) { fprintf(stderr, "  [HS] Expected Hello\n"); return -2; }

    if (Proto_ParseHello(data, len, sess) != 0) return -3;

    if (Crypto_Random(sess->nonce_h, NONCE_SIZE) != 0) return -4;

    if (Proto_BuildHandshake(data, &len, sess, MK_DATA) != 0) return -5;

    printf("  [HS] Sending Handshake (HMAC with MK_DATA)...\n");
    Proto_DumpFrame("Send", FRAME_CMD_HANDSHAKE, data, len);
    ret = Serial_WriteFrame(hDev, FRAME_CMD_HANDSHAKE, data, len);
    if (ret != 0) return -6;

    Serial_FlushRx(hDev);
    printf("  [HS] Waiting for STM32 ACK...\n");

    {
        int ack_retries = 0;
        while (1) {
            ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS);
            if (ret <= 0) { sess->state = HS_TIMEOUT; return -7; }
            Proto_DumpFrame("Recv", cmd, data, len);
            ack_retries++;
            if (cmd == FRAME_CMD_HELLO) {
                printf("  [HS]   (discarding stale Hello)\n"); continue;
            }
            if (cmd == FRAME_CMD_ACK) break;
            if (ack_retries > 10) return -8;
        }
    }

    if (Proto_ParseAck(data, len) != 0) { sess->state = HS_FAILED; return -9; }
    if (Proto_DeriveSK(sess, MK_DATA) != 0) return -10;

    printf("  [OK] Handshake complete, SK2 derived\n");
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 等待数据请求 → 发送双层密文
 *══════════════════════════════════════════════════════════*/
static int handle_data_request(HANDLE hDev, SessionCtx *sess)
{
    uint8_t cmd, data[FRAME_PAYLOAD_MAX];
    uint8_t len;
    uint8_t payload[FRAME_PAYLOAD_MAX];
    uint8_t out_len;
    int     ret;

    /* Step 1: 等 STM32 发数据请求 (CMD 0x11) */
    printf("\n  [Data] Waiting for STM32 data request (CMD 0x11)...\n");
    ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS);
    if (ret <= 0) { fprintf(stderr, "  [Data] Request timeout\n"); return -1; }
    Proto_DumpFrame("Recv", cmd, data, len);
    if (cmd != FRAME_CMD_READ_TASK) {
        fprintf(stderr, "  [Data] Expected READ_TASK(0x11), got 0x%02X\n", cmd);
        return -2;
    }

    /* Step 2: 模拟 PLC 数据 → 双层加密 */
    printf("  [Data] Simulating PLC data collection...\n");
    {
        /* 模拟原始数据 */
        const char *raw_data = "PLC-Station-07|Modbus 40001=23.5,40002=67.8,40003=12.3|timestamp=2026-06-16T12:00:00Z";
        uint32_t raw_len = (uint32_t)strlen(raw_data);

        /*
         * 双层加密: inner = AES-GCM(MK_DATA, raw)
         *           outer = AES-GCM(SK2, inner)
         * Demo: 直接传明文 (TODO: 量产加双层加密)
         */
        (void)raw_len;
        memcpy(payload, raw_data, raw_len + 1);
        out_len = (uint8_t)(raw_len + 1);

        printf("  [Data] Raw: %s (%u bytes)\n", raw_data, out_len);
    }

    /* Step 3: 发送双层密文 (CMD 0x12) */
    printf("  [Data] Sending outer ciphertext (CMD 0x12)...\n");
    Proto_DumpFrame("Send", FRAME_CMD_WRITE_DATA, payload, out_len);
    ret = Serial_WriteFrame(hDev, FRAME_CMD_WRITE_DATA, payload, out_len);
    if (ret != 0) { fprintf(stderr, "  [Data] Send failed\n"); return -3; }

    /* Step 4: 等 ACK */
    printf("  [Data] Waiting for ACK...\n");
    ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS);
    if (ret <= 0) { fprintf(stderr, "  [Data] ACK timeout\n"); return -4; }
    Proto_DumpFrame("Recv", cmd, data, len);
    if (cmd == FRAME_CMD_ACK && Proto_ParseAck(data, len) == 0) {
        printf("  [OK] Data transfer complete\n");
        return 0;
    }
    return -5;
}

/*══════════════════════════════════════════════════════════
 * 主函数
 *══════════════════════════════════════════════════════════*/
int main(int argc, char *argv[])
{
    SessionCtx  sess;
    HANDLE      hDev;
    const char *com_arg = NULL;
    int         ret;

    console_init();

    printf("========================================\n");
    printf("  SecuFerry-OS Agent Tool v1.0\n");
    printf("  Transport: CH340 Serial (COM port)\n");
    printf("  Side:      Industrial Gateway (MK_DATA)\n");
    printf("========================================\n\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (argc > 1) {
        if (strcmp(argv[1], "--list") == 0) { Serial_ListAllPorts(); return 0; }
        com_arg = argv[1];
    }

    if (Crypto_Init() != 0) { fprintf(stderr, "Crypto init failed\n"); return 1; }

    while (1)
    {
        Session_Init(&sess);

        if (com_arg)
            hDev = Serial_OpenComPort(com_arg);
        else
            hDev = Serial_OpenDevice();

        if (hDev == INVALID_HANDLE_VALUE) {
            printf("  ."); fflush(stdout); Sleep(2000); continue;
        }
        g_hDev = hDev;

        ret = do_handshake(hDev, &sess);
        if (ret != 0) {
            fprintf(stderr, "\n  [FAIL] Handshake failed (code %d)\n\n", ret);
            Session_Destroy(&sess);
            Serial_CloseDevice(hDev);
            g_hDev = INVALID_HANDLE_VALUE;
            if (com_arg) break;
            Sleep(2000); continue;
        }

        ret = handle_data_request(hDev, &sess);

        Session_Destroy(&sess);
        Serial_CloseDevice(hDev);
        g_hDev = INVALID_HANDLE_VALUE;

        if (ret == 0) {
            printf("\n  [OK] Data collection complete!\n\n");
        }
        if (com_arg) break;
        printf("  Waiting for next device... (Ctrl+C to exit)\n\n");
    }

    Crypto_Cleanup();
    return (ret == 0) ? 0 : 1;
}
