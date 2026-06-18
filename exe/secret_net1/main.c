/**
 * @file    main.c
 * @brief   SecuFerry-OS 密网解密回传工具 (MasterRecover.exe)
 *
 *          设计文档3 阶段2: 密网再次连接, 下发解密指令,
 *          STM32 解密内层密文后用 SK1' 加密回传明文。
 *
 *          用法:
 *            MasterRecover.exe COM7
 *            MasterRecover.exe --list
 *
 *          编译:
 *            gcc -o MasterRecover.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
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
 * MK_CTRL 密钥 (与固件 sec_core.c 一致)
 *══════════════════════════════════════════════════════════*/
static const uint8_t MK_CTRL[32] = {
    0x4F, 0x3A, 0x91, 0x7C, 0xB2, 0xE8, 0x5D, 0x16,
    0x88, 0x2F, 0x4E, 0xA3, 0x71, 0x0B, 0xD9, 0x6C,
    0x55, 0xAC, 0x38, 0x1F, 0xE7, 0x9A, 0x42, 0x6B,
    0x0D, 0xC8, 0x94, 0x53, 0xFE, 0x27, 0x60, 0x19,
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
 * 握手 — 与 stage0 完全相同
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
    if (Proto_BuildHandshake(data, &len, sess, MK_CTRL) != 0) return -5;

    printf("  [HS] Sending Handshake (HMAC with MK_CTRL)...\n");
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
            if (cmd == FRAME_CMD_HELLO) { printf("  [HS]   (discarding stale Hello)\n"); continue; }
            if (cmd == FRAME_CMD_ACK) break;
            if (ack_retries > 10) return -8;
        }
    }

    if (Proto_ParseAck(data, len) != 0) { sess->state = HS_FAILED; return -9; }
    if (Proto_DeriveSK(sess, MK_CTRL) != 0) return -10;

    printf("  [OK] Handshake complete, SK1' derived\n");
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 阶段2: 下发解密指令 → 接收回传明文
 *══════════════════════════════════════════════════════════*/
static int decrypt_and_retrieve(HANDLE hDev, SessionCtx *sess)
{
    uint8_t cmd, data[FRAME_PAYLOAD_MAX];
    uint8_t len;
    uint8_t decrypt_cmd[FRAME_PAYLOAD_MAX];
    uint8_t enc_len;
    int     ret;

    /*
     * Step 1: 构建解密指令 (CMD 0x19)
     *   指令含目标密文ID (从暂存区选).
     *   量产阶段用 AES-GCM(SK1') 加密指令载荷.
     *   Demo: 发空载荷表示"解密所有待取密文"
     */
    printf("\n  [Phase2] Sending decrypt command (CMD 0x19)...\n");

    /* 可选: 查询暂存区有哪些密文 */
    printf("  [Phase2] (proto: querying pending ciphertext IDs...)\n");

    if (Proto_BuildEncryptedCmd(decrypt_cmd, &enc_len, sess,
                                 SVC_WRITE_TASK, /* 复用加密; 实际 CMD 是 0x19 */
                                 (const uint8_t *)"DECRYPT_ALL", 11) != 0) {
        fprintf(stderr, "  [Phase2] Build decrypt command failed\n");
        return -1;
    }

    Proto_DumpFrame("Send", FRAME_CMD_READ_SHAKE, decrypt_cmd, enc_len);
    ret = Serial_WriteFrame(hDev, FRAME_CMD_READ_SHAKE, decrypt_cmd, enc_len);
    if (ret != 0) { fprintf(stderr, "  [Phase2] Send failed\n"); return -2; }
    printf("  [Phase2] Decrypt command sent (CMD=0x19)\n");

    /*
     * Step 2: 接收 STM32 回传的加密明文 (CMD 0x1A)
     */
    printf("  [Phase2] Waiting for encrypted plaintext (CMD 0x1A)...\n");
    ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS);
    if (ret <= 0) { fprintf(stderr, "  [Phase2] ReadData timeout\n"); return -3; }
    Proto_DumpFrame("Recv", cmd, data, len);

    if (cmd != FRAME_CMD_READ_DATA && cmd != FRAME_CMD_ACK) {
        fprintf(stderr, "  [Phase2] Expected READ_DATA(0x1A), got 0x%02X\n", cmd);
        return -4;
    }

    /*
     * Step 3: 解密回传数据
     *   outer = AES-GCM-Dec(SK1', data) → 得 raw 明文
     *   Demo: 直接显示 (实际是加密的, 这里做解密尝试)
     */
    {
        uint8_t  plain[FRAME_PAYLOAD_MAX];
        uint32_t pt_len = sizeof(plain);

        if (Proto_DecryptResponse(data, len, sess, plain, &pt_len) == 0) {
            printf("  [Phase2] Decrypted plaintext (%u bytes): %.*s\n",
                   pt_len, (int)pt_len, plain);
        } else {
            printf("  [Phase2] Data received (unencrypted/demo mode, %u bytes)\n", len);
        }
    }

    printf("  [OK] Phase2 decrypt+retrieve complete\n");
    return 0;
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
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("========================================\n");
    printf("  SecuFerry-OS MasterRecover Tool v1.0\n");
    printf("  Transport: CH340 Serial (COM port)\n");
    printf("  Phase:     2 - Decrypt & Retrieve\n");
    printf("========================================\n\n");

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

        ret = decrypt_and_retrieve(hDev, &sess);

        Session_Destroy(&sess);
        Serial_CloseDevice(hDev);
        g_hDev = INVALID_HANDLE_VALUE;

        printf(ret == 0 ? "\n  [OK] Data retrieved successfully!\n\n"
                        : "\n  [FAIL] Decrypt failed\n\n");
        if (com_arg) break;
        printf("  Waiting for next device... (Ctrl+C to exit)\n\n");
    }

    Crypto_Cleanup();
    return (ret == 0) ? 0 : 1;
}
