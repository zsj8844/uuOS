/**
 * @file    main.c
 * @brief   SecuFerry-OS 密网任务下发工具 (MasterTask.exe)
 *
 *          通信接口: CH340 串口 (虚拟 COM 口, 115200-8N1)
 *          握手方向: STM32 主动发起 → EXE 被动响应
 *
 *          时序 (设计文档3 阶段0):
 *            1. 后台等待 STM32 插入并发起握手 (STM32 主动发 Hello)
 *            2. HMAC 挑战-应答完成双向认证
 *            3. 派生会话密钥 SK1
 *            4. 管理员填写任务 → 加密下发 (SVC 0x10)
 *            5. 等待 STM32 ACK → 完成
 *
 *          用法:
 *            MasterTask.exe             自动查找 CH340 串口
 *            MasterTask.exe COM5        指定 COM 口
 *            MasterTask.exe --list      列出所有 COM 口
 *
 *          编译 (MinGW-w64):
 *            gcc -o MasterTask.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
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
 * MK_CTRL 密钥 (与 STM32 固件 sec_core.c 一致)
 * 量产阶段从 mk_ctrl.key 文件或 HSM 读取
 *══════════════════════════════════════════════════════════*/
static const uint8_t MK_CTRL[32] = {
    0x4F, 0x3A, 0x91, 0x7C, 0xB2, 0xE8, 0x5D, 0x16,
    0x88, 0x2F, 0x4E, 0xA3, 0x71, 0x0B, 0xD9, 0x6C,
    0x55, 0xAC, 0x38, 0x1F, 0xE7, 0x9A, 0x42, 0x6B,
    0x0D, 0xC8, 0x94, 0x53, 0xFE, 0x27, 0x60, 0x19,
};

/* 全局设备句柄 (用于信号处理清理) */
static HANDLE g_hDev = INVALID_HANDLE_VALUE;

/*══════════════════════════════════════════════════════════
 * 信号处理
 *══════════════════════════════════════════════════════════*/
static void sig_handler(int sig)
{
    (void)sig;
    printf("\n\n  Ctrl+C - cleaning up...\n");
    if (g_hDev != INVALID_HANDLE_VALUE) {
        Serial_CloseDevice(g_hDev);
        g_hDev = INVALID_HANDLE_VALUE;
    }
    Crypto_Cleanup();
    exit(0);
}

/*══════════════════════════════════════════════════════════
 * 控制台初始化
 *══════════════════════════════════════════════════════════*/
static void console_init(void)
{
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

/*══════════════════════════════════════════════════════════
 * 等待 STM32 设备 (轮询模式)
 *══════════════════════════════════════════════════════════*/
static HANDLE wait_for_device(const char *com_arg)
{
    HANDLE hDev;

    if (com_arg) {
        /* 用户指定了 COM 口 */
        printf("  Opening %s...\n", com_arg);
        hDev = Serial_OpenComPort(com_arg);
        if (hDev == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "  Failed to open %s\n", com_arg);
            exit(1);
        }
        return hDev;
    }

    /* 自动查找 CH340 */
    printf("  Waiting for CH340 device...\n");
    while (1) {
        hDev = Serial_OpenDevice();
        if (hDev != INVALID_HANDLE_VALUE) {
            return hDev;
        }
        printf("  .");
        fflush(stdout);
        Sleep(2000);
    }
}

/*══════════════════════════════════════════════════════════
 * 握手阶段: 等待 Hello → 回复 Handshake → 等 ACK
 *══════════════════════════════════════════════════════════*/
static int do_handshake(HANDLE hDev, SessionCtx *sess)
{
    uint8_t cmd, data[FRAME_PAYLOAD_MAX];
    uint8_t len;
    int     ret;

    /* Step 1: 等待 STM32 发送 Hello */
    printf("\n  [HS] Waiting for STM32 Hello...\n");
    ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS * 2);
    if (ret <= 0) {
        fprintf(stderr, "  [HS] Hello timeout/error (ret=%d)\n", ret);
        return -1;
    }

    Proto_DumpFrame("Recv", cmd, data, len);

    if (cmd != FRAME_CMD_HELLO) {
        fprintf(stderr, "  [HS] Expected Hello(0x01), got 0x%02X\n", cmd);
        return -2;
    }
    if (Proto_ParseHello(data, len, sess) != 0) {
        fprintf(stderr, "  [HS] Hello parse failed\n");
        return -3;
    }

    /* Step 2: 生成 nonce_h, 构建 Handshake */
    if (Crypto_Random(sess->nonce_h, NONCE_SIZE) != 0) {
        fprintf(stderr, "  [HS] nonce_h generation failed\n");
        return -4;
    }

    if (Proto_BuildHandshake(data, &len, sess, MK_CTRL) != 0) {
        return -5;
    }

    printf("  [HS] Sending Handshake (CMD=0x%02X, LEN=%u)...\n",
           FRAME_CMD_HANDSHAKE, len);
    Proto_DumpFrame("Send", FRAME_CMD_HANDSHAKE, data, len);
    ret = Serial_WriteFrame(hDev, FRAME_CMD_HANDSHAKE, data, len);
    if (ret != 0) {
        fprintf(stderr, "  [HS] Handshake send failed (ret=%d)\n", ret);
        return -6;
    }
    printf("  [HS] Handshake sent (%u bytes on wire)\n", 3 + len + 1);

    /* Step 3: 等待 ACK — 清空缓冲, 循环读取: Hello 丢弃, ACK 才算数 */
    Serial_FlushRx(hDev);
    printf("  [HS] Waiting for STM32 ACK (discarding stale Hellos)...\n");

    {
        int ack_retries = 0;
        while (1) {
            ret = Serial_ReadFrame(hDev, &cmd, data, &len, SERIAL_READ_TIMEOUT_MS);
            if (ret <= 0) {
                fprintf(stderr, "  [HS] ACK timeout after %d reads (ret=%d)\n",
                        ack_retries, ret);
                sess->state = HS_TIMEOUT;
                return -7;
            }

            Proto_DumpFrame("Recv", cmd, data, len);
            ack_retries++;

            if (cmd == FRAME_CMD_HELLO) {
                /* 缓存的 Hello — 丢弃, 继续等 ACK */
                printf("  [HS]   (discarding stale Hello, waiting for ACK...)\n");
                continue;
            }

            if (cmd == FRAME_CMD_ACK) {
                break;  /* ACK! */
            }

            fprintf(stderr, "  [HS] Unexpected frame CMD=0x%02X, "
                    "waiting for ACK...\n", cmd);
            if (ack_retries > 10) {
                sess->state = HS_FAILED;
                return -8;
            }
        }
    }

    if (Proto_ParseAck(data, len) != 0) {
        sess->state = HS_FAILED;
        return -9;
    }

    /* Step 4: 派生会话密钥 SK1 */
    if (Proto_DeriveSK(sess, MK_CTRL) != 0) {
        return -10;
    }

    printf("  [OK] Handshake complete, session key derived\n");
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 任务下发: TaskPayload → AES-GCM → SVC 0x10
 *══════════════════════════════════════════════════════════*/
static int send_task(HANDLE hDev, SessionCtx *sess,
                     const char *target_id, const char *data_points,
                     uint32_t valid_days)
{
    uint8_t     data[FRAME_PAYLOAD_MAX];
    uint8_t     respData[FRAME_PAYLOAD_MAX];
    uint8_t     cmd, len;
    uint32_t    respLen;
    TaskPayload task;
    int         ret;

    /* 构建任务 */
    memset(&task, 0, sizeof(task));
    task.valid_from   = (uint32_t)time(NULL);
    task.valid_to     = task.valid_from + (valid_days * 86400);
    task.strategy     = 1;  /* continuous */
    task.interval_sec = 1;
    strncpy(task.target_id,   target_id,   TASK_TARGET_ID_LEN - 1);
    strncpy(task.data_points, data_points, TASK_DATA_POINTS_LEN - 1);

    printf("\n  [Task] Building task:\n");
    printf("    Target:     %s\n", task.target_id);
    printf("    DataPoints: %s\n", task.data_points);
    printf("    ValidDays:  %u\n", valid_days);

    /* 加密并发送 */
    if (Proto_BuildEncryptedCmd(data, &len, sess, SVC_WRITE_TASK,
                                (const uint8_t *)&task,
                                sizeof(TaskPayload)) != 0) {
        fprintf(stderr, "  [Task] Build encrypted command failed\n");
        return -1;
    }

    ret = Serial_WriteFrame(hDev, FRAME_CMD_WRITE_TASK, data, len);
    if (ret != 0) {
        fprintf(stderr, "  [Task] Send failed (ret=%d)\n", ret);
        return -2;
    }
    printf("  [Task] Sent SVC 0x10 (WRITE_TASK), ct_len=%u\n", len);

    /* 等待 ACK */
    printf("  [Task] Waiting for ACK...\n");
    ret = Serial_ReadFrame(hDev, &cmd, respData, &len, SERIAL_READ_TIMEOUT_MS);
    if (ret <= 0) {
        fprintf(stderr, "  [Task] ACK timeout\n");
        return -3;
    }

    Proto_DumpFrame("Recv", cmd, respData, len);

    /* 尝试解密响应 */
    respLen = sizeof(respData);
    if (cmd == FRAME_CMD_ACK) {
        if (Proto_ParseAck(respData, len) == 0) {
            printf("  [OK] Task assignment complete\n");
            return 0;
        }
    }

    /* 可能是加密响应, 尝试解密 */
    respLen = sizeof(respData);
    if (Proto_DecryptResponse(respData, len, sess,
                              respData, &respLen) == 0) {
        printf("  [Task] Decrypted ACK: %u bytes\n", respLen);
        printf("  [OK] Task assignment complete\n");
        return 0;
    }

    printf("  [Task] ACK received (unencrypted)\n");
    printf("  [OK] Task assignment complete\n");
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

    printf("========================================\n");
    printf("  SecuFerry-OS MasterTask Tool v2.0\n");
    printf("  Transport: CH340 Serial (COM port)\n");
    printf("  Handshake: STM32 initiates, EXE responds\n");
    printf("========================================\n\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 参数解析 */
    if (argc > 1) {
        if (strcmp(argv[1], "--list") == 0 || strcmp(argv[1], "-l") == 0) {
            Serial_ListAllPorts();
            return 0;
        }
        /* 假定为 COM 口名称 */
        com_arg = argv[1];
    }

    if (Crypto_Init() != 0) {
        fprintf(stderr, "Crypto init failed\n");
        return 1;
    }

    /* 主循环 */
    while (1)
    {
        Session_Init(&sess);

        hDev = wait_for_device(com_arg);
        g_hDev = hDev;

        /* 握手 */
        ret = do_handshake(hDev, &sess);
        if (ret != 0) {
            fprintf(stderr, "\n  [FAIL] Handshake failed (code %d), retrying...\n\n", ret);
            Session_Destroy(&sess);
            Serial_CloseDevice(hDev);
            g_hDev = INVALID_HANDLE_VALUE;
            if (com_arg) break;  /* 指定 COM 口时不重试 */
            Sleep(2000);
            continue;
        }

        /* 下发任务 */
        printf("\n  ----------------------------------------\n");
        printf("  Preparing task...\n");

        ret = send_task(hDev, &sess,
                        "PLC-Station-07",
                        "Modbus 40001-40050, OPC-UA /plant1/temp/*",
                        1);

        Session_Destroy(&sess);
        Serial_CloseDevice(hDev);
        g_hDev = INVALID_HANDLE_VALUE;

        if (ret == 0) {
            printf("\n  ----------------------------------------\n");
            printf("  [OK] Task assigned! Device can be removed.\n");
            printf("  ----------------------------------------\n\n");
        } else {
            fprintf(stderr, "\n  [FAIL] Task assignment failed\n\n");
        }

        if (com_arg) break;  /* 指定 COM 口时只执行一次 */

        printf("  Waiting for next device... (Ctrl+C to exit)\n\n");
    }

    Crypto_Cleanup();
    return (ret == 0) ? 0 : 1;
}
