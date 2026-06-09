/**
 * @file    main.c
 * @brief   SecuFerry-OS 密网任务下发工具 (MasterTask.exe)
 *
 *          运行在密网总部 PC, 通过 USB HID 与 STM32 通信:
 *            1. 后台等待 STM32 插入并发起握手 (STM32 主动发 Hello)
 *            2. HMAC 挑战-应答完成双向认证
 *            3. 派生会话密钥 SK1
 *            4. 管理员填写任务 → 加密下发 (SVC 0x10)
 *            5. 等待 STM32 ACK → 完成
 *
 *          编译 (MSVC):
 *            cl /Fe:MasterTask.exe main.c hid_comm.c crypto_win.c protocol.c /link hid.lib setupapi.lib bcrypt.lib
 *
 *          编译 (MinGW):
 *            gcc -o MasterTask.exe main.c hid_comm.c crypto_win.c protocol.c -lhid -lsetupapi -lbcrypt
 */

#include "protocol.h"
#include "crypto_win.h"
#include "hid_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/*══════════════════════════════════════════════════════════
 * MK_CTRL 密钥 (原型阶段硬编码, 与固件 sec_core.c 一致)
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
 * 信号处理 -- Ctrl+C 时安全退出
 *══════════════════════════════════════════════════════════*/
static void sig_handler(int sig)
{
    (void)sig;
    printf("\n\n  Ctrl+C - cleaning up...\n");
    if (g_hDev != INVALID_HANDLE_VALUE) {
        HID_CloseDevice(g_hDev);
        g_hDev = INVALID_HANDLE_VALUE;
    }
    Crypto_Cleanup();
    exit(0);
}

/*══════════════════════════════════════════════════════════
 * 控制台 UTF-8 初始化
 *══════════════════════════════════════════════════════════*/
static void console_init(void)
{
    /* Set console output to UTF-8 code page (65001) */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

/*══════════════════════════════════════════════════════════
 * 等待设备插入 (轮询模式)
 *══════════════════════════════════════════════════════════*/
static HANDLE wait_for_device(void)
{
    HANDLE hDev;
    int retries = 0;

    printf("  Waiting for STM32 device (VID=0x0483 PID=0x5750)...\n");
    while (1) {
        hDev = HID_OpenDevice(STM32_HID_VID, STM32_HID_PID);
        if (hDev != INVALID_HANDLE_VALUE) {
            printf("  [OK] Device connected\n");
            return hDev;
        }
        retries++;
        if (retries % 10 == 0) {
            printf("  .");
            fflush(stdout);
        }
        Sleep(1000);
    }
}

/*══════════════════════════════════════════════════════════
 * 握手阶段: 等待 STM32 Hello -> 回复 Handshake -> 等 ACK
 *══════════════════════════════════════════════════════════*/
static int do_handshake(HANDLE hDev, SessionCtx *sess)
{
    HIDFrame frame;
    int      ret;

    /* Step 1: wait for STM32 to send Hello */
    printf("\n  [HS] Waiting for STM32 Hello...\n");
    ret = HID_ReadFrame(hDev, (uint8_t *)&frame, HID_READ_TIMEOUT_MS * 2);
    if (ret <= 0) {
        fprintf(stderr, "  [HS] Hello timeout/error (ret=%d)\n", ret);
        return -1;
    }

    Proto_DumpFrame("Recv", &frame);

    if (Proto_ParseHello(&frame, sess) != 0) {
        fprintf(stderr, "  [HS] Hello parse failed\n");
        return -2;
    }

    /* Step 2: generate nonce_h, build Handshake */
    if (Crypto_Random(sess->nonce_h, NONCE_SIZE) != 0) {
        fprintf(stderr, "  [HS] nonce_h generation failed\n");
        return -3;
    }

    memset(&frame, 0, sizeof(frame));
    if (Proto_BuildHandshake(&frame, sess, MK_CTRL) != 0) {
        return -4;
    }

    Proto_DumpFrame("Send Handshake", &frame);

    ret = HID_WriteFrame(hDev, (const uint8_t *)&frame);
    if (ret != 0) {
        fprintf(stderr, "  [HS] Handshake send failed (ret=%d)\n", ret);
        return -5;
    }

    /* Step 3: wait for STM32 ACK */
    printf("  [HS] Waiting for STM32 ACK...\n");
    ret = HID_ReadFrame(hDev, (uint8_t *)&frame, HID_READ_TIMEOUT_MS);
    if (ret <= 0) {
        fprintf(stderr, "  [HS] ACK timeout (ret=%d)\n", ret);
        sess->state = HS_TIMEOUT;
        return -6;
    }

    Proto_DumpFrame("Recv", &frame);

    if (Proto_ParseAck(&frame, sess) != 0) {
        sess->state = HS_FAILED;
        return -7;
    }

    /* Step 4: derive session key SK1 */
    if (Proto_DeriveSK(sess, MK_CTRL) != 0) {
        return -8;
    }

    printf("  [OK] Handshake complete, session key derived\n");
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 任务下发: TaskPayload -> AES-GCM -> SVC 0x10
 *══════════════════════════════════════════════════════════*/
static int send_task(HANDLE hDev, SessionCtx *sess,
                     const char *target_id, const char *data_points,
                     uint32_t valid_days)
{
    HIDFrame    frame;
    TaskPayload task;
    uint8_t     respBuf[FRAME_PAYLOAD_SIZE];
    uint32_t    respLen = sizeof(respBuf);
    int         ret;

    /* Build task */
    memset(&task, 0, sizeof(task));
    task.valid_from = (uint32_t)time(NULL);
    task.valid_to   = task.valid_from + (valid_days * 86400);
    task.strategy   = 1;  /* continuous */
    task.interval_sec = 1;
    strncpy(task.target_id, target_id, TASK_TARGET_ID_LEN - 1);
    strncpy(task.data_points, data_points, TASK_DATA_POINTS_LEN - 1);

    printf("\n  [Task] Building task:\n");
    printf("    Target:     %s\n", task.target_id);
    printf("    DataPoints: %s\n", task.data_points);
    printf("    ValidDays:  %u\n", valid_days);
    printf("    Strategy:   continuous, interval=%us\n", task.interval_sec);

    /* Encrypt and send */
    if (Proto_BuildEncryptedCmd(&frame, sess, SVC_WRITE_TASK,
                                (const uint8_t *)&task,
                                sizeof(TaskPayload)) != 0) {
        fprintf(stderr, "  [Task] Build encrypted command failed\n");
        return -1;
    }

    ret = HID_WriteFrame(hDev, (const uint8_t *)&frame);
    if (ret != 0) {
        fprintf(stderr, "  [Task] Send failed (ret=%d)\n", ret);
        return -2;
    }
    printf("  [Task] Sent SVC 0x10 (WRITE_TASK)\n");

    /* Wait for ACK */
    ret = HID_ReadFrame(hDev, (uint8_t *)&frame, HID_READ_TIMEOUT_MS);
    if (ret <= 0) {
        fprintf(stderr, "  [Task] ACK timeout\n");
        return -3;
    }

    /* Decrypt response */
    respLen = sizeof(respBuf);
    if (Proto_DecryptResponse(&frame, sess, respBuf, &respLen) == 0) {
        printf("  [Task] Encrypted ACK decrypted (%u bytes)\n", respLen);
    } else {
        printf("  [Task] Response received (plaintext/demo mode)\n");
    }

    printf("  [OK] Task assignment complete, device can be removed\n");
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 主函数
 *══════════════════════════════════════════════════════════*/
int main(int argc, char *argv[])
{
    SessionCtx sess;
    HANDLE     hDev;
    int        ret;

    /* Fix console encoding for Chinese Windows */
    console_init();

    printf("========================================\n");
    printf("  SecuFerry-OS MasterTask Tool v1.0\n");
    printf("  Handshake: STM32 initiates, EXE responds\n");
    printf("========================================\n\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (Crypto_Init() != 0) {
        fprintf(stderr, "Crypto init failed\n");
        return 1;
    }

    /* List devices mode */
    if (argc > 1 && strcmp(argv[1], "--list") == 0) {
        HID_ListAllDevices();
        Crypto_Cleanup();
        return 0;
    }

    /* Main loop: wait for device -> handshake -> send task */
    while (1)
    {
        Session_Init(&sess);

        hDev = wait_for_device();
        g_hDev = hDev;

        /* Handshake (STM32 initiates) */
        ret = do_handshake(hDev, &sess);
        if (ret != 0) {
            fprintf(stderr, "\n  [FAIL] Handshake failed (code %d), retrying...\n\n", ret);
            Session_Destroy(&sess);
            HID_CloseDevice(hDev);
            g_hDev = INVALID_HANDLE_VALUE;
            Sleep(2000);
            continue;
        }

        /* Send task */
        printf("\n  ----------------------------------------\n");
        printf("  Preparing task...\n");

        ret = send_task(hDev, &sess,
                        "PLC-Station-07",
                        "Modbus 40001-40050, OPC-UA /plant1/temp/*",
                        1);

        Session_Destroy(&sess);
        HID_CloseDevice(hDev);
        g_hDev = INVALID_HANDLE_VALUE;

        if (ret == 0) {
            printf("\n  ----------------------------------------\n");
            printf("  [OK] Task assigned! Remove device.\n");
            printf("  ----------------------------------------\n\n");
        } else {
            fprintf(stderr, "\n  [FAIL] Task assignment failed\n\n");
        }

        printf("  Waiting for next device... (Ctrl+C to exit)\n\n");
    }

    Crypto_Cleanup();
    return 0;
}
