/**
 * @file    Syscall/main.c
 * @brief   SecuFerry-OS 主程序
 *
 *          模式切换 (三选一, 取消对应注释):
 *            TEST_RGB      → 纯RGB灯效轮播, 验证接线+驱动
 *            SELFTEST_NO_USB → 自测握手+SVC命令循环, 不依赖USB
 *            两个都注释    → USB HID 模式, 等待主机通信
 */

#include "stm32f10x.h"
#include "syscall.h"
#include "sec_core.h"
#include "usb_hid.h"
#include "rgb_led.h"
#include <string.h>

/* ══════ 模式选择 (三选一) ══════ */
#define TEST_RGB
//#define SELFTEST_NO_USB

/*══════════════════════════════════════════════════════════
 * TEST_RGB: RGB灯效轮播
 *══════════════════════════════════════════════════════════*/
#ifdef TEST_RGB
int main(void)
{
    RGB_Init();

    FerryState_t test_seq[] = {
        STATE_INIT, STATE_IDLE, STATE_ASSIGNED,
        STATE_PULLING, STATE_LOCK, STATE_READ_ALLOW,
        STATE_CORE_PANIC
    };
    int idx = 0;

    while (1) {
        g_FerryState = test_seq[idx];
        for (int tick = 0; tick < 80; tick++) {      /* ~8秒/状态 */
            RGB_Update();
            for (volatile uint32_t d = 0; d < 72000; d++) __NOP();
        }
        idx = (idx + 1) % 7;
    }
}
#endif /* TEST_RGB */

/*══════════════════════════════════════════════════════════
 * SELFTEST_NO_USB: 自测握手 + SVC命令循环
 *══════════════════════════════════════════════════════════*/
#ifdef SELFTEST_NO_USB

static void selftest_handshake(void)
{
    /* ── 启动信号: 绿灯快闪 1 次 ── */
    RGB_BlinkN(1, 100, 200, 0, BRIGHT_FULL, 0);

    SecCore_Init();
    g_FerryState = STATE_LOCK;
    SecCore_StartHandshake();

    /* 模拟 EXE 计算 Handshake */
    uint8_t nonce_h[16], hmac_resp[32], challenge[48];
    SecCore_GenNonce(nonce_h);
    {
        uint8_t combined[32];
        memcpy(combined, g_NonceDev, 16);
        memcpy(combined + 16, nonce_h, 16);
        SecCore_HMAC_SHA256(SecCore_GetMK_CTRL(), MK_CTRL_SIZE,
                            combined, 32, hmac_resp);
        SecCore_MemZero(combined, 32);
    }
    memcpy(challenge,      nonce_h,   16);
    memcpy(challenge + 16, hmac_resp, 32);

    if (SecCore_VerifyChallenge(challenge, 48) == 0) {
        /* 握手成功 → 绿灯慢闪 4 次 */
        RGB_BlinkN(4, 200, 200, 0, BRIGHT_FULL, 0);
    } else {
        /* 握手失败 → 红灯快闪报警 */
        RGB_BlinkN(10, 50, 50, BRIGHT_FULL, 0, 0);
        while (1) { __NOP(); }
    }

    SecCore_MemZero(nonce_h, 16);
    SecCore_MemZero(hmac_resp, 32);
    SecCore_MemZero(challenge, 48);
}

int main(void)
{
    RGB_Init();
    RGB_SetRaw(0, 0, BRIGHT_FULL);       /* 蓝灯常亮 = 已上电 */

    selftest_handshake();
    SwitchToUserMode();

    while (1) {
        sys_WriteTask(0, 0);   RGB_Update();  sys_DelayMs(150);
        sys_ReadTask(0, 0);    RGB_Update();  sys_DelayMs(150);
        sys_WriteData(0, 0);   RGB_Update();  sys_DelayMs(150);
        {
            uint8_t buf[32] = {0};
            sys_ReadShake((uint32_t)buf, 32);
        }
        RGB_Update();  sys_DelayMs(150);
        sys_ReadData(0, 0);    RGB_Update();  sys_DelayMs(250);
    }
}
#endif /* SELFTEST_NO_USB */

/*══════════════════════════════════════════════════════════
 * USB HID 模式 (默认)
 *══════════════════════════════════════════════════════════*/
#if !defined(TEST_RGB) && !defined(SELFTEST_NO_USB)

static void build_hello_frame(uint8_t *frame)
{
    memset(frame, 0, 64);
    frame[0] = 0x01;
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0x00;
    memcpy(frame + 4, g_NonceDev, 16);
}

static void build_ack_frame(uint8_t *frame, uint8_t ok)
{
    memset(frame, 0, 64);
    frame[0] = 0x01;
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0x02;
    frame[4] = ok ? 0x01 : 0x00;
}

int main(void)
{
    RGB_Init();
    SecCore_Init();
    USB_HID_Init();

    uint8_t frame[64];
    int     hs_done = 0;

    while (1) {
        USB_HID_Poll();
        RGB_Update();

        if (!USB_HID_IsConfigured()) {
            continue;   /* 枚举中, 灯效由状态机驱动 */
        }

        /* ── Hello ── */
        if (!hs_done && g_FerryState == STATE_IDLE) {
            g_FerryState = STATE_LOCK;
            SecCore_StartHandshake();
            build_hello_frame(frame);
            USB_HID_SendReport(frame);
            /* Hello 已发 → 绿灯短闪一下 */
            RGB_BlinkN(1, 100, 100, 0, BRIGHT_FULL, 0);
        }

        /* ── Handshake ── */
        if (!hs_done && USB_HID_RecvReport(frame)) {
            if (frame[0]==0x01 && frame[1]==0x00 &&
                frame[2]==0x00 && frame[3]==0x01) {
                if (SecCore_VerifyChallenge(frame+4, 48) == 0) {
                    build_ack_frame(frame, 1);
                    USB_HID_SendReport(frame);
                    hs_done = 1;
                    RGB_BlinkN(4, 200, 200, 0, BRIGHT_FULL, 0);
                } else {
                    build_ack_frame(frame, 0);
                    USB_HID_SendReport(frame);
                    if (g_FerryState == STATE_CORE_PANIC) {
                        RGB_PanicLoop();
                    }
                    SecCore_StartHandshake();
                    build_hello_frame(frame);
                    USB_HID_SendReport(frame);
                }
            }
        }

        /* ── 命令分发 ── */
        if (hs_done && USB_HID_RecvReport(frame)) {
            uint8_t cmd = frame[1];
            switch (cmd) {
            case 0x10: sys_WriteTask(0,0);  break;
            case 0x11: sys_ReadTask(0,0);   break;
            case 0x12: sys_WriteData(0,0);  break;
            case 0x19: sys_ReadShake(0,0);  break;
            case 0x1A: sys_ReadData(0,0);   break;
            }
        }
    }
}
#endif
