/**
 * @file    Syscall/main.c
 * @brief   SecuFerry-OS SVC + 握手验证 Demo
 *
 *          SELFTEST_NO_USB (当前默认):
 *            自测握手 → SVC 命令循环, 不依赖 USB。
 *            时钟: HSI 8MHz (SystemInit 默认值)。
 *
 *          USB 模式 (注释掉 SELFTEST_NO_USB):
 *            等待主机枚举 → STM32 主动发 Hello → HMAC 握手 → 收发 SVC 命令。
 *            时钟: HSE 8MHz → PLL 72MHz。
 */

#include "stm32f10x.h"
#include "syscall.h"
#include "sec_core.h"
#include "usb_hid.h"
#include <string.h>

//#define SELFTEST_NO_USB

/*══════════════════════════════════════════════════════════
 * 硬件延时 (8MHz HSI 下 ~0.5s)
 *══════════════════════════════════════════════════════════*/
static void delay_500ms(void)
{
    for (volatile uint32_t i = 0; i < 360000; i++) __NOP();
}

/*══════════════════════════════════════════════════════════
 * LED 波形工具
 *══════════════════════════════════════════════════════════*/
static void led_on(void)  { GPIOC->BRR  = GPIO_Pin_13; }
static void led_off(void) { GPIOC->BSRR = GPIO_Pin_13; }

static void led_blink_n(int n, uint32_t on_ms, uint32_t off_ms)
{
    while (n--) {
        led_on();
        for (volatile uint32_t i = 0; i < (on_ms  * 720); i++) __NOP();
        led_off();
        for (volatile uint32_t i = 0; i < (off_ms * 720); i++) __NOP();
    }
}

/*══════════════════════════════════════════════════════════
 * 自测握手 (无 USB 主机时——STM32 扮演双方)
 *══════════════════════════════════════════════════════════*/
#ifdef SELFTEST_NO_USB
static void selftest_handshake(void)
{
    /* ── 启动信号: 快闪 1 次 = 代码已运行 ── */
    led_on();
    for (volatile uint32_t i = 0; i < 72000; i++) __NOP();   /* ~100ms */
    led_off();
    delay_500ms();
    delay_500ms();

    /* ── 初始化 ── */
    SecCore_Init();                  /* STATE_IDLE */
    g_FerryState = STATE_LOCK;       /* 模拟工控回来封仓 */
    SecCore_StartHandshake();        /* 生成 nonce_s */

    /* ── 模拟 EXE 计算 Handshake ── */
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
    /* challenge = nonce_h(16) || HMAC_tag(32) = 48 bytes */
    memcpy(challenge,      nonce_h,   16);
    memcpy(challenge + 16, hmac_resp, 32);

    /* ── 验证 ── */
    if (SecCore_VerifyChallenge(challenge, 48) == 0) {
        /* 握手成功 → 慢闪 4 次 (~200ms on, ~200ms off) */
        led_blink_n(4, 200, 200);
        delay_500ms();
        delay_500ms();
    } else {
        /* 握手失败 → 快闪 10 次告警 */
        led_blink_n(10, 50, 50);
        while (1) { __NOP(); }
    }

    SecCore_MemZero(nonce_h, 16);
    SecCore_MemZero(hmac_resp, 32);
    SecCore_MemZero(challenge, 32);
}
#endif

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
    GPIO_InitTypeDef gpio;

    /* ── LED: PC13 ── */
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
    gpio.GPIO_Pin   = GPIO_Pin_13;
    gpio.GPIO_Mode  = GPIO_Mode_Out_PP;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOC, &gpio);
    led_off();

#ifdef SELFTEST_NO_USB
    /* ══════ 自测模式 (8MHz HSI, 无需 USB) ══════ */
    selftest_handshake();     /* 握手成功 → 慢闪 4 次 */

    SwitchToUserMode();       /* 切到用户态, 之后不能直接操作硬件 */

    /*
     * SVC 命令循环: 不同命令对应不同 LED 闪烁次数。
     * 延时参数已按 8MHz HSI 调整 (sys_DelayMs 内部 7200 循环/ms 在
     * 8MHz 下约 = 6ms/单位, 故用 150 代替 1500 ≈ 0.9s 间隔)。
     */
    while (1)
    {
        sys_WriteTask(0, 0);   /* SVC 0x10 → 闪 1 次 */
        sys_DelayMs(150);       /* ~0.9s */

        sys_ReadTask(0, 0);    /* SVC 0x11 → 闪 2 次 */
        sys_DelayMs(150);

        sys_WriteData(0, 0);   /* SVC 0x12 → 闪 3 次 */
        sys_DelayMs(150);

        {
            uint8_t buf[32] = {0};
            sys_ReadShake((uint32_t)buf, 32);  /* SVC 0x19 → 闪 4×2 */
        }
        sys_DelayMs(150);

        sys_ReadData(0, 0);    /* SVC 0x1A → 闪 5 次 */
        sys_DelayMs(250);       /* ~1.5s, 本轮结束 */
    }
#else
    /* ══════ USB 模式 (HSE+PLL 72MHz) ══════ */
    SecCore_Init();
    USB_HID_Init();            /* 切换时钟到 72MHz, 初始化 USB */

    {
        uint8_t frame[64];
        int     hs_done = 0;

        while (1) {
            USB_HID_Poll();

            if (!USB_HID_IsConfigured()) {
                /* 枚举中: LED 慢闪 */
                static uint32_t tick = 0;
                if (++tick > 800000) {   /* 72MHz 下延时补偿 */
                    tick = 0;
                    GPIOC->ODR ^= GPIO_Pin_13;
                }
                continue;
            }

            /* Hello */
            if (!hs_done && g_FerryState == STATE_IDLE) {
                g_FerryState = STATE_LOCK;
                SecCore_StartHandshake();
                build_hello_frame(frame);
                USB_HID_SendReport(frame);
                /* 短闪 1 次 = Hello 已发 */
                led_on();  delay_500ms();  led_off();
            }

            /* Handshake */
            if (!hs_done && USB_HID_RecvReport(frame)) {
                if (frame[0]==0x01 && frame[1]==0x00 &&
                    frame[2]==0x00 && frame[3]==0x01) {
                    if (SecCore_VerifyChallenge(frame+4, 48) == 0) {
                        build_ack_frame(frame, 1);
                        USB_HID_SendReport(frame);
                        hs_done = 1;
                        /* 慢闪 4 次 = 握手成功 */
                        led_blink_n(4, 200, 200);
                    } else {
                        build_ack_frame(frame, 0);
                        USB_HID_SendReport(frame);
                        if (g_FerryState == STATE_CORE_PANIC) {
                            while (1) { led_blink_n(1, 50, 50); }
                        }
                        SecCore_StartHandshake();
                        build_hello_frame(frame);
                        USB_HID_SendReport(frame);
                    }
                }
            }

            /* 命令 */
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
}
