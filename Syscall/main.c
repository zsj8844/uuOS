/**
 * @file    Syscall/main.c
 * @brief   SecuFerry-OS 主程序 —— 设计文档3 阶段0+1
 *
 *          域自动识别: 收到 Handshake 后, 依次用 MK_CTRL / MK_DATA 验证 HMAC,
 *          哪个密钥匹配就激活对应侧。无需编译开关。
 *
 *          通信接口: CH340 (USART1 重映射, PB6/PB7, 9600)
 */

#include "stm32f10x.h"
#include "syscall.h"
#include "sec_core.h"
#include "rgb_led.h"
#include "ch340_comm.h"
#include <string.h>

extern void sha256_direct(const uint8_t *d, uint32_t len, uint8_t *out);

/* 域标识 */
#define DOMAIN_NONE       0
#define DOMAIN_SECRET     1   /* 密网: MK_CTRL → SK1, CMD 0x10 WriteTask */
#define DOMAIN_INDUSTRIAL 2   /* 工控: MK_DATA → SK2, CMD 0x11 ReadTask + 0x12 WriteData */

/*══════════════════════════════════════════════════════════
 * 主函数
 *══════════════════════════════════════════════════════════*/
int main(void)
{
    uint8_t  frame[256];
    uint8_t  cmd, len;
    uint8_t  hs_done      = 0;
    uint8_t  task_ok      = 0;
    uint8_t  my_domain    = DOMAIN_NONE;   /* 握手时自动确定 */
    uint8_t  data_pending = 0;             /* 工控: 数据请求已发 */

    /* ── 初始化 ── */
    RGB_Init();
    SecCore_Init();
    CH340_Comm_Init();

    /* ── SHA-256 + HMAC 自测 ── */
    {
        uint8_t buf[32];
        sha256_direct((const uint8_t*)"abc", 3, buf);
    }
    {
        uint8_t tk[20], out[32];
        for (int i = 0; i < 20; i++) tk[i] = 0x0b;
        SecCore_HMAC_SHA256(tk, 20, (const uint8_t*)"Hi There", 8, out);
    }

    /* ── 板载 LED PC13 ── */
    {
        GPIO_InitTypeDef g;
        RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
        g.GPIO_Pin = GPIO_Pin_13;
        g.GPIO_Mode = GPIO_Mode_Out_PP;
        g.GPIO_Speed = GPIO_Speed_2MHz;
        GPIO_Init(GPIOC, &g);
        GPIOC->BSRR = GPIO_Pin_13;
    }

    /* ── 发 Hello (不设 domain, nonce_s 仅 16 字节) ── */
    g_FerryState = STATE_LOCK;
    SecCore_StartHandshake();

    CH340_Comm_Send(FRAME_CMD_HELLO, (const uint8_t *)g_NonceDev, 16);

    /* ══════════════════════════════════════════════════════
     * 主循环
     * ══════════════════════════════════════════════════════*/
    while (1)
    {
        RGB_Update();
        CH340_Comm_ResetIfTimeout();

        /* 坏帧诊断 */
        {
            static uint32_t last_bad = 0;
            if (g_rx_frame_bad != last_bad) {
                last_bad = g_rx_frame_bad;
                GPIOC->BRR = GPIO_Pin_13;
                for(volatile uint32_t d=0;d<2160000;d++)__NOP();
                GPIOC->BSRR= GPIO_Pin_13;
            }
        }

        /* 定期重发 Hello */
        {
            static uint32_t hello_tick = 0;
            hello_tick++;
            if (!hs_done && (hello_tick % 80) == 0) {
                CH340_Comm_Send(FRAME_CMD_HELLO,
                                (const uint8_t *)g_NonceDev, 16);
            }
        }

        /* 轮询接收帧 */
        if (!CH340_Comm_Recv(&cmd, frame, &len)) {
            continue;
        }

        /*════════════════════════════════════════════════════
         * Handshake 响应 — 双密钥自动识别域
         *════════════════════════════════════════════════════*/
        if (!hs_done && cmd == FRAME_CMD_HANDSHAKE) {

            if (len >= 48) {
                uint8_t result;

                /*
                 * 用 MK_CTRL 试密网, 再用 MK_DATA 试工控.
                 * 哪个 HMAC 匹配, my_domain 就设哪个.
                 * 两个都不匹配 → 验证失败.
                 */
                result = SecCore_VerifyHandshake(
                    frame, 48,
                    SecCore_GetMK_CTRL(), MK_CTRL_SIZE);
                if (result == 0) {
                    my_domain = DOMAIN_SECRET;
                } else {
                    /* 重置失败计数, 再试 MK_DATA */
                    g_ChallengeFailCount = 0;
                    g_FerryState = STATE_LOCK;

                    result = SecCore_VerifyHandshake(
                        frame, 48,
                        SecCore_GetMK_DATA(), MK_DATA_SIZE);
                    if (result == 0) {
                        my_domain = DOMAIN_INDUSTRIAL;
                    }
                }

                if (result == 0) {
                    /* 握手成功 */
                    frame[0] = 0x01;
                    CH340_Comm_Send(FRAME_CMD_ACK, frame, 1);
                    hs_done = 1;

                    /* RGB: 密网=蓝灯, 工控=绿灯 */
                    g_FerryState = (my_domain == DOMAIN_SECRET)
                                   ? STATE_INIT       /* 蓝灯常亮 */
                                   : STATE_ASSIGNED;  /* 绿灯慢闪 */

                    /* PC13 LED: 密网=5下, 工控=3下 */
                    int blinks = (my_domain == DOMAIN_SECRET) ? 5 : 3;
                    for (int a = 0; a < blinks; a++) {
                        GPIOC->BRR = GPIO_Pin_13;
                        for(volatile uint32_t d=0;d<2880000;d++)__NOP();
                        GPIOC->BSRR= GPIO_Pin_13;
                        for(volatile uint32_t d=0;d<1440000;d++)__NOP();
                    }
                } else {
                    /* 两个密钥都不匹配 — 发 NACK 重试 */
                    frame[0] = 0x00;
                    CH340_Comm_Send(FRAME_CMD_ACK, frame, 1);
                    if (g_FerryState == STATE_CORE_PANIC) {
                        RGB_PanicLoop();
                    }
                    for (int a = 0; a < 10; a++) {
                        GPIOC->BRR = GPIO_Pin_13;
                        for(volatile uint32_t d=0;d<1440000;d++)__NOP();
                        GPIOC->BSRR= GPIO_Pin_13;
                        for(volatile uint32_t d=0;d<720000;d++)__NOP();
                    }
                    SecCore_MemZero(g_SessionSK, SK_SIZE);
                    g_FerryState = STATE_LOCK;
                    SecCore_StartHandshake();
                    CH340_Comm_Send(FRAME_CMD_HELLO,
                                    (const uint8_t *)g_NonceDev, 16);
                }
            }
        }

        /*════════════════════════════════════════════════════
         * 密网侧: WriteTask / ReadShake / ReadData
         *════════════════════════════════════════════════════*/
        if (hs_done && !task_ok && my_domain == DOMAIN_SECRET) {

            /* ── 阶段0: 接收 WriteTask (CMD 0x10) ── */
            if (cmd == FRAME_CMD_WRITE_TASK) {
                sys_WriteTask((uint32_t)frame, len);
                frame[0] = 0x01;
                CH340_Comm_Send(FRAME_CMD_ACK, frame, 1);
                task_ok = 1;
                RGB_BlinkN(2, 200, 200, 0, BRIGHT_FULL, 0);
                SecCore_MemZero(g_SessionSK, SK_SIZE);
                g_FerryState = STATE_INIT;
                hs_done = 1;
            }

            /* ── 阶段2: 解密回传 (CMD 0x19 → CMD 0x1A) ── */
            if (cmd == FRAME_CMD_READ_SHAKE) {
                /*
                 * PC 发解密指令 (含目标密文ID, SK1' 加密)
                 * Kernel_ReadShake 验证 → 解密模块使能
                 *   raw = AES-GCM-Dec(MK_DATA, inner)
                 *   outer = AES-GCM-Enc(SK1', raw)
                 *   通过 CMD 0x1A 泵出
                 */
                sys_ReadShake((uint32_t)frame, len);
                sys_ReadData((uint32_t)frame, len);
                CH340_Comm_Send(FRAME_CMD_READ_DATA, frame, 0);
                task_ok = 1;
                RGB_BlinkN(2, 200, 200, 0, BRIGHT_FULL, 0);
                SecCore_MemZero(g_SessionSK, SK_SIZE);
                g_FerryState = STATE_INIT;
                hs_done = 1;
            }
        }

        /*════════════════════════════════════════════════════
         * 工控侧: 读任务 → 请求数据 → 接收密文
         *════════════════════════════════════════════════════*/
        if (hs_done && my_domain == DOMAIN_INDUSTRIAL) {

            /* Step 1: 握手完成后发送数据请求 */
            if (!data_pending) {
                sys_ReadTask(0, 0);         /* SVC 0x11: 读取预存任务 */
                CH340_Comm_Send(FRAME_CMD_READ_TASK, frame, 0);
                RGB_BlinkN(3, 200, 200, 0, BRIGHT_FULL, 0);
                data_pending = 1;
            }

            /* Step 2: 接收双层密文 */
            if (cmd == FRAME_CMD_WRITE_DATA) {
                sys_WriteData((uint32_t)frame, len); /* SVC 0x12 */

                frame[0] = 0x01;
                CH340_Comm_Send(FRAME_CMD_ACK, frame, 1);

                task_ok = 1;
                RGB_BlinkN(2, 200, 200, 0, BRIGHT_FULL, 0);
                SecCore_MemZero(g_SessionSK, SK_SIZE);
                g_FerryState = STATE_ASSIGNED;  /* 工控: 绿灯 */
                hs_done = 1;
            }
        }
    }
}
