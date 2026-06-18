/**
 * @file    Syscall/rgb_led.c
 * @brief   RGB全彩LED驱动实现 —— TIM2 CH1/CH2/CH3 → PA0/PA1/PA2
 *
 *          PWM 参数: 72MHz / 72 = 1MHz → ARR=999 → 1kHz
 *          占空比分辨率: 0~999 (约 0.1% 步进)
 *          默认共阴驱动. 若模块为共阳, 取消下行注释:
 */
//#define RGB_COMMON_ANODE
#define RGB_COMMON_ANODE

#include "rgb_led.h"

/*─────────────────────────────────────────────────────────
 * 内部常量
 *─────────────────────────────────────────────────────────*/

/* TIM2 时基: 1kHz */
#define TIM2_PRESCALER  71    /* 72MHz / (71+1) = 1MHz */
#define TIM2_PERIOD     999   /* 1MHz / (999+1) = 1kHz  */

/* 亮度等级 (0~255 → 映射到 0~TIM2_PERIOD) */

/*─────────────────────────────────────────────────────────
 * 灯效时序参数 (单位: RGB_Update 调用次数)
 *
 *  延时循环按 8MHz HSI 粗略标定, 72MHz 下实际会更快.
 *  如需微调节奏, 增减下面的 ON/OFF 值即可.
 *─────────────────────────────────────────────────────────*/

/* 慢闪: ~1.6s 周期 (~800ms亮 + ~800ms灭) */
#define SLOW_BLINK_ON   64
#define SLOW_BLINK_OFF  64

/* 爆闪 (绿): ~500ms 周期 */
#define FAST_BLINK_ON   12
#define FAST_BLINK_OFF  12

/* 爆闪 (红 PANIC): ~400ms 周期 */
#define PANIC_BLINK_ON   8
#define PANIC_BLINK_OFF  8

/* 蓝绿交替爆闪: ~800ms 周期 */
#define ALT_BLINK_ON    16
#define ALT_BLINK_OFF   16

/*─────────────────────────────────────────────────────────
 * 内部静态变量
 *─────────────────────────────────────────────────────────*/
static uint16_t g_tick    = 0;   /* 累计调用计数 */
static uint8_t  g_on_off  = 1;   /* 当前亮/灭 (1=亮, 0=灭) */

/*─────────────────────────────────────────────────────────
 * 辅助: 0~255 → TIM2 CCR (0~999)
 *─────────────────────────────────────────────────────────*/
static uint16_t scale_ccr(uint8_t v)
{
    /* (v / 255) * 999 ≈ v * 999 / 255 */
    return (uint16_t)(((uint32_t)v * TIM2_PERIOD) / 255);
}

/*─────────────────────────────────────────────────────────
 * 辅助: 写三路 CCR
 *─────────────────────────────────────────────────────────*/
static void write_rgb(uint8_t r, uint8_t g, uint8_t b)
{
#ifdef RGB_COMMON_ANODE
    r = BRIGHT_FULL - r;
    g = BRIGHT_FULL - g;
    b = BRIGHT_FULL - b;
#endif
    /* 接线: PA0=G, PA1=B, PA2=R */
    TIM2->CCR1 = scale_ccr(g);
    TIM2->CCR2 = scale_ccr(b);
    TIM2->CCR3 = scale_ccr(r);
}

/*─────────────────────────────────────────────────────────
 * 公共 API
 *─────────────────────────────────────────────────────────*/

/**
 * @brief  初始化 PA0/PA1/PA2 为 TIM2 复用推挽输出
 */
void RGB_Init(void)
{
    GPIO_InitTypeDef  gpio;
    TIM_TimeBaseInitTypeDef   tim_base;
    TIM_OCInitTypeDef         tim_oc;

    /* ── 时钟 ── */
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOA |
                           RCC_APB2Periph_AFIO,  ENABLE);
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM2,  ENABLE);

    /* ── GPIO: PA0=R, PA1=G, PA2=B 复用推挽 ── */
    gpio.GPIO_Pin   = GPIO_Pin_0 | GPIO_Pin_1 | GPIO_Pin_2;
    gpio.GPIO_Mode  = GPIO_Mode_AF_PP;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOA, &gpio);

    /* ── TIM2 时基: 1kHz ── */
    TIM_TimeBaseStructInit(&tim_base);
    tim_base.TIM_Prescaler         = TIM2_PRESCALER;
    tim_base.TIM_Period            = TIM2_PERIOD;
    tim_base.TIM_ClockDivision     = TIM_CKD_DIV1;
    tim_base.TIM_CounterMode       = TIM_CounterMode_Up;
    TIM_TimeBaseInit(TIM2, &tim_base);

    /* ── TIM2 CH1/CH2/CH3: PWM Mode 1 ── */
    TIM_OCStructInit(&tim_oc);
    tim_oc.TIM_OCMode      = TIM_OCMode_PWM1;
    tim_oc.TIM_OutputState = TIM_OutputState_Enable;
    tim_oc.TIM_Pulse       = 0;
    tim_oc.TIM_OCPolarity  = TIM_OCPolarity_High;

    TIM_OC1Init(TIM2, &tim_oc);   /* PA0 */
    TIM_OC2Init(TIM2, &tim_oc);   /* PA1 */
    TIM_OC3Init(TIM2, &tim_oc);   /* PA2 */

    /* 预装载使能 */
    TIM_OC1PreloadConfig(TIM2, TIM_OCPreload_Enable);
    TIM_OC2PreloadConfig(TIM2, TIM_OCPreload_Enable);
    TIM_OC3PreloadConfig(TIM2, TIM_OCPreload_Enable);

    TIM_ARRPreloadConfig(TIM2, ENABLE);

    /* 启动 TIM2 */
    TIM_Cmd(TIM2, ENABLE);

    /* 初始: 全灭 */
    write_rgb(0, 0, 0);
}

/**
 * @brief  直接设置三路颜色
 */
void RGB_SetRaw(uint8_t r, uint8_t g, uint8_t b)
{
    write_rgb(r, g, b);
}

/**
 * @brief  状态机 → 灯效映射 (周期性调用)
 */
void RGB_Update(void)
{
    uint16_t cycle;         /* 当前状态对应的完整周期 */
    uint16_t phase;         /* 当前在周期中的位置 */

    g_tick++;

    /* ── 亮灭判定 ── */
    switch (g_FerryState) {

    case STATE_INIT:
        /* 绿灯常亮 — 就绪, 等待连接 */
        write_rgb(0, BRIGHT_FULL, 0);
        return;

    case STATE_IDLE:
        /* 绿灯慢闪 — 空闲等待任务 */
        cycle = SLOW_BLINK_ON + SLOW_BLINK_OFF;
        phase = g_tick % cycle;
        g_on_off = (phase < SLOW_BLINK_ON) ? 1 : 0;
        if (g_on_off)
            write_rgb(0, BRIGHT_FULL, 0);
        else
            write_rgb(0, 0, 0);
        return;

    case STATE_ASSIGNED:
        /* 蓝灯常亮 — 任务已存储 (WriteTask 完成) */
        write_rgb(0, 0, BRIGHT_FULL);
        return;

    case STATE_PULLING:
        /* 绿灯慢闪 — 数据已加密落盘 (WriteData 完成) */
        cycle = SLOW_BLINK_ON + SLOW_BLINK_OFF;
        phase = g_tick % cycle;
        g_on_off = (phase < SLOW_BLINK_ON) ? 1 : 0;
        if (g_on_off)
            write_rgb(0, BRIGHT_FULL, 0);
        else
            write_rgb(0, 0, 0);
        return;

    case STATE_LOCK:
        /* 青灯常亮 (G+B) — 握手等待中 */
        write_rgb(0, BRIGHT_FULL, BRIGHT_FULL);
        return;

    case STATE_READ_ALLOW:
        /* 白灯常亮 (R+G+B) — 数据已取出 (ReadData 完成) */
        write_rgb(BRIGHT_FULL, BRIGHT_FULL, BRIGHT_FULL);
        return;

    case STATE_CORE_PANIC:
        /* 红灯爆闪 */
        cycle = PANIC_BLINK_ON + PANIC_BLINK_OFF;
        phase = g_tick % cycle;
        g_on_off = (phase < PANIC_BLINK_ON) ? 1 : 0;
        if (g_on_off)
            write_rgb(BRIGHT_FULL, 0, 0);
        else
            write_rgb(0, 0, 0);
        return;

    default:
        /* 未知状态: 全灭保底 */
        write_rgb(0, 0, 0);
        return;
    }
}

/**
 * @brief  阻塞闪烁 n 次 (可在中断上下文中调用)
 * @note   延时循环按 ~8MHz HSI 标定
 */
void RGB_BlinkN(uint32_t n, uint32_t ms_on, uint32_t ms_off,
                uint8_t r, uint8_t g, uint8_t b)
{
    while (n--) {
        write_rgb(r, g, b);
        for (volatile uint32_t i = 0; i < (ms_on * 720); i++) __NOP();
        write_rgb(0, 0, 0);
        for (volatile uint32_t i = 0; i < (ms_off * 720); i++) __NOP();
    }
}

/**
 * @brief  PANIC 死循环红灯爆闪, 永不返回
 */
void RGB_PanicLoop(void)
{
    while (1) {
        write_rgb(BRIGHT_FULL, 0, 0);
        for (volatile uint32_t i = 0; i < 108000; i++) __NOP();
        write_rgb(0, 0, 0);
        for (volatile uint32_t i = 0; i < 108000; i++) __NOP();
    }
}
