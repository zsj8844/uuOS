/**
 * @file    Syscall/rgb_led.h
 * @brief   RGB全彩LED模块驱动 —— 4脚(V/R/B/G), TIM2 PWM三通道
 *
 *          硬件接线:
 *            V  → 5V (或 3.3V, 视模块规格)
 *            R  → PA0 (TIM2_CH1)
 *            G  → PA1 (TIM2_CH2)  
 *            B  → PA2 (TIM2_CH3)
 *
 *          默认共阴驱动 (HIGH=亮). 若为共阳模块, 在 rgb_led.c 中
 *          取消 #define RGB_COMMON_ANODE 注释即可自动取反.
 */

#ifndef __RGB_LED_H
#define __RGB_LED_H

#include "stm32f10x.h"
#include "sec_core.h"

/*─────────────────────────────────────────────────────────
 * 亮度常量 (供外部调用 RGB_BlinkN 等使用)
 *─────────────────────────────────────────────────────────*/
#define BRIGHT_FULL   255
#define BRIGHT_HALF   128
#define BRIGHT_OFF    0

/*─────────────────────────────────────────────────────────
 * API
 *─────────────────────────────────────────────────────────*/

/**
 * @brief  初始化 RGB LED (GPIO + TIM2 PWM, 频率 ~1kHz)
 * @note   必须在主时钟配置完成后、主循环前调用
 */
void RGB_Init(void);

/**
 * @brief  直接设置三路占空比 (0~255)
 * @param  r  红色分量 (0=灭, 255=最亮)
 * @param  g  绿色分量
 * @param  b  蓝色分量
 */
void RGB_SetRaw(uint8_t r, uint8_t g, uint8_t b);

/**
 * @brief  根据全局状态机 g_FerryState 更新灯效
 * @note   需在主循环中周期性调用 (建议每 20~50ms 一次)
 *
 *         状态 ↔ 灯效映射:
 *           STATE_INIT       → 蓝灯常亮
 *           STATE_IDLE       → 蓝灯慢闪 (800ms 周期)
 *           STATE_ASSIGNED   → 绿灯慢闪 (800ms 周期)
 *           STATE_PULLING    → 蓝绿交替爆闪 (200ms 周期)
 *           STATE_LOCK       → 黄灯常亮 (红+绿)
 *           STATE_READ_ALLOW → 绿灯爆闪 (150ms 周期)
 *           STATE_CORE_PANIC → 红灯爆闪 (100ms 周期)
 */
void RGB_Update(void);

/**
 * @brief  阻塞闪烁 n 次 (用于 SVC 中断等一次性信号)
 * @param  n      闪烁次数
 * @param  ms_on  每次亮持续时间 (~ms @8MHz HSI)
 * @param  ms_off 每次灭持续时间
 * @param  r/g/b  闪烁颜色分量 (0~255)
 */
void RGB_BlinkN(uint32_t n, uint32_t ms_on, uint32_t ms_off,
                uint8_t r, uint8_t g, uint8_t b);

/**
 * @brief  死循环红灯爆闪 (PANIC 态专用, 永不返回)
 */
void RGB_PanicLoop(void);

#endif /* __RGB_LED_H */
