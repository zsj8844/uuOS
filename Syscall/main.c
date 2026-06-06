/**
  * @file    Syscall/main.c
  * @brief   演示: STM32F103 上通过 SVC 分离用户态与内核态
  *
  *          ┌─────────────────────────────────────┐
  *          │  用户态 (Unprivileged Thread)        │
  *          │  无权碰 GPIO/RCC/SPI 等外设寄存器     │
  *          │  需要硬件操作 → sys_* 宏 → SVC 提权   │
  *          └──────────────┬──────────────────────┘
  *                         │ SVC 指令 (唯一铁闸)
  *                         ▼
  *          ┌─────────────────────────────────────┐
  *          │  内核态 (Privileged Handler)          │
  *          │  直接操作硬件寄存器                    │
  *          └─────────────────────────────────────┘
  */

#include "stm32f10x.h"
#include "syscall.h"

int main(void)
{
    /* ══════════ 阶段 1: 特权态初始化 ══════════ */
    GPIO_InitTypeDef gpio;

    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);//写RCC寄存器
    gpio.GPIO_Pin   = GPIO_Pin_13;//初始化GPIOC13为输出模式
    gpio.GPIO_Mode  = GPIO_Mode_Out_PP;//推挽输出模式
    gpio.GPIO_Speed = GPIO_Speed_50MHz;//50MHz输出速度
    GPIO_Init(GPIOC, &gpio);//写GPIO寄存器
    GPIO_SetBits(GPIOC, GPIO_Pin_13);  /* 灭灯 */;//将GPIOC13设置为高电平，即灭灯

    /* ══════════ 阶段 2: 切到用户态 ══════════ */
    SwitchToUserMode();//切换到用户态

    /*
     * 注意: 从这里起无权直接写 GPIO 寄存器.
     * GPIO_ResetBits(GPIOC, GPIO_Pin_13); ← 会触发 HardFault!
     */

    /* ══════════ 阶段 3: 用户态通过 SVC 闪灯 ══════════ */
    while (1)
    {
        sys_GPIO_Reset((uint32_t)GPIOC, GPIO_Pin_13);  /* SVC #0x01 → 内核亮灯 */
        sys_DelayMs(500);                                /* SVC #0x03 → 内核延时 */
        sys_GPIO_Set((uint32_t)GPIOC, GPIO_Pin_13);    /* SVC #0x02 → 内核灭灯 */
        sys_DelayMs(500);
    }
}
