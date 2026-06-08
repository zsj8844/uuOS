/**
  * @file    Syscall/main.c
  * @brief   SecuFerry-OS SVC 中断验证 Demo (无外设 STM32F103)
  *
  *  协议命令流程 (参照 文档管理/流程.md):
  *
  *    Phase 0:  sys_WriteTask()    → SVC 0x10 → LED闪1次 (表示刻录任务)
  *    Phase 1:  sys_ReadTask()     → SVC 0x11 → LED闪2次 (表示校验令牌)
  *    Phase 1:  sys_WriteData()    → SVC 0x12 → LED闪3次 (表示加密落盘)
  *    Phase 3:  sys_ReadShake()    → SVC 0x19 → LED闪4次 (表示握手挑战)
  *    Phase 3:  sys_ReadData()     → SVC 0x1A → LED闪5次 (表示泵出密文)
  *
  *  接线: 3.3V → 电阻1K → LED → PC13 (板载LED自带)
  *  观察: LED 闪烁次数对应不同 SVC 命令, 证明中断已触发
  */

#include "stm32f10x.h"
#include "syscall.h"

int main(void)
{
    /* ══════════ Phase 0: 特权态初始化硬件 ══════════ */
    GPIO_InitTypeDef gpio;

    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
    gpio.GPIO_Pin   = GPIO_Pin_13;
    gpio.GPIO_Mode  = GPIO_Mode_Out_PP;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOC, &gpio);
    GPIO_SetBits(GPIOC, GPIO_Pin_13);  /* 初始灭灯 */

    /* ══════════ Phase 1: 切到用户态 ══════════ */
    SwitchToUserMode();

    /*
     *  从此处起, CPU 处于 Unprivileged Thread Mode
     *  不能直接写 GPIO 寄存器!  所有硬件操作必须走 SVC
     */

    /* ══════════ Phase 2: 协议命令 Demo 循环 ══════════ */
    while (1)
    {
        /* ── 0x10: WRITE_TASK (密网刻录任务) ── */
        sys_WriteTask(0, 0);
        sys_DelayMs(1500);  /* 间隔等待, 方便观察 */

        /* ── 0x11: READ_TASK (工控校验令牌) ── */
        sys_ReadTask(0, 0);
        sys_DelayMs(1500);

        /* ── 0x12: WRITE_DATA (工控推送数据) ── */
        sys_WriteData(0, 0);
        sys_DelayMs(1500);

        /* ── 0x19: READ_SHAKE (密网握手挑战) ── */
        sys_ReadShake(0);
        sys_DelayMs(1500);

        /* ── 0x1A: READ_DATA (密网泵出密文) ── */
        sys_ReadData(0, 0);
        sys_DelayMs(2500);  /* 本轮结束, 长间隔再下一轮 */
    }
}
