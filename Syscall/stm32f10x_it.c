/**
  * @file    Syscall/stm32f10x_it.c
  * @brief   内核态代码 —— SVC 提权铁闸 + 内核服务函数
  *
  *          SVC_Handler:  汇编铁闸, 区分 MSP/PSP, 跳转 SVC_Router
  *          SVC_Router:   解析 SVC 立即数, 分发到内核服务
  *          Kernel_*:     运行在 Handler Mode (Privileged), 直接操作硬件
  */
// 中断处理函数的实现
#include "stm32f10x_it.h"
#include "syscall.h"

/* ── 前向声明 ── */
static void Kernel_GPIO_Set(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_GPIO_Reset(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_DelayMs(uint32_t ms);

/*═════════════════════════════════════════════════════════════
 * L1: SVC 路由分发器
 *═════════════════════════════════════════════════════════════*/
void SVC_Router(uint32_t *pStackFrame)
{
    uint8_t svc_num = *((uint8_t *)pStackFrame[6] - 2);  /* PC[-2] = SVC 立即数 */

    switch (svc_num)
    {
        case SVC_ID_GPIO_SET:   /* R0=port, R1=pin */
            Kernel_GPIO_Set((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_GPIO_RESET: /* R0=port, R1=pin */
            Kernel_GPIO_Reset((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_DELAY_MS:   /* R0=ms */
            Kernel_DelayMs(pStackFrame[0]);
            break;
        default:
            break;
    }
}

/*═════════════════════════════════════════════════════════════
 * L0: SVC_Handler 汇编铁闸 (用户态→内核态唯一通道)
 *═════════════════════════════════════════════════════════════*/
__asm void SVC_Handler(void)
{
    IMPORT  SVC_Router
    TST     LR, #4
    ITE     EQ
    MRSEQ   R0, MSP
    MRSNE   R0, PSP
    B       SVC_Router
    ALIGN
}

/*═════════════════════════════════════════════════════════════
 * 其他异常 (保留骨架)
 *═════════════════════════════════════════════════════════════*/
void NMI_Handler(void)        { while(1); }
void HardFault_Handler(void)  { while(1); }
void MemManage_Handler(void)  { while(1); }
void BusFault_Handler(void)   { while(1); }
void UsageFault_Handler(void) { while(1); }
void DebugMon_Handler(void)   { }
void PendSV_Handler(void)     { }
void SysTick_Handler(void)    { }

/*═════════════════════════════════════════════════════════════
 * L2: 内核服务函数 (Handler Mode, Privileged)
 *═════════════════════════════════════════════════════════════*/
static void Kernel_GPIO_Set(GPIO_TypeDef *port, uint16_t pin)
{
    if (port) port->BSRR = pin;
}

static void Kernel_GPIO_Reset(GPIO_TypeDef *port, uint16_t pin)
{
    if (port) port->BRR = pin;
}

static void Kernel_DelayMs(uint32_t ms)
{
    while (ms--) {
        for (volatile uint32_t i = 0; i < 7200; i++) __NOP();
    }
}
