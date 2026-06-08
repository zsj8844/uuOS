/**
  * @file    Syscall/stm32f10x_it.c
  * @brief   内核态代码 —— SVC 提权铁闸 + 内核服务函数
  *
  *          SVC_Handler:  汇编铁闸, 区分 MSP/PSP, 跳转 SVC_Router
  *          SVC_Router:   解析 SVC 立即数, 分发到内核服务
  *          Kernel_*:     运行在 Handler Mode (Privileged), 直接操作硬件
  */
#include "stm32f10x_it.h"
#include "syscall.h"

/* ── 前向声明 ── */
static void Kernel_GPIO_Set(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_GPIO_Reset(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_DelayMs(uint32_t ms);
/* ── 协议命令内核实现 ── */
static void Kernel_WriteTask(uint32_t buf, uint32_t len);
static void Kernel_ReadTask(uint32_t buf, uint32_t len);
static void Kernel_WriteData(uint32_t buf, uint32_t len);
static void Kernel_ReadShake(uint32_t challenge);
static void Kernel_ReadData(uint32_t buf, uint32_t len);

/*═════════════════════════════════════════════════════════════
 * L1: SVC 路由分发器
 * 从 SVC 指令中提取立即数, 按号分派到对应内核函数
 *═════════════════════════════════════════════════════════════*/
void SVC_Router(uint32_t *pStackFrame)
{
    uint8_t svc_num = *((uint8_t *)pStackFrame[6] - 2);  /* PC[-2] = SVC 立即数 */

    switch (svc_num)
    {
        /* ── 实用 SVC ── */
        case SVC_ID_GPIO_SET:   /* R0=port, R1=pin */
            Kernel_GPIO_Set((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_GPIO_RESET: /* R0=port, R1=pin */
            Kernel_GPIO_Reset((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_DELAY_MS:   /* R0=ms */
            Kernel_DelayMs(pStackFrame[0]);
            break;

        /* ── SecuFerry-OS 协议命令 SVC ── */
        case SVC_ID_WRITE_TASK: /* R0=buf, R1=len */
            Kernel_WriteTask(pStackFrame[0], pStackFrame[1]);
            break;
        case SVC_ID_READ_TASK:  /* R0=buf, R1=len */
            Kernel_ReadTask(pStackFrame[0], pStackFrame[1]);
            break;
        case SVC_ID_WRITE_DATA: /* R0=buf, R1=len */
            Kernel_WriteData(pStackFrame[0], pStackFrame[1]);
            break;
        case SVC_ID_READ_SHAKE: /* R0=challenge */
            Kernel_ReadShake(pStackFrame[0]);
            break;
        case SVC_ID_READ_DATA:  /* R0=buf, R1=len */
            Kernel_ReadData(pStackFrame[0], pStackFrame[1]);
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
 * L2: 实用内核服务函数 (Handler Mode, Privileged)
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

/*═════════════════════════════════════════════════════════════
 * L2: SecuFerry-OS 协议命令内核服务 (Demo: LED 闪烁确认 SVC 已触发)
 *
 *   当前无外设(SD卡/USB/SPI), 仅用 PC13 LED 闪烁次数验证:
 *     WRITE_TASK → 闪 1 次
 *     READ_TASK  → 闪 2 次
 *     WRITE_DATA → 闪 3 次
 *     READ_SHAKE → 闪 4 次
 *     READ_DATA  → 闪 5 次
 *
 *   后续接入 SD 卡后:
 *     Kernel_WriteTask   → sd_raw_write_sector(1024, buf)
 *     Kernel_ReadTask    → sd_raw_read_sector(1024, buf)
 *     Kernel_WriteData   → aes_encrypt_raw(buf) → sd_raw_write_sector(1025+, ...)
 *     Kernel_ReadShake   → sec_audit_packet(challenge)
 *     Kernel_ReadData    → sd_raw_read_sector(1025+, buf)
 *═════════════════════════════════════════════════════════════*/

/** LED 快速闪烁 n 次 (内核态直接操作硬件, 不经过 SVC) */
static void Kernel_BlinkN(uint32_t n)
{
    while (n--)
    {
        GPIOC->BRR  = GPIO_Pin_13;              /* 亮 */
        for (volatile uint32_t i = 0; i < 360000; i++) __NOP();  /* ~500ms */
        GPIOC->BSRR = GPIO_Pin_13;              /* 灭 */
        for (volatile uint32_t i = 0; i < 360000; i++) __NOP();  /* ~500ms */
    }
}

static void Kernel_WriteTask(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(1);   /* 闪 1 次: 证明 SVC_ID_WRITE_TASK (0x10) 已触发 */
    (void)buf; (void)len;
}

static void Kernel_ReadTask(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(2);   /* 闪 2 次: 证明 SVC_ID_READ_TASK (0x11) 已触发 */
    (void)buf; (void)len;
}

static void Kernel_WriteData(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(3);   /* 闪 3 次: 证明 SVC_ID_WRITE_DATA (0x12) 已触发 */
    (void)buf; (void)len;
}

static void Kernel_ReadShake(uint32_t challenge)
{
    Kernel_BlinkN(4);   /* 闪 4 次: 证明 SVC_ID_READ_SHAKE (0x19) 已触发 */
    (void)challenge;
}

static void Kernel_ReadData(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(5);   /* 闪 5 次: 证明 SVC_ID_READ_DATA (0x1A) 已触发 */
    (void)buf; (void)len;
}
