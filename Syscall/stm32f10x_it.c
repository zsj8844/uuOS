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
#include "sec_core.h"
#include <string.h>

/* ── 前向声明 ── */
static void Kernel_GPIO_Set(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_GPIO_Reset(GPIO_TypeDef *port, uint16_t pin);
static void Kernel_DelayMs(uint32_t ms);
/* ── 协议命令内核实现 ── */
static void Kernel_WriteTask(uint32_t buf, uint32_t len);
static void Kernel_ReadTask(uint32_t buf, uint32_t len);
static void Kernel_WriteData(uint32_t buf, uint32_t len);
static void Kernel_ReadShake(uint32_t buf, uint32_t len);
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
        case SVC_ID_READ_SHAKE: /* R0=buf, R1=len */
            Kernel_ReadShake(pStackFrame[0], pStackFrame[1]);
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
 * L2: SecuFerry-OS 协议命令内核服务
 *
 *   当前 Demo 阶段:
 *     - 无 USB 通信, 自测验证握手逻辑
 *     - Kernel_ReadShake: 真正的 HMAC 挑战-应答验证
 *     - Kernel_ReadData:  状态机门控, 仅在 STATE_READ_ALLOW 下允许
 *     - 失败 3 次 → STATE_CORE_PANIC → 红灯爆闪死锁
 *
 *   后续接入 USB HID 后:
 *     - 握手由 USB 协议层 (parse_terminal_cmd) 发起, SVC 0x19 验证挑战
 *     - 数据泵出由 sd_raw_read_sector() 实现
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
    Kernel_BlinkN(1);   /* 闪 1 次: SVC_ID_WRITE_TASK (0x10) 已触发 */
    (void)buf; (void)len;
}

static void Kernel_ReadTask(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(2);   /* 闪 2 次: SVC_ID_READ_TASK (0x11) 已触发 */
    (void)buf; (void)len;
}

static void Kernel_WriteData(uint32_t buf, uint32_t len)
{
    Kernel_BlinkN(3);   /* 闪 3 次: SVC_ID_WRITE_DATA (0x12) 已触发 */
    (void)buf; (void)len;
}

/** PANIC 红灯爆闪 (快速闪烁, 不退出) */
static void Kernel_PanicBlink(void)
{
    while (1)
    {
        GPIOC->BRR  = GPIO_Pin_13;
        for (volatile uint32_t i = 0; i < 120000; i++) __NOP();  /* ~150ms */
        GPIOC->BSRR = GPIO_Pin_13;
        for (volatile uint32_t i = 0; i < 120000; i++) __NOP();  /* ~150ms */
    }
}

/**
 * @brief  SVC 0x19: 密网握手响应验证 (内核态)
 * @param  buf: 用户态传来的 Handshake 数据指针 (nonce_h || HMAC)
 * @param  len: 数据长度 (≥16 字节)
 *
 *  握手由 STM32 主动发起:
 *    1. STM32 插入 USB → SecCore_StartHandshake() 生成 nonce_s
 *    2. STM32 通过 USB 发送 Hello(Domain, nonce_s) → EXE
 *    3. EXE 收到 → 生成 nonce_h → 计算 HMAC → 回复 Handshake(nonce_h, HMAC)
 *    4. USB 中断 → parse_terminal_cmd → SVC 0x19 → 本函数
 *    5. SecCore_VerifyChallenge() HMAC 比对
 *
 *  验证结果:
 *    通过 → LED 闪 4 次×2 (STATE_READ_ALLOW, 派生 SK)
 *    失败 → 快闪 1 次, 累计 3 次 → Kernel_PanicBlink() 死锁
 *   4. 失败 → 闪 1 次快闪, 累计 3 次失败 → Kernel_PanicBlink()
 */
static void Kernel_ReadShake(uint32_t buf, uint32_t len)
{
    uint8_t  challenge[32];
    uint32_t copy_len;
    uint8_t  result;

    /* 边界保护: 最多读取 32 字节 */
    copy_len = (len > 32) ? 32 : len;
    if (buf == 0 || copy_len < 16) {
        /* 参数无效, 视为挑战失败 */
        SecCore_VerifyChallenge(NULL, 0);
        return;
    }

    /* 从用户态缓冲区拷贝挑战数据 (内核态私有栈, 防 TOCTOU) */
    SecCore_MemZero(challenge, sizeof(challenge));
    memcpy(challenge, (const void *)buf, copy_len);

    /* 执行 HMAC 挑战-应答验证 */
    result = SecCore_VerifyChallenge(challenge, copy_len);
    SecCore_MemZero(challenge, sizeof(challenge));

    if (result == 0) {
        /* 验证通过 → STATE_READ_ALLOW, 绿灯爆闪 4 次 */
        Kernel_BlinkN(4);
        /* 延长亮灭间隔以示与失败的区别 */
        for (volatile uint32_t i = 0; i < 720000; i++) __NOP();
        Kernel_BlinkN(4);
    } else {
        /* 验证失败 */
        if (g_FerryState == STATE_CORE_PANIC) {
            /* 已达失败上限 → 自毁死锁 */
            Kernel_PanicBlink();
        } else {
            /* 失败但未达上限 → 快闪 1 次报错 */
            GPIOC->BRR  = GPIO_Pin_13;
            for (volatile uint32_t i = 0; i < 120000; i++) __NOP();
            GPIOC->BSRR = GPIO_Pin_13;
            for (volatile uint32_t i = 0; i < 720000; i++) __NOP();
        }
    }
}

/**
 * @brief  SVC 0x1A: 密文数据泵出 (内核态)
 *         当前 Demo: LED 闪 5 次 (仅在 STATE_READ_ALLOW 下)
 *         量产接入 SD 卡后: sd_raw_read_sector() 盲泵密文
 */
static void Kernel_ReadData(uint32_t buf, uint32_t len)
{
    /* 状态机门控: 仅 STATE_READ_ALLOW 允许数据回读 */
    if (!SecCore_IsReadAllowed()) {
        /* 门控拒绝: 快闪 2 次警告 */
        Kernel_BlinkN(1);
        GPIOC->BRR  = GPIO_Pin_13;
        for (volatile uint32_t i = 0; i < 120000; i++) __NOP();
        GPIOC->BSRR = GPIO_Pin_13;
        return;
    }

    /* 验证通过, 执行数据泵出 */
    Kernel_BlinkN(5);   /* 闪 5 次: SVC_ID_READ_DATA (0x1A) 已触发 */
    (void)buf; (void)len;

    /* TODO: 量产阶段替换为 sd_raw_read_sector() 纯密文盲泵 */
}
