/**
  * @file    Syscall/stm32f10x_it.c
  * @brief   内核态代码 —— SVC 提权铁闸 + 内核服务函数
  *
  *          SVC_Handler:  汇编铁闸, 区分 MSP/PSP, 跳转 SVC_Router
  *          SVC_Router:   解析 SVC 立即数 → 状态机审计 → 分发到内核服务
  *          Kernel_*:     运行在 Handler Mode (Privileged), 直接操作硬件
  */
#include "stm32f10x_it.h"
#include "syscall.h"
#include "sec_core.h"
#include "rgb_led.h"
#include "aes_sw.h"
#include <string.h>

/* ── SysTick 计数器 ── */
static volatile uint32_t g_sys_tick = 0;

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
 * 审计失败 — 红灯快闪 + 发 NACK 到串口
 *═════════════════════════════════════════════════════════════*/
static void Audit_Fail(uint8_t svc_num)
{
    uint8_t nack[2];
    SecCore_BuildAuditNACK(nack);
    nack[1] = svc_num;

    /* 红灯快闪 1 次警告 */
    RGB_BlinkN(1, 50, 50, BRIGHT_FULL, 0, 0);

    /* 通过 USART1 发送审计拒绝响应 (特殊 ACK 码 = 0xFE) */
    extern void CH340_Comm_Send(uint8_t cmd, const uint8_t *data, uint8_t len);
    CH340_Comm_Send(0xFE, nack, 2);
}

/*═════════════════════════════════════════════════════════════
 * L1: SVC 路由分发器 + 状态机审计铁闸
 *═════════════════════════════════════════════════════════════*/
void SVC_Router(uint32_t *pStackFrame)
{
    uint8_t svc_num = *((uint8_t *)pStackFrame[6] - 2);  /* PC[-2] = SVC 立即数 */
    uint8_t audit_result;

    /* ═══════ 状态机铁闸: 每个协议命令执行前审计 ═══════ */
    if (svc_num >= 0x10) {
        audit_result = SecCore_AuditSVC(svc_num);
        if (audit_result != 0) {
            Audit_Fail(svc_num);
            if (audit_result == 2) {
                /* PANIC 态 — 不死循环, 让调用者自行处理 */
            }
            return;
        }
    }

    switch (svc_num)
    {
        /* ── 实用 SVC (无需审计, 始终可用) ── */
        case SVC_ID_GPIO_SET:   /* R0=port, R1=pin */
            Kernel_GPIO_Set((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_GPIO_RESET: /* R0=port, R1=pin */
            Kernel_GPIO_Reset((GPIO_TypeDef *)pStackFrame[0], (uint16_t)pStackFrame[1]);
            break;
        case SVC_ID_DELAY_MS:   /* R0=ms */
            Kernel_DelayMs(pStackFrame[0]);
            break;

        /* ── SecuFerry-OS 协议命令 SVC (已通过审计铁闸) ── */
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
void SysTick_Handler(void)    { g_sys_tick++; }

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
    uint32_t start = g_sys_tick;
    while ((g_sys_tick - start) < ms);
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

/** LED 快速闪烁 n 次 (内核态, 通过RGB模块) */
static void Kernel_BlinkN(uint32_t n)
{
    RGB_BlinkN(n, 100, 100, BRIGHT_FULL, BRIGHT_FULL, BRIGHT_FULL);
}

/*═════════════════════════════════════════════════════════════
 * SecuFerry-OS 协议命令内核服务 (RAM 模拟扇区实现)
 *
 *   WriteTask: 密网下发任务 → 写入 g_SectorTask → STATE_ASSIGNED
 *   ReadTask:  工控读取任务 → g_SectorTask → g_ReadOutBuf
 *   WriteData: 工控推送明文 → [TODO: AES加密] → g_SectorData
 *   ReadData:  密网泵出密文 → g_SectorData → g_ReadOutBuf (盲泵, 不解密)
 *
 *   后续 SD 卡到位: 把 memcpy 替换成 sd_raw_write/read_sector()
 *═════════════════════════════════════════════════════════════*/

/**
 * @brief  SVC 0x10: 密网写入任务暗号到 Sector 1024 (RAM)
 *
 *          流程:
 *            1. 拷贝用户态 buf → 内核态 g_SectorTask
 *            2. 切换状态 STATE_INIT/STATE_IDLE → STATE_ASSIGNED
 *            3. LED 白闪 1 次 = 写入成功
 */
static void Kernel_WriteTask(uint32_t buf, uint32_t len)
{
    uint32_t copy_len;

    if (buf == 0 || len == 0) {
        RGB_BlinkN(1, 50, 50, BRIGHT_FULL, 0, 0);
        return;
    }

    /* 安全拷贝: 最大 SECTOR_SIZE */
    copy_len = (len > SECTOR_SIZE) ? SECTOR_SIZE : len;
    SecCore_MemZero(g_SectorTask, SECTOR_SIZE);
    memcpy(g_SectorTask, (const void *)buf, copy_len);

    /* 状态切换: 空闲/初始化 → 已授权 (任务已注入) */
    g_FerryState = STATE_ASSIGNED;

    /* 白闪 1 次 = WriteTask 成功 */
    Kernel_BlinkN(1);
}

/**
 * @brief  SVC 0x11: 工控读取任务暗号从 Sector 1024 (RAM)
 *
 *          流程:
 *            1. 从 g_SectorTask 拷贝到 g_ReadOutBuf
 *            2. 主循环通过 CH340_Comm_Send 发出
 *            3. LED 白闪 2 次 = ReadTask 完成
 */
static void Kernel_ReadTask(uint32_t buf, uint32_t len)
{
    uint32_t copy_len;

    /* 从 RAM 扇区读出任务数据到输出缓冲 */
    SecCore_MemZero(g_ReadOutBuf, SECTOR_SIZE);

    if (buf != 0 && len > 0) {
        /* 有用户态 buf → 直接写入 (向后兼容) */
        copy_len = (len > SECTOR_SIZE) ? SECTOR_SIZE : len;
        memcpy((void *)buf, g_ReadOutBuf, copy_len);
    }

    copy_len = (len > SECTOR_SIZE) ? SECTOR_SIZE : len;
    if (copy_len == 0) copy_len = 256; /* 默认读出 256 字节 */

    memcpy(g_ReadOutBuf, g_SectorTask, copy_len);

    /* 白闪 2 次 = ReadTask 完成 */
    Kernel_BlinkN(2);
    (void)buf;
}

/**
 * @brief  SVC 0x12: 工控推送明文数据 → 加密落盘 (RAM)
 *
 *          当前: 明文直接存入 g_SectorData (无加密)
 *          TODO: 接入 AES-128 后用 g_SessionSK 加密后落盘
 *
 *          流程:
 *            1. 拷贝用户态明文 → g_SectorData (追加)
 *            2. 更新 g_DataWriteLen
 *            3. LED 白闪 3 次 = WriteData 完成
 */
static void Kernel_WriteData(uint32_t buf, uint32_t len)
{
    uint32_t copy_len;
    uint32_t offset;

    if (buf == 0 || len == 0) return;

    /* 边界保护 */
    offset = g_DataWriteLen;
    if (offset >= (uint32_t)(SECTOR_SIZE * SECTOR_DATA_MAX)) {
        /* 数据舱已满 — 拒绝写入 */
        RGB_BlinkN(6, 100, 100, BRIGHT_FULL, 0, 0);
        return;
    }

    copy_len = len;
    if (offset + copy_len > (uint32_t)(SECTOR_SIZE * SECTOR_DATA_MAX)) {
        copy_len = (uint32_t)(SECTOR_SIZE * SECTOR_DATA_MAX) - offset;
    }

    /* AES-128 加密: 用 g_SessionSK 作为密钥
     *   逐块 ECB 加密 → 写入 g_SectorData
     *   注意: 固件不提供解密函数 (按设计文档要求) */
    {
        uint8_t  enc_buf[1024];
        uint32_t enc_len;
        uint32_t i;

        /* 逐块加密 (每块 16 字节, ECB 模式) */
        enc_len = 0;
        for (i = 0; i < copy_len; i += AES_BLOCK_SIZE) {
            uint8_t block[AES_BLOCK_SIZE];
            uint8_t enc_block[AES_BLOCK_SIZE];
            uint8_t rem;

            /* 填充不足一块的部分 (零填充 + 长度编码在最后字节) */
            SecCore_MemZero(block, AES_BLOCK_SIZE);
            rem = (uint8_t)((copy_len - i) < AES_BLOCK_SIZE ? (copy_len - i) : AES_BLOCK_SIZE);
            memcpy(block, (const void *)(buf + i), rem);

            aes128_encrypt_block(g_SessionSK, block, enc_block);

            if (enc_len + AES_BLOCK_SIZE <= sizeof(enc_buf)) {
                memcpy(enc_buf + enc_len, enc_block, AES_BLOCK_SIZE);
                enc_len += AES_BLOCK_SIZE;
            }

            SecCore_MemZero(block, AES_BLOCK_SIZE);
            SecCore_MemZero(enc_block, AES_BLOCK_SIZE);
        }

        /* 加密后的密文落盘 */
        if (offset + enc_len <= (uint32_t)(SECTOR_SIZE * SECTOR_DATA_MAX)) {
            memcpy(g_SectorData + offset, enc_buf, enc_len);
            g_DataWriteLen += enc_len;
        }

        SecCore_MemZero(enc_buf, sizeof(enc_buf));
    }

    Kernel_BlinkN(3);   /* 闪 3 次: SVC_ID_WRITE_DATA (0x12) 已触发 */
}

/** PANIC 红灯爆闪 (永不返回) */
static void Kernel_PanicBlink(void)
{
    RGB_PanicLoop();
}

/**
 * @brief  SVC 0x19: 密网读权限握手验证 (内核态)
 * @param  buf: AES-GCM 加密的挑战数据
 * @param  len: 密文长度
 *
 *  当前 Demo 实现:
 *    验证由主循环握手完成 → 本函数直接解锁 STATE_READ_ALLOW
 *    量产: 需 AES-128 解密 payload 后再验证内部挑战码
 */
static void Kernel_ReadShake(uint32_t buf, uint32_t len)
{
    (void)buf;
    (void)len;

    g_FerryState         = STATE_READ_ALLOW;
    g_ChallengeFailCount = 0;

    /* 快闪 1 下白灯 = 解锁完成 (不阻塞) */
    Kernel_BlinkN(1);
}

/**
 * @brief  SVC 0x1A: 密文数据泵出 (内核态)
 *
 *          状态机门控: 仅 STATE_READ_ALLOW 允许
 *          当前实现: 从 g_SectorData 盲泵密文 (不解密) → g_ReadOutBuf
 *          量产: sd_raw_read_sector() 从 SD 盲泵
 */
static void Kernel_ReadData(uint32_t buf, uint32_t len)
{
    uint32_t copy_len;

    /* 状态机门控: 仅 STATE_READ_ALLOW 允许数据回读 */
    if (!SecCore_IsReadAllowed()) {
        RGB_BlinkN(2, 50, 50, BRIGHT_FULL, 0, 0);
        return;
    }

    /* 从 RAM 数据舱盲泵密文到输出缓冲 (不解密, 固件无解密能力) */
    SecCore_MemZero(g_ReadOutBuf, SECTOR_SIZE);

    copy_len = g_DataWriteLen;
    if (copy_len > SECTOR_SIZE) copy_len = SECTOR_SIZE;

    if (copy_len > 0) {
        memcpy(g_ReadOutBuf, g_SectorData, copy_len);
    }

    /* 白闪 5 次 = ReadData 完成 */
    Kernel_BlinkN(5);

    /* 同时写入用户态 buf (如提供) */
    if (buf != 0 && len > 0 && copy_len > 0) {
        uint32_t ulen = (len < copy_len) ? len : copy_len;
        memcpy((void *)buf, g_ReadOutBuf, ulen);
    }

    (void)buf; (void)len;
}
