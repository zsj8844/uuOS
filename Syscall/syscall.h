/**
  * @file    Syscall/syscall.h
  * @brief   用户态/内核态切换接口 (ARM Compiler 5)
  *          实用 SVC + SecuFerry-OS 协议命令 SVC
  *          Demo: 无外设验证 —— 不同 SVC → LED 不同闪烁次数
  */

#ifndef __SYSCALL_H
#define __SYSCALL_H

#include "stm32f10x.h"

/*═════════════════════════════════════════════════════════════
 * SVC 调用号定义
 *═════════════════════════════════════════════════════════════*/

/* ── 实用 SVC (硬件操作) ── */
#define SVC_ID_GPIO_SET     0x01    /* 引脚输出高 (灭灯) */
#define SVC_ID_GPIO_RESET   0x02    /* 引脚输出低 (亮灯) */
#define SVC_ID_DELAY_MS     0x03    /* 阻塞延时 */

/* ── SecuFerry-OS 协议命令 SVC ── */
/* 参照 文档管理/流程.md, 每条协议指令对应一个 SVC 号 */
#define SVC_ID_WRITE_TASK   0x10    /* 0x00: Phase 0  密网→刻录任务暗号到 Sector 1024 */
#define SVC_ID_READ_TASK    0x11    /* 0x01: Phase 1  工控→读取任务暗号 */
#define SVC_ID_WRITE_DATA   0x12    /* 0x02: Phase 1  工控→推送明文数据流(加密落盘) */
#define SVC_ID_READ_SHAKE   0x19    /* 0x09: Phase 3  密网→校验特权读暗号(状态机解锁) */
#define SVC_ID_READ_DATA    0x1A    /* 0x0A: Phase 3  密网→批量抽取密文流 */

/*═════════════════════════════════════════════════════════════
 * SVC 系统调用声明 (ARMCC __svc 关键字)
 * 参数通过 R0,R1 传递, 内核从 pStackFrame[0],[1] 取回
 *═════════════════════════════════════════════════════════════*/

/* ── 实用 ── */
void __svc(SVC_ID_GPIO_SET)   sys_GPIO_Set(uint32_t port, uint32_t pin);
void __svc(SVC_ID_GPIO_RESET) sys_GPIO_Reset(uint32_t port, uint32_t pin);
void __svc(SVC_ID_DELAY_MS)   sys_DelayMs(uint32_t ms);

/* ── 协议命令 ── */
/** 下发任务: buf→任务数据指针, len→长度 (Demo: LED闪1次) */
void __svc(SVC_ID_WRITE_TASK) sys_WriteTask(uint32_t buf, uint32_t len);

/** 读取任务: buf→缓冲区, len→长度 (Demo: LED闪2次) */
void __svc(SVC_ID_READ_TASK)  sys_ReadTask(uint32_t buf, uint32_t len);

/** 写入数据: buf→明文数据, len→长度 (Demo: LED闪3次) */
void __svc(SVC_ID_WRITE_DATA) sys_WriteData(uint32_t buf, uint32_t len);

/** 握手挑战: challenge→鉴别码 (Demo: LED闪4次) */
void __svc(SVC_ID_READ_SHAKE) sys_ReadShake(uint32_t challenge);

/** 读取数据: buf→缓冲区, len→长度 (Demo: LED闪5次) */
void __svc(SVC_ID_READ_DATA)  sys_ReadData(uint32_t buf, uint32_t len);

/*═════════════════════════════════════════════════════════════
 * 切换到用户态
 *═════════════════════════════════════════════════════════════*/
/**
  * @brief  从特权态切到非特权用户态
  * @note   必须在硬件初始化完成后、进入主循环前调用。
  *         调用后无权直接访问外设寄存器, 必须走 sys_* 系统调用。
  */
static __inline void SwitchToUserMode(void)
{
    static uint8_t __attribute__((aligned(8))) user_sp[1024];
    __set_PSP((uint32_t)(user_sp + sizeof(user_sp)));
    __set_CONTROL(0x3);  /* bit1=PSP, bit0=Unprivileged */
    __ISB();
}

#endif /* __SYSCALL_H */
