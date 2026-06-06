/**
  * @file    Syscall/syscall.h
  * @brief   用户态/内核态切换接口 (ARM Compiler 5)
  *          仅提供: 切换到用户态 + 3 个 SVC 系统调用用于演示
  */

#ifndef __SYSCALL_H
#define __SYSCALL_H

/* ── 系统调用的接口 ── */
#include "stm32f10x.h"

/* ── SVC 调用号 ── */
#define SVC_ID_GPIO_SET     0x01
#define SVC_ID_GPIO_RESET   0x02
#define SVC_ID_DELAY_MS     0x03

/* ── SVC 系统调用 (ARMCC __svc 关键字) ── */
/** 请求内核设置 GPIO 引脚  (port→R0, pin→R1, SVC #0x01) */
void __svc(SVC_ID_GPIO_SET)   sys_GPIO_Set(uint32_t port, uint32_t pin);

/** 请求内核复位 GPIO 引脚  (port→R0, pin→R1, SVC #0x02) */
void __svc(SVC_ID_GPIO_RESET) sys_GPIO_Reset(uint32_t port, uint32_t pin);

/** 请求内核做阻塞延时      (ms→R0, SVC #0x03) */
void __svc(SVC_ID_DELAY_MS)   sys_DelayMs(uint32_t ms);

/* ── 切换到用户态 ── */
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
