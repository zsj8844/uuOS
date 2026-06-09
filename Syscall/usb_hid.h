/**
 * @file    Syscall/usb_hid.h
 * @brief   STM32F103 USB Custom HID Device 驱动
 *
 *          裸寄存器实现, 无 RTOS 依赖, ~350 行。
 *          端点: EP0=Control, EP1=Interrupt IN(0x81)+OUT(0x01)
 *          Report: 64 字节双向
 */

#ifndef __USB_HID_H
#define __USB_HID_H

#include "stm32f10x.h"

/*══════════════════════════════════════════════════════════
 * HID 协议常量 (与 EXE 侧 protocol.h 一致)
 *══════════════════════════════════════════════════════════*/
#define USB_HID_REPORT_SIZE   64
#define USB_HID_VID           0x0483
#define USB_HID_PID           0x5750
#define USB_HID_POLL_INTERVAL 1   /* 1ms 轮询间隔 */

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  初始化 USB HID 设备
 *         配置 PA11(USB_DM), PA12(USB_DP), 上拉电阻, USB 时钟,
 *         复位 USB 外设, 初始化 EP0/EP1, 清除缓冲区。
 */
void USB_HID_Init(void);

/**
 * @brief  发送 64 字节 Report 到主机 (EP1 IN, 阻塞直到发送完成)
 * @param  data: 64 字节数据缓冲区
 */
void USB_HID_SendReport(const uint8_t *data);

/**
 * @brief  检查主机是否发来了新 Report (EP1 OUT)
 * @param  data: 输出缓冲区 (64 字节)
 * @return 1=有新数据并已拷贝到 data, 0=无新数据
 */
int  USB_HID_RecvReport(uint8_t *data);

/**
 * @brief  USB 是否已完成枚举 (主机已 SetConfiguration)
 * @return 1=已配置, 0=未配置
 */
int  USB_HID_IsConfigured(void);

/**
 * @brief  轮询方式处理 USB 事件 (非 IRQ 模式下在主循环中调用)
 *         原型阶段使用此简化方式, 量产改用 IRQ
 */
void USB_HID_Poll(void);

/**
 * @brief  清除接收缓冲区 (丢弃旧数据)
 */
void USB_HID_FlushRecv(void);

#endif /* __USB_HID_H */
