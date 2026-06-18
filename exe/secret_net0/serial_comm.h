/**
 * @file    serial_comm.h
 * @brief   CH340 串口通信层 —— COM 端口发现 + 帧读写
 *
 *          CH340 插入 PC 后映射为虚拟 COM 口 (如 COM3)。
 *          程序自动枚举 COM 口, 查找"CH340"设备。
 *          也可通过命令行参数指定: MasterTask.exe COM5
 *
 *          帧格式 (与 STM32 固件 ch340_comm.c 一致):
 *            [0x7E][CMD][LEN][PAYLOAD 0..60B][XOR]
 */

#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CH340 设备标识 */
#define CH340_VID      0x1A86
#define CH340_PID_1    0x7523   /* CH340 standard */
#define CH340_PID_2    0x55D4   /* CH340 variant */

/* 串口默认参数 */
#define SERIAL_BAUD        9600
#define SERIAL_FRAME_MAX   264
#define SERIAL_PAYLOAD_MAX 255

/* 读写超时 (毫秒) */
#define SERIAL_READ_TIMEOUT_MS  8000
#define SERIAL_WRITE_TIMEOUT_MS 2000

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  自动查找 CH340 串口并打开
 * @return 有效的 COM 口句柄, 失败返回 INVALID_HANDLE_VALUE
 */
HANDLE Serial_OpenDevice(void);

/**
 * @brief  通过 COM 口名称打开设备
 * @param  com_name: 如 "COM3" 或 "\\.\COM3"
 * @return 设备句柄
 */
HANDLE Serial_OpenComPort(const char *com_name);

/**
 * @brief  关闭串口
 */
void Serial_CloseDevice(HANDLE hDev);

/**
 * @brief  读取一帧 (阻塞, 等待 STM32 主动发送)
 * @param  hDev:     设备句柄
 * @param  cmd:      输出 — 命令字节
 * @param  data:     输出 — 载荷数据 (至少 SERIAL_PAYLOAD_MAX 字节)
 * @param  len:      输出 — 载荷长度
 * @param  timeout_ms: 超时毫秒
 * @return >0=成功, 0=超时, <0=错误
 */
int Serial_ReadFrame(HANDLE hDev, uint8_t *cmd, uint8_t *data,
                     uint8_t *len, uint32_t timeout_ms);

/**
 * @brief  发送一帧
 * @param  hDev: 设备句柄
 * @param  cmd:  命令字节
 * @param  data: 载荷数据
 * @param  len:  载荷长度
 * @return 0=成功, <0=错误
 */
int Serial_WriteFrame(HANDLE hDev, uint8_t cmd,
                      const uint8_t *data, uint8_t len);

/**
 * @brief  清空接收缓冲区 (丢弃所有缓存数据)
 */
void Serial_FlushRx(HANDLE hDev);

/**
 * @brief  列出系统中所有串口 (调试用)
 */
void Serial_ListAllPorts(void);

#ifdef __cplusplus
}
#endif

#endif /* SERIAL_COMM_H */
