/**
 * @file    hid_comm.h
 * @brief   USB HID 通信层 —— 设备发现 + 阻塞读写
 *
 *          STM32 作为 USB HID Device, 使用 Custom HID 协议。
 *          EXE 作为 USB Host, 通过 Windows HID API 通信。
 *
 *          握手方向: STM32 主动发 Hello → EXE 被动响应
 */

#ifndef HID_COMM_H
#define HID_COMM_H

#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* STM32 Custom HID 设备标识 (需与固件 USB 描述符一致) */
#define STM32_HID_VID       0x0483   /* STMicroelectronics */
#define STM32_HID_PID       0x5750   /* STM32 Custom HID (示例, 量产可自定义) */
#define STM32_HID_USAGE_PAGE 0xFF00  /* Vendor-defined */
#define STM32_HID_USAGE      0x0001

/* HID Report 大小 (与固件一致) */
#define HID_REPORT_SIZE      64

/* 读写超时 (毫秒) */
#define HID_READ_TIMEOUT_MS  5000    /* Hello 等待: 5 秒 */
#define HID_WRITE_TIMEOUT_MS 2000

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  查找并打开 STM32 HID 设备
 * @param  vid: 厂商 ID (0 表示使用默认 STM32_HID_VID)
 * @param  pid: 产品 ID (0 表示使用默认 STM32_HID_PID)
 * @return 设备句柄 (INVALID_HANDLE_VALUE 表示未找到)
 */
HANDLE HID_OpenDevice(uint16_t vid, uint16_t pid);

/**
 * @brief  关闭 HID 设备
 */
void HID_CloseDevice(HANDLE hDev);

/**
 * @brief  从设备读取一帧 (阻塞, 等待 STM32 主动发送)
 * @param  hDev:     设备句柄
 * @param  report:   输出缓冲区 (64 字节)
 * @param  timeout_ms: 超时毫秒
 * @return >0=实际读取字节数, 0=超时, <0=错误
 */
int HID_ReadFrame(HANDLE hDev, uint8_t *report, uint32_t timeout_ms);

/**
 * @brief  向设备发送一帧
 * @param  hDev:   设备句柄
 * @param  report: 64 字节帧
 * @return 0=成功, <0=错误
 */
int HID_WriteFrame(HANDLE hDev, const uint8_t *report);

/**
 * @brief  获取设备的 HID 描述符信息 (调试用)
 */
void HID_DumpDeviceInfo(HANDLE hDev);

/**
 * @brief  列出系统中所有 HID 设备 (调试用)
 */
void HID_ListAllDevices(void);

#ifdef __cplusplus
}
#endif

#endif /* HID_COMM_H */
