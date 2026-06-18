/**
 * @file    Syscall/ch340_comm.h
 * @brief   CH340 串口通信模块 —— USART3 帧协议 (设计文档3 阶段0)
 *
 *          硬件接线 (避开板载 PA9/PA10):
 *            CH340 TX  → PB11 (USART3_RX)
 *            CH340 RX  → PB10 (USART3_TX)
 *            CH340 GND → GND
 *
 *          帧格式:
 *            [0x7E][CMD][LEN][PAYLOAD 0..60B][XOR]
 *            XOR = CMD ^ LEN ^ PAYLOAD[0] ^ ... ^ PAYLOAD[LEN-1]
 */

#ifndef __CH340_COMM_H
#define __CH340_COMM_H

#include "stm32f10x.h"

/*─────────────────────────────────────────────────────────
 * 帧常量
 *─────────────────────────────────────────────────────────*/
#define FRAME_SYNC          0x7E

/* 命令字节 (对应设计文档3 SVC 立即数) */
#define FRAME_CMD_HELLO         0x01   /* STM32→PC: Domain(1B) + nonce_s(16B) */
#define FRAME_CMD_HANDSHAKE     0x02   /* PC→STM32: nonce_m(16B) + HMAC(32B)  */
#define FRAME_CMD_ACK           0x03   /* STM32→PC: status(1B)                */
#define FRAME_CMD_WRITE_TASK    0x10   /* PC→STM32: SK1加密的任务数据         */
#define FRAME_CMD_READ_TASK     0x11   /* STM32→PC: 读取任务暗号(SK2加密)     */
#define FRAME_CMD_WRITE_DATA    0x12   /* PC→STM32: 双层密文数据(SK2外层加密) */
#define FRAME_CMD_READ_SHAKE    0x19   /* PC→STM32: 解密指令(目标密文ID)      */
#define FRAME_CMD_READ_DATA     0x1A   /* STM32→PC: SK1'加密的明文回传       */

#define FRAME_MAX_PAYLOAD   255
#define FRAME_BUF_SIZE      260

/* 诊断: USART RX 字节计数器 (main.c 可读取以判断是否有数据到达) */
extern volatile uint32_t g_rx_byte_count;
extern volatile uint32_t g_rx_frame_ok;     /* 有效帧计数 */
extern volatile uint32_t g_rx_frame_bad;    /* 坏帧计数 */
void CH340_Comm_ResetIfTimeout(void);        /* 帧超时重置 */

/*─────────────────────────────────────────────────────────
 * API
 *─────────────────────────────────────────────────────────*/

/**
 * @brief  初始化 USART3 (PB10/PB11, 38400-8N1, RXNE+IDLE 中断)
 */
void CH340_Comm_Init(void);

/**
 * @brief  发送一帧数据 (自动打包帧头/长度/校验)
 * @param  cmd:  命令字节
 * @param  data: 载荷数据指针
 * @param  len:  载荷长度 (0~60)
 */
void CH340_Comm_Send(uint8_t cmd, const uint8_t *data, uint8_t len);

/**
 * @brief  接收一帧数据 (非阻塞)
 * @param  cmd:  输出 — 命令字节
 * @param  data: 输出缓冲区 — 载荷数据
 * @param  len:  输出 — 载荷长度
 * @return 1 = 收到完整帧, 0 = 无帧待处理
 */
uint8_t CH340_Comm_Recv(uint8_t *cmd, uint8_t *data, uint8_t *len);

#endif /* __CH340_COMM_H */
