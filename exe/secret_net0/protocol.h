/**
 * @file    protocol.h
 * @brief   密网 EXE 协议层 —— 串口帧格式、握手状态机、命令封装
 *
 *          通信接口: CH340 (虚拟 COM 口), 帧格式与 STM32 固件 ch340_comm.c 一致
 *
 *          帧格式:
 *            [0x7E][CMD][LEN][PAYLOAD 0..60B][XOR]
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*══════════════════════════════════════════════════════════
 * 帧格式常量 (与 STM32 固件 ch340_comm.h 一致)
 *══════════════════════════════════════════════════════════*/
#define FRAME_SYNC          0x7E
#define FRAME_PAYLOAD_MAX   255

/* 帧命令字节 (与 STM32 固件一致) */
#define FRAME_CMD_HELLO      0x01   /* STM32→PC: Domain + nonce_s */
#define FRAME_CMD_HANDSHAKE  0x02   /* PC→STM32: nonce_h + HMAC  */
#define FRAME_CMD_ACK        0x03   /* STM32→PC: status           */
#define FRAME_CMD_WRITE_TASK 0x10   /* PC→STM32: 加密任务数据     */

/* Domain 字节 */
#define DOMAIN_SECRET_NET   0x01   /* 密网 */
#define DOMAIN_INDUSTRIAL   0x02   /* 工控 */

/* SVC 命令码 */
#define SVC_WRITE_TASK      0x10

/* 加密常量 */
#define NONCE_SIZE          16
#define HMAC_TAG_SIZE       32
#define SK_SIZE             16      /* AES-128 */

/*══════════════════════════════════════════════════════════
 * 握手状态机
 *══════════════════════════════════════════════════════════*/
typedef enum {
    HS_WAIT_HELLO      = 0,
    HS_SENT_HANDSHAKE  = 1,
    HS_ESTABLISHED     = 2,
    HS_TIMEOUT         = 3,
    HS_FAILED          = 4,
} HandshakeState_t;

/*══════════════════════════════════════════════════════════
 * 握手上下文
 *══════════════════════════════════════════════════════════*/
typedef struct {
    HandshakeState_t state;
    uint8_t  nonce_s[NONCE_SIZE];
    uint8_t  nonce_h[NONCE_SIZE];
    uint8_t  sk[SK_SIZE];
} SessionCtx;

/*══════════════════════════════════════════════════════════
 * 任务结构体
 *══════════════════════════════════════════════════════════*/
#define TASK_TARGET_ID_LEN    32
#define TASK_DATA_POINTS_LEN  128

#pragma pack(push, 1)
typedef struct {
    uint32_t valid_from;
    uint32_t valid_to;
    char     target_id[TASK_TARGET_ID_LEN];
    uint8_t  strategy;
    uint16_t interval_sec;
    char     data_points[TASK_DATA_POINTS_LEN];
} TaskPayload;
#pragma pack(pop)

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  解析 Hello 帧载荷 (仅 nonce_s, 16 字节, 不包含 domain)
 * @return 0=成功, 非0=格式无效
 */
int Proto_ParseHello(const uint8_t *data, uint8_t len, SessionCtx *sess);

/**
 * @brief  构建 Handshake 帧载荷
 * @param  data:    输出缓冲区
 * @param  out_len: 输出 — 载荷长度
 * @param  sess:    会话上下文
 * @param  mk_ctrl: MK_CTRL 密钥
 * @return 0=成功
 */
int Proto_BuildHandshake(uint8_t *data, uint8_t *out_len,
                         const SessionCtx *sess, const uint8_t *mk_ctrl);

/**
 * @brief  解析 ACK 帧载荷
 * @param  data: 帧载荷 (status byte)
 * @param  len:  载荷长度
 * @return 0=ACK有效, 非0=NACK/无效
 */
int Proto_ParseAck(const uint8_t *data, uint8_t len);

/**
 * @brief  派生会话密钥 SK1
 */
int Proto_DeriveSK(SessionCtx *sess, const uint8_t *mk_ctrl);

/**
 * @brief  构建加密命令帧载荷 (AES-GCM)
 * @param  data:     输出缓冲区
 * @param  out_len:  输出 — 载荷长度
 * @param  sess:     会话上下文
 * @param  svc_cmd:  SVC 命令码
 * @param  input:    明文数据
 * @param  input_len: 明文长度
 * @return 0=成功
 */
int Proto_BuildEncryptedCmd(uint8_t *data, uint8_t *out_len,
                            SessionCtx *sess, uint8_t svc_cmd,
                            const uint8_t *input, uint32_t input_len);

/**
 * @brief  解密加密响应帧载荷
 */
int Proto_DecryptResponse(const uint8_t *data, uint8_t len,
                          const SessionCtx *sess,
                          uint8_t *out, uint32_t *out_len);

/**
 * @brief  打印帧 (调试用)
 */
void Proto_DumpFrame(const char *label, uint8_t cmd,
                     const uint8_t *data, uint8_t len);

/**
 * @brief  会话管理
 */
void Session_Init(SessionCtx *sess);
void Session_Destroy(SessionCtx *sess);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */
