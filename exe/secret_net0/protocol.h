/**
 * @file    protocol.h
 * @brief   密网 EXE 协议层 —— 帧格式、握手状态机、命令封装
 *
 *          参照 文档管理/exe设计.md §2.2 帧格式定义
 *          握手由 STM32 主动发起, EXE 被动等待并响应
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*══════════════════════════════════════════════════════════
 * 帧格式常量 (64 字节 HID Report)
 *══════════════════════════════════════════════════════════*/
#define HID_REPORT_SIZE   64

/* 字段偏移 */
#define FRAME_OFF_DOMAIN   0
#define FRAME_OFF_CMD      1
#define FRAME_OFF_SEQ      2
#define FRAME_OFF_PAYLOAD  4
#define FRAME_OFF_CRC      60
#define FRAME_PAYLOAD_SIZE 56
#define FRAME_CRC_SIZE     4

/* Domain 字节 */
#define DOMAIN_SECRET_NET  0x01   /* 密网 */
#define DOMAIN_INDUSTRIAL  0x02   /* 工控 */

/* 协议控制命令 (非 SVC, 用于 Hello/Handshake/ACK) */
#define PCMD_HELLO         0x00   /* STM32→EXE: Hello(nonce_s) */
#define PCMD_HANDSHAKE     0x00   /* EXE→STM32: Handshake(nonce_h, HMAC) */
#define PCMD_ACK           0x00   /* 双向 ACK */

/* SVC 命令码 (与固件 syscall.h 一致) */
#define SVC_WRITE_TASK     0x10
#define SVC_READ_TASK      0x11
#define SVC_WRITE_DATA     0x12
#define SVC_READ_SHAKE     0x19
#define SVC_READ_DATA      0x1A

/* 握手阶段 nonce 长度 */
#define NONCE_SIZE         16
#define HMAC_TAG_SIZE      32
#define SK_SIZE            16       /* AES-128 密钥 */

/*══════════════════════════════════════════════════════════
 * 帧结构体 (64 字节 HID Report)
 *══════════════════════════════════════════════════════════*/
#pragma pack(push, 1)
typedef struct {
    uint8_t  domain;                          /* 0x01=密网, 0x02=工控 */
    uint8_t  cmd;                             /* 0x00=协议控制, 0x10~0x1A=SVC */
    uint8_t  seq_hi;                          /* 序列号 (大端, 高字节) */
    uint8_t  seq_lo;                          /* 序列号 (大端, 低字节) */
    uint8_t  payload[FRAME_PAYLOAD_SIZE];     /* 有效载荷 */
    uint8_t  crc[FRAME_CRC_SIZE];             /* CRC-32 (大端) */
} HIDFrame;
#pragma pack(pop)

/*══════════════════════════════════════════════════════════
 * 握手状态机
 *══════════════════════════════════════════════════════════*/
typedef enum {
    HS_WAIT_HELLO      = 0,  /* 等待 STM32 发送 Hello */
    HS_SENT_HANDSHAKE  = 1,  /* 已发送 Handshake, 等待 ACK */
    HS_ESTABLISHED     = 2,  /* 握手完成, SK1 已派生, 可发送命令 */
    HS_TIMEOUT         = 3,  /* 握手超时 */
    HS_FAILED          = 4,  /* 握手失败 (HMAC 不匹配 / 设备拒绝) */
} HandshakeState_t;

/*══════════════════════════════════════════════════════════
 * 握手上下文 (一次会话的完整状态)
 *══════════════════════════════════════════════════════════*/
typedef struct {
    HandshakeState_t state;
    uint8_t  nonce_s[NONCE_SIZE];      /* STM32 发来的 nonce */
    uint8_t  nonce_h[NONCE_SIZE];      /* EXE 生成的 nonce */
    uint8_t  sk[SK_SIZE];              /* 派生会话密钥 SK1 */
    uint16_t seq_tx;                   /* 发送序列号 */
    uint16_t seq_rx;                   /* 接收序列号 (期望值) */
} SessionCtx;

/*══════════════════════════════════════════════════════════
 * 任务结构体 (Phase 0 下发内容)
 *══════════════════════════════════════════════════════════*/
#define TASK_TARGET_ID_LEN  32
#define TASK_DATA_POINTS_LEN 128

#pragma pack(push, 1)
typedef struct {
    uint32_t valid_from;                       /* Unix 时间戳, 有效期起始 */
    uint32_t valid_to;                         /* Unix 时间戳, 有效期结束 */
    char     target_id[TASK_TARGET_ID_LEN];    /* 目标工控机标识 */
    uint8_t  strategy;                         /* 0=单次, 1=连续 */
    uint16_t interval_sec;                     /* 连续采集间隔 (秒) */
    char     data_points[TASK_DATA_POINTS_LEN]; /* 数据点描述 */
} TaskPayload;
#pragma pack(pop)

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  解析 STM32 发来的 Hello 帧
 * @param  frame: 收到的 64 字节帧
 * @param  sess:  会话上下文 (提取 nonce_s)
 * @return 0=成功, 非0=帧无效
 */
int Proto_ParseHello(const HIDFrame *frame, SessionCtx *sess);

/**
 * @brief  构建 Handshake 响应帧
 * @param  frame: 输出的 64 字节帧
 * @param  sess:  会话上下文 (nonce_s, nonce_h)
 * @param  mk_ctrl: MK_CTRL 密钥 (32 bytes)
 * @return 0=成功
 */
int Proto_BuildHandshake(HIDFrame *frame, const SessionCtx *sess,
                         const uint8_t *mk_ctrl);

/**
 * @brief  解析 STM32 发来的 ACK 帧
 * @return 0=ACK有效, 非0=无效
 */
int Proto_ParseAck(const HIDFrame *frame, const SessionCtx *sess);

/**
 * @brief  派生会话密钥 SK1 = HMAC-SHA256(MK_CTRL, nonce_s || nonce_h)[:16]
 * @param  sess:   会话上下文 (nonce_s, nonce_h → sk)
 * @param  mk_ctrl: MK_CTRL 密钥 (32 bytes)
 * @return 0=成功
 */
int Proto_DeriveSK(SessionCtx *sess, const uint8_t *mk_ctrl);

/**
 * @brief  构建加密的命令帧 (在 SK 隧道中发送 SVC 命令)
 * @param  frame:   输出的 64 字节帧
 * @param  sess:    会话上下文 (SK, seq)
 * @param  svc_cmd: SVC 命令码 (0x10~0x1A)
 * @param  data:    明文载荷
 * @param  data_len: 明文载荷长度 (≤ FRAME_PAYLOAD_SIZE - 16 - 16)
 * @return 0=成功
 */
int Proto_BuildEncryptedCmd(HIDFrame *frame, SessionCtx *sess,
                            uint8_t svc_cmd,
                            const uint8_t *data, uint32_t data_len);

/**
 * @brief  解密 STM32 发来的加密响应帧
 * @param  frame: 收到的帧
 * @param  sess:  会话上下文 (SK)
 * @param  out:   输出的明文缓冲区
 * @param  out_len: 输入=缓冲区大小, 输出=实际明文长度
 * @return 0=成功
 */
int Proto_DecryptResponse(const HIDFrame *frame, const SessionCtx *sess,
                          uint8_t *out, uint32_t *out_len);

/**
 * @brief  计算 CRC-32 (与 STM32 固件一致)
 */
uint32_t Proto_CRC32(const uint8_t *data, uint32_t len);

/**
 * @brief  填充帧的 CRC 字段
 */
void Proto_FillCRC(HIDFrame *frame);

/**
 * @brief  验证帧的 CRC
 * @return 0=正确, 非0=CRC错误
 */
int Proto_VerifyCRC(const HIDFrame *frame);

/**
 * @brief  打印帧内容 (调试用)
 */
void Proto_DumpFrame(const char *label, const HIDFrame *frame);

/**
 * @brief  初始化会话上下文
 */
void Session_Init(SessionCtx *sess);

/**
 * @brief  销毁会话上下文 (安全清零)
 */
void Session_Destroy(SessionCtx *sess);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */
