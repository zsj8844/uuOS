/**
 * @file    Syscall/sec_core.h
 * @brief   安全核心模块 —— HMAC 挑战-应答 + 全局状态机 + 根密钥存储
 *
 *          参照 文档管理/设计文档3.md 和 文档管理/exe设计.md:
 *            - HMAC-SHA256 挑战-应答握手
 *            - 会话密钥 SK 派生
 *            - 状态机 STATE_LOCK → STATE_READ_ALLOW → STATE_CORE_PANIC
 */

#ifndef __SEC_CORE_H
#define __SEC_CORE_H

#include "stm32f10x.h"

/*═════════════════════════════════════════════════════════════
 * 全局状态机 (FerryState_t)
 *═════════════════════════════════════════════════════════════*/
typedef enum {
    STATE_INIT        = 0,  /* 硬件自检, 蓝灯常亮 */
    STATE_IDLE        = 1,  /* 空闲等待任务, 蓝灯慢闪 */
    STATE_ASSIGNED    = 2,  /* 任务已注入, 绿灯慢闪 */
    STATE_PULLING     = 3,  /* 加密吸数中, 蓝绿交替爆闪 */
    STATE_LOCK        = 4,  /* 数据封仓, 黄灯常亮 */
    STATE_READ_ALLOW  = 5,  /* 回读解锁, 绿灯爆闪 */
    STATE_CORE_PANIC  = 6,  /* 死锁自毁, 红灯爆闪 */
} FerryState_t;

/*═════════════════════════════════════════════════════════════
 * 密钥与握手常量
 *═════════════════════════════════════════════════════════════*/

/* 预共享根密钥 (原型阶段硬编码, 量产写入 RDP 保护 Flash) */
#define MK_CTRL_SIZE  32   /* HMAC-SHA256 密钥 = 32 字节 */
#define MK_DATA_SIZE  32
#define HMAC_OUT_SIZE 32   /* HMAC-SHA256 输出 = 32 字节 */
#define SK_SIZE       16   /* 会话密钥 = AES-128 = 16 字节 */

/* 挑战失败上限 */
#define MAX_CHALLENGE_FAILS  3

/*═════════════════════════════════════════════════════════════
 * 全局状态
 *═════════════════════════════════════════════════════════════*/
extern FerryState_t g_FerryState;                     /* 当前状态机状态 */
extern uint8_t      g_NonceDev[16];                   /* STM32 生成的随机 nonce */
extern uint8_t      g_SessionSK[SK_SIZE];             /* 派生的会话密钥 SK1/SK1' */
extern uint8_t      g_ChallengeFailCount;             /* 累计挑战失败次数 */

/*═════════════════════════════════════════════════════════════
 * 安全核心 API
 *═════════════════════════════════════════════════════════════*/

/**
 * @brief  安全核心初始化 (在特权态阶段调用)
 *         初始化状态机为 STATE_IDLE
 */
void SecCore_Init(void);

/**
 * @brief  STM32 主动发起握手 (USB 插入时由固件调用)
 *
 *         此函数由 STM32 固件在检测到 USB 插入后调用,
 *         生成 nonce_s 并准备通过 USB 发送 Hello 帧。
 *
 *         时序 (参照 文档管理/设计文档3.md §2):
 *           [STM32] ──Hello(Domain, nonce_s)──▶ [EXE]
 *           [STM32] ◀──Handshake(nonce_h, HMAC)── [EXE]
 *           [STM32] ──ACK──────────────────▶ [EXE]
 *
 *         nonce_s 存入 g_NonceDev, 后续由 EXE 通过 USB 读取,
 *         EXE 计算 HMAC(MK, nonce_s || nonce_h) 回复 Handshake,
 *         STM32 收到后调用 SecCore_VerifyChallenge() 验证。
 */
void SecCore_StartHandshake(void);

/**
 * @brief  获取 MK_CTRL 根密钥指针 (内部使用, 不可外泄)
 * @return 指向 32 字节 MK_CTRL 的只读指针
 */
const uint8_t* SecCore_GetMK_CTRL(void);

/**
 * @brief  获取 MK_DATA 根密钥指针
 */
const uint8_t* SecCore_GetMK_DATA(void);

/**
 * @brief  生成 16 字节硬件随机 nonce
 *         原型阶段: 使用 SysTick + ADC 噪声 LSB 混合
 *         量产阶段: 使用硬件 TRNG (若芯片支持)
 */
void SecCore_GenNonce(uint8_t *nonce_out);

/**
 * @brief  HMAC-SHA256 计算
 * @param  key:   密钥指针
 * @param  key_len: 密钥长度 (字节)
 * @param  data:  消息指针
 * @param  data_len: 消息长度 (字节)
 * @param  out:   输出缓冲区 (32 字节)
 */
void SecCore_HMAC_SHA256(const uint8_t *key, uint32_t key_len,
                         const uint8_t *data, uint32_t data_len,
                         uint8_t *out);

/**
 * @brief  验证密网挑战码 (由 Kernel_ReadShake 调用)
 * @param  challenge_buf: 主机发来的 HMAC 响应 (32 字节)
 * @param  challenge_len: 实际长度
 * @return 0 = 验证通过, 非 0 = 验证失败
 *
 * 流程:
 *   1. g_NonceDev 已在握手阶段生成
 *   2. expected = HMAC-SHA256(MK_CTRL, g_NonceDev || challenge_buf)
 *   3. 若主机持有 MK_CTRL, 则其发送的 HMAC 应与 expected 一致
 *   4. 验证通过 → STATE_READ_ALLOW
 *   5. 验证失败 → g_ChallengeFailCount++, ≥3 次 → STATE_CORE_PANIC
 */
uint8_t SecCore_VerifyChallenge(const uint8_t *challenge_buf, uint32_t challenge_len);

/**
 * @brief  派生会话密钥 SK
 *         SK = HMAC-SHA256(MK, nonce_dev || nonce_host)[:16]
 *         取前 16 字节作为 AES-128 密钥
 */
void SecCore_DeriveSK(const uint8_t *mk, const uint8_t *nonce_dev,
                      const uint8_t *nonce_host, uint8_t *sk_out);

/**
 * @brief  检查当前状态是否允许数据回读 (由 Kernel_ReadData 门控)
 * @return 1 = 允许, 0 = 拒绝
 */
uint8_t SecCore_IsReadAllowed(void);

/**
 * @brief  触发 PANIC: 清空 SK, 状态锁死, LED 红灯爆闪
 */
void SecCore_Panic(void);

/**
 * @brief  memset_s —— 安全内存清零 (防止编译器优化掉)
 */
void SecCore_MemZero(volatile void *buf, uint32_t len);

#endif /* __SEC_CORE_H */
