/**
 * @file    crypto_win.h
 * @brief   Windows BCrypt 加密封装 —— HMAC-SHA256 + AES-128-GCM
 *
 *          使用 Windows 内置 CNG (Cryptography API: Next Generation),
 *          无需额外依赖 (无 OpenSSL, 无 mbedTLS)。
 *
 *          与 STM32 固件 sec_core.c 的 SHA-256/HMAC/AES-GCM 算法兼容。
 */

#ifndef CRYPTO_WIN_H
#define CRYPTO_WIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*══════════════════════════════════════════════════════════
 * 密钥和标签长度常量 (与固件 sec_core.h 一致)
 *══════════════════════════════════════════════════════════*/
#define CRYPTO_SHA256_OUT   32
#define CRYPTO_AES128_KEY   16
#define CRYPTO_AES_GCM_IV   12
#define CRYPTO_AES_GCM_TAG  16

/*══════════════════════════════════════════════════════════
 * API
 *══════════════════════════════════════════════════════════*/

/**
 * @brief  初始化加密模块 (加载 BCrypt provider)
 * @return 0=成功
 */
int Crypto_Init(void);

/**
 * @brief  清理加密模块
 */
void Crypto_Cleanup(void);

/**
 * @brief  HMAC-SHA256 计算
 * @param  key:       密钥
 * @param  key_len:   密钥长度 (字节)
 * @param  data:      消息
 * @param  data_len:  消息长度
 * @param  out:       输出 (32 字节)
 * @return 0=成功
 */
int Crypto_HMAC_SHA256(const uint8_t *key, uint32_t key_len,
                       const uint8_t *data, uint32_t data_len,
                       uint8_t *out);

/**
 * @brief  AES-128-GCM 加密
 * @param  key:       密钥 (16 字节)
 * @param  key_len:   密钥长度 (必须为 16)
 * @param  plaintext: 明文
 * @param  pt_len:    明文长度
 * @param  ciphertext: 密文输出 (长度 = pt_len + 16 tag)
 * @param  ct_len:    输出: 实际密文长度
 * @return 0=成功
 *
 * 密文格式: IV(12B) || ciphertext(pt_len) || tag(16B)
 */
int Crypto_AES_GCM_Encrypt(const uint8_t *key, uint32_t key_len,
                           const uint8_t *plaintext, uint32_t pt_len,
                           uint8_t *ciphertext, uint32_t *ct_len);

/**
 * @brief  AES-128-GCM 解密
 * @param  key:       密钥 (16 字节)
 * @param  key_len:   密钥长度 (必须为 16)
 * @param  ciphertext: 密文 (格式: IV || ct || tag)
 * @param  ct_len:    密文长度
 * @param  plaintext: 明文输出
 * @param  pt_len:    输出: 实际明文长度
 * @return 0=成功
 */
int Crypto_AES_GCM_Decrypt(const uint8_t *key, uint32_t key_len,
                           const uint8_t *ciphertext, uint32_t ct_len,
                           uint8_t *plaintext, uint32_t *pt_len);

/**
 * @brief  生成密码学安全随机数
 * @param  buf: 输出缓冲区
 * @param  len: 字节数
 * @return 0=成功
 */
int Crypto_Random(uint8_t *buf, uint32_t len);

/**
 * @brief  安全内存清零
 */
void Crypto_MemZero(volatile void *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_WIN_H */
