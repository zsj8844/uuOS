/**
 * @file    Syscall/aes_sw.h
 * @brief   AES-128 纯软件实现 (Cortex-M3 友好, ~600 字节 RAM)
 *
 *          ECB 模式逐块加解密. 无硬件加速依赖.
 *          仅提供 AES-128 (16 字节密钥), 不含 AES-256.
 */

#ifndef __AES_SW_H
#define __AES_SW_H

#include <stdint.h>

#define AES_BLOCK_SIZE  16
#define AES128_KEY_SIZE 16

/**
 * @brief  AES-128 加密单块 (16 字节)
 * @param  key: 16 字节密钥
 * @param  in:  16 字节明文输入
 * @param  out: 16 字节密文输出 (可与 in 相同)
 */
void aes128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out);

/**
 * @brief  AES-128 加密多块 (ECB 模式)
 * @param  key:    16 字节密钥
 * @param  in:     明文输入
 * @param  in_len: 输入长度 (自动补足到 16 的倍数, 最多 4096 字节)
 * @param  out:    密文输出 (可与 in 相同)
 * @return 输出长度 (含对齐填充)
 */
uint32_t aes128_encrypt(const uint8_t *key, const uint8_t *in,
                        uint32_t in_len, uint8_t *out);

#endif /* __AES_SW_H */
