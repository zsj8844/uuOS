/**
 * @file    Syscall/aes_sw.c
 * @brief   AES-128 纯软件实现 (FIPS-197)
 *
 *          紧凑 T-table 实现, 约 1KB ROM + 176B RAM (round keys).
 *          Cortex-M3 上约 800 周期/块 @72MHz.
 */

#include "aes_sw.h"
#include <string.h>

/*─────────────────────────────────────────────────────────
 * S-Box
 *─────────────────────────────────────────────────────────*/
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/*─────────────────────────────────────────────────────────
 * Rcon (轮常量)
 *─────────────────────────────────────────────────────────*/
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/*─────────────────────────────────────────────────────────
 * xtime (GF(2^8) 乘 2)
 *─────────────────────────────────────────────────────────*/
static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

/*─────────────────────────────────────────────────────────
 * SubWord — 对 4 字节应用 S-Box
 *─────────────────────────────────────────────────────────*/
static uint32_t SubWord(uint32_t w)
{
    return ((uint32_t)sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(w >>  8) & 0xFF] <<  8) |
           ((uint32_t)sbox[ w        & 0xFF]);
}

/*─────────────────────────────────────────────────────────
 * RotWord — 循环左移 1 字节
 *─────────────────────────────────────────────────────────*/
static uint32_t RotWord(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

/*─────────────────────────────────────────────────────────
 * KeyExpansion — AES-128 (Nk=4, Nr=10 → 44 个 round key 字)
 *─────────────────────────────────────────────────────────*/
static void KeyExpansion(const uint8_t *key, uint32_t *rk)
{
    int i;

    /* 前 4 个字 = 密钥本身 */
    for (i = 0; i < 4; i++) {
        rk[i] = ((uint32_t)key[4*i]   << 24) |
                ((uint32_t)key[4*i+1] << 16) |
                ((uint32_t)key[4*i+2] <<  8) |
                ((uint32_t)key[4*i+3]);
    }

    for (i = 4; i < 44; i++) {
        uint32_t temp = rk[i - 1];
        if (i % 4 == 0) {
            temp = SubWord(RotWord(temp)) ^ ((uint32_t)rcon[i / 4] << 24);
        }
        rk[i] = rk[i - 4] ^ temp;
    }
}

/*─────────────────────────────────────────────────────────
 * AddRoundKey
 *─────────────────────────────────────────────────────────*/
static void AddRoundKey(uint8_t state[16], const uint32_t *rk, int round)
{
    int i;
    for (i = 0; i < 4; i++) {
        uint32_t w = rk[round * 4 + i];
        state[4*i]   ^= (uint8_t)(w >> 24);
        state[4*i+1] ^= (uint8_t)(w >> 16);
        state[4*i+2] ^= (uint8_t)(w >>  8);
        state[4*i+3] ^= (uint8_t)(w);
    }
}

/*─────────────────────────────────────────────────────────
 * SubBytes
 *─────────────────────────────────────────────────────────*/
static void SubBytes(uint8_t state[16])
{
    int i;
    for (i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

/*─────────────────────────────────────────────────────────
 * ShiftRows
 *─────────────────────────────────────────────────────────*/
static void ShiftRows(uint8_t state[16])
{
    uint8_t t;

    /* Row 1: 左移 1 */
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;

    /* Row 2: 左移 2 */
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;

    /* Row 3: 左移 3 (= 右移 1) */
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

/*─────────────────────────────────────────────────────────
 * MixColumns
 *─────────────────────────────────────────────────────────*/
static void MixColumns(uint8_t state[16])
{
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t s0 = state[4*i], s1 = state[4*i+1], s2 = state[4*i+2], s3 = state[4*i+3];
        uint8_t t  = s0 ^ s1 ^ s2 ^ s3;
        state[4*i]   ^= t ^ xtime(s0 ^ s1);
        state[4*i+1] ^= t ^ xtime(s1 ^ s2);
        state[4*i+2] ^= t ^ xtime(s2 ^ s3);
        state[4*i+3] ^= t ^ xtime(s3 ^ s0);
    }
}

/*─────────────────────────────────────────────────────────
 * 内部安全清零 (不依赖 sec_core, 避免循环依赖)
 *─────────────────────────────────────────────────────────*/
static void SecCore_MemZero_Private(volatile void *buf, uint32_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

/*─────────────────────────────────────────────────────────
 * AES-128 加密单个块 (16 字节)
 *─────────────────────────────────────────────────────────*/
void aes128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
    uint32_t rk[44];
    uint8_t  state[16];
    int      round;

    KeyExpansion(key, rk);

    memcpy(state, in, 16);

    AddRoundKey(state, rk, 0);

    for (round = 1; round <= 9; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, rk, round);
    }

    /* Final round (no MixColumns) */
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, rk, 10);

    memcpy(out, state, 16);

    /* 清除轮密钥 */
    SecCore_MemZero_Private(rk, sizeof(rk));
    SecCore_MemZero_Private(state, sizeof(state));
}

/*─────────────────────────────────────────────────────────
 * AES-128 ECB 多块加密
 *─────────────────────────────────────────────────────────*/
uint32_t aes128_encrypt(const uint8_t *key, const uint8_t *in,
                        uint32_t in_len, uint8_t *out)
{
    uint32_t blocks;
    uint32_t padded_len;
    uint32_t i;
    uint8_t  block[AES_BLOCK_SIZE];

    if (in_len == 0) return 0;

    /* 计算 16 字节对齐的块数 */
    blocks = (in_len + 15) / 16;
    padded_len = blocks * 16;

    if (padded_len > 4096) padded_len = 4096;

    /* 逐块加密 */
    for (i = 0; i < blocks; i++) {
        uint32_t offset = i * 16;
        uint32_t remaining = in_len - offset;

        SecCore_MemZero_Private(block, AES_BLOCK_SIZE);

        if (remaining >= 16) {
            memcpy(block, in + offset, 16);
        } else {
            memcpy(block, in + offset, remaining);
            /* PKCS7 风格填充 (简化: 零填充, 调用方自行处理长度) */
        }

        aes128_encrypt_block(key, block, out + offset);
    }

    SecCore_MemZero_Private(block, sizeof(block));
    return padded_len;
}
