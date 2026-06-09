/**
 * @file    Syscall/sec_core.c
 * @brief   安全核心模块实现 —— SHA-256 → HMAC-SHA256 → 挑战-应答 → 状态机
 */

#include "sec_core.h"
#include <string.h>

/*═════════════════════════════════════════════════════════════
 * 根密钥 (原型阶段硬编码, 量产写入 RDP Level 1/2 保护 Flash)
 *
 *   MK_CTRL: 密网控制鉴权密钥 (与 MasterTask.exe / MasterRecover.exe 共享)
 *   MK_DATA: 工控数据加解密密钥 (与 Agent.exe 共享)
 *
 *   ⚠️ 原型用固定值, 量产必须替换为随机生成的独立密钥
 *═════════════════════════════════════════════════════════════*/
static const uint8_t MK_CTRL[MK_CTRL_SIZE] = {
    0x4F, 0x3A, 0x91, 0x7C, 0xB2, 0xE8, 0x5D, 0x16,
    0x88, 0x2F, 0x4E, 0xA3, 0x71, 0x0B, 0xD9, 0x6C,
    0x55, 0xAC, 0x38, 0x1F, 0xE7, 0x9A, 0x42, 0x6B,
    0x0D, 0xC8, 0x94, 0x53, 0xFE, 0x27, 0x60, 0x19,
};

static const uint8_t MK_DATA[MK_DATA_SIZE] = {
    0x8B, 0x1C, 0x56, 0xEA, 0x3F, 0x70, 0xD2, 0x94,
    0x09, 0x4E, 0x17, 0xA6, 0xFD, 0x85, 0x23, 0x61,
    0xCC, 0x39, 0x7B, 0x0A, 0xE1, 0x58, 0x2D, 0x9F,
    0x46, 0x13, 0x80, 0xDC, 0x67, 0xB4, 0x35, 0xAA,
};

/*═════════════════════════════════════════════════════════════
 * 全局状态
 *═════════════════════════════════════════════════════════════*/
FerryState_t g_FerryState         = STATE_INIT;
uint8_t      g_NonceDev[16]       = {0};
uint8_t      g_SessionSK[SK_SIZE] = {0};
uint8_t      g_ChallengeFailCount = 0;

/*═════════════════════════════════════════════════════════════
 * SHA-256 原语 (FIPS 180-4)
 *═════════════════════════════════════════════════════════════*/

#define ROTR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR32(x, n)   ((x) >> (n))
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)      (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)      (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)      (ROTR32(x,  7) ^ ROTR32(x, 18) ^ SHR32(x,  3))
#define SSIG1(x)      (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR32(x, 10))

static const uint32_t K256[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

typedef struct {
    uint32_t  H[8];
    uint32_t  total_bits_hi;
    uint32_t  total_bits_lo;
    uint8_t   buf[64];
    uint8_t   buf_len;
    uint8_t   finalized;
} SHA256_CTX;

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *block)
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;
    int t;

    /* 前 16 个字直接来自 block (大端) */
    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t*4]   << 24) |
               ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] <<  8) |
               ((uint32_t)block[t*4+3]);
    }
    /* 扩展 48 个字 */
    for (t = 16; t < 64; t++) {
        W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
    }

    a = ctx->H[0]; b = ctx->H[1]; c = ctx->H[2]; d = ctx->H[3];
    e = ctx->H[4]; f = ctx->H[5]; g = ctx->H[6]; h = ctx->H[7];

    for (t = 0; t < 64; t++) {
        T1 = h + BSIG1(e) + CH(e,f,g) + K256[t] + W[t];
        T2 = BSIG0(a) + MAJ(a,b,c);
        h = g;  g = f;  f = e;  e = d + T1;
        d = c;  c = b;  b = a;  a = T1 + T2;
    }

    ctx->H[0] += a;  ctx->H[1] += b;  ctx->H[2] += c;  ctx->H[3] += d;
    ctx->H[4] += e;  ctx->H[5] += f;  ctx->H[6] += g;  ctx->H[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->H[0] = 0x6A09E667;  ctx->H[1] = 0xBB67AE85;
    ctx->H[2] = 0x3C6EF372;  ctx->H[3] = 0xA54FF53A;
    ctx->H[4] = 0x510E527F;  ctx->H[5] = 0x9B05688C;
    ctx->H[6] = 0x1F83D9AB;  ctx->H[7] = 0x5BE0CD19;
    ctx->total_bits_hi = 0;
    ctx->total_bits_lo = 0;
    ctx->buf_len = 0;
    ctx->finalized = 0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    uint64_t bits = (uint64_t)len * 8;

    ctx->total_bits_lo += (uint32_t)bits;
    if (ctx->total_bits_lo < (uint32_t)bits) {
        ctx->total_bits_hi++;
    }
    ctx->total_bits_hi += (uint32_t)(bits >> 32);

    for (i = 0; i < len; i++) {
        ctx->buf[ctx->buf_len++] = data[i];
        if (ctx->buf_len == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t *out)
{
    uint8_t pad[64];
    uint32_t pad_len, i;
    uint64_t total_bits;

    if (!ctx->finalized) {
        ctx->finalized = 1;

        /* 补位: 0x80 + 0x00 + 64-bit 长度 (大端) */
        pad[0] = 0x80;
        for (i = 1; i < 64; i++) pad[i] = 0x00;

        if (ctx->buf_len < 56) {
            pad_len = 56 - ctx->buf_len;
        } else {
            pad_len = 64 + 56 - ctx->buf_len;
        }
        sha256_update(ctx, pad, pad_len);

        /* 写入 64-bit 长度 (大端) */
        total_bits = ((uint64_t)ctx->total_bits_hi << 32) | ctx->total_bits_lo;
        pad[0] = (uint8_t)(total_bits >> 56);
        pad[1] = (uint8_t)(total_bits >> 48);
        pad[2] = (uint8_t)(total_bits >> 40);
        pad[3] = (uint8_t)(total_bits >> 32);
        pad[4] = (uint8_t)(total_bits >> 24);
        pad[5] = (uint8_t)(total_bits >> 16);
        pad[6] = (uint8_t)(total_bits >>  8);
        pad[7] = (uint8_t)(total_bits);
        sha256_update(ctx, pad, 8);
    }

    /* 输出 32 字节 (大端) */
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->H[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->H[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->H[i] >>  8);
        out[i*4+3] = (uint8_t)(ctx->H[i]);
    }
}

/*═════════════════════════════════════════════════════════════
 * HMAC-SHA256 (RFC 2104)
 *
 *   HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
 *
 *   其中 ipad = 0x36 重复 64 次, opad = 0x5C 重复 64 次
 *═════════════════════════════════════════════════════════════*/
void SecCore_HMAC_SHA256(const uint8_t *key, uint32_t key_len,
                         const uint8_t *data, uint32_t data_len,
                         uint8_t *out)
{
    uint8_t  k_ipad[64], k_opad[64];
    uint8_t  k_work[32];
    SHA256_CTX ctx;
    uint8_t  inner_hash[32];
    int i;

    /* 若 key 长于 64 字节, 先 hash 一次 */
    if (key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k_work);
        key = k_work;
        key_len = 32;
    }

    /* 构造 ipad / opad key */
    for (i = 0; i < 64; i++) {
        if (i < (int)key_len) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        } else {
            k_ipad[i] = 0x36;
            k_opad[i] = 0x5C;
        }
    }

    /* inner: H(k_ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    /* outer: H(k_opad || inner_hash) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out);
}

/*═════════════════════════════════════════════════════════════
 * 安全核心 API 实现
 *═════════════════════════════════════════════════════════════*/

void SecCore_Init(void)
{
    g_FerryState         = STATE_IDLE;
    g_ChallengeFailCount = 0;
    SecCore_MemZero(g_NonceDev, sizeof(g_NonceDev));
    SecCore_MemZero(g_SessionSK, sizeof(g_SessionSK));
}

/**
 * @brief  STM32 主动发起握手 —— USB 插入时调用
 *
 *         生成 nonce_s, 存入 g_NonceDev。
 *         STM32 随后应将 nonce_s 打包进 Hello 帧通过 USB 发送给主机。
 *
 *         握手时序:
 *           [STM32] 主动 ──Hello(Domain, g_NonceDev)──▶ [EXE]
 *           [STM32] 被动 ◀──Handshake(nonce_host, HMAC)── [EXE]
 *           [STM32] 主动 ──ACK──────────────────▶ [EXE]
 *
 *         后续 EXE 通过 USB 发送的 Handshake 数据由 Kernel_ReadShake
 *         (SVC 0x19) 接收并调用 SecCore_VerifyChallenge 验证。
 */
void SecCore_StartHandshake(void)
{
    /* 生成硬件随机 nonce_s (16 bytes), 将随 Hello 帧发送给主机 */
    SecCore_GenNonce(g_NonceDev);

    /* 清除上一次握手的会话密钥 */
    SecCore_MemZero(g_SessionSK, sizeof(g_SessionSK));
}

const uint8_t* SecCore_GetMK_CTRL(void)
{
    return MK_CTRL;
}

const uint8_t* SecCore_GetMK_DATA(void)
{
    return MK_DATA;
}

/**
 * @brief  生成 16 字节随机 nonce
 *         原型阶段: 混合 SysTick 计数器 + ADC (内部温度传感器) 噪声 LSB
 *         量产阶段: 替换为硬件 TRNG 或 RNG 外设
 */
void SecCore_GenNonce(uint8_t *nonce_out)
{
    volatile uint32_t mix = 0;
    int i;

    /* 熵源 1: SysTick 当前计数值 (持续递减, 低 8 位不可预测) */
    mix ^= SysTick->VAL;

    /* 熵源 2: 循环空转, 利用指令时序抖动 (编译器不可优化) */
    for (i = 0; i < 128; i++) {
        mix ^= (SysTick->VAL << (i & 0x0F));
        __NOP();
    }

    /* 展开为 16 字节 nonce (原型: 确定性扩展, 量产: 真随机源) */
    for (i = 0; i < 16; i++) {
        mix = (mix * 1103515245U + 12345U);  /* LCG 扰动 */
        nonce_out[i] = (uint8_t)((mix >> 16) ^ (mix & 0xFF));
    }
}

void SecCore_DeriveSK(const uint8_t *mk, const uint8_t *nonce_dev,
                      const uint8_t *nonce_host, uint8_t *sk_out)
{
    uint8_t combined[32];  /* nonce_dev(16) || nonce_host(16) */
    uint8_t hmac_out[HMAC_OUT_SIZE];

    /* 拼接 nonce_dev || nonce_host */
    SecCore_MemZero(combined, sizeof(combined));
    memcpy(combined, nonce_dev, 16);
    memcpy(combined + 16, nonce_host, 16);

    /* SK = HMAC-SHA256(MK, nonce_dev || nonce_host)[:16] */
    SecCore_HMAC_SHA256(mk, MK_CTRL_SIZE, combined, 32, hmac_out);
    memcpy(sk_out, hmac_out, SK_SIZE);

    /* 阅后即焚 */
    SecCore_MemZero(combined, sizeof(combined));
    SecCore_MemZero(hmac_out, sizeof(hmac_out));
}

/**
 * @brief  验证主机 Handshake 响应 (由 Kernel_ReadShake / selftest 调用)
 *
 *         握手由 STM32 主动发起:
 *           1. STM32 → SecCore_StartHandshake() → 生成 nonce_s
 *           2. STM32 ──Hello(nonce_s)──▶ EXE
 *           3. EXE → 生成 nonce_h, 计算 HMAC(MK, nonce_s || nonce_h)
 *           4. EXE ──Handshake(nonce_h, HMAC)──▶ STM32
 *           5. STM32 → 提取 nonce_h, 重算 HMAC, 比对, 派生 SK
 *
 *         challenge_buf 结构: nonce_h(16) || hmac_tag(32) = 48 字节
 *
 *         验证通过 → STATE_READ_ALLOW + 派生 g_SessionSK
 *         验证失败 → g_ChallengeFailCount++, ≥3 → PANIC
 */
uint8_t SecCore_VerifyChallenge(const uint8_t *challenge_buf, uint32_t challenge_len)
{
    uint8_t hmac_expected[HMAC_OUT_SIZE];
    uint8_t hmac_received[HMAC_OUT_SIZE];
    uint8_t nonce_h[16];
    uint8_t combined[32];         /* nonce_s(16) || nonce_h(16) */
    int i;

    /* 只允许 STATE_LOCK 状态下进行挑战 */
    if (g_FerryState != STATE_LOCK) {
        return 0xFF;
    }

    /* 挑战数据长度: 必须 >= 48 (nonce_h 16 + HMAC tag 32) */
    if (challenge_buf == NULL || challenge_len < 48) {
        goto fail;
    }

    /* 提取 nonce_h 和 HMAC tag */
    memcpy(nonce_h,       challenge_buf,      16);
    memcpy(hmac_received, challenge_buf + 16, 32);

    /* 拼接 nonce_s || nonce_h, 计算 expected HMAC */
    SecCore_MemZero(combined, sizeof(combined));
    memcpy(combined,       g_NonceDev, 16);
    memcpy(combined + 16,  nonce_h,    16);

    SecCore_HMAC_SHA256(MK_CTRL, MK_CTRL_SIZE,
                        combined, 32, hmac_expected);

    /* 恒定时间比对 32 字节 HMAC tag */
    {
        volatile uint8_t diff = 0;
        for (i = 0; i < 32; i++) {
            diff |= (hmac_expected[i] ^ hmac_received[i]);
        }
        SecCore_MemZero(hmac_expected, sizeof(hmac_expected));
        SecCore_MemZero(combined, sizeof(combined));

        if (diff != 0) {
            goto fail;
        }
    }

    /* ══════ 验证通过 ══════ */
    /* SK = HMAC-SHA256(MK_CTRL, nonce_s || nonce_h)[:16] */
    SecCore_DeriveSK(MK_CTRL, g_NonceDev, nonce_h, g_SessionSK);

    SecCore_MemZero(nonce_h, sizeof(nonce_h));
    SecCore_MemZero(hmac_received, sizeof(hmac_received));

    g_FerryState         = STATE_READ_ALLOW;
    g_ChallengeFailCount = 0;
    return 0;

fail:
    g_ChallengeFailCount++;
    if (g_ChallengeFailCount >= MAX_CHALLENGE_FAILS) {
        SecCore_Panic();
    }
    return 0xFF;
}

uint8_t SecCore_IsReadAllowed(void)
{
    return (g_FerryState == STATE_READ_ALLOW) ? 1 : 0;
}

void SecCore_Panic(void)
{
    g_FerryState = STATE_CORE_PANIC;

    /* 安全清除会话密钥和 nonce */
    SecCore_MemZero(g_SessionSK, sizeof(g_SessionSK));
    SecCore_MemZero(g_NonceDev, sizeof(g_NonceDev));

    /* 死锁: LED 红灯爆闪 (在 stm32f10x_it.c 中实现), 不再处理任何指令 */
}

/* memset_s: 安全内存清零 (volatile 防止编译器优化消除) */
void SecCore_MemZero(volatile void *buf, uint32_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}
