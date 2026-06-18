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
 * RAM 扇区缓冲区 (SD 卡到位后替换为 sd_raw_read/write_sector)
 *═════════════════════════════════════════════════════════════*/
uint8_t  g_SectorTask[SECTOR_SIZE]                          = {0};
uint8_t  g_SectorData[SECTOR_SIZE * SECTOR_DATA_MAX]        = {0};
uint32_t g_DataWriteLen                                     = 0;
uint8_t  g_ReadOutBuf[SECTOR_SIZE]                          = {0};

/*═════════════════════════════════════════════════════════════
 * SHA-256 原语 (FIPS 180-4) — 使用 uint64_t 计数器
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
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
    0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
    0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
    0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
    0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
    0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
    0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
    0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
    0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
};

typedef struct {
    uint32_t H[8];
    uint64_t total;       /* 总比特数 (换成 uint64_t 避免 hi/lo 操作) */
    uint8_t  buf[64];
    uint8_t  buf_len;
} SHA256_CTX;

static void sha256_transform(uint32_t H[8], const uint8_t block[64])
{
    uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
    int t;

    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t*4]<<24) | ((uint32_t)block[t*4+1]<<16) |
               ((uint32_t)block[t*4+2]<<8)  |  (uint32_t)block[t*4+3];
    }
    for (t = 16; t < 64; t++) {
        W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
    }

    a=H[0]; b=H[1]; c=H[2]; d=H[3]; e=H[4]; f=H[5]; g=H[6]; h=H[7];

    for (t = 0; t < 64; t++) {
        T1 = h + BSIG1(e) + CH(e,f,g) + K256[t] + W[t];
        T2 = BSIG0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }

    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->H[0]=0x6A09E667; ctx->H[1]=0xBB67AE85; ctx->H[2]=0x3C6EF372; ctx->H[3]=0xA54FF53A;
    ctx->H[4]=0x510E527F; ctx->H[5]=0x9B05688C; ctx->H[6]=0x1F83D9AB; ctx->H[7]=0x5BE0CD19;
    ctx->total=0; ctx->buf_len=0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    ctx->total += (uint64_t)len * 8;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->buf_len++] = data[i];
        if (ctx->buf_len == 64) {
            sha256_transform(ctx->H, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t out[32])
{
    uint64_t msg_bits = ctx->total;   /* save BEFORE padding */
    uint8_t  pad;
    uint32_t i;

    /* Append 0x80 */
    pad = 0x80;
    sha256_update(ctx, &pad, 1);

    /* Pad with zeros until (total_bytes % 64) == 56 */
    while (ctx->buf_len != 56) {
        pad = 0x00;
        sha256_update(ctx, &pad, 1);
    }

    /* Append 64-bit message length in big-endian */
    for (i = 0; i < 8; i++) {
        pad = (uint8_t)(msg_bits >> (56 - i*8));
        sha256_update(ctx, &pad, 1);
    }
    /* buf_len should now be 0 (just processed last block) */

    /* Output in big-endian */
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->H[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->H[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->H[i] >>  8);
        out[i*4+3] = (uint8_t)(ctx->H[i]);
    }
}

/* 便捷函数: 一次性 SHA-256 + 自测 */
void sha256_direct(const uint8_t *data, uint32_t len, uint8_t out[32])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);

    /* 如果输入是 "abc" → 板载 LED 自测 */
    if (len == 3 && data[0]=='a' && data[1]=='b' && data[2]=='c') {
        const uint8_t exp[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        volatile uint8_t diff = 0;
        int i;
        for (i = 0; i < 32; i++) diff |= out[i] ^ exp[i];

        /* 初始化 PC13 (防止 GPIO 未配) */
        RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
        {
            GPIO_InitTypeDef g;
            g.GPIO_Pin   = GPIO_Pin_13;
            g.GPIO_Mode  = GPIO_Mode_Out_PP;
            g.GPIO_Speed = GPIO_Speed_2MHz;
            GPIO_Init(GPIOC, &g);
            GPIOC->BSRR = GPIO_Pin_13;  /* 灭 */
        }

        if (diff == 0) {
            /* SHA256 通过 → 闪 3 下 */
            for (int b = 0; b < 3; b++) {
                GPIOC->BRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<1440000;x++)__NOP();
                GPIOC->BSRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<720000;x++)__NOP();
            }
        } else {
            /* SHA256 失败 → 闪第 1 字节高 4 位次数 */
            uint8_t nibble = out[0] >> 4;
            if (nibble == 0) nibble = 1;
            for (int b = 0; b < (int)nibble; b++) {
                GPIOC->BRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<360000;x++)__NOP();
                GPIOC->BSRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<180000;x++)__NOP();
            }
            for(volatile uint32_t x=0;x<7200000;x++)__NOP(); /* 等 1 秒 */
        }
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

    /* HMAC 自测: key=0x0b*20, data="Hi There" → RFC 4231 TC1 */
    if (key_len == 20 && data_len == 8 && key[0] == 0x0b && key[1] == 0x0b
        && data[0] == 'H' && data[1] == 'i') {
        /* 正常计算, 但验证结果 */
    }

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

    /* HMAC 自测验证 */
    if (key_len == 20 && data_len == 8 && key[0] == 0x0b
        && data[0] == 'H' && data[1] == 'i') {
        const uint8_t exp[32] = {
            0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
            0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
            0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
            0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
        };
        volatile uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= out[i] ^ exp[i];
        if (diff == 0) {
            /* HMAC 通过: 在 SHA256 测试后额外闪 3 下快闪 */
            for (int b = 0; b < 3; b++) {
                GPIOC->BRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<360000;x++)__NOP();
                GPIOC->BSRR = GPIO_Pin_13;
                for(volatile uint32_t x=0;x<360000;x++)__NOP();
            }
        }
    }
}

/*═════════════════════════════════════════════════════════════
 * 安全核心 API 实现
 *═════════════════════════════════════════════════════════════*/

void SecCore_Init(void)
{
    g_FerryState         = STATE_INIT;  /* 绿灯 — 就绪 */
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
 *
 *          熵源:
 *            1. SysTick 计数器低 8 位 (持续递减, 不可预测)
 *            2. CPU 指令时序抖动 (编译器不可优化)
 *            3. ADC 内部温度传感器噪声 LSB
 *
 *          STM32F103 无硬件 TRNG, 但三源混合后经 LCG 扩展,
 *          每次上电 nonce 不同, 满足原型阶段安全需求。
 */
static int g_adc_noise_inited = 0;

void SecCore_GenNonce(uint8_t *nonce_out)
{
    volatile uint32_t mix = 0;
    int i;

    /* ── 熵源 1: SysTick ── */
    mix ^= SysTick->VAL;

    /* ── 熵源 2: 指令时序抖动 ── */
    for (i = 0; i < 128; i++) {
        mix ^= (SysTick->VAL << (i & 0x0F));
        __NOP();
    }

    /* ── 熵源 3: ADC 内部温度传感器噪声 (首次调用时初始化) ── */
    if (!g_adc_noise_inited) {
        g_adc_noise_inited = 1;

        /* 使能 ADC1 + 内部温度传感器 */
        RCC_APB2PeriphClockCmd(RCC_APB2Periph_ADC1, ENABLE);
        ADC_TempSensorVrefintCmd(ENABLE);

        /* ADC1 基础配置 */
        ADC_InitTypeDef adc;
        ADC_StructInit(&adc);
        adc.ADC_Mode = ADC_Mode_Independent;
        adc.ADC_ScanConvMode = DISABLE;
        adc.ADC_ContinuousConvMode = DISABLE;
        adc.ADC_ExternalTrigConv = ADC_ExternalTrigConv_None;
        adc.ADC_DataAlign = ADC_DataAlign_Right;
        adc.ADC_NbrOfChannel = 1;
        ADC_Init(ADC1, &adc);

        /* 校准 ADC */
        ADC_Cmd(ADC1, ENABLE);
        ADC_ResetCalibration(ADC1);
        while (ADC_GetResetCalibrationStatus(ADC1));
        ADC_StartCalibration(ADC1);
        while (ADC_GetCalibrationStatus(ADC1));
    }

    /* 采样温度传感器通道 (ADC1_CH16), 取 LSB 噪声混合 */
    ADC_RegularChannelConfig(ADC1, ADC_Channel_16, 1, ADC_SampleTime_239Cycles5);
    ADC_SoftwareStartConvCmd(ADC1, ENABLE);
    while (!ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC));
    mix ^= ADC_GetConversionValue(ADC1) & 0x0FFF;

    /* ── LCG 扩展为 16 字节 nonce ── */
    for (i = 0; i < 16; i++) {
        mix = (mix * 1103515245U + 12345U);
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
/**
 * @brief  通用 HMAC 挑战-应答验证 (可指定密钥)
 *
 *         challenge_buf: nonce_h(16) || HMAC(32) = 48 bytes
 *         验证通过 → STATE_READ_ALLOW + 派生 g_SessionSK
 *         验证失败 → g_ChallengeFailCount++, ≥3 → STATE_CORE_PANIC
 */
uint8_t SecCore_VerifyHandshake(const uint8_t *challenge_buf,
                                uint32_t challenge_len,
                                const uint8_t *mk, uint32_t mk_len)
{
    uint8_t hmac_expected[HMAC_OUT_SIZE];
    uint8_t hmac_received[HMAC_OUT_SIZE];
    uint8_t nonce_h[16];
    uint8_t combined[32];
    int i;

    if (g_FerryState == STATE_CORE_PANIC) return 0xFF;
    if (challenge_buf == NULL || challenge_len < 48) goto fail;

    memcpy(nonce_h,       challenge_buf,      16);
    memcpy(hmac_received, challenge_buf + 16, 32);

    SecCore_MemZero(combined, sizeof(combined));
    memcpy(combined,       g_NonceDev, 16);
    memcpy(combined + 16,  nonce_h,    16);

    SecCore_HMAC_SHA256(mk, mk_len, combined, 32, hmac_expected);

    {
        volatile uint8_t diff = 0;
        for (i = 0; i < 32; i++) diff |= (hmac_expected[i] ^ hmac_received[i]);
        SecCore_MemZero(hmac_expected, sizeof(hmac_expected));
        SecCore_MemZero(combined, sizeof(combined));
        if (diff != 0) goto fail;
    }

    SecCore_DeriveSK(mk, g_NonceDev, nonce_h, g_SessionSK);
    SecCore_MemZero(nonce_h, sizeof(nonce_h));
    SecCore_MemZero(hmac_received, sizeof(hmac_received));

    g_ChallengeFailCount = 0;
    return 0;

fail:
    g_ChallengeFailCount++;
    if (g_ChallengeFailCount >= MAX_CHALLENGE_FAILS) SecCore_Panic();
    return 0xFF;
}

uint8_t SecCore_VerifyChallenge(const uint8_t *challenge_buf, uint32_t challenge_len)
{
    return SecCore_VerifyHandshake(challenge_buf, challenge_len,
                                   MK_CTRL, MK_CTRL_SIZE);
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

/*═════════════════════════════════════════════════════════════
 * 状态机铁闸 — 命令级访问控制
 *═════════════════════════════════════════════════════════════*/

/**
 * @brief  检查当前状态是否允许执行指定 SVC 命令
 * @return 0=允许, 1=拒绝(状态不符), 2=PANIC绝拒绝一切
 */
uint8_t SecCore_AuditSVC(uint8_t svc_id)
{
    /* PANIC 态拒绝一切 */
    if (g_FerryState == STATE_CORE_PANIC) return 2;

    switch (svc_id) {
        /* 实用 SVC — 始终允许 */
        case 0x01: /* GPIO_Set   */
        case 0x02: /* GPIO_Reset */
        case 0x03: /* DelayMs    */
            return 0;

        /* WriteTask (0x10) — 仅 STATE_INIT 或 STATE_IDLE */
        case 0x10:
            if (g_FerryState == STATE_INIT || g_FerryState == STATE_IDLE)
                return 0;
            break;

        /* ReadTask (0x11) / WriteData (0x12) — STATE_ASSIGNED或累积态 */
        case 0x11:
        case 0x12:
            if (g_FerryState == STATE_ASSIGNED ||
                g_FerryState == STATE_PULLING ||
                g_FerryState == STATE_READ_ALLOW)
                return 0;
            break;

        /* ReadShake (0x19) — 非 PANIC 均可 (握手挑战) */
        case 0x19:
            return 0;

        /* ReadData (0x1A) — 仅 STATE_READ_ALLOW */
        case 0x1A:
            if (g_FerryState == STATE_READ_ALLOW)
                return 0;
            break;

        default:
            break;
    }
    return 1; /* 状态不符合 */
}

/**
 * @brief  构建审计 NACK 帧载荷
 *         格式: [当前状态(1B)] [被拒绝的SVC号(1B)]
 */
uint8_t SecCore_BuildAuditNACK(uint8_t *out)
{
    out[0] = (uint8_t)g_FerryState;
    out[1] = 0xFF; /* 调用者回填 svc_id */
    return 2;
}
