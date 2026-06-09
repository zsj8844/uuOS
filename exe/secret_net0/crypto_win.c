/**
 * @file    crypto_win.c
 * @brief   Windows BCrypt 加密封装实现
 *
 *          使用 BCrypt (CNG) API:
 *            - BCRYPT_SHA256_ALGORITHM  → HMAC-SHA256
 *            - BCRYPT_AES_ALGORITHM     → AES-128-GCM
 *            - BCRYPT_RNG_ALGORITHM     → 安全随机数
 *
 *          链接: -lbcrypt
 */

#include "crypto_win.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

/* 全局 provider 句柄 */
static BCRYPT_ALG_HANDLE g_hSha256   = NULL;
static BCRYPT_ALG_HANDLE g_hAesGcm   = NULL;
static BCRYPT_ALG_HANDLE g_hRng      = NULL;

/*══════════════════════════════════════════════════════════
 * 初始化 / 清理
 *══════════════════════════════════════════════════════════*/
int Crypto_Init(void)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&g_hSha256, BCRYPT_SHA256_ALGORITHM,
                                         NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider(SHA256) failed: 0x%08X\n", (unsigned)status);
        return -1;
    }

    status = BCryptOpenAlgorithmProvider(&g_hAesGcm, BCRYPT_AES_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider(AES) failed: 0x%08X\n", (unsigned)status);
        return -2;
    }
    /* 设置 GCM 链接模式 */
    status = BCryptSetProperty(g_hAesGcm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptSetProperty(GCM) failed: 0x%08X\n", (unsigned)status);
        return -3;
    }

    status = BCryptOpenAlgorithmProvider(&g_hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider(RNG) failed: 0x%08X\n", (unsigned)status);
        return -4;
    }

    printf("  [Crypto] BCrypt initialized (SHA256 + AES-GCM + RNG)\n");
    return 0;
}

void Crypto_Cleanup(void)
{
    if (g_hSha256) { BCryptCloseAlgorithmProvider(g_hSha256, 0); g_hSha256 = NULL; }
    if (g_hAesGcm) { BCryptCloseAlgorithmProvider(g_hAesGcm, 0); g_hAesGcm = NULL; }
    if (g_hRng)    { BCryptCloseAlgorithmProvider(g_hRng, 0);    g_hRng    = NULL; }
}

/*══════════════════════════════════════════════════════════
 * HMAC-SHA256
 *══════════════════════════════════════════════════════════*/
int Crypto_HMAC_SHA256(const uint8_t *key, uint32_t key_len,
                       const uint8_t *data, uint32_t data_len,
                       uint8_t *out)
{
    NTSTATUS status;
    BCRYPT_HASH_HANDLE hHash = NULL;

    status = BCryptCreateHash(g_hSha256, &hHash, NULL, 0,
                              (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptCreateHash(HMAC) failed: 0x%08X\n", (unsigned)status);
        return -1;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        return -2;
    }

    status = BCryptFinishHash(hHash, out, CRYPTO_SHA256_OUT, 0);
    BCryptDestroyHash(hHash);

    return BCRYPT_SUCCESS(status) ? 0 : -3;
}

/*══════════════════════════════════════════════════════════
 * AES-128-GCM 加密
 *
 * CT = IV(12B) || ciphertext || tag(16B)
 *══════════════════════════════════════════════════════════*/
int Crypto_AES_GCM_Encrypt(const uint8_t *key, uint32_t key_len,
                           const uint8_t *plaintext, uint32_t pt_len,
                           uint8_t *ciphertext, uint32_t *ct_len)
{
    NTSTATUS status;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t iv[CRYPTO_AES_GCM_IV];
    uint8_t tag[CRYPTO_AES_GCM_TAG];
    ULONG  cbResult = 0;
    uint32_t total_len;

    if (key_len != CRYPTO_AES128_KEY) return -1;

    /* 生成随机 IV */
    if (Crypto_Random(iv, sizeof(iv)) != 0) return -2;

    /* 导入 AES 密钥 */
    status = BCryptGenerateSymmetricKey(g_hAesGcm, &hKey, NULL, 0,
                                        (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenerateSymmetricKey failed: 0x%08X\n", (unsigned)status);
        return -3;
    }

    /* GCM 认证加密 */
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce        = iv;
        authInfo.cbNonce        = sizeof(iv);
        authInfo.pbTag          = tag;
        authInfo.cbTag          = sizeof(tag);

        status = BCryptEncrypt(hKey, (PUCHAR)plaintext, pt_len,
                               &authInfo, NULL, 0,
                               ciphertext + CRYPTO_AES_GCM_IV, pt_len,
                               &cbResult, 0);
    }

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptEncrypt(GCM) failed: 0x%08X\n", (unsigned)status);
        return -4;
    }

    /* 组装输出: IV || CT || TAG */
    memcpy(ciphertext, iv, CRYPTO_AES_GCM_IV);
    memcpy(ciphertext + CRYPTO_AES_GCM_IV + pt_len, tag, CRYPTO_AES_GCM_TAG);
    total_len = CRYPTO_AES_GCM_IV + pt_len + CRYPTO_AES_GCM_TAG;

    if (*ct_len < total_len) return -5;
    *ct_len = total_len;
    return 0;
}

/*══════════════════════════════════════════════════════════
 * AES-128-GCM 解密
 *══════════════════════════════════════════════════════════*/
int Crypto_AES_GCM_Decrypt(const uint8_t *key, uint32_t key_len,
                           const uint8_t *ciphertext, uint32_t ct_len,
                           uint8_t *plaintext, uint32_t *pt_len)
{
    NTSTATUS status;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG  cbResult = 0;
    uint32_t inner_ct_len;

    if (key_len != CRYPTO_AES128_KEY) return -1;
    if (ct_len < CRYPTO_AES_GCM_IV + CRYPTO_AES_GCM_TAG) return -2;

    inner_ct_len = ct_len - CRYPTO_AES_GCM_IV - CRYPTO_AES_GCM_TAG;

    /* 导入 AES 密钥 */
    status = BCryptGenerateSymmetricKey(g_hAesGcm, &hKey, NULL, 0,
                                        (PUCHAR)key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) return -3;

    /* GCM 认证解密 */
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce  = (PUCHAR)ciphertext;              /* IV 在头部 */
        authInfo.cbNonce  = CRYPTO_AES_GCM_IV;
        authInfo.pbTag    = (PUCHAR)(ciphertext + CRYPTO_AES_GCM_IV + inner_ct_len);
        authInfo.cbTag    = CRYPTO_AES_GCM_TAG;

        status = BCryptDecrypt(hKey,
                               (PUCHAR)(ciphertext + CRYPTO_AES_GCM_IV), inner_ct_len,
                               &authInfo, NULL, 0,
                               plaintext, *pt_len, &cbResult, 0);
    }

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptDecrypt(GCM) failed: 0x%08X (auth tag mismatch?)\n", (unsigned)status);
        return -4;
    }

    *pt_len = cbResult;
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 安全随机数
 *══════════════════════════════════════════════════════════*/
int Crypto_Random(uint8_t *buf, uint32_t len)
{
    NTSTATUS status = BCryptGenRandom(g_hRng, buf, len, 0);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
}

/*══════════════════════════════════════════════════════════
 * 安全内存清零
 *══════════════════════════════════════════════════════════*/
void Crypto_MemZero(volatile void *buf, uint32_t len)
{
    SecureZeroMemory((PVOID)buf, len);
}
