/**
 * @file    protocol.c
 * @brief   协议层: 帧构建/解析, HMAC 握手, AES-GCM 加解密
 *
 *          串口帧载荷:
 *            Hello:     Domain(1B) + nonce_s(16B) = 17B
 *            Handshake: nonce_h(16B) + HMAC(32B)   = 48B
 *            ACK:       status(1B)                 = 1B
 *            WriteTask: AES-GCM 密文 (变长)
 */

#include "protocol.h"
#include "crypto_win.h"
#include <stdio.h>
#include <string.h>

/*══════════════════════════════════════════════════════════
 * 会话管理
 *══════════════════════════════════════════════════════════*/
void Session_Init(SessionCtx *sess)
{
    memset(sess, 0, sizeof(*sess));
    sess->state = HS_WAIT_HELLO;
}

void Session_Destroy(SessionCtx *sess)
{
    volatile uint8_t *p = (volatile uint8_t *)sess;
    for (size_t i = 0; i < sizeof(*sess); i++) p[i] = 0;
}

/*══════════════════════════════════════════════════════════
 * Hello 帧解析
 *
 *   载荷格式: Domain(1) || nonce_s(16) = 17 bytes
 *══════════════════════════════════════════════════════════*/
int Proto_ParseHello(const uint8_t *data, uint8_t len, SessionCtx *sess)
{
    if (len < NONCE_SIZE) {
        fprintf(stderr, "  [Proto] Hello payload too short: %u bytes (need %u)\n",
                len, NONCE_SIZE);
        return -1;
    }

    /* 提取 nonce_s (STM32 不再发 domain, 域由 Handshake HMAC 密钥自动识别) */
    memcpy(sess->nonce_s, data, NONCE_SIZE);
    sess->state = HS_WAIT_HELLO;

    printf("  [Proto] Hello received: nonce_s=");
    for (int i = 0; i < 8; i++) printf("%02X", sess->nonce_s[i]);
    printf("...\n");

    return 0;
}

/*══════════════════════════════════════════════════════════
 * Handshake 帧构建
 *
 *   载荷格式: nonce_h(16) || HMAC(32) = 48 bytes
 *   HMAC = HMAC-SHA256(MK_CTRL, nonce_s || nonce_h)
 *══════════════════════════════════════════════════════════*/
int Proto_BuildHandshake(uint8_t *data, uint8_t *out_len,
                         const SessionCtx *sess, const uint8_t *mk_ctrl)
{
    uint8_t combined[2 * NONCE_SIZE];
    uint8_t hmac_tag[HMAC_TAG_SIZE];

    /* 拼接 nonce_s || nonce_h */
    memcpy(combined, sess->nonce_s, NONCE_SIZE);
    memcpy(combined + NONCE_SIZE, sess->nonce_h, NONCE_SIZE);

    /* HMAC-SHA256(MK_CTRL, nonce_s || nonce_h) */
    if (Crypto_HMAC_SHA256(mk_ctrl, 32, combined, sizeof(combined), hmac_tag) != 0) {
        fprintf(stderr, "  [Proto] HMAC computation failed\n");
        return -1;
    }

    /* 构建载荷: nonce_h || HMAC */
    memcpy(data, sess->nonce_h, NONCE_SIZE);
    memcpy(data + NONCE_SIZE, hmac_tag, HMAC_TAG_SIZE);
    *out_len = NONCE_SIZE + HMAC_TAG_SIZE;  /* 48 */

    printf("  [Proto] Handshake built: nonce_h=");
    for (int i = 0; i < 8; i++) printf("%02X", sess->nonce_h[i]);
    printf("..., HMAC=");
    for (int i = 0; i < 8; i++) printf("%02X", hmac_tag[i]);
    printf("...\n");

    memset(combined, 0, sizeof(combined));
    memset(hmac_tag, 0, sizeof(hmac_tag));

    return 0;
}

/*══════════════════════════════════════════════════════════
 * ACK 帧解析
 *
 *   载荷格式: status(1) — 0x01=OK, 其他=失败
 *══════════════════════════════════════════════════════════*/
int Proto_ParseAck(const uint8_t *data, uint8_t len)
{
    if (len < 1) return -1;

    if (data[0] == 0x01) {
        printf("  [Proto] ACK received (OK)\n");
        return 0;
    }
    printf("  [Proto] NACK received (status=0x%02X, handshake rejected)\n", data[0]);
    return -1;
}

/*══════════════════════════════════════════════════════════
 * 派生会话密钥 SK1
 *
 *   SK1 = HMAC-SHA256(MK_CTRL, nonce_s || nonce_h)[:16]
 *══════════════════════════════════════════════════════════*/
int Proto_DeriveSK(SessionCtx *sess, const uint8_t *mk_ctrl)
{
    uint8_t combined[2 * NONCE_SIZE];
    uint8_t hmac_out[HMAC_TAG_SIZE];

    memcpy(combined, sess->nonce_s, NONCE_SIZE);
    memcpy(combined + NONCE_SIZE, sess->nonce_h, NONCE_SIZE);

    if (Crypto_HMAC_SHA256(mk_ctrl, 32, combined, sizeof(combined), hmac_out) != 0) {
        return -1;
    }

    /* SK1 = HMAC output 前 16 字节 */
    memcpy(sess->sk, hmac_out, SK_SIZE);

    memset(combined, 0, sizeof(combined));
    memset(hmac_out, 0, sizeof(hmac_out));

    sess->state = HS_ESTABLISHED;

    printf("  [Proto] SK1 derived: ");
    for (int i = 0; i < 8; i++) printf("%02X", sess->sk[i]);
    printf("...\n");

    return 0;
}

/*══════════════════════════════════════════════════════════
 * 构建加密命令帧载荷
 *
 *   payload = AES-128-GCM(SK1, plaintext)
 *   密文格式: IV(12B) || ciphertext || tag(16B)
 *══════════════════════════════════════════════════════════*/
int Proto_BuildEncryptedCmd(uint8_t *data, uint8_t *out_len,
                            SessionCtx *sess, uint8_t svc_cmd,
                            const uint8_t *input, uint32_t input_len)
{
    uint8_t  plaintext[FRAME_PAYLOAD_MAX];
    uint8_t  ciphertext[FRAME_PAYLOAD_MAX];
    uint32_t ct_len = sizeof(ciphertext);  /* 必须初始化为缓冲区大小 */
    uint32_t pt_len;

    (void)svc_cmd;  /* CMD 由调用方在发送时指定 */

    if (sess->state != HS_ESTABLISHED) {
        fprintf(stderr, "  [Proto] Error: handshake not complete\n");
        return -1;
    }

    /* 明文格式: data_len(2B LE) || data */
    pt_len = 2 + input_len;
    if (pt_len > sizeof(plaintext)) {
        fprintf(stderr, "  [Proto] Payload too large: %u bytes "
                "(pt_len=%u, buf_size=%u)\n",
                input_len, (unsigned)pt_len, (unsigned)sizeof(plaintext));
        return -2;
    }

    memset(plaintext, 0, sizeof(plaintext));
    plaintext[0] = (uint8_t)(input_len & 0xFF);
    plaintext[1] = (uint8_t)((input_len >> 8) & 0xFF);
    if (input && input_len > 0) {
        memcpy(plaintext + 2, input, input_len);
    }

    /* AES-128-GCM 加密 */
    if (Crypto_AES_GCM_Encrypt(sess->sk, SK_SIZE,
                               plaintext, pt_len,
                               ciphertext, &ct_len) != 0) {
        fprintf(stderr, "  [Proto] AES-GCM encrypt failed\n");
        return -3;
    }

    if (ct_len > FRAME_PAYLOAD_MAX) {
        fprintf(stderr, "  [Proto] Ciphertext too large: %u bytes\n", (unsigned)ct_len);
        return -4;
    }

    memcpy(data, ciphertext, ct_len);
    *out_len = (uint8_t)ct_len;

    printf("  [Proto] Encrypted cmd: pt=%u → ct=%u bytes\n", input_len, (unsigned)ct_len);
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 解密响应帧
 *
 *   载荷 = AES-128-GCM(SK1, plaintext)
 *══════════════════════════════════════════════════════════*/
int Proto_DecryptResponse(const uint8_t *data, uint8_t len,
                          const SessionCtx *sess,
                          uint8_t *out, uint32_t *out_len)
{
    uint8_t  plaintext[FRAME_PAYLOAD_MAX];
    uint32_t pt_len = sizeof(plaintext);
    uint16_t data_len;

    if (Crypto_AES_GCM_Decrypt(sess->sk, SK_SIZE,
                               data, len,
                               plaintext, &pt_len) != 0) {
        return -1;
    }

    if (pt_len < 2) return -2;

    data_len = plaintext[0] | ((uint16_t)plaintext[1] << 8);
    if (data_len > *out_len || data_len > pt_len - 2) return -3;

    memcpy(out, plaintext + 2, data_len);
    *out_len = data_len;
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 调试: 打印帧
 *══════════════════════════════════════════════════════════*/
void Proto_DumpFrame(const char *label, uint8_t cmd,
                     const uint8_t *data, uint8_t len)
{
    uint8_t display_len = (len > 16) ? 16 : len;

    printf("  [%s] CMD=0x%02X LEN=%u Payload=",
           label, cmd, len);
    for (uint8_t i = 0; i < display_len; i++) {
        printf("%02X ", data[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}
