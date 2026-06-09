/**
 * @file    protocol.c
 * @brief   Protocol layer: frame build/parse, HMAC handshake, AES-GCM encrypt/decrypt
 */

#include "protocol.h"
#include "crypto_win.h"
#include <stdio.h>
#include <string.h>

/*══════════════════════════════════════════════════════════
 * CRC-32 (IEEE 802.3, compatible with STM32 sec_core)
 *══════════════════════════════════════════════════════════*/
static const uint32_t crc32_table[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,
    0xE963A535,0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,
    0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,
    0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
    0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,
    0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,
    0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
    0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
    0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,
    0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
    0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,
    0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
    0x7807C9D2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,
    0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
    0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,
    0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
    0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,
    0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,
    0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,0x5005713C,0x270241AA,
    0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
    0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
    0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,
    0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,
    0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
    0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,
    0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,
    0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,0xA1D1937E,
    0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
    0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,
    0x316E8EEF,0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,
    0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,
    0x2BB45A92,0x5CB30A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
    0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,
    0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,
    0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
    0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
    0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,
    0x616BFFD3,0x166CCF45,0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C4,
    0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,0xAED16A4A,0xD9D65ADC,
    0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
    0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,
    0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
    0xB40BBE37,0xC30C8EA3,0x5A05DF1B,0x2D02EF8D,
};

uint32_t Proto_CRC32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (uint32_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

void Proto_FillCRC(HIDFrame *frame)
{
    uint32_t crc = Proto_CRC32((const uint8_t *)frame, FRAME_OFF_CRC);
    frame->crc[0] = (uint8_t)(crc >> 24);
    frame->crc[1] = (uint8_t)(crc >> 16);
    frame->crc[2] = (uint8_t)(crc >>  8);
    frame->crc[3] = (uint8_t)(crc);
}

int Proto_VerifyCRC(const HIDFrame *frame)
{
    uint32_t expected = Proto_CRC32((const uint8_t *)frame, FRAME_OFF_CRC);
    uint32_t received = ((uint32_t)frame->crc[0] << 24) |
                        ((uint32_t)frame->crc[1] << 16) |
                        ((uint32_t)frame->crc[2] <<  8) |
                        ((uint32_t)frame->crc[3]);
    return (expected == received) ? 0 : -1;
}

/*══════════════════════════════════════════════════════════
 * Session management
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
 * Hello frame parse (STM32 -> EXE)
 *══════════════════════════════════════════════════════════*/
int Proto_ParseHello(const HIDFrame *frame, SessionCtx *sess)
{
    if (frame->domain != DOMAIN_SECRET_NET) {
        fprintf(stderr, "  [Proto] Domain mismatch: expected 0x%02X, got 0x%02X\n",
                DOMAIN_SECRET_NET, frame->domain);
        return -1;
    }

    if (Proto_VerifyCRC(frame) != 0) {
        fprintf(stderr, "  [Proto] CRC check failed\n");
        return -2;
    }

    /* Extract nonce_s from payload[0..15] */
    memcpy(sess->nonce_s, frame->payload, NONCE_SIZE);
    sess->state = HS_WAIT_HELLO;

    printf("  [Proto] Hello received: nonce_s=");
    for (int i = 0; i < 8; i++) printf("%02X", sess->nonce_s[i]);
    printf("...\n");

    return 0;
}

/*══════════════════════════════════════════════════════════
 * Handshake frame build (EXE -> STM32)
 *══════════════════════════════════════════════════════════*/
int Proto_BuildHandshake(HIDFrame *frame, const SessionCtx *sess,
                         const uint8_t *mk_ctrl)
{
    uint8_t combined[2 * NONCE_SIZE];
    uint8_t hmac_tag[HMAC_TAG_SIZE];

    memset(frame, 0, sizeof(*frame));

    frame->domain  = DOMAIN_SECRET_NET;
    frame->cmd     = PCMD_HANDSHAKE;
    frame->seq_hi  = 0;
    frame->seq_lo  = 1;

    /* Payload: nonce_h(16) || HMAC-SHA256(MK_CTRL, nonce_s || nonce_h)(32) */
    memcpy(frame->payload, sess->nonce_h, NONCE_SIZE);

    memcpy(combined, sess->nonce_s, NONCE_SIZE);
    memcpy(combined + NONCE_SIZE, sess->nonce_h, NONCE_SIZE);

    if (Crypto_HMAC_SHA256(mk_ctrl, 32, combined, sizeof(combined), hmac_tag) != 0) {
        fprintf(stderr, "  [Proto] HMAC computation failed\n");
        return -1;
    }
    memcpy(frame->payload + NONCE_SIZE, hmac_tag, HMAC_TAG_SIZE);

    Proto_FillCRC(frame);

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
 * ACK frame parse (STM32 -> EXE)
 *══════════════════════════════════════════════════════════*/
int Proto_ParseAck(const HIDFrame *frame, const SessionCtx *sess)
{
    (void)sess;
    if (Proto_VerifyCRC(frame) != 0) return -1;
    if (frame->payload[0] == 0x01) {
        printf("  [Proto] ACK received (handshake OK)\n");
        return 0;
    }
    printf("  [Proto] NACK received (handshake rejected)\n");
    return -1;
}

/*══════════════════════════════════════════════════════════
 * Session key derivation
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

    /* SK1 = first 16 bytes of HMAC output */
    memcpy(sess->sk, hmac_out, SK_SIZE);

    memset(combined, 0, sizeof(combined));
    memset(hmac_out, 0, sizeof(hmac_out));

    sess->state = HS_ESTABLISHED;
    sess->seq_tx = 2;  /* Hello=0, Handshake=1, first cmd at 2 */

    printf("  [Proto] SK1 derived: ");
    for (int i = 0; i < 8; i++) printf("%02X", sess->sk[i]);
    printf("...\n");

    return 0;
}

/*══════════════════════════════════════════════════════════
 * Encrypted command build (EXE -> STM32)
 *══════════════════════════════════════════════════════════*/
int Proto_BuildEncryptedCmd(HIDFrame *frame, SessionCtx *sess,
                            uint8_t svc_cmd,
                            const uint8_t *data, uint32_t data_len)
{
    uint8_t  plaintext[FRAME_PAYLOAD_SIZE];
    uint8_t  ciphertext[FRAME_PAYLOAD_SIZE];
    uint32_t ct_len = 0;

    if (sess->state != HS_ESTABLISHED) {
        fprintf(stderr, "  [Proto] Error: handshake not complete, cannot send command\n");
        return -1;
    }

    /* Plaintext: data_len(2B LE) || data */
    memset(plaintext, 0, sizeof(plaintext));
    plaintext[0] = (uint8_t)(data_len & 0xFF);
    plaintext[1] = (uint8_t)((data_len >> 8) & 0xFF);
    if (data && data_len > 0) {
        memcpy(plaintext + 2, data, data_len);
    }

    /* AES-128-GCM encrypt */
    if (Crypto_AES_GCM_Encrypt(sess->sk, SK_SIZE,
                               plaintext, 2 + data_len,
                               ciphertext, &ct_len) != 0) {
        fprintf(stderr, "  [Proto] AES-GCM encrypt failed\n");
        return -2;
    }

    /* Build frame */
    memset(frame, 0, sizeof(*frame));
    frame->domain = DOMAIN_SECRET_NET;
    frame->cmd    = svc_cmd;
    frame->seq_hi = (uint8_t)(sess->seq_tx >> 8);
    frame->seq_lo = (uint8_t)(sess->seq_tx & 0xFF);

    if (ct_len > FRAME_PAYLOAD_SIZE) ct_len = FRAME_PAYLOAD_SIZE;
    memcpy(frame->payload, ciphertext, ct_len);

    Proto_FillCRC(frame);
    sess->seq_tx++;

    printf("  [Proto] Encrypted cmd SVC=0x%02X Seq=%u ct_len=%u\n",
           svc_cmd, sess->seq_tx - 1, ct_len);
    return 0;
}

/*══════════════════════════════════════════════════════════
 * Decrypt response (STM32 -> EXE)
 *══════════════════════════════════════════════════════════*/
int Proto_DecryptResponse(const HIDFrame *frame, const SessionCtx *sess,
                          uint8_t *out, uint32_t *out_len)
{
    uint8_t plaintext[FRAME_PAYLOAD_SIZE];
    uint32_t pt_len = 0;
    uint16_t data_len;

    if (Proto_VerifyCRC(frame) != 0) return -1;

    if (Crypto_AES_GCM_Decrypt(sess->sk, SK_SIZE,
                               frame->payload, FRAME_PAYLOAD_SIZE,
                               plaintext, &pt_len) != 0) {
        return -2;
    }

    if (pt_len < 2) return -3;
    data_len = plaintext[0] | ((uint16_t)plaintext[1] << 8);
    if (data_len > *out_len || data_len > pt_len - 2) return -4;

    memcpy(out, plaintext + 2, data_len);
    *out_len = data_len;
    return 0;
}

/*══════════════════════════════════════════════════════════
 * Debug dump
 *══════════════════════════════════════════════════════════*/
void Proto_DumpFrame(const char *label, const HIDFrame *frame)
{
    printf("  [%s] Domain=0x%02X Cmd=0x%02X Seq=%u\n",
           label, frame->domain, frame->cmd,
           ((uint16_t)frame->seq_hi << 8) | frame->seq_lo);
    printf("    Payload: ");
    for (int i = 0; i < 16; i++) printf("%02X ", frame->payload[i]);
    printf("...\n");
}
