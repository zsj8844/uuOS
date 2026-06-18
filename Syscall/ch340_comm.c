/**
 * @file    Syscall/ch340_comm.c
 * @brief   CH340 串口通信 —— USART1 重映射到 PB6/PB7
 *
 *          USART1 在 APB2 上: PCLK2 = 72MHz
 *          波特率: 9600 → BRR = 72M / (16×9600) = 468.75 → DIV=468, FRAC=12
 *          Remap: PB6=TX, PB7=RX (通过 AFIO 重映射)
 */

#include "ch340_comm.h"

/*─────────────────────────────────────────────────────────
 * RX 状态机
 *─────────────────────────────────────────────────────────*/
#define RX_ST_SYNC   0
#define RX_ST_CMD    1
#define RX_ST_LEN    2
#define RX_ST_DATA   3
#define RX_ST_XOR    4

volatile uint32_t g_rx_byte_count = 0;
volatile uint32_t g_rx_frame_ok  = 0;   /* 诊断: 有效帧计数 */
volatile uint32_t g_rx_frame_bad = 0;   /* 诊断: 校验失败计数 */

/* 帧超时: 主循环每轮调用, 超过 FRAME_TIMEOUT_MS 未收到字节则重置状态机 */
#define FRAME_TIMEOUT_MS 200
void CH340_Comm_ResetIfTimeout(void);    /* 在 main 循环中定期调用 */

static volatile uint8_t  rx_state   = RX_ST_SYNC;
static volatile uint8_t  rx_cmd;
static volatile uint8_t  rx_len;
static volatile uint8_t  rx_idx;
static volatile uint8_t  rx_buf[FRAME_MAX_PAYLOAD];
static volatile uint8_t  rx_xor;

static volatile uint8_t  rx_frame_ready = 0;
static volatile uint8_t  rx_frame_cmd;
static volatile uint8_t  rx_frame_len;
static volatile uint8_t  rx_frame_data[FRAME_MAX_PAYLOAD];

/*─────────────────────────────────────────────────────────
 * CH340_Comm_Init
 *─────────────────────────────────────────────────────────*/
void CH340_Comm_Init(void)
{
    GPIO_InitTypeDef  gpio;
    USART_InitTypeDef usart;
    NVIC_InitTypeDef  nvic;

    /* ── 时钟: GPIOB + USART1 + AFIO ── */
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB |
                           RCC_APB2Periph_USART1 |
                           RCC_APB2Periph_AFIO, ENABLE);

    /* ── USART1 重映射到 PB6/PB7 ── */
    GPIO_PinRemapConfig(GPIO_Remap_USART1, ENABLE);

    /* ── PB6 = TX (复用推挽), PB7 = RX (浮空输入) ── */
    gpio.GPIO_Pin   = GPIO_Pin_6;
    gpio.GPIO_Mode  = GPIO_Mode_AF_PP;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOB, &gpio);

    gpio.GPIO_Pin  = GPIO_Pin_7;
    gpio.GPIO_Mode = GPIO_Mode_IN_FLOATING;
    GPIO_Init(GPIOB, &gpio);

    /* ── USART1: 9600-8-N-1 ── */
    USART_StructInit(&usart);
    usart.USART_BaudRate            = 9600;
    usart.USART_WordLength          = USART_WordLength_8b;
    usart.USART_StopBits            = USART_StopBits_1;
    usart.USART_Parity              = USART_Parity_No;
    usart.USART_Mode                = USART_Mode_Rx | USART_Mode_Tx;
    usart.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
    USART_Init(USART1, &usart);

    /* ── 中断 ── */
    USART_ITConfig(USART1, USART_IT_RXNE, ENABLE);
    /* 不用 IDLE — CH340 USB 缓冲会导致 >1ms 间隔, IDLE 过早清掉半帧 */

    nvic.NVIC_IRQChannel                   = USART1_IRQn;
    nvic.NVIC_IRQChannelPreemptionPriority = 0;
    nvic.NVIC_IRQChannelSubPriority        = 0;
    nvic.NVIC_IRQChannelCmd                = ENABLE;
    NVIC_Init(&nvic);

    USART_Cmd(USART1, ENABLE);
}

/*─────────────────────────────────────────────────────────
 * CH340_Comm_Send
 *─────────────────────────────────────────────────────────*/
void CH340_Comm_Send(uint8_t cmd, const uint8_t *data, uint8_t len)
{
    uint8_t xor_val;

    USART_SendData(USART1, FRAME_SYNC);
    while (RESET == USART_GetFlagStatus(USART1, USART_FLAG_TXE));

    USART_SendData(USART1, cmd);
    while (RESET == USART_GetFlagStatus(USART1, USART_FLAG_TXE));
    xor_val = cmd;

    USART_SendData(USART1, len);
    while (RESET == USART_GetFlagStatus(USART1, USART_FLAG_TXE));
    xor_val ^= len;

    while (len--) {
        USART_SendData(USART1, *data);
        while (RESET == USART_GetFlagStatus(USART1, USART_FLAG_TXE));
        xor_val ^= *data++;
    }

    USART_SendData(USART1, xor_val);
    while (RESET == USART_GetFlagStatus(USART1, USART_FLAG_TC));
}

/*─────────────────────────────────────────────────────────
 * CH340_Comm_Recv
 *─────────────────────────────────────────────────────────*/
uint8_t CH340_Comm_Recv(uint8_t *cmd, uint8_t *data, uint8_t *len)
{
    uint8_t i;
    if (!rx_frame_ready) return 0;
    *cmd = rx_frame_cmd;
    *len = rx_frame_len;
    for (i = 0; i < rx_frame_len; i++) data[i] = rx_frame_data[i];
    rx_frame_ready = 0;
    return 1;
}

/*─────────────────────────────────────────────────────────
 * USART1 中断
 *─────────────────────────────────────────────────────────*/
void USART1_IRQHandler(void)
{
    uint8_t byte;

    if (USART_GetITStatus(USART1, USART_IT_RXNE) != RESET) {
        byte = (uint8_t)USART_ReceiveData(USART1);
        g_rx_byte_count++;

        switch (rx_state) {
        case RX_ST_SYNC:
            if (byte == FRAME_SYNC) rx_state = RX_ST_CMD;
            break;
        case RX_ST_CMD:
            rx_cmd = byte; rx_xor = byte; rx_state = RX_ST_LEN;
            break;
        case RX_ST_LEN:
            rx_len = byte; rx_xor ^= byte;
            if (rx_len > FRAME_MAX_PAYLOAD) rx_state = RX_ST_SYNC;
            else if (rx_len == 0) rx_state = RX_ST_XOR;
            else { rx_idx = 0; rx_state = RX_ST_DATA; }
            break;
        case RX_ST_DATA:
            rx_buf[rx_idx] = byte; rx_xor ^= byte; rx_idx++;
            if (rx_idx >= rx_len) rx_state = RX_ST_XOR;
            break;
        case RX_ST_XOR:
            if (byte == rx_xor) {
                rx_frame_cmd = rx_cmd; rx_frame_len = rx_len;
                for (rx_idx = 0; rx_idx < rx_len; rx_idx++)
                    rx_frame_data[rx_idx] = rx_buf[rx_idx];
                rx_frame_ready = 1;
                g_rx_frame_ok++;
            } else {
                g_rx_frame_bad++;
            }
            rx_state = RX_ST_SYNC;
            break;
        }
    }

    /* IDLE 已移除 — 改用 CH340_Comm_ResetIfTimeout() 软超时 */
}

/*
 * 帧超时: 若超过 FRAME_TIMEOUT_MS 未收到新字节且状态机卡住, 重置
 */
void CH340_Comm_ResetIfTimeout(void)
{
    static uint32_t last_count = 0;
    static uint32_t stuck_ticks = 0;

    if (g_rx_byte_count != last_count) {
        last_count = g_rx_byte_count;
        stuck_ticks = 0;
    } else {
        stuck_ticks++;
    }

    if (stuck_ticks > 3000) {  /* ~1000ms at ~3 ticks/ms */
        if (rx_state != RX_ST_SYNC) {
            rx_state = RX_ST_SYNC;
            g_rx_frame_bad++;
        }
        stuck_ticks = 0;
    }
}
