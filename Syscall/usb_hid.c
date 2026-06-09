/**
 * @file    Syscall/usb_hid.c
 * @brief   STM32F103 USB Custom HID Device 裸寄存器驱动
 *
 *          USB_FS 基址: 0x40005C00
 *          包缓冲区:    0x40006000 (512 bytes 共享 SRAM)
 *
 *          端点分配:
 *            EP0 (0x00/0x80) — Control, 枚举
 *            EP1 (0x01/0x81) — Interrupt, 64B HID Report
 *
 *          不使用 ST 官方 USB 库, 无 RTOS 依赖。
 */

#include "usb_hid.h"
#include <string.h>

/*══════════════════════════════════════════════════════════
 * USB 外设寄存器 (STM32F10x CMSIS 未包含 USB 寄存器, 自行定义)
 *   USB FS Base: 0x40005C00
 *   包缓冲区 PMA: 0x40006000 (512 bytes)
 *══════════════════════════════════════════════════════════*/

/* USB 外设寄存器结构体 (精简版, 仅用到的字段) */
typedef struct {
    volatile uint16_t EP0R;    /* 0x00 */
    volatile uint16_t RES0;    /* 0x02 */
    volatile uint16_t EP1R;    /* 0x04 */
    volatile uint16_t RES1;    /* 0x06 */
    volatile uint16_t EP2R;    /* 0x08 */
    volatile uint16_t RES2;    /* 0x0A */
    volatile uint16_t EP3R;    /* 0x0C */
    volatile uint16_t RES3;    /* 0x0E */
    volatile uint16_t EP4R;    /* 0x10 */
    volatile uint16_t RES4;    /* 0x12 */
    volatile uint16_t EP5R;    /* 0x14 */
    volatile uint16_t RES5;    /* 0x16 */
    volatile uint16_t EP6R;    /* 0x18 */
    volatile uint16_t RES6;    /* 0x1A */
    volatile uint16_t EP7R;    /* 0x1C */
    volatile uint16_t RES7[17];/* 0x1E..0x3E */
    volatile uint16_t CNTR;    /* 0x40 */
    volatile uint16_t RES8;    /* 0x42 */
    volatile uint16_t ISTR;    /* 0x44 */
    volatile uint16_t RES9;    /* 0x46 */
    volatile uint16_t FNR;     /* 0x48 */
    volatile uint16_t RESA;    /* 0x4A */
    volatile uint16_t DADDR;   /* 0x4C */
    volatile uint16_t RESB;    /* 0x4E */
    volatile uint16_t BTABLE;  /* 0x50 */
} USB_TypeDef;

#define USB_BASE          0x40005C00u
#define USB               ((USB_TypeDef *)USB_BASE)
#define USB_BUF_BASE      0x40006000u   /* 包缓冲区基址 */

/* 缓冲区偏移 (从 USB_BUF_BASE 起) */
#define BUF_EP0_TX         0x00   /* EP0 TX: 64 bytes */
#define BUF_EP0_RX         0x40   /* EP0 RX: 64 bytes */
#define BUF_EP1_TX         0x80   /* EP1 TX: 64 bytes */
#define BUF_EP1_RX         0xC0   /* EP1 RX: 64 bytes */
/* BTABLE 在 0x00, 占用 8*4=32 bytes, 缓冲区从 0x20 开始 */

/* 端点编号 */
#define EP0                 0
#define EP1                 1

/* EPnR 寄存器位 */
#define EP_CTR_RX          (1<<15)  /* 接收正确传输 */
#define EP_DTOG_RX         (1<<14)  /* 接收数据翻转 */
#define EP_STAT_RX         (0x3000) /* 接收状态掩码 */
#define EP_STAT_RX_VALID   (0x3000) /* VALID (使能接收) */
#define EP_STAT_RX_NAK     (0x2000) /* NAK */
#define EP_STAT_RX_STALL   (0x1000) /* STALL */
#define EP_STAT_RX_DIS     (0x0000) /* DISABLED */
#define EP_SETUP           (1<<11)  /* Setup 事务完成 */
#define EP_TYPE            (0x0600) /* 端点类型掩码 */
#define EP_TYPE_CONTROL    (0x0600) /* Control */
#define EP_TYPE_ISO        (0x0400) /* Isochronous */
#define EP_TYPE_BULK       (0x0000) /* Bulk */
#define EP_TYPE_INTERRUPT  (0x0200) /* Interrupt */
#define EP_KIND            (1<<8)   /* Kind (CTL=STATUS OUT) */
#define EP_CTR_TX          (1<<7)   /* 发送正确传输 */
#define EP_DTOG_TX         (1<<6)   /* 发送数据翻转 */
#define EP_STAT_TX         (0x0030) /* 发送状态掩码 */
#define EP_STAT_TX_VALID   (0x0030) /* VALID (使能发送) */
#define EP_STAT_TX_NAK     (0x0020) /* NAK */
#define EP_STAT_TX_STALL   (0x0010) /* STALL */
#define EP_STAT_TX_DIS     (0x0000) /* DISABLED */
#define EP_ADDR            (0x000F) /* 端点地址 */

/* CNTR 位 */
#define CNTR_CTRM          (1<<15)  /* 正确传输中断 */
#define CNTR_RESETM        (1<<11)  /* USB 复位中断 */
#define CNTR_SUSPM         (1<<9)   /* 挂起中断 */
#define CNTR_WKUPM         (1<<8)   /* 唤醒中断 */
#define CNTR_FRES          (1<<4)   /* 强制复位 */
#define CNTR_PDWN          (1<<1)   /* 掉电模式 */
#define CNTR_LP_MODE       (1<<0)   /* 低功耗模式 */

/* ISTR 位 */
#define ISTR_CTR           (1<<15)  /* 正确传输 */
#define ISTR_RESET         (1<<10)  /* USB 复位 */
#define ISTR_SUSP          (1<<5)   /* 挂起 */
#define ISTR_WKUP          (1<<4)   /* 唤醒 */
#define ISTR_DIR           (1<<4)   /* CTR 事务方向 (TX=0, RX=1) */
#define ISTR_EP_ID         (0x000F) /* CTR 的端点号 */

/* DADDR 位 */
#define DADDR_EF           (1<<7)

/*──────────────────────────────────────────────────────────
 * 缓冲区描述表条目 (每 EP 2 条: TX + RX, 每条 4 个 uint16_t)
 *──────────────────────────────────────────────────────────*/
#define BTABLE_OFFSET      0x00  /* BTABLE 从 PMA 偏移 0 开始 */

/* 写 PMA 缓冲区 (16-bit 访问) */
static void pma_write(uint16_t addr, const uint8_t *data, uint16_t len)
{
    volatile uint16_t *pma = (volatile uint16_t *)(USB_BUF_BASE + addr);
    uint16_t i;
    for (i = 0; i < len; i += 2) {
        uint16_t w = data[i];
        if (i + 1 < len) w |= ((uint16_t)data[i + 1] << 8);
        *pma++ = w;
    }
}

/* 读 PMA 缓冲区 */
static void pma_read(uint16_t addr, uint8_t *data, uint16_t len)
{
    volatile uint16_t *pma = (volatile uint16_t *)(USB_BUF_BASE + addr);
    uint16_t i;
    for (i = 0; i < len; i += 2) {
        uint16_t w = *pma++;
        data[i] = (uint8_t)(w & 0xFF);
        if (i + 1 < len) data[i + 1] = (uint8_t)(w >> 8);
    }
}

/* 写 BTABLE 条目 (两个 16-bit 值: ADDR + COUNT) */
static void btable_set(uint16_t ep, int is_tx, uint16_t addr, uint16_t count)
{
    volatile uint16_t *pma = (volatile uint16_t *)(USB_BUF_BASE + BTABLE_OFFSET);
    uint16_t idx = ep * 4 + (is_tx ? 0 : 2);
    pma[idx]     = addr;
    pma[idx + 1] = count;
}

/*══════════════════════════════════════════════════════════
 * USB 描述符
 *══════════════════════════════════════════════════════════*/

/* Device Descriptor */
static const uint8_t usb_dev_desc[] = {
    0x12,                   /* bLength */
    0x01,                   /* bDescriptorType: Device */
    0x00, 0x02,             /* bcdUSB 2.0 */
    0x00,                   /* bDeviceClass (defined in interface) */
    0x00,                   /* bDeviceSubClass */
    0x00,                   /* bDeviceProtocol */
    0x40,                   /* bMaxPacketSize0 = 64 */
    (uint8_t)USB_HID_VID, (uint8_t)(USB_HID_VID >> 8),
    (uint8_t)USB_HID_PID, (uint8_t)(USB_HID_PID >> 8),
    0x00, 0x01,             /* bcdDevice 1.00 */
    0x01,                   /* iManufacturer */
    0x02,                   /* iProduct */
    0x03,                   /* iSerialNumber */
    0x01,                   /* bNumConfigurations */
};

/* Config + Interface + HID + EP1 IN + EP1 OUT */
static const uint8_t usb_cfg_desc[] = {
    /* Configuration */
    0x09, 0x02,             /* bLength, bDescriptorType */
    0x29, 0x00,             /* wTotalLength = 41 */
    0x01,                   /* bNumInterfaces */
    0x01,                   /* bConfigurationValue */
    0x00,                   /* iConfiguration */
    0xC0,                   /* bmAttributes: Self-powered */
    0x32,                   /* bMaxPower: 100mA */

    /* Interface */
    0x09, 0x04,             /* bLength, bDescriptorType */
    0x00,                   /* bInterfaceNumber */
    0x00,                   /* bAlternateSetting */
    0x02,                   /* bNumEndpoints (EP1 IN + EP1 OUT) */
    0x03,                   /* bInterfaceClass: HID */
    0x00,                   /* bInterfaceSubClass: none (boot=1) */
    0x00,                   /* bInterfaceProtocol: none (kbd=1, mouse=2) */
    0x00,                   /* iInterface */

    /* HID */
    0x09, 0x21,             /* bLength, bDescriptorType: HID */
    0x00, 0x01,             /* bcdHID 1.00 */
    0x00,                   /* bCountryCode */
    0x01,                   /* bNumDescriptors */
    0x22,                   /* bDescriptorType: Report */
    0x3A, 0x00,             /* wDescriptorLength = 58 */

    /* Endpoint 1 IN (device→host) */
    0x07, 0x05,             /* bLength, bDescriptorType */
    0x81,                   /* bEndpointAddress: EP1 IN */
    0x03,                   /* bmAttributes: Interrupt */
    0x40, 0x00,             /* wMaxPacketSize: 64 */
    USB_HID_POLL_INTERVAL,  /* bInterval: 1ms */

    /* Endpoint 1 OUT (host→device) */
    0x07, 0x05,             /* bLength, bDescriptorType */
    0x01,                   /* bEndpointAddress: EP1 OUT */
    0x03,                   /* bmAttributes: Interrupt */
    0x40, 0x00,             /* wMaxPacketSize: 64 */
    USB_HID_POLL_INTERVAL,  /* bInterval: 1ms */
};

/* HID Report Descriptor (58 bytes) */
static const uint8_t usb_hid_report_desc[] = {
    0x06, 0x00, 0xFF,       /* Usage Page (Vendor 0xFF00) */
    0x09, 0x01,             /* Usage (Vendor 1) */
    0xA1, 0x01,             /* Collection (Application) */

    /* Input Report (64 bytes, device → host) */
    0x09, 0x02,             /*   Usage (Vendor 2) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x26, 0xFF, 0x00,       /*   Logical Maximum (255) */
    0x75, 0x08,             /*   Report Size (8 bits) */
    0x96, 0x40, 0x00,       /*   Report Count (64) */
    0x81, 0x02,             /*   Input (Data, Variable, Absolute) */

    /* Output Report (64 bytes, host → device) */
    0x09, 0x03,             /*   Usage (Vendor 3) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x26, 0xFF, 0x00,       /*   Logical Maximum (255) */
    0x75, 0x08,             /*   Report Size (8 bits) */
    0x96, 0x40, 0x00,       /*   Report Count (64) */
    0x91, 0x02,             /*   Output (Data, Variable, Absolute) */

    0xC0,                   /* End Collection */
};

/* String descriptors (UNICODE, 需要 langID 0x0409) */
static const uint8_t usb_str_lang[] = { 0x04, 0x03, 0x09, 0x04 };
static const uint8_t usb_str_mfg[]  = {
    0x1A, 0x03,
    'S',0,'e',0,'c',0,'u',0,'F',0,'e',0,'r',0,'r',0,'y',0,'-',0,'O',0,'S',0
};
static const uint8_t usb_str_prod[] = {
    0x24, 0x03,
    'S',0,'T',0,'M',0,'3',0,'2',0,' ',0,'H',0,'I',0,'D',0,' ',0,
    'D',0,'e',0,'v',0,'i',0,'c',0,'e',0
};
static const uint8_t usb_str_ser[]  = {
    0x0A, 0x03,
    '0',0,'0',0,'0',0,'1',0
};

/*══════════════════════════════════════════════════════════
 * 全局状态
 *══════════════════════════════════════════════════════════*/
static volatile uint8_t g_usb_configured = 0;
static volatile uint8_t g_rx_ready        = 0;  /* EP1 OUT 有新数据 */
static          uint8_t g_rx_buf[USB_HID_REPORT_SIZE];
static          uint8_t g_tx_buf[USB_HID_REPORT_SIZE];

/*══════════════════════════════════════════════════════════
 * 端点操作
 *══════════════════════════════════════════════════════════*/

/* 设置 EP 状态 (保持其他位不变) */
static void ep_set_status(uint8_t ep, uint16_t mask, uint16_t val)
{
    uint16_t *reg = (uint16_t *)(&USB->EP0R + ep);
    uint16_t old = *reg;
    uint16_t new = (old & ~mask) ^ val;
    /* toggle 位需要写 0 来翻转 (硬件 XOR 逻辑) */
    if ((old ^ new) & EP_DTOG_RX) new ^= EP_DTOG_RX;
    if ((old ^ new) & EP_DTOG_TX) new ^= EP_DTOG_TX;
    *reg = new;
}

/* 获取 EP 寄存器 */
static uint16_t ep_get(uint8_t ep)
{
    return *((volatile uint16_t *)(&USB->EP0R + ep));
}

/*══════════════════════════════════════════════════════════
 * EP0: Control 传输处理 (枚举)
 *══════════════════════════════════════════════════════════*/

static const uint8_t *g_ep0_tx_data = NULL;
static uint16_t       g_ep0_tx_len  = 0;
static uint8_t        g_usb_addr    = 0;

static void ep0_send_desc(const uint8_t *desc, uint16_t len)
{
    g_ep0_tx_data = desc;
    g_ep0_tx_len  = len;
}

static void ep0_handle_setup(void)
{
    /* 读取 8 字节 Setup 包 (从 EP0 RX 缓冲区) */
    uint8_t setup[8];
    pma_read(BUF_EP0_RX, setup, 8);

    uint8_t  bmRequestType = setup[0];
    uint8_t  bRequest      = setup[1];
    uint16_t wValue        = setup[2] | ((uint16_t)setup[3] << 8);
    uint16_t wIndex        = setup[4] | ((uint16_t)setup[5] << 8);
    uint16_t wLength       = setup[6] | ((uint16_t)setup[7] << 8);
    (void)wIndex;

    /* 默认: 无数据阶段 */
    g_ep0_tx_data = NULL;
    g_ep0_tx_len  = 0;

    if ((bmRequestType & 0x60) == 0x00) {
        /* ── Standard Device Request ── */
        switch (bRequest) {
        case 0x00: /* GET_STATUS */
            { static uint8_t status[] = {0x00, 0x00}; ep0_send_desc(status, 2); }
            break;
        case 0x05: /* SET_ADDRESS */
            g_usb_addr = (uint8_t)(wValue & 0x7F);
            break;
        case 0x06: /* GET_DESCRIPTOR */
            switch ((wValue >> 8) & 0xFF) {
            case 0x01: ep0_send_desc(usb_dev_desc, sizeof(usb_dev_desc)); break;
            case 0x02: ep0_send_desc(usb_cfg_desc, sizeof(usb_cfg_desc)); break;
            case 0x03:
                switch (wValue & 0xFF) {
                case 0x00: ep0_send_desc(usb_str_lang, sizeof(usb_str_lang)); break;
                case 0x01: ep0_send_desc(usb_str_mfg,  sizeof(usb_str_mfg));  break;
                case 0x02: ep0_send_desc(usb_str_prod, sizeof(usb_str_prod)); break;
                case 0x03: ep0_send_desc(usb_str_ser,  sizeof(usb_str_ser));  break;
                }
                break;
            }
            break;
        case 0x08: /* GET_CONFIGURATION */
            { static uint8_t cfg = 0x01; ep0_send_desc(&cfg, 1); }
            break;
        case 0x09: /* SET_CONFIGURATION */
            if (wValue != 0) {
                g_usb_configured = 1;
                /* 配置 EP1 IN */
                ep_set_status(EP1, EP_ADDR | EP_TYPE | EP_STAT_TX,
                              0x81 | EP_TYPE_INTERRUPT | EP_STAT_TX_NAK);
                btable_set(EP1, 1, BUF_EP1_TX, 0);
                /* 配置 EP1 OUT */
                ep_set_status(EP1, EP_ADDR | EP_TYPE | EP_STAT_RX,
                              0x01 | EP_TYPE_INTERRUPT | EP_STAT_RX_VALID);
                btable_set(EP1, 0, BUF_EP1_RX, ((uint16_t)64 << 10) | 0x8400);
            }
            break;
        }
    } else if ((bmRequestType & 0x60) == 0x20) {
        /* ── HID Class Request (Interface) ── */
        switch (bRequest) {
        case 0x01: /* GET_REPORT */ break;
        case 0x02: /* GET_IDLE */  { static uint8_t idle = 0; ep0_send_desc(&idle, 1); } break;
        case 0x03: /* GET_PROTOCOL */ break;
        case 0x06: /* GET_DESCRIPTOR (HID Report) */
            if ((wValue >> 8) == 0x22)
                ep0_send_desc(usb_hid_report_desc, sizeof(usb_hid_report_desc));
            break;
        case 0x09: /* SET_REPORT */ break; /* Host sends report via EP1 OUT, not here */
        case 0x0A: /* SET_IDLE */  break;
        case 0x0B: /* SET_PROTOCOL */ break;
        }
    }

    /* 触发 EP0 IN 发送响应 */
    if (g_ep0_tx_data && g_ep0_tx_len > 0) {
        uint16_t send_len = (g_ep0_tx_len > wLength) ? wLength : g_ep0_tx_len;
        if (send_len > 64) send_len = 64;
        pma_write(BUF_EP0_TX, g_ep0_tx_data, send_len);
        btable_set(EP0, 1, BUF_EP0_TX, send_len);
        ep_set_status(EP0, EP_STAT_TX, EP_STAT_TX_VALID);
    } else {
        /* 无数据阶段: 发送零长度状态包 */
        btable_set(EP0, 1, BUF_EP0_TX, 0);
        ep_set_status(EP0, EP_STAT_TX, EP_STAT_TX_VALID);
    }
}

/* EP0 IN 完成 (数据已发送, 可能还有更多数据要发) */
static void ep0_tx_done(void)
{
    /* 清除 CTR_TX 标志 */
    ep_set_status(EP0, EP_CTR_TX, 0);

    if (g_usb_addr) {
        USB->DADDR = (uint16_t)(g_usb_addr | DADDR_EF);
        g_usb_addr = 0;
    }

    /* 设置 EP0 RX 为 VALID, 准备下一个 Setup */
    btable_set(EP0, 0, BUF_EP0_RX, ((uint16_t)64 << 10) | 0x8400);
    ep_set_status(EP0, EP_STAT_RX | EP_STAT_TX,
                  EP_STAT_RX_VALID | EP_STAT_TX_NAK);
}

/* EP0 OUT 完成 (Setup 或 OUT 数据已收到) */
static void ep0_rx_done(void)
{
    ep_set_status(EP0, EP_CTR_RX, 0);

    if (ep_get(EP0) & EP_SETUP) {
        /* Setup 包 */
        ep0_handle_setup();
        /* 清除 SETUP 位 (写 0 翻转) */
        ep_set_status(EP0, EP_SETUP, 0);
    }
}

/*══════════════════════════════════════════════════════════
 * EP1: HID Report 收发
 *══════════════════════════════════════════════════════════*/

void USB_HID_SendReport(const uint8_t *data)
{
    if (!g_usb_configured) return;

    /* 等待上一次发送完成 */
    while ((ep_get(EP1) & EP_STAT_TX) == EP_STAT_TX_VALID) {
        __NOP();
    }

    memcpy(g_tx_buf, data, USB_HID_REPORT_SIZE);
    pma_write(BUF_EP1_TX, g_tx_buf, USB_HID_REPORT_SIZE);
    btable_set(EP1, 1, BUF_EP1_TX, USB_HID_REPORT_SIZE);
    ep_set_status(EP1, EP_STAT_TX, EP_STAT_TX_VALID);
}

int USB_HID_RecvReport(uint8_t *data)
{
    if (g_rx_ready) {
        memcpy(data, g_rx_buf, USB_HID_REPORT_SIZE);
        g_rx_ready = 0;
        return 1;
    }
    return 0;
}

int USB_HID_IsConfigured(void)
{
    return g_usb_configured;
}

void USB_HID_FlushRecv(void)
{
    g_rx_ready = 0;
    memset(g_rx_buf, 0, sizeof(g_rx_buf));
}

/*══════════════════════════════════════════════════════════
 * USB 中断处理 (轮询模式 —— 在主循环中调用)
 *══════════════════════════════════════════════════════════*/

void USB_HID_Poll(void)
{
    uint16_t istr = USB->ISTR;

    /* ── RESET ── */
    if (istr & ISTR_RESET) {
        USB->ISTR = (uint16_t)(~ISTR_RESET);
        g_usb_configured = 0;
        g_usb_addr       = 0;
        g_rx_ready       = 0;
        /* 初始化 EP0 */
        btable_set(EP0, 0, BUF_EP0_RX, ((uint16_t)64 << 10) | 0x8400);
        btable_set(EP0, 1, BUF_EP0_TX, 0);
        ep_set_status(EP0, EP_ADDR | EP_STAT_RX | EP_STAT_TX,
                      0x00 | EP_STAT_RX_VALID | EP_STAT_TX_NAK);
        USB->DADDR = DADDR_EF; /* 使能 USB 地址 0 */
        return;
    }

    /* ── CTR (正确传输) ── */
    if (istr & ISTR_CTR) {
        uint8_t ep_num = (uint8_t)(istr & ISTR_EP_ID);
        uint16_t epreg = ep_get(ep_num);

        if (ep_num == 0) {
            /* EP0 */
            if (epreg & EP_CTR_RX) ep0_rx_done();
            if (epreg & EP_CTR_TX) ep0_tx_done();
        } else if (ep_num == 1) {
            /* EP1 */
            if (epreg & EP_CTR_TX) {
                /* IN 完成: 清除标志, 设 NAK */
                ep_set_status(EP1, EP_CTR_TX, 0);
                ep_set_status(EP1, EP_STAT_TX, EP_STAT_TX_NAK);
            }
            if (epreg & EP_CTR_RX) {
                /* OUT 完成: 读取数据 */
                uint16_t rx_count = (
                    *(volatile uint16_t *)(USB_BUF_BASE + BTABLE_OFFSET + EP1 * 4 + 2)
                ) & 0x03FF;
                if (rx_count > USB_HID_REPORT_SIZE) rx_count = USB_HID_REPORT_SIZE;
                pma_read(BUF_EP1_RX, g_rx_buf, rx_count);
                g_rx_ready = 1;
                ep_set_status(EP1, EP_CTR_RX, 0);
                /* 重新使能 OUT 接收 */
                btable_set(EP1, 0, BUF_EP1_RX, ((uint16_t)64 << 10) | 0x8400);
                ep_set_status(EP1, EP_STAT_RX, EP_STAT_RX_VALID);
            }
        }

        USB->ISTR = (uint16_t)(~ISTR_CTR);
        return;
    }

    /* ── SUSPEND / WAKEUP ── */
    if (istr & ISTR_SUSP) {
        USB->ISTR = (uint16_t)(~ISTR_SUSP);
    }
    if (istr & ISTR_WKUP) {
        USB->ISTR = (uint16_t)(~ISTR_WKUP);
    }
}

/*══════════════════════════════════════════════════════════
 * USB 初始化
 *══════════════════════════════════════════════════════════*/

void USB_HID_Init(void)
{
    GPIO_InitTypeDef gpio;
    uint16_t *ep;

    /* ── USB 时钟: HSE(8MHz) → PLL×9=72MHz → USBCLK=48MHz ── */
    {
        volatile uint32_t timeout;

        /* 尝试启动 HSE (部分 Blue Pill 无外部晶振, 需回退 HSI) */
        RCC_HSEConfig(RCC_HSE_ON);
        timeout = 0x100000;
        while (RCC_GetFlagStatus(RCC_FLAG_HSERDY) == RESET && --timeout) {
            __NOP();
        }

        if (timeout == 0) {
            /* HSE 不工作 (无晶振或损坏), 回退到 HSI+PLL */
            RCC_HSEConfig(RCC_HSE_OFF);
            /* HSI = 8MHz, PLL×9 = 72MHz, PLL src = HSI/2 = 4MHz × 9 = 36MHz...
               不对, HSI/2 = 4MHz, PLL×12 = 48MHz → USB 可直接用
               简化: 直接用 HSI 8MHz, 不切 PLL, USB 用 HSI 直接驱动 (不稳定但可能工作) */
            /* 保持 HSI 8MHz, 尝试 PLL: HSI/2=4MHz × 12 = 48MHz */
            RCC_PLLCmd(DISABLE);
            RCC_PLLConfig(RCC_PLLSource_HSI_Div2, RCC_PLLMul_12);
            RCC_PLLCmd(ENABLE);
            timeout = 0x100000;
            while (RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET && --timeout) { __NOP(); }
            if (timeout) {
                RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);
                while (RCC_GetSYSCLKSource() != 0x08) { __NOP(); }
                /* USB prescaler: PLL/1 = 48MHz (PLL=48MHz) */
                RCC_USBCLKConfig(RCC_USBCLKSource_PLLCLK_Div1);
            }
        } else {
            /* HSE OK → PLL: HSE × 9 = 72MHz, USB prescaler = /1.5 → 48MHz */
            RCC_PLLCmd(DISABLE);
            RCC_PLLConfig(RCC_PLLSource_HSE_Div1, RCC_PLLMul_9);
            RCC_PLLCmd(ENABLE);
            timeout = 0x100000;
            while (RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET && --timeout) { __NOP(); }
            if (timeout) {
                RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);
                while (RCC_GetSYSCLKSource() != 0x08) { __NOP(); }
                RCC_USBCLKConfig(RCC_USBCLKSource_PLLCLK_1Div5);
            }
        }
    }

    /* ── GPIO / AFIO ── */
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOA | RCC_APB2Periph_AFIO, ENABLE);
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_USB, ENABLE);

    /* ── PA11(USB_DM), PA12(USB_DP) ── */
    gpio.GPIO_Pin   = GPIO_Pin_11 | GPIO_Pin_12;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    gpio.GPIO_Mode  = GPIO_Mode_AF_PP;   /* 复用推挽 */
    GPIO_Init(GPIOA, &gpio);

    /* ── USB 外设复位 ── */
    USB->CNTR = CNTR_FRES;
    for (volatile int i = 0; i < 200; i++) __NOP();
    USB->CNTR = 0;
    USB->ISTR = 0;
    USB->BTABLE = BTABLE_OFFSET;

    /* ── 清除 EP 寄存器 ── */
    for (ep = (uint16_t *)&USB->EP0R;
         ep <= (uint16_t *)&USB->EP7R; ep++) {
        *ep = 0;
    }

    /* ── 初始化缓冲区 ── */
    {
        volatile uint16_t *pma = (volatile uint16_t *)USB_BUF_BASE;
        for (int i = 0; i < 256; i++) *pma++ = 0;
    }

    /* ── 使能 USB 中断 ── */
    USB->CNTR = CNTR_CTRM | CNTR_RESETM | CNTR_SUSPM | CNTR_WKUPM;

    g_usb_configured = 0;
    g_rx_ready = 0;
}
