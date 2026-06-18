/**
 * @file    serial_comm.c
 * @brief   CH340 串口通信层实现
 *
 *          Windows COM 口操作关键步骤:
 *            1. SetupDi 枚举 GUID_DEVINTERFACE_COMPORT
 *            2. 检查 friendly name 或 hardware ID 中是否含 "CH340"
 *            3. CreateFile("\\.\COMx") 打开端口
 *            4. GetCommState / SetCommState → 115200-8-N-1
 *            5. SetCommTimeouts → 字节间超时
 *            6. ReadFile / WriteFile → 读写
 *
 *          帧同步: 搜索 0x7E 起始字节, 读取完整帧后验证 XOR 校验
 */

#include "serial_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* No external libs needed — uses CreateFile for COM port scan */

/*─────────────────────────────────────────────────────────
 * 辅助: 枚举所有 COM 口, 回调匹配函数
 *─────────────────────────────────────────────────────────*/
/*
 * 扫描 COM1~COM32, 收集所有可用 COM 口到列表中
 * 返回找到的 COM 口总数, ports[] 存储 COM 口号 (如 "COM3")
 */
static int scan_com_ports(char ports[][16], int max_ports)
{
    int    count = 0;
    char   path[32];
    HANDLE h;

    for (int i = 1; i <= 32 && count < max_ports; i++)
    {
        snprintf(path, sizeof(path), "\\\\.\\COM%d", i);
        h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            snprintf(ports[count], 16, "COM%d", i);
            count++;
        }
    }
    return count;
}

/*─────────────────────────────────────────────────────────
 * 列出所有 COM 口 (用于 --list)
 *─────────────────────────────────────────────────────────*/
static void list_com_ports(void)
{
    char ports[32][16];
    int  n = scan_com_ports(ports, 32);

    printf("  === System COM Ports ===\n");
    if (n == 0) {
        printf("    (no COM ports available)\n");
    } else {
        for (int i = 0; i < n; i++) {
            printf("    %s\n", ports[i]);
        }
    }
}

/*─────────────────────────────────────────────────────────
 * Serial_OpenDevice: 自动选择 COM 口
 *
 *   策略: USB 虚拟串口 (CH340) 通常分配较高 COM 号。
 *   取编号最高的可用 COM 口, 同时列出所有可选端口。
 *   如需指定, 使用: MasterTask.exe COM7
 *─────────────────────────────────────────────────────────*/
HANDLE Serial_OpenDevice(void)
{
    char ports[32][16];
    int  n = scan_com_ports(ports, 32);

    printf("  [Serial] Searching for COM port...\n");

    if (n == 0) {
        fprintf(stderr, "  [Serial] No COM port found. "
                "Check CH340 connection and driver.\n");
        fprintf(stderr, "  [Serial] Or specify: MasterTask.exe COM7\n");
        return INVALID_HANDLE_VALUE;
    }

    /* 列出所有可选端口 */
    printf("  [Serial] Available COM ports:");
    for (int i = 0; i < n; i++) {
        printf(" %s", ports[i]);
    }
    printf("\n");

    /*
     * 优先选编号最高的 (USB 虚拟串口通常高编号)。
     * 若只有一个 COM 口, 直接用。
     * 若多个, 选最后一个并提示用户可手动指定。
     */
    printf("  [Serial] Auto-selecting %s (highest number = likely USB serial)\n",
           ports[n - 1]);
    if (n > 1) {
        printf("  [Serial]   If wrong, specify: MasterTask.exe COM7\n");
    }

    return Serial_OpenComPort(ports[n - 1]);
}

/*─────────────────────────────────────────────────────────
 * Serial_OpenComPort: 打开指定 COM 口
 *─────────────────────────────────────────────────────────*/
HANDLE Serial_OpenComPort(const char *com_name)
{
    HANDLE hDev;
    char   path[64];
    DCB    dcb;
    COMMTIMEOUTS timeouts;

    /* 构造 NT 设备路径: "\\.\COM3" */
    if (strncmp(com_name, "\\\\.\\", 4) == 0) {
        strncpy(path, com_name, sizeof(path) - 1);
    } else {
        snprintf(path, sizeof(path), "\\\\.\\%s", com_name);
    }

    hDev = CreateFileA(path,
                       GENERIC_READ | GENERIC_WRITE,
                       0,        /* 独占访问 */
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "  [Serial] Cannot open %s (error %lu)\n",
                com_name, GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    /* ── 配置 DCB: 115200-8-N-1 ── */
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(hDev, &dcb)) {
        fprintf(stderr, "  [Serial] GetCommState failed\n");
        CloseHandle(hDev);
        return INVALID_HANDLE_VALUE;
    }

    dcb.BaudRate = SERIAL_BAUD;
    dcb.ByteSize = 8;
    dcb.Parity   = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary  = TRUE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;   /* 拉高 DTR */
    dcb.fRtsControl = RTS_CONTROL_ENABLE;   /* 拉高 RTS */

    if (!SetCommState(hDev, &dcb)) {
        fprintf(stderr, "  [Serial] SetCommState failed\n");
        CloseHandle(hDev);
        return INVALID_HANDLE_VALUE;
    }

    /* ── 超时设置 ── */
    timeouts.ReadIntervalTimeout         = 100;    /* 字节间超时 100ms */
    timeouts.ReadTotalTimeoutMultiplier  = 10;     /* 每字节 10ms */
    timeouts.ReadTotalTimeoutConstant    = 5000;   /* 总超时 5s */
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant   = 2000;

    if (!SetCommTimeouts(hDev, &timeouts)) {
        fprintf(stderr, "  [Serial] SetCommTimeouts failed\n");
        CloseHandle(hDev);
        return INVALID_HANDLE_VALUE;
    }

    /* 清空缓冲区 */
    PurgeComm(hDev, PURGE_RXCLEAR | PURGE_TXCLEAR);

    printf("  [Serial] %s opened (%u-8N1)\n", com_name, SERIAL_BAUD);
    return hDev;
}

/*─────────────────────────────────────────────────────────
 * Serial_CloseDevice
 *─────────────────────────────────────────────────────────*/
void Serial_CloseDevice(HANDLE hDev)
{
    if (hDev != INVALID_HANDLE_VALUE) {
        PurgeComm(hDev, PURGE_RXCLEAR | PURGE_TXCLEAR);
        CloseHandle(hDev);
    }
}

/*─────────────────────────────────────────────────────────
 * Serial_ReadFrame: 阻塞读取一帧
 *
 *   同步逻辑:
 *     1. 逐字节读取, 搜索 0x7E
 *     2. 找到后读 CMD, LEN, PAYLOAD, XOR
 *     3. 验证 XOR, 成功则返回
 *     4. 超时返回 0
 *─────────────────────────────────────────────────────────*/
int Serial_ReadFrame(HANDLE hDev, uint8_t *cmd, uint8_t *data,
                     uint8_t *len, uint32_t timeout_ms)
{
    uint8_t  byte;
    DWORD    bytesRead, startTime;
    int      state = 0;  /* 0=sync, 1=cmd, 2=len, 3=data, 4=xor */
    uint8_t  rx_cmd, rx_len, rx_idx, rx_xor;
    uint8_t  rx_buf[SERIAL_PAYLOAD_MAX];

    startTime = GetTickCount();

    while (1)
    {
        /* 检查超时 */
        if (GetTickCount() - startTime > timeout_ms) {
            return 0;
        }

        /* 读取单个字节 */
        if (!ReadFile(hDev, &byte, 1, &bytesRead, NULL) || bytesRead == 0) {
            /* 字节间无数据, 继续轮询 */
            Sleep(1);
            continue;
        }

        switch (state) {

        case 0:  /* 等待 0x7E */
            if (byte == 0x7E) {
                state = 1;
            }
            break;

        case 1:  /* CMD */
            rx_cmd = byte;
            rx_xor = byte;
            state = 2;
            break;

        case 2:  /* LEN */
            rx_len = byte;
            rx_xor ^= byte;
            if (rx_len > SERIAL_PAYLOAD_MAX) {
                state = 0;  /* 非法, 重新同步 */
            } else if (rx_len == 0) {
                state = 4;  /* 无载荷, 直接校验 */
            } else {
                rx_idx = 0;
                state = 3;
            }
            break;

        case 3:  /* PAYLOAD */
            rx_buf[rx_idx] = byte;
            rx_xor ^= byte;
            rx_idx++;
            if (rx_idx >= rx_len) {
                state = 4;
            }
            break;

        case 4:  /* XOR */
            if (byte == rx_xor) {
                /* 有效帧 */
                *cmd = rx_cmd;
                *len = rx_len;
                memcpy(data, rx_buf, rx_len);
                return 1;
            }
            /* XOR 不匹配, 重新同步 */
            state = 0;
            break;
        }
    }
}

/*─────────────────────────────────────────────────────────
 * Serial_WriteFrame: 发送一帧
 *─────────────────────────────────────────────────────────*/
int Serial_WriteFrame(HANDLE hDev, uint8_t cmd,
                      const uint8_t *data, uint8_t len)
{
    uint8_t buf[SERIAL_FRAME_MAX];
    uint8_t xor_val, total;
    DWORD   written;
    int     idx = 0;

    /* 帧头 */
    buf[idx++] = 0x7E;

    /* CMD */
    buf[idx++] = cmd;
    xor_val = cmd;

    /* LEN */
    buf[idx++] = len;
    xor_val ^= len;

    /* PAYLOAD */
    while (len--) {
        buf[idx] = *data;
        xor_val ^= *data;
        data++;
        idx++;
    }

    /* XOR */
    buf[idx++] = xor_val;

    total = idx;

    if (!WriteFile(hDev, buf, total, &written, NULL)) {
        fprintf(stderr, "  [Serial] WriteFile failed (error %lu)\n",
                GetLastError());
        return -1;
    }
    if (written != total) {
        fprintf(stderr, "  [Serial] Short write: %lu/%u bytes\n",
                written, total);
        return -2;
    }

    return 0;
}

/*─────────────────────────────────────────────────────────
 * Serial_ListAllPorts: 列出所有 COM 口
 *─────────────────────────────────────────────────────────*/
void Serial_FlushRx(HANDLE hDev)
{
    PurgeComm(hDev, PURGE_RXCLEAR);
}

void Serial_ListAllPorts(void)
{
    list_com_ports();
}
