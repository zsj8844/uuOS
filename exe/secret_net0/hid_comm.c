/**
 * @file    hid_comm.c
 * @brief   USB HID 通信层实现
 *
 *          Windows HID API 关键步骤:
 *            1. HidD_GetHidGuid()    → 获取 HID GUID
 *            2. SetupDiGetClassDevs() → 枚举 HID 设备
 *            3. SetupDiEnumDeviceInterfaces() → 遍历设备
 *            4. SetupDiGetDeviceInterfaceDetail() → 获取设备路径
 *            5. CreateFile()         → 打开设备
 *            6. HidD_GetAttributes() → 检查 VID/PID
 *            7. ReadFile()/WriteFile() → 读写 Report
 *
 *          链接: -lhid -lsetupapi
 */

#include "hid_comm.h"

#include <stdio.h>
#include <string.h>
#include <initguid.h>
#include <hidclass.h>
#include <hidsdi.h>
#include <setupapi.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

/*══════════════════════════════════════════════════════════
 * 打开设备
 *══════════════════════════════════════════════════════════*/
HANDLE HID_OpenDevice(uint16_t vid, uint16_t pid)
{
    GUID    hidGuid;
    HDEVINFO devInfo;
    SP_DEVICE_INTERFACE_DATA ifData;
    SP_DEVICE_INTERFACE_DETAIL_DATA_W *ifDetail = NULL;
    HANDLE  hDev = INVALID_HANDLE_VALUE;
    BOOL    found = FALSE;
    DWORD   idx = 0;
    DWORD   requiredSize = 0;

    if (vid == 0) vid = STM32_HID_VID;
    if (pid == 0) pid = STM32_HID_PID;

    HidD_GetHidGuid(&hidGuid);
    devInfo = SetupDiGetClassDevsW(&hidGuid, NULL, NULL,
                                   DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "SetupDiGetClassDevs failed: %lu\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    ifData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    while (SetupDiEnumDeviceInterfaces(devInfo, NULL, &hidGuid, idx, &ifData))
    {
        /* 第一次调用获取所需缓冲区大小 */
        SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, NULL, 0,
                                         &requiredSize, NULL);
        if (requiredSize == 0) { idx++; continue; }

        ifDetail = (SP_DEVICE_INTERFACE_DETAIL_DATA_W *)malloc(requiredSize);
        if (!ifDetail) break;
        ifDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, ifDetail,
                                              requiredSize, NULL, NULL)) {
            free(ifDetail); idx++; continue;
        }

        /* 打开设备 */
        hDev = CreateFileW(ifDetail->DevicePath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, /* 异步 I/O (支持超时) */
                           NULL);
        if (hDev != INVALID_HANDLE_VALUE) {
            /* 检查 VID/PID */
            HIDD_ATTRIBUTES attr;
            attr.Size = sizeof(attr);
            if (HidD_GetAttributes(hDev, &attr)) {
                if (attr.VendorID == vid && attr.ProductID == pid) {
                    printf("  [HID] Found device VID=0x%04X PID=0x%04X Ver=%u\n",
                           attr.VendorID, attr.ProductID, attr.VersionNumber);
                    found = TRUE;
                    free(ifDetail);
                    break;
                }
            }
            CloseHandle(hDev);
            hDev = INVALID_HANDLE_VALUE;
        }

        free(ifDetail);
        idx++;
    }

    SetupDiDestroyDeviceInfoList(devInfo);

    if (!found) {
        fprintf(stderr, "  [HID] Device not found VID=0x%04X PID=0x%04X\n", vid, pid);
        return INVALID_HANDLE_VALUE;
    }

    /* 设置读取超时 (在 ReadFile 中通过 OVERLAPPED 实现) */
    return hDev;
}

/*══════════════════════════════════════════════════════════
 * 关闭设备
 *══════════════════════════════════════════════════════════*/
void HID_CloseDevice(HANDLE hDev)
{
    if (hDev != INVALID_HANDLE_VALUE) {
        CloseHandle(hDev);
    }
}

/*══════════════════════════════════════════════════════════
 * 读取帧 (阻塞, 等待 STM32 主动发送)
 *══════════════════════════════════════════════════════════*/
int HID_ReadFrame(HANDLE hDev, uint8_t *report, uint32_t timeout_ms)
{
    OVERLAPPED ov = {0};
    DWORD      bytesRead = 0;
    BOOL       result;

    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return -1;

    /* Report ID = 0 (不使用 Report ID) */
    report[0] = 0x00;

    result = ReadFile(hDev, report, HID_REPORT_SIZE + 1, /* +1 for Report ID */
                      NULL, &ov);
    if (!result && GetLastError() == ERROR_IO_PENDING) {
        DWORD waitResult = WaitForSingleObject(ov.hEvent, timeout_ms);
        if (waitResult == WAIT_TIMEOUT) {
            CancelIo(hDev);
            CloseHandle(ov.hEvent);
            return 0;  /* 超时 */
        }
        if (waitResult != WAIT_OBJECT_0) {
            CloseHandle(ov.hEvent);
            return -2;
        }
        result = GetOverlappedResult(hDev, &ov, &bytesRead, FALSE);
    }

    CloseHandle(ov.hEvent);

    if (!result) return -3;

    /* 如果有 Report ID 前缀, 去掉它 */
    if (bytesRead == HID_REPORT_SIZE + 1 && report[0] == 0x00) {
        memmove(report, report + 1, HID_REPORT_SIZE);
        bytesRead = HID_REPORT_SIZE;
    }

    return (int)bytesRead;
}

/*══════════════════════════════════════════════════════════
 * 写入帧
 *══════════════════════════════════════════════════════════*/
int HID_WriteFrame(HANDLE hDev, const uint8_t *report)
{
    OVERLAPPED ov = {0};
    DWORD      bytesWritten = 0;
    BOOL       result;
    uint8_t    outBuf[HID_REPORT_SIZE + 1];

    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return -1;

    /* Report ID = 0, 数据从字节 1 开始 */
    outBuf[0] = 0x00;
    memcpy(outBuf + 1, report, HID_REPORT_SIZE);

    result = WriteFile(hDev, outBuf, HID_REPORT_SIZE + 1,
                       NULL, &ov);
    if (!result && GetLastError() == ERROR_IO_PENDING) {
        DWORD waitResult = WaitForSingleObject(ov.hEvent, HID_WRITE_TIMEOUT_MS);
        if (waitResult != WAIT_OBJECT_0) {
            CancelIo(hDev);
            CloseHandle(ov.hEvent);
            return -2;
        }
        result = GetOverlappedResult(hDev, &ov, &bytesWritten, FALSE);
    }

    CloseHandle(ov.hEvent);

    if (!result) return -3;
    return 0;
}

/*══════════════════════════════════════════════════════════
 * 调试工具
 *══════════════════════════════════════════════════════════*/
void HID_DumpDeviceInfo(HANDLE hDev)
{
    HIDD_ATTRIBUTES attr = {0};
    WCHAR            mfg[128] = {0};
    WCHAR            prod[128] = {0};
    attr.Size = sizeof(attr);
    if (HidD_GetAttributes(hDev, &attr)) {
        printf("  VID=0x%04X  PID=0x%04X  Ver=%u\n",
               attr.VendorID, attr.ProductID, attr.VersionNumber);
    }

    if (HidD_GetManufacturerString(hDev, mfg, sizeof(mfg))) {
        wprintf(L"  Mfg: %s\n", mfg);
    }
    if (HidD_GetProductString(hDev, prod, sizeof(prod))) {
        wprintf(L"  Product: %s\n", prod);
    }
}

void HID_ListAllDevices(void)
{
    GUID    hidGuid;
    HDEVINFO devInfo;
    SP_DEVICE_INTERFACE_DATA ifData;
    DWORD   idx = 0;

    printf("  === System HID Devices ===\n");
    HidD_GetHidGuid(&hidGuid);
    devInfo = SetupDiGetClassDevsW(&hidGuid, NULL, NULL,
                                   DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    ifData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    while (SetupDiEnumDeviceInterfaces(devInfo, NULL, &hidGuid, idx, &ifData))
    {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, NULL, 0,
                                         &requiredSize, NULL);
        if (requiredSize == 0) { idx++; continue; }

        SP_DEVICE_INTERFACE_DETAIL_DATA_W *ifDetail =
            (SP_DEVICE_INTERFACE_DETAIL_DATA_W *)malloc(requiredSize);
        if (!ifDetail) break;
        ifDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, ifDetail,
                                             requiredSize, NULL, NULL))
        {
            HANDLE h = CreateFileW(ifDetail->DevicePath, 0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attr;
                attr.Size = sizeof(attr);
                if (HidD_GetAttributes(h, &attr)) {
                    printf("  [%lu] VID=0x%04X PID=0x%04X\n",
                           idx, attr.VendorID, attr.ProductID);
                }
                CloseHandle(h);
            }
        }
        free(ifDetail);
        idx++;
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    printf("  Total: %lu HID devices\n", idx);
}
