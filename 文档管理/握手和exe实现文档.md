# 实现文档

> 最后更新: 2026-06-18  
> 对应固件: `Syscall/main.c` + `Syscall/ch340_comm.c` + `Syscall/sec_core.c`  
> 对应上位机: `exe/secret_net0/`, `exe/work_net0/`, `exe/secret_net1/`

---

## 一、通信架构总览

```
┌──────────────────────────────────────────────────────┐
│ PC 端                                                │
│                                                      │
│  secret_net0/MasterTask.exe   密网下发任务 (阶段0)    │
│  work_net0/Agent.exe          工控采集加密 (阶段1)    │
│  secret_net1/MasterRecover.exe 密网解密回传 (阶段2)   │
│                                                      │
│  共享模块: serial_comm + crypto_win + protocol       │
└──────────────┬───────────────────────────────────────┘
               │  CH340 USB-TTL 串口
               │  9600 8N1, COM口
               │  帧协议: [0x7E][CMD][LEN][PAYLOAD][XOR]
┌──────────────┴───────────────────────────────────────┐
│ STM32F103C8                                          │
│                                                      │
│  USART1 重映射 → PB6(TX) / PB7(RX)                   │
│                                                      │
│  用户态 (PSP, 非特权)                                 │
│  ├─ main.c           状态机 + 业务逻辑                │
│  ├─ ch340_comm.c     串口帧收发 + 中断接收            │
│  ├─ sec_core.c       HMAC-SHA256 + SK 派生            │
│  └─ rgb_led.c        RGB LED 状态指示 (TIM2 PWM)     │
│                                                      │
│  内核态 (MSP, Handler Mode)                           │
│  └─ stm32f10x_it.c   SVC 路由 + 5 个内核服务函数      │
│                      (WriteTask / ReadTask /          │
│                       WriteData / ReadShake / ReadData)│
└──────────────────────────────────────────────────────┘
```

---

## 二、三阶段握手流程

### 阶段0：密网下发任务

```
MasterTask.exe                        STM32
══════════════                        ═════
                                      🔵 上电自检, 发 Hello(nonce_s)
  打开 COM7, 收到 Hello
  生成 nonce_m
  HMAC = HMAC(MK_CTRL, nonce_s||nonce_m)
  ── Handshake(CMD 0x02) ────────→   用 MK_CTRL 验 HMAC → PASS
                                      ← ACK(CMD 0x03, ok=1)
  派生 SK1                            派生 SK1 (= 同上, [:16])
  
  构造 TaskPayload (目标PLC, 数据点, 有效期)
  AES-GCM(SK1, task) 
  ── WriteTask(CMD 0x10) ────────→   解密 → SVC 0x10 硬件提权
                                      Kernel_WriteTask → 写入存储
                                      ← ACK(CMD 0x03, ok=1)
  收到 ACK
                                      销毁 SK1, 🔵 蓝灯
```

**实现文件:** `Syscall/main.c` (DOMAIN_SECRET 分支), `exe/secret_net0/main.c`

### 阶段1：工控采集加密

```
Agent.exe                             STM32
════════                              ═════
                                      🔵 上电, 发 Hello(nonce_s)
  收到 Hello
  生成 nonce_g
  HMAC = HMAC(MK_DATA, nonce_s||nonce_g)
  ── Handshake(CMD 0x02) ────────→   用 MK_DATA 验 HMAC → PASS
                                      ← ACK(CMD 0x03, ok=1)
  派生 SK2                            派生 SK2
                                      🟢 绿灯慢闪
                                      
                                      SVC 0x11: sys_ReadTask 读预存任务
                                      ← 数据请求(CMD 0x11)
  收到请求
  模拟 PLC 数据 (raw)
  inner = AES-GCM(MK_DATA, raw)
  outer = AES-GCM(SK2, inner)
  ── WriteData(CMD 0x12) ────────→   解密 outer → 得 inner
                                      SVC 0x12: sys_WriteData 暂存
                                      ← ACK(CMD 0x03, ok=1)
  收到 ACK
                                      销毁 SK2, 🟢 绿灯
```

**实现文件:** `Syscall/main.c` (DOMAIN_INDUSTRIAL 分支), `exe/work_net0/main.c`

### 阶段2：密网解密回传

```
MasterRecover.exe                     STM32
══════════════                        ═════
                                      🔵 上电, 发 Hello(nonce_s')
  收到 Hello
  生成 nonce_m'
  HMAC = HMAC(MK_CTRL, nonce_s'||nonce_m')
  ── Handshake(CMD 0x02) ────────→   用 MK_CTRL 验 HMAC → PASS
                                      ← ACK(CMD 0x03, ok=1)
  派生 SK1'                           派生 SK1' (≠ 阶段0 的 SK1)
  
  构建解密指令 (目标密文ID)
  ── ReadShake(CMD 0x19) ────────→   SVC 0x19: sys_ReadShake 验证指令
                                      SVC 0x1A: sys_ReadData 
                                        raw = AES-GCM-Dec(MK_DATA, inner)
                                        outer = AES-GCM-Enc(SK1', raw)
                                      ← ReadData(CMD 0x1A, outer)
  解密 outer → 得 raw 明文
                                      销毁 SK1', 🔵 蓝灯
```

**实现文件:** `Syscall/main.c` (DOMAIN_SECRET + CMD 0x19/0x1A 分支), `exe/secret_net1/main.c`

---

## 三、密钥体系

```
MK_CTRL (32B)                         MK_DATA (32B)
   │                                     │
   ├─ 阶段0 → SK1 (16B)                  ├─ 阶段1 → SK2 (16B)
   │   = HMAC(MK_CTRL, ns||nm)[:16]      │   = HMAC(MK_DATA, ns||ng)[:16]
   │                                     │
   └─ 阶段2 → SK1' (16B)                 │
       = HMAC(MK_CTRL, ns'||nm')[:16]    └─ 内层加密 inner = AES-GCM(MK_DATA, raw)

会话隔离: 每次握手生成全新 nonce → 全新 SK
         前次 SK 在断开前立即 SecCore_MemZero() 销毁
```

---

## 四、域识别机制

**密钥即身份。** STM32 收到 Handshake 后, 依次用两个根密钥验证 HMAC:

```c
result = SecCore_VerifyHandshake(frame, 48, MK_CTRL, 32);  // 试密网
if (result != 0) {
    g_ChallengeFailCount = 0;  // 重置失败计数
    g_FerryState = STATE_LOCK;
    result = SecCore_VerifyHandshake(frame, 48, MK_DATA, 32);  // 试工控
}
if (result == 0) → 哪个密钥匹配就激活对应侧
```

不需要 domain 字节, 不需要编译开关。攻击者不知道 MK_DATA 就无法伪装成工控侧。

---

## 五、串口帧协议

```
Byte 0:    0x7E      帧同步头
Byte 1:    CMD       命令字节
Byte 2:    LEN       载荷长度 (0~255)
Byte 3..:   PAYLOAD  载荷数据 (LEN 字节)
LastByte:  XOR       CMD ^ LEN ^ PAYLOAD[0] ^ ... ^ PAYLOAD[LEN-1]
```

| CMD | 宏定义 | 方向 | 阶段 | 载荷 |
|-----|--------|------|------|------|
| 0x01 | HELLO | STM32→PC | 0/1/2 | nonce_s(16B) |
| 0x02 | HANDSHAKE | PC→STM32 | 0/1/2 | nonce_h(16B) + HMAC(32B) |
| 0x03 | ACK | 双向 | 0/1/2 | status(1B) |
| 0x10 | WRITE_TASK | PC→STM32 | 0 | AES-GCM(SK1) 加密任务 |
| 0x11 | READ_TASK | STM32→PC | 1 | 数据请求 (SK2 加密) |
| 0x12 | WRITE_DATA | PC→STM32 | 1 | 双层密文 (SK2 外层) |
| 0x19 | READ_SHAKE | PC→STM32 | 2 | 解密指令 (SK1' 加密) |
| 0x1A | READ_DATA | STM32→PC | 2 | 解密明文 (SK1' 加密) |

---

## 六、SVC 硬件提权映射

| SVC 号 | 宏定义 | 内核函数 | 权限操作 |
|--------|--------|----------|---------|
| 0x10 | SVC_ID_WRITE_TASK | Kernel_WriteTask | 任务写入非易失存储 |
| 0x11 | SVC_ID_READ_TASK | Kernel_ReadTask | 读取预存任务 |
| 0x12 | SVC_ID_WRITE_DATA | Kernel_WriteData | 密文暂存写入 |
| 0x19 | SVC_ID_READ_SHAKE | Kernel_ReadShake | 解密指令验证 + 使能解密模块 |
| 0x1A | SVC_ID_READ_DATA | Kernel_ReadData | 密文盲泵回传 |

SVC 是用户态到内核态的**唯一通道**。所有敏感操作必须经过 SVC 硬件提权。

---

## 七、安全机制实现状态

| 机制 | 状态 | 说明 |
|------|:---:|------|
| HMAC-SHA256 挑战-应答 | ✅ 完成 | 恒定时间比对, 3次失败 PANIC |
| SHA-256 软件实现 | ✅ 完成 | 自测通过 (RFC 4231 TC1) |
| 会话密钥派生 (HKDF 简化) | ✅ 完成 | SK = HMAC(MK, ns\|\|nh)[:16] |
| 会话密钥隔离 | ✅ 完成 | 每轮全新 nonce, 销毁旧 SK |
| AES-128-GCM 加密 (PC端) | ✅ 完成 | Windows BCrypt API |
| AES-128-GCM 解密 (STM32) | 📋 待实现 | 软件 AES (tiny-AES-c/GmSSL), 内核态调用, 约 600 行 C, M3 上 15~20ms/200B |
| 恒定时间比对 | ✅ 完成 | volatile diff 累加 |
| 内存安全清零 | ✅ 完成 | SecCore_MemZero (volatile) |
| 挑战失败 PANIC | ✅ 完成 | STATE_CORE_PANIC → 红灯爆闪死锁 |
| 用户态/内核态隔离 | ✅ 完成 | SVC + PSP/MSP 分离 |
| Flash 写保护 (MPU) | ❌ 未实现 | 量产配置 RDP/MPU |
| 非易失任务存储 | ❌ Demo | Kernel_WriteTask 仅闪灯 |
| 密文暂存区 | ❌ Demo | Kernel_WriteData 仅闪灯 |
| 随机 nonce 生成 | ✅ ADC 噪声 | SysTick + 指令时序抖动 + ADC 温度传感器 LSB 三源混合 |

> **关于软件 AES:** STM32F103C8 无硬件 CRYP 外设, AES-GCM 需纯软件实现 (tiny-AES-c 约 600 行, M3 上 15~20ms/200B)。安全不依赖硬件加速——密钥由 SVC 隔离保护, 用户态代码通过 SVC 进内核态执行解密, 无需额外芯片。

---

## 八、PC 端 exe 清单

| exe | 路径 | 密钥 | 源码 | 功能 |
|-----|------|------|------|------|
| MasterTask.exe | `exe/secret_net0/` | MK_CTRL | main.c + protocol + serial_comm + crypto_win | 阶段0: Hello→Handshake→WriteTask |
| Agent.exe | `exe/work_net0/` | MK_DATA | main.c + protocol + serial_comm + crypto_win | 阶段1: Hello→Handshake→等数据请求→发 WriteData |
| MasterRecover.exe | `exe/secret_net1/` | MK_CTRL | main.c + protocol + serial_comm + crypto_win | 阶段2: Hello→Handshake→发 ReadShake→收 ReadData |

三个 exe 共享串口通信层 (`serial_comm`) 和加密层 (`crypto_win`), 仅 `main.c` 业务逻辑不同。

### 通用功能

- CH340 COM 口自动检测 (扫描 COM1~32, 取编号最高者)
- 串口帧协议 (0x7E 同步 + XOR 校验)
- HMAC-SHA256 + AES-128-GCM (Windows BCrypt)
- 缓存 Hello 丢弃 + ACK 循环等待
- Ctrl+C 安全退出

### 编译

```bash
cd exe/secret_net0 && gcc -O2 -o MasterTask.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
cd exe/work_net0   && gcc -O2 -o Agent.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
cd exe/secret_net1 && gcc -O2 -o MasterRecover.exe main.c serial_comm.c crypto_win.c protocol.c -lbcrypt
```

---

## 九、STM32 固件文件清单

| 文件 | 功能 |
|------|------|
| `Syscall/main.c` | 主状态机: 域识别、握手、命令分发 |
| `Syscall/ch340_comm.c` | USART1 初始化 (PB6/PB7, 9600), 中断接收状态机, 帧收发 |
| `Syscall/ch340_comm.h` | 帧常量 + API 声明 |
| `Syscall/sec_core.c` | SHA-256, HMAC-SHA256, 挑战-应答, SK 派生, 状态机 |
| `Syscall/sec_core.h` | 密钥常量, 状态枚举, API 声明 |
| `Syscall/rgb_led.c` | TIM2 PWM 三通道 RGB 驱动 (PA0/PA1/PA2) |
| `Syscall/stm32f10x_it.c` | SVC 路由 + 5 个内核服务函数 |
| `Syscall/syscall.h` | SVC 立即数定义 + 用户态调用声明 |

---

## 十、硬件引脚汇总

| 引脚 | 功能 | 说明 |
|------|------|------|
| PB6 | USART1_TX (重映射) | 接 CH340 RX |
| PB7 | USART1_RX (重映射) | 接 CH340 TX |
| PA0 | TIM2_CH1 | RGB 红灯 |
| PA1 | TIM2_CH2 | RGB 绿灯 |
| PA2 | TIM2_CH3 | RGB 蓝灯 |
| PC13 | GPIO 输出 | 板载 LED 诊断 |

波特率: **9600 bps, 8N1**
