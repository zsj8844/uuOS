# SecuFerry-OS 密网任务下发工具 Makefile
#
# 支持 MinGW-w64 和 MSVC (cl.exe)
#
# MinGW:
#   make
#
# MSVC (Developer Command Prompt):
#   make TOOLCHAIN=msvc
#
# 清理:
#   make clean

TARGET    = MasterTask.exe
SOURCES   = main.c hid_comm.c crypto_win.c protocol.c
OBJS      = $(SOURCES:.c=.o)

# ── MinGW-w64 ──────────────────────────────────────────
CC        = gcc
CFLAGS    = -Wall -Wextra -O2 -municode
LDFLAGS   = -lhid -lsetupapi -lbcrypt

# ── MSVC override ──────────────────────────────────────
ifeq ($(TOOLCHAIN),msvc)
  CC      = cl
  CFLAGS  = /nologo /W3 /O2 /Fe$(TARGET)
  LDFLAGS = /link hid.lib setupapi.lib bcrypt.lib
  OBJS    = $(SOURCES)
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
ifeq ($(TOOLCHAIN),msvc)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS)
else
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
endif

ifeq ($(TOOLCHAIN),msvc)
# MSVC: 无 .o 中间文件, 直接编译链接
%.obj: %.c
	$(CC) /c $(CFLAGS) $<
else
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
endif

clean:
ifeq ($(TOOLCHAIN),msvc)
	del /Q $(TARGET) *.obj 2>nul || true
else
	rm -f $(TARGET) $(OBJS)
endif
