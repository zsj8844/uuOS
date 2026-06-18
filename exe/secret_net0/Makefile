# SecuFerry-OS 密网任务下发工具 Makefile
#
# Transport: CH340 Serial (COM port)
#
# MinGW-w64:
#   make
#
# MSVC (Developer Command Prompt):
#   make TOOLCHAIN=msvc
#
# 清理:
#   make clean

TARGET    = MasterTask.exe
SOURCES   = main.c serial_comm.c crypto_win.c protocol.c
OBJS      = $(SOURCES:.c=.o)

# ── MinGW-w64 ──────────────────────────────────────────
CC        = gcc
CFLAGS    = -Wall -Wextra -O2
LDFLAGS   = -lbcrypt

# ── MSVC override ──────────────────────────────────────
ifeq ($(TOOLCHAIN),msvc)
  CC      = cl
  CFLAGS  = /nologo /W3 /O2 /Fe$(TARGET)
  LDFLAGS = /link bcrypt.lib
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
# MSVC: no intermediate .o
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
