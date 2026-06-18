TARGET    = MasterRecover.exe
SOURCES   = main.c serial_comm.c crypto_win.c protocol.c
CC        = gcc
CFLAGS    = -Wall -Wextra -O2
LDFLAGS   = -lbcrypt

all: $(TARGET)
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	rm -f $(TARGET)
