TARGET    = Agent.exe
SOURCES   = main.c serial_comm.c crypto_win.c protocol.c
OBJS      = $(SOURCES:.c=.o)
CC        = gcc
CFLAGS    = -Wall -Wextra -O2
LDFLAGS   = -lbcrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
