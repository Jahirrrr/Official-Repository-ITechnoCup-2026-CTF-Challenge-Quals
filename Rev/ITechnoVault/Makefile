CC := x86_64-w64-mingw32-gcc
CFLAGS ?= -Os -Wall -Wextra -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-ident
LDFLAGS ?= -s -Wl,--gc-sections

TARGET := ./public/itechno_vault.exe
SRC := challenge.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
