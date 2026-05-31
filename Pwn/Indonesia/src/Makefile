CC ?= gcc
STRIP ?= strip
CFLAGS ?= -O2 -Wall -Wextra -fno-stack-protector -D_FORTIFY_SOURCE=0 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro -Wl,-z,now

TARGET := indonesia
SRC := indonesia.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	$(STRIP) -s $(TARGET)

clean:
	rm -f $(TARGET)
