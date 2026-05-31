CC ?= gcc
STRIP ?= strip

NAME := Siuuuuuuu
SRC := src/$(NAME).c
BUILD_DIR := build
DIST_DIR := dist
DEBUG_BIN := $(BUILD_DIR)/$(NAME).debug
DIST_BIN := $(DIST_DIR)/$(NAME)

CFLAGS ?= -O2 -g -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

.PHONY: all clean release

all: $(DIST_BIN)

release: $(DIST_BIN)

$(BUILD_DIR) $(DIST_DIR):
	mkdir -p $@

$(DEBUG_BIN): $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(DIST_BIN): $(DEBUG_BIN) | $(DIST_DIR)
	cp $(DEBUG_BIN) $(DIST_BIN)
	$(STRIP) --strip-all $(DIST_BIN)

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
