# Build the IPv4 OS fingerprinting program.
# Expected layout:
#   headers/*.h
#   src/*.c
#   nmap-os-db

CC = gcc
TARGET ?= os-fingerprint
SRC_DIR ?= src
HEADER_DIR ?= headers
BUILD_DIR ?= build

CPPFLAGS += -I$(HEADER_DIR)
CFLAGS ?= -Wall -Wextra -g -O0
LDFLAGS ?=
LDLIBS ?= -lpcap -lm -lz

SOURCES := $(sort $(wildcard $(SRC_DIR)/*.c))
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
DEPENDENCIES := $(OBJECTS:.o=.d)

.PHONY: all clean help

ifeq ($(strip $(SOURCES)),)
all:
	@echo "No C source files found under $(SRC_DIR)/. Expected layout: src/*.c and headers/*.h."
	@exit 1
else
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPENDENCIES)
endif

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

help:
	@echo "make          Build $(TARGET)"
	@echo "make clean    Remove compiled files"
	@echo "make help     Show this help"
