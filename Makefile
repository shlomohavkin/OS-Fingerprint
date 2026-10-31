CC = gcc
TARGET ?= os-fingerprint
SRC_DIR ?= src
HEADER_DIR ?= headers
TEST_DIR ?= tests
BUILD_DIR ?= build
MAIN_SRC ?= main.c

CPPFLAGS += -I$(HEADER_DIR)
CFLAGS ?= -Wall -Wextra -g -O0
LDFLAGS ?=
LDLIBS ?= -lpcap -lm -lz

SOURCES := $(sort $(wildcard $(SRC_DIR)/*.c))
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
DEPENDENCIES := $(OBJECTS:.o=.d)

# Objects every test links against
LIB_OBJECTS := $(filter-out $(BUILD_DIR)/$(MAIN_SRC:.c=.o),$(OBJECTS))

# Test files, empty files are skipped
TEST_SOURCES := $(sort $(shell find $(TEST_DIR) -name 'test_*.c' -size +0 2>/dev/null))
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%,$(TEST_SOURCES))
TEST_DEPS := $(TEST_BINS:=.d)

.PHONY: all clean test

ifeq ($(strip $(SOURCES)),)
all test:
	@echo "No C source files found under $(SRC_DIR)/. Expected layout: src/*.c and headers/*.h."
	@exit 1
else
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

# Build one executable per test file
$(BUILD_DIR)/tests/%: $(TEST_DIR)/%.c $(LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP $< $(LIB_OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)

# Build and run all tests; stop at the first failure
test: $(TEST_BINS)
	@if [ -z "$(TEST_BINS)" ]; then echo "No tests found under $(TEST_DIR)/."; exit 1; fi
	@for t in $(TEST_BINS); do \
		echo "==> Running $$t"; \
		./$$t || { echo "FAILED: $$t"; exit 1; }; \
	done
	@echo "All tests passed."

-include $(DEPENDENCIES) $(TEST_DEPS)
endif

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
