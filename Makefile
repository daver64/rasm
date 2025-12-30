CC ?= gcc
CFLAGS ?= -std=c17 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
BIN := rasm

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

build:
	@mkdir -p $@

clean:
	rm -rf build $(BIN)

test: $(BIN)
	bash tests/smoke.sh

.PHONY: all clean test
