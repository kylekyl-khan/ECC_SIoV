CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c99 -D_POSIX_C_SOURCE=200809L
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
BIN = bin/siov

MIRACL_CORE_DIR ?= third_party/miracl-core/c
MIRACL_INCLUDE = -I$(MIRACL_CORE_DIR)/include
MIRACL_LIB ?= $(MIRACL_CORE_DIR)/lib/libcore.a

INCLUDES = -Iinclude $(MIRACL_INCLUDE)

all: $(BIN)

$(BIN): $(OBJ) | bin
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(MIRACL_LIB)

bin:
	mkdir -p bin

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
