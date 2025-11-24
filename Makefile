# Makefile at project root
CC       := gcc
CFLAGS   := -O2 -Wall -Wextra
LDFLAGS  := -lpbc -lgmp
TARGET   := bin/siov
SRC      := src/siov.c

.PHONY: all clean run

all: $(TARGET)

bin:
	mkdir -p bin

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
