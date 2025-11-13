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

$(TARGET): bin $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf bin

run: all
	./bin/siov --count 3 --message-size 64 --verify on --trace off
