export LD_LIBRARY_PATH=$(PWD)/opt/lib
LDFLAGS=-L./opt/lib opt/lib/libcrypto.a opt/lib/libssl.a -ldl
CFLAGS=-g -I./opt/include -O0
CC=gcc
OUT=lockpick

$(OUT): lockpick.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(OUT)
	./$(OUT) test

run: $(OUT)
	./$(OUT) 192.168.98.1
