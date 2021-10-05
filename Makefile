export C_INCLUDE_PATH=/usr/lib/musl/include
LDFLAGS=-L./opt/lib libcrypto.a -static 
CFLAGS=-I./opt/include -Os -Wall
CC=musl-gcc
OUT=lockpick

$(OUT): lockpick.c libcrypto.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


libcrypto.a:
	cp openssl-1.0.2/libcrypto.a .

openssl-1.0.2/libcrypto.a:
	./mk-libcrypto.sh

test: $(OUT)
	./$(OUT) test

run: $(OUT)
	./$(OUT) 192.168.98.1

clean: 
	rm -f lockpick libcrypto.a

distclean: clean
	make -C openssl-1.0.2 clean
