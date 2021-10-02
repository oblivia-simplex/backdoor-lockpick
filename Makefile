export LD_LIBRARY_PATH=$(PWD)/opt/lib
LDFLAGS=-L./opt/lib opt/lib/libcrypto.a opt/lib/libssl.a -ldl
CFLAGS=-g -I./opt/include -O0
CC=gcc

all:
	$(CC) $(CFLAGS) -o chosen_plaintext_attack chosen_plaintext_attack.c $(LDFLAGS)


test: all
	./chosen_plaintext_attack test

run: all
	./chosen_plaintext_attack
