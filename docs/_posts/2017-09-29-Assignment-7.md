---
title:  Assignment 7
description: Create a Custom Crypter
order: 7
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

For this challenge, we will be creating an encrypter and a decrypter, for which I chose to use the [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) (TEA).  Below is the implementation in c:

```c
#include <stdint.h>

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
```

Despite this algorithm being notoriously tiny, codewise, it proved to have pretty substantial challenges.  Unlike RC4, which is a stream cipher, TEA is a block cipher, so our first challenge is to parse and chunk our input shellcode to meet TEA's requirements.  I used the following functions to help accomplish this:

```c
int parse(unsigned char *str, unsigned char c) {
  char *pr = str, *pw = str;
  while (*pr) {
    *pw = *pr++;
    pw += (*pw != c);
  }
  *pw = '\0';
  return 0;
}

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
  char *tmp = *dest;
  for (i = 0; i < srclen; i++) {
    *tmp++ = '\\';
    *tmp++ = 'x';
    for (j = 0; j < len; j++) {
      *tmp++ = src[i++];
    }
    i--;
  }
  *tmp++ = '\0';
  return 0;
}
```

The implementation of the parser is quite simple, shown below:

```c
  ...
  beforeLength = strlen(argv[1]);
  before = malloc(sizeof(unsigned char)*beforeLength + 1);
  memset(before, '\0', beforeLength);
  strncpy(before, argv[1], beforeLength);
  memset(&before[beforeLength], '\0', 1);

  printf("[+] Input (%i): %s\n", strlen(before)/4, before);

  parse(before, '\\');
  parse(before, 'x');
  
  printf("[+] Parsed (%i): %s\n", strlen(before)/2, before);
  ...
```

By parsing out "\x" from our shellcode, I can properly ingest the shellcode for processing by the encryption algorithm.  Next, I combined the chunking implementation with the encrypting, shown with the code below:

```c
  ...
  chunkedLength = beforeLength;
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

    printf("[~] Encrypting: {0x%08x, 0x%08x}\n", v0, v1);
    uint32_t v[] = {v0, v1};
    encrypt(v, KEY);
    printf("[+] Encrypted: {0x%08x, 0x%08x}\n", v[0], v[1]);

    unsigned char buf[BUFSIZE + 1];
    memset(buf, '\0', BUFSIZE);
    sprintf(buf, "%08x", v[0]);
    memset(&buf[BUFSIZE], '\0', 1);
    strcat(after, buf);

    memset(buf, '\0', BUFSIZE);
    sprintf(buf, "%08x", v[1]);
    memset(&buf[BUFSIZE], '\0', 1);
    strcat(after, buf);

    token = strtok(NULL, "\n");
  }
  ...
```

As you can see, I used **strtok** to iterate through the chunked character strings, then converted every 8 characters into a 4 byte unsigned long using **strtoul**, 2 of which are needed for each iteration of TEA.  Once every chunk has been encrypted, a string of bytes can now be formatted for output.

```c
  ...
  finalLength = afterLength * 2;
  final = malloc(sizeof(unsigned char)*finalLength + 1);
  memset(final, '\0', finalLength);
  finalize(after, &final, 2);
  memset(&final[finalLength], '\0', 1);
  printf("[+] Encrypted (%i): %s\n", strlen(final)/4, final);
  ...
```

With the newly encrypted shellcode formatted and output, that shellcode can be directly copied into our decrypter, which follows almost exactly the same process in reverse.  The only substantial difference is that instead of formatting the resulting shellcode for output, we format it for execution.

```c
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

int main() {
  ...
  finalLength = afterLength / 2;
  final = malloc(sizeof(unsigned char)*finalLength + 1);
  memset(final, '\0', finalLength);
  finalize(after, &final, 2);
  memset(&final[finalLength], '\0', 1);

  int (*ret)() = (int(*)())final;
  ret();
  ...
```

And with that final change, we now have a working shellcode-encrypter-decrypter pair using TEA.  You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_7](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_7).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
