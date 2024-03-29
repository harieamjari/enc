// The author disclaims copyright to this source code
// and releases it into the public domain.
//
// COMES WITH NO WARRANTY OR GUARANTEE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

extern void sha256sum(void *, void *, size_t);


const unsigned int skey_len = 32;

static inline void memxor(void *dst, void *buf, size_t s) {
  char *d = dst, *b = buf;
  for (size_t i = 0; i < s; i++)
    d[i] ^= b[i];
}

static void dencrypt(char *salt, FILE *fpin, FILE *fpout) {
  // modify this key to suit your needs
  unsigned char skey[32] = {
    0x80, 0x82, 0xe4, 0xb3, 0x92, 0x18, 0x35, 0x0d, 0x77, 0xd8, 0xd1, 0x8e,
    0xbe, 0x7a, 0xa2, 0x58, 0xce, 0xfd, 0x7e, 0xd7, 0x0f, 0x48, 0x84, 0xc0,
    0x9c, 0x61, 0xdf, 0x27, 0x22, 0x10, 0xe8, 0xca
  };

  // current key
  uint8_t ckey[32] = {0};
  // previous key
  uint8_t pkey[32] = {0};

  char buf[32];
  char saltk[32];
  {
    char s1[8 + skey_len];
    char s2[32];
    memcpy(s1, salt, 8);
    memcpy(s1 + 8, skey, skey_len);
    sha256sum(s2, s1, 8 + skey_len);

    memcpy(saltk, s2, 32);
    memxor(s2, skey, 32);
    sha256sum(ckey, s2, 32);
  }

  while (1) {
    memcpy(pkey, ckey, 32);
    sha256sum(ckey, saltk, 32);

    // update base key generator
    for (size_t i = 0; i < 32; i++) {
      //fprintf(stderr, "%02x -> ", saltk[i]);
      saltk[i] ^=  ((ckey[i] & 0xaa) | (pkey[i] & 0x55));
      //fprintf(stderr, "%02x\n", saltk[i]);
    }

    size_t s = fread(buf, 1, 32, fpin);
    if (s != 32 && !feof(fpin)) {
      assert(0);
    }
    memxor(buf, ckey, s);
    fwrite(buf, 1, s, fpout);
    
    if (feof(fpin))
      break;
  }
}

static void encrypt(FILE *fpin, FILE *fpout) {
  int fd;
  char salt[8];
  if ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
    fprintf(stderr, "failed to open /dev/urandom");
    abort();
  }
  if (read(fd, salt, 8) != 8) {
    assert(0);
  }
  close(fd);

  if (fwrite(salt, 1, 8, fpout) != 8) {
    assert(0);
  }

  dencrypt(salt, fpin, fpout);
}

static void decrypt(FILE *fpin, FILE *fpout) {
  char salt[8];

  if (fread(salt, 1, 8, fpin) != 8) {
    assert(0);
  }

  dencrypt(salt, fpin, fpout);
}

int main(int argc, char *argv[]){
  FILE *fp;
  if (argc == 1) {
    fprintf(stderr,
      "usage: %s e file > file.enc\n"
      "usage: %s d file.enc > file.dec\n"
      "usage: cat file | %s e > file.enc\n"
      "usage: cat file.enc | %s d > file.dec\n",
       argv[0], argv[0], 
       argv[0], argv[0]
    );
    return 1;
  }

  if (argc == 3)  {
    if ((fp = fopen(argv[2], "rb")) == NULL) {
      perror(argv[2]);
      return 1;
    }
  } else if (argc == 2)
    fp = stdin;
  else {
    assert(0);
  }

  if (argv[1][0] == 'e') {
    encrypt(fp, stdout);
  }
  else if (argv[1][0] == 'd') {
    decrypt(fp, stdout);
  } else {
    assert(0);
  }
   
  return 0;
}
