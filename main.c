#define AES_IMPLEMENTATION
#include "./aes.h"

int main(void) {
  const char *key = "Thats my Kung Fu";
  const char *txt = "aa bb aaa aaa";
  
  char encrypted[256] = {0};
  char decrypted[256] = {0};

  // encrypted message
  //const char *emsg = "\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A"; //Two One Nine Two
  //const char *emsg = "\xce\x0d\x4c\x21\x45\x0a\x7d\x28\xb4\x54\x47\x43\x0c\xeb\x27\x93"; // Nguyen Tuan
  //const char *emsg = "\xf9\x97\x35\x44\x99\xb2\xfe\xcc\x69\x9b\x06\x5b\x7b\x41\xae\x4f"; // Nguyen Tuan Minh
  const char *emsg = "\xb2\xe2\xd3\x00\x9d\xf5\xa8\x97\x50\x60\xe0\xb8\x91\x55\xd6\xa9"; // aa bb aaa aaa
  

  printf("Encrypted message: ");
  AES_ENCRYPT(txt, key, encrypted);
  
  printf("%s\n", encrypted);
  /* -------------------------------------------------- */

  printf("\n");
  printf("Decrypted message: ");
  
  AES_DECRYPT(emsg, key, decrypted);
  printf("%s\n", decrypted);

  return 0;
}
