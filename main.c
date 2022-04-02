#include "./aes.h"

int main(void) {
  const char *key = "Thats my Kung Fu";
  const char *txt = "Two One Nine Two";
  char *emsg = "\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A";
  State state = {0};

  printf("Encrypted message: ");
  state = AES_ENCRYPT(txt, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));
  printf("Decrypted message: ");
  state = AES_DECRYPT(emsg, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));
}
