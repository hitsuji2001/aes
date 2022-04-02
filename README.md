## Description

A reimplementaion of AES (Advanced Encryption Standard)  
More infomation about it in [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## Example

```c
#include "./aes.h"

int main(void) {
  const char *key = "Thats my Kung Fu";
  const char *txt = "Two One Nine Two";
  // Encrypted message
  char *emsg = "\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A";

  State state = {0};

  printf("Encrypted message: ");
  state = AES_ENCRYPT(txt, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));
  
  printf("Encrypted message in hex form: ");
  print_current_state(&state);

  printf("\n");
  printf("Decrypted message: ");
  state = AES_DECRYPT(emsg, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));

  printf("Decrypted message in hex form: ");
  print_current_state(&state);

  return 0;
}
```
