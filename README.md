## Description

A reimplementaion of AES (Advanced Encryption Standard)  
More infomation about it in [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

#### Note

Currently only the AES128 version works but is not fully work.

## Example

```c
#include "./aes.h"

int main(void) {
  const char *key = "Thats my Kung Fu";
  const char *txt = "aa bb aaa aaa";
  // Encrypted message
  //const char *emsg = "\x29\xC3\x50\x5F\x57\x14\x20\xF6\x40\x22\x99\xB3\x1A\x02\xD7\x3A"; //Two One Nine Two
  //const char *emsg = "\xce\x0d\x4c\x21\x45\x0a\x7d\x28\xb4\x54\x47\x43\x0c\xeb\x27\x93"; // Nguyen Tuan
  //const char *emsg = "\xf9\x97\x35\x44\x99\xb2\xfe\xcc\x69\x9b\x06\x5b\x7b\x41\xae\x4f"; // Nguyen Tuan Minh
  const char *emsg = "\xb2\xe2\xd3\x00\x9d\xf5\xa8\x97\x50\x60\xe0\xb8\x91\x55\xd6\xa9"; // aa bb aaa aaa


  State state = {0};

  printf("Encrypted message: ");
  state = AES_ENCRYPT(txt, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));
  
  printf("Encrypted message in hex form: ");
  print_current_state(&state);

  /* -------------------------------------------------- */

  printf("\n");
  printf("Decrypted message: ");
  
  for (int i = 0; i < Nb; ++i) {
    for (int j = 0; j < Nb; ++j) {
      state.state[i][j] = 0;
    }
  }

  state = AES_DECRYPT(emsg, key);
  printf("%s\n", from_state_matrix_to_plain_text(&state));

  printf("Decrypted message in hex form: ");
  print_current_state(&state);

  return 0;
```
