#include "./aes.h"

// Message should be 16 bytes
void from_string_to_key(const char *str, Key *key) {
  for (size_t i = 0; i < strlen(str); ++i) {
    key->key[i] = str[i];
  }
}

void from_plain_text_to_state_matrix(const char *txt, State *state) {
  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      state->state[row][col] = 0x00;
    }
  }

  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      state->state[row][col] = txt[col * Nb + row];
    }
  }
}

char *from_state_matrix_to_plain_text(const State *state) {
  static char mess[128] = {0};
  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      mess[col * Nb + row] = state->state[row][col];
    }
  }

  return mess;
}

// Deprecated
void print_message_to_hex(const char *msg) {
  for (size_t i = 0; i < strlen(msg); ++i) {
    printf("x%02x ", msg[i]);
  }
  printf("\n");
}

State AES_ENCRYPT(const char *mssg, const char *key) {
  Key key_mat = {0};
  State state = {0};
  RoundKey round_key = {0};

  // Parsing
  from_string_to_key(key, &key_mat);
  from_plain_text_to_state_matrix(mssg, &state);

  key_expansion(&round_key, &key_mat);
  
  aes_encrypt(&state, &round_key);

  return state;
}

State AES_DECRYPT(const char *mssg, const char *key) {
  Key key_mat = {0};
  State state = {0};
  RoundKey round_key = {0};

  // Parsing
  from_string_to_key(key, &key_mat);
  from_plain_text_to_state_matrix(mssg, &state);

  key_expansion(&round_key, &key_mat);
  
  aes_decrypt(&state, &round_key);

  return state;
}
//////////////// End of Parser /////////////////


//////////////////// Encryption Module ////////////////////
void sub_bytes(State *state) {
  for (int col = 0; col < Nb; ++col) {
    for (int row = 0; row < Nb; ++row) {
      int x = state->state[row][col] >> 4;
      int y = state->state[row][col] & 0x0F;
      state->state[row][col] = sbox[x * 16 + y];
    }
  }
}

void shift_rows(State *state) {
  uint8_t temp;

  // Row 2
  temp = state->state[1][0];
  state->state[1][0] = state->state[1][1];
  state->state[1][1] = state->state[1][2];
  state->state[1][2] = state->state[1][3];
  state->state[1][3] = temp;

  // Row 3
  temp = state->state[2][0];
  state->state[2][0] = state->state[2][2];
  state->state[2][2] = temp;

  temp = state->state[2][3];
  state->state[2][3] = state->state[2][1];
  state->state[2][1] = temp;

  // Row 4
  temp = state->state[3][3];
  state->state[3][3] = state->state[3][2];
  state->state[3][2] = state->state[3][1];
  state->state[3][1] = state->state[3][0];
  state->state[3][0] = temp;
}

void mix_columns(State *state) {
  mul_with_gf(state, GF);
}

void add_round_key(State *state, const RoundKey *round_key, int round) {
  uint8_t words[Nk][Nk];

  for (int i = 0; i < Nk; ++i) {
    for (int j = 0; j < Nk; ++j) {
      words[j][i] = (round_key->word[Nk * round + i] >> (8 * (4 - j - 1))) & 0xFF;
    }
  }

  for (int i = 0; i < Nb; ++i) {
    for (int j = 0; j < Nb; ++j) {
      state->state[i][j] ^= words[i][j];
    }
  }
}

void aes_encrypt(State *state, const RoundKey *round_key) {
  add_round_key(state, round_key, 0);

  for (int i = 0; i < Nr - 1; ++i) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_key, i + 1);
  }

  // Last round
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, round_key, Nr);
}
///////////////// End of Encryption Module ////////////////

//////////////////// Decryption Module ////////////////////
void sub_bytes_inv(State *state) {
  for (int col = 0; col < Nb; ++col) {
    for (int row = 0; row < Nb; ++row) {
      int x = state->state[row][col] >> 4;
      int y = state->state[row][col] & 0x0F;
      state->state[row][col] = rsbox[x * 16 + y];
    }
  }
}

void shift_rows_inv(State *state) {
  uint8_t temp;

  // Row 2
  temp = state->state[1][3];
  state->state[1][3] = state->state[1][2];
  state->state[1][2] = state->state[1][1];
  state->state[1][1] = state->state[1][0];
  state->state[1][0] = temp;

  // Row 3
  temp = state->state[2][3];
  state->state[2][3] = state->state[2][1];
  state->state[2][1] = temp;

  temp = state->state[2][0];
  state->state[2][0] = state->state[2][2];
  state->state[2][2] = temp;

  // Row 4
  temp = state->state[3][0];
  state->state[3][0] = state->state[3][1];
  state->state[3][1] = state->state[3][2];
  state->state[3][2] = state->state[3][3];
  state->state[3][3] = temp;
}

void mix_columns_inv(State *state) {
  mul_with_gf(state, rGF);
}

void aes_decrypt(State *state, const RoundKey *round_key) {
  add_round_key(state, round_key, Nr);

  for (int i = 0; i < Nr - 1; ++i) {
    shift_rows_inv(state);
    sub_bytes_inv(state);
    add_round_key(state, round_key, Nr - i - 1);
    mix_columns_inv(state);
  }

  // Last round
  shift_rows_inv(state);
  sub_bytes_inv(state);
  add_round_key(state, round_key, 0);
}
///////////////// End of Decryption Module ////////////////

/////////////////// Key Expansion Module //////////////////
uint32_t rot_word(const uint32_t word) {
  uint32_t num = 0;
  uint8_t words[4] = {0};
  uint8_t res[4] = {0};

  for (int i = 0; i < 4; ++i) {
    words[i] = (word >> (8 * (4 - i))) & 0xFF;
  }

  for (int i = 0; i < 4; ++i) {
    res[i] = words[i + 1];
  }
  res[3] = words[0];

  for (int i = 0; i < 4; ++i) {
    num ^= (res[i] << (8 * (4 - i))) & 0xFFFFFFFF;
  }

  return num;
}
 
uint32_t sub_word(const uint32_t word) {
  uint32_t num = 0;
  uint8_t res[4] = {0};

  for (int i = 0; i < 4; ++i) {
    res[i] = (word >> (8 * (4 - i))) & 0xFF;
  }

  for (int i = 0; i < 4; ++i) {
    res[i] = sbox[res[i]];
  }

  for (int i = 0; i < 4; ++i) {
    num ^= (res[i] << (8 * (4 - i))) & 0xFFFFFFFF;
  }

  return num;
}

void key_expansion(RoundKey *round_key, const Key *key) {
  // First 4 words
  for (int i = 0; i < Nk; ++i) {
    round_key->word[i] = 0x00;
    for (int j = 0; j < 4; ++j) {
      round_key->word[i] ^= (key->key[i * Nb + j] << (8 * (4 - j - 1))) & 0xFFFFFFFF;
    }
  }

  for (int i = Nk; i < 4 * (Nr + 1); ++i) {
    if (i % Nk == 0) {
      round_key->word[i] = round_key->word[i - Nk] ^ (sub_word(rot_word(round_key->word[i - 1])) ^ (RCon[i / Nk] << (8 * 3)));
    } else if (Nk >= 6 && i % Nk == 4) {
      round_key->word[i] = round_key->word[i - Nk] ^ sub_word(round_key->word[i - 1]);
    } else {
      round_key->word[i] = round_key->word[i - Nk] ^ round_key->word[i - 1];
    }
  }
}
//////////////// End of Key Expansion Module //////////////

//////////////////// Utils ////////////////////
void print_current_state(const State *state) {
  for (int i = 0; i < Nb; ++i) {
    for (int j = 0; j < Nb; ++j) {
      printf("x%02x ", state->state[j][i]);
    }
  }
  printf("\n");
}

void matrix_mul(const uint8_t *gf, uint8_t *arr) {
  uint8_t res[4] = {0};

  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      res[row] ^= gmul((gf[row * Nb + col]), arr[col]);
    }
  }

  for (int i = 0; i < Nb; ++i) {
    arr[i] = res[i];
  }
}

void mul_with_gf(State *state, const uint8_t *gf) {
  uint8_t arr[4] = {0};
  
  for (int col = 0; col < Nb; ++col) {
    // Seperate a column of the state matrix
    for (int i = 0; i < Nb; ++i) {
      arr[i] = state->state[i][col];
    }

    // Result has been saved to arr after this function
    matrix_mul(gf, arr);

    // Save the result back to the state matrix
    for (int i = 0; i < Nb; ++i) {
      state->state[i][col] = arr[i];
    }
  }
}

// See: https://en.wikipedia.org/wiki/Finite_field_arithmetic for more information
uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0; // accumulator for the product of the multiplication
 
 while (a != 0 && b != 0) {
    if (b & 0x01) {
      // Basicly check if b is odd
      // if the polynomial for b has a constant term, add(XOR) the corresponding a to p
      p ^= a;
    }
    if (a & 0x80) {
      // Check if a >= 128(0x80)
      // GF modulo: if a has a nonzero term x^7, then must be reduced when it becomes x^8
      a = (a << 1) ^ 0x11b; // subtract (XOR) the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible
    } else {
      a <<= 1; // equivalent to a*x
    }
    b >>= 1;
  }
  return p;
}

///////////////// End of Utils ////////////////
