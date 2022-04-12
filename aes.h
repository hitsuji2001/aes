#ifndef __AES_INCLUDE_GUARD__
#define __AES_INCLUDE_GUARD__

/***************************** Function *****************************/
void AES_ENCRYPT(const char *mssg, const char *key, char encrypted_msg[]);
void AES_DECRYPT(const char *code, const char *key, char decrypted_msg[]);
/************************* End of Function *************************/

#ifdef AES_IMPLEMENTATION

#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>

#define Nb 4

#if defined(AES256)
  #define Nk 8
  #define Nr 14
#elif defined(AES192)
  #define Nk 6
  #define Nr 12
#else // Default will be AES128
  #define Nk 4
  #define Nr 10
#endif // AES(type)

typedef struct {
  uint8_t state[Nb][Nb];
} State;

typedef struct {
  uint32_t word[4 * (Nr + 1)];
} RoundKey;

typedef struct {
  uint8_t key[Nb * Nb];
} Key;

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t GF[16] = {
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02
};

static const uint8_t rGF[16] = {
  0x0e, 0x0b, 0x0d, 0x09,
  0x09, 0x0e, 0x0b, 0x0d,
  0x0d, 0x09, 0x0e, 0x0b,
  0x0b, 0x0d, 0x09, 0x0e
};

// The first 0x00 is just a filler and will never be used
static const uint8_t RCon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

//////////////////// Parser ////////////////////

// Currently message should be 16 bytes
void from_string_to_key(const char *str, Key *key);
void from_plain_text_to_state_matrix(const char *txt, State *state);
void print_message_to_hex(const char *msg);

// Deprecated
char *from_state_matrix_to_plain_text(const State *state);

//////////////// End of Parser /////////////////

//////////////////// Encryption Module ////////////////////
void sub_bytes(State *state);
void shift_rows(State *state);
void mix_columns(State *state);
void add_round_key(State *state, const RoundKey *round_key, int round);

void aes_encrypt(State *state, const RoundKey *round_key);
///////////////// End of Encryption Module ////////////////

//////////////////// Decryption Module ////////////////////
void sub_bytes_inv(State *state);
void shift_rows_inv(State *state);
void mix_columns_inv(State *state);

void aes_decrypt(State *state, const RoundKey *round_key);
///////////////// End of Decryption Module ////////////////

/////////////////// Key Expansion Module //////////////////
// See: https://en.wikipedia.org/wiki/AES_key_schedule
// for more information about key expansion module
uint32_t rot_word(const uint32_t word);
uint32_t sub_word(const uint32_t word);

void key_expansion(RoundKey *round_key, const Key *key);
//////////////// End of Key Expansion Module //////////////

//////////////////// Utils ////////////////////
void print_current_state(const State *state);
void matrix_mul(const uint8_t *gf, uint8_t *arr);
void mul_with_gf(State *state, const uint8_t *gf);

// See: https://en.wikipedia.org/wiki/Finite_field_arithmetic
// for more information about multiplication in GF(2^8) field
uint8_t gmul(uint8_t a, uint8_t b);

///////////////// End of Utils ////////////////

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

void AES_ENCRYPT(const char *mssg, const char *key, char encrypted_msg[]) {
  Key key_mat = {0};
  State state = {0};
  RoundKey round_key = {0};

  // Parsing
  from_string_to_key(key, &key_mat);
  from_plain_text_to_state_matrix(mssg, &state);

  key_expansion(&round_key, &key_mat);
  
  aes_encrypt(&state, &round_key);

  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      encrypted_msg[col * Nb + row] = state.state[row][col];
    }
  }
}

void AES_DECRYPT(const char *code, const char *key, char decrypted_msg[]) {
  Key key_mat = {0};
  State state = {0};
  RoundKey round_key = {0};

  // Parsing
  from_string_to_key(key, &key_mat);
  from_plain_text_to_state_matrix(code, &state);

  key_expansion(&round_key, &key_mat);
  
  aes_decrypt(&state, &round_key);

  for (int row = 0; row < Nb; ++row) {
    for (int col = 0; col < Nb; ++col) {
      decrypted_msg[col * Nb + row] = state.state[row][col];
    }
  }
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

#endif // AES_IMPLEMENTATION
#endif // __AES_INCLUDE_GUARD__
