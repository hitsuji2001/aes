#ifndef __AES_H__
#define __AES_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "./aes_util.h"

#define Nb 4

#if defined(AES256)
  #define Nk 8
  #define Nr 14
#elif defined(AES192)
  #define Nk 6
  #define Nr 12
#else
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

//////////////////// Parser ////////////////////

// Message should be 16 bytes
void from_string_to_key(const char *str, Key *key);
void from_plain_text_to_state_matrix(const char *txt, State *state);
void print_message_to_hex(const char *msg);

char *from_state_matrix_to_plain_text(const State *state);

// If echoable != 0, these function will print out the output message
// in hexa form and the result string itself, else it will return
// just the result string.
State AES_ENCRYPT(const char *mssg, const char *key);
State AES_DECRYPT(const char *code, const char *key);
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

#endif // __AES_H__
