#include <stdio.h>
#include <string.h>

#include "test/test.h"
#include "src/common.h"
#include "src/scrypt.h"

typedef struct scrypt_block_mix_test_s scrypt_block_mix_test_t;
typedef struct scrypt_ro_mix_test_s scrypt_ro_mix_test_t;
typedef struct scrypt_scrypt_test_s scrypt_scrypt_test_t;

struct scrypt_block_mix_test_s {
  unsigned int r;
  uint8_t input[128];
  uint8_t expected[128];
};

struct scrypt_ro_mix_test_s {
  unsigned int r;
  unsigned int n;
  uint8_t input[128];
  uint8_t expected[128];
};

struct scrypt_scrypt_test_s {
  const char* passphrase;
  const char* salt;

  unsigned int r;
  unsigned int n;
  unsigned int p;

  uint8_t expected[64];
};

SCRYPT_TEST(scrypt_block_mix) {
  size_t i;

  scrypt_block_mix_test_t tests[] = {
    /* https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-8 */
    {
      .r = 1,
      .input = {
        0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4,
        0x10, 0x8c, 0xf5, 0xab, 0xe9, 0x12, 0xff, 0xdd,
        0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e,
        0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad,
        0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8, 0x7b,
        0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29,
        0x09, 0x4f, 0x01, 0x84, 0x63, 0x95, 0x74, 0xf3,
        0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,

        0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22,
        0x6c, 0x25, 0xb5, 0x4d, 0xa8, 0x63, 0x70, 0xfb,
        0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb,
        0x8f, 0xfc, 0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0,
        0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5, 0xfe,
        0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b,
        0x7f, 0x4d, 0x1c, 0xad, 0x6a, 0x52, 0x3c, 0xda,
        0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89
      },
      .expected = {
        0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99,
        0x3b, 0x81, 0xca, 0xcb, 0x02, 0x0c, 0xef, 0x05,
        0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d,
        0xfd, 0x7b, 0x1c, 0x63, 0x96, 0x68, 0x2f, 0x29,
        0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6, 0xbc,
        0xfe, 0x6b, 0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba,
        0xe4, 0x24, 0xcc, 0x10, 0x2c, 0x91, 0x74, 0x5c,
        0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81,

        0x20, 0xed, 0xc9, 0x75, 0x32, 0x38, 0x81, 0xa8,
        0x05, 0x40, 0xf6, 0x4c, 0x16, 0x2d, 0xcd, 0x3c,
        0x21, 0x07, 0x7c, 0xfe, 0x5f, 0x8d, 0x5f, 0xe2,
        0xb1, 0xa4, 0x16, 0x8f, 0x95, 0x36, 0x78, 0xb7,
        0x7d, 0x3b, 0x3d, 0x80, 0x3b, 0x60, 0xe4, 0xab,
        0x92, 0x09, 0x96, 0xe5, 0x9b, 0x4d, 0x53, 0xb6,
        0x5d, 0x2a, 0x22, 0x58, 0x77, 0xd5, 0xed, 0xf5,
        0x84, 0x2c, 0xb9, 0xf1, 0x4e, 0xef, 0xe4, 0x25
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    scrypt_block_mix_test_t* v;
    uint8_t out[sizeof(v->expected)];
    size_t j;

    v = &tests[i];

    scrypt_block_mix(v->input, v->r, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j]){
        printf("0x%02x =1= 0x%02x \n",
                out[j],
                v->expected[j]);
        continue;
      }

      fprintf(stderr,
              "0x%02x != 0x%02x at %d (test vector: %d)\n",
              out[j],
              v->expected[j],
              (int) j,
              (int) i);
      ASSERT(0, "scrypt_block_mix failure");
    }
  }
}


SCRYPT_TEST(scrypt_ro_mix) {
  size_t i;

  scrypt_ro_mix_test_t tests[] = {
    /* https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-8 */
    {
      .r = 1,
      .n = 16,
      .input = {
        0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4,
        0x10, 0x8c, 0xf5, 0xab, 0xe9, 0x12, 0xff, 0xdd,
        0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e,
        0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad,
        0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8, 0x7b,
        0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29,
        0x09, 0x4f, 0x01, 0x84, 0x63, 0x95, 0x74, 0xf3,
        0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
        0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22,
        0x6c, 0x25, 0xb5, 0x4d, 0xa8, 0x63, 0x70, 0xfb,
        0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb,
        0x8f, 0xfc, 0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0,
        0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5, 0xfe,
        0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b,
        0x7f, 0x4d, 0x1c, 0xad, 0x6a, 0x52, 0x3c, 0xda,
        0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89
      },
      .expected = {
        0x79, 0xcc, 0xc1, 0x93, 0x62, 0x9d, 0xeb, 0xca,
        0x04, 0x7f, 0x0b, 0x70, 0x60, 0x4b, 0xf6, 0xb6,
        0x2c, 0xe3, 0xdd, 0x4a, 0x96, 0x26, 0xe3, 0x55,
        0xfa, 0xfc, 0x61, 0x98, 0xe6, 0xea, 0x2b, 0x46,
        0xd5, 0x84, 0x13, 0x67, 0x3b, 0x99, 0xb0, 0x29,
        0xd6, 0x65, 0xc3, 0x57, 0x60, 0x1f, 0xb4, 0x26,
        0xa0, 0xb2, 0xf4, 0xbb, 0xa2, 0x00, 0xee, 0x9f,
        0x0a, 0x43, 0xd1, 0x9b, 0x57, 0x1a, 0x9c, 0x71,
        0xef, 0x11, 0x42, 0xe6, 0x5d, 0x5a, 0x26, 0x6f,
        0xdd, 0xca, 0x83, 0x2c, 0xe5, 0x9f, 0xaa, 0x7c,
        0xac, 0x0b, 0x9c, 0xf1, 0xbe, 0x2b, 0xff, 0xca,
        0x30, 0x0d, 0x01, 0xee, 0x38, 0x76, 0x19, 0xc4,
        0xae, 0x12, 0xfd, 0x44, 0x38, 0xf2, 0x03, 0xa0,
        0xe4, 0xe1, 0xc4, 0x7e, 0xc3, 0x14, 0x86, 0x1f,
        0x4e, 0x90, 0x87, 0xcb, 0x33, 0x39, 0x6a, 0x68,
        0x73, 0xe8, 0xf9, 0xd2, 0x53, 0x9a, 0x4b, 0x8e
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    scrypt_ro_mix_test_t* v;
    scrypt_state_t state;
    uint8_t out[sizeof(v->expected)];
    size_t j;

    v = &tests[i];

    state.r = v->r;
    state.n = v->n;
    state.p = 1;
    ASSERT(0 == scrypt_state_init(&state), "Failed to alloc state");

    scrypt_ro_mix(&state, v->input, out);
    scrypt_state_destroy(&state);

    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j]){
        printf("0x%02x =2= 0x%02x \n",
                out[j],
                v->expected[j]);
        continue;
      }

      fprintf(stderr,
              "0x%02x != 0x%02x at %d (test vector: %d)\n",
              out[j],
              v->expected[j],
              (int) j,
              (int) i);
      ASSERT(0, "scrypt failure");
    }
  }
}


SCRYPT_TEST(scrypt) {
  size_t i;

  scrypt_scrypt_test_t tests[] = {
    /* https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-10 */
    {
      .n = 16,
      .r = 1,
      .p = 1,
      .passphrase = "",
      .salt = "",
      .expected = {
        0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
        0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
        0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
        0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
        0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
        0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
        0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
        0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
      }
    },
    {
      .n = 1024,
      .r = 8,
      .p = 16,
      .passphrase = "password",
      .salt = "NaCl",
      .expected = {
        0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
        0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
        0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
        0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
        0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
        0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
        0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
        0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
      }
    },
    {
      .n = 16384,
      .r = 8,
      .p = 1,
      .passphrase = "pleaseletmein",
      .salt = "SodiumChloride",
      .expected = {
        0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48,
        0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
        0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
        0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
        0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
        0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
        0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
        0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87
      }
    },
    {
      .n = 1048576,
      .r = 8,
      .p = 1,
      .passphrase = "pleaseletmein",
      .salt = "SodiumChloride",
      .expected = {
        0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae,
        0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81,
        0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d,
        0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47,
        0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f,
        0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
        0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb,
        0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    scrypt_scrypt_test_t* v;
    scrypt_state_t state;
    uint8_t out[sizeof(v->expected)];
    size_t j;

    v = &tests[i];

    state.n = v->n;
    state.r = v->r;
    state.p = v->p;
    ASSERT(0 == scrypt_state_init(&state), "Failed to alloc state");

    scrypt(&state,
           (const uint8_t*) v->passphrase,
           strlen(v->passphrase),
           (const uint8_t*) v->salt,
           strlen(v->salt),
           out,
           sizeof(out));
    scrypt_state_destroy(&state);

    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j]) {
        printf("0x%02x =3= 0x%02x \n",
                out[j],
                v->expected[j]);
        continue;
      }

      fprintf(stderr,
              "0x%02x != 0x%02x at %d (test vector: %d)\n",
              out[j],
              v->expected[j],
              (int) j,
              (int) i);
      ASSERT(0, "scrypt_ro_mix failure");
    }
  }
}
