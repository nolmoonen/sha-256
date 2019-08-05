#include <stdio.h> // printf
#include <stdint.h> // uint32_t and uint64_t
#include <mem.h> // strlen
#include <stdlib.h> // malloc

/*
 * Size definitions
 */
#define WORDS8_IN_WORD32 (sizeof(uint32_t) / sizeof(uint8_t))

#define WORDS32_IN_M_BLOCK 64

#define BITS_IN_WORD8 8
#define BITS_IN_WORD32 32
#define BITS_IN_WORD64 64

#define BITS_IN_BLOCK 512
#define WORDS8_IN_BLOCK 64
#define WORDS32_IN_BLOCK 16

#define WORDS32_IN_HASH 8

/*
 * ASCII definitions.
 */

#define ASCII_VALUES_START 32 // index of first value in ASCII table that is expected in a hash
#define NROF_ASCII_VALUES 128 // amount of values in ASCII table

#define LETTERS_ONLY // whether only letters are expected when dehasing, greatly improves computing time

#ifdef LETTERS_ONLY

#define FIRST_LOWER_LETTER_VALUE 97 // ASCII a
#define LAST_LOWER_LETTER_VALUE 122 // ASCII z

#define FIRST_UPPER_LETTER_VALUE 65 // ASCII A
#define LAST_UPPER_LETTER_VALUE 90 // ASCII Z

#endif

typedef uint32_t block[WORDS32_IN_BLOCK];

/*
 * sha-265 functions
 */

uint32_t rotr(uint32_t x, uint32_t n);

uint32_t sha(uint32_t x, uint32_t n);

uint32_t sigma_0(uint32_t x);

uint32_t sigma_1(uint32_t x);

uint32_t big_sigma_0(uint32_t x);

uint32_t big_sigma_1(uint32_t x);

uint32_t ch(uint32_t x, uint32_t y, uint32_t z);

uint32_t maj(uint32_t x, uint32_t y, uint32_t z);

/**
 * Converts a hex character into an integer value.
 */
uint8_t hex_to_int(char c);

/**
 * Converts a 64 character hex string (256 bit) into an array of word 32 in little endian.
 */
int string_to_hash(uint32_t *hash, char *s);

/**
 * Attempts to dehash a hash by finding all strings up to a certain max_length.
 */
void dehash(uint32_t MAX_LEN, const uint32_t *secret);

/**
 * Attempts to dehash a hash by finding all permutations of a string of a fixed length.
 */
void
find_string(uint32_t index, uint32_t MAX_LEN, uint8_t *data, const uint32_t *secret, uint32_t *done, uint32_t *result);

/**
 * ASCII hashing.
 */
uint32_t *hash(uint32_t *hash, uint8_t *message);

/**
 * Prints a hash.
 */
void print_hash(uint32_t *hash);

int main() {
    int mode; // whether we want to hash or dehash
    int cont = 1; // whether we want to continue or stop

    while (cont) {
        printf("Hash (0) or dehash (1)?");
        scanf("%d", &mode);

        switch (mode) {
            case 0: {
                // calculate a hash
                char *string = (char *) malloc(64 + 1);
                printf("put in a secret (at most 64 characters): ");
                scanf("%s", string);

                uint32_t *result = (uint32_t *) malloc(sizeof(uint32_t) * 8);
                print_hash(hash(result, (uint8_t *) string));
                free(result);
                break;
            }
            case 1: {
                // brute force a string
                uint32_t *result = (uint32_t *) malloc(sizeof(uint32_t) * 8);
                char *string = (char *) malloc(64 + 1);
                printf("put in a hash (64 characters): ");
                scanf("%s", string);

                string_to_hash(result, string);
                dehash(10, result);
                free(result);
                break;
            }
            default:
                printf("please use provided format\n");
        }

        printf("Stop (0) or continue (1)?");
        scanf("%d", &cont);
    }

    return 0;
}

uint8_t hex_to_int(char c) {
    if (c > 96) return (uint8_t) (c - 87);
    if (c > 64) return (uint8_t) (c - 55);
    return (uint8_t) (c - 48);
}

int string_to_hash(uint32_t *hash, char *s) {
    for (uint32_t i = 0; i < 8; i++) {
        hash[i] = 0;

        for (uint32_t j = 0; j < 8; j++) {
            hash[i] |= (hex_to_int(s[i * 8 + (7 - j)])) << (j * 4);
        }
    }

    return 0;
}

uint32_t *hash(uint32_t *hash, uint8_t *message) {
    /*
     * Pre processing
     */
    // length of message
    uint32_t nrof_words8 = strlen((const char *) message);

    // number of blocks required
    uint64_t nrof_blocks = (nrof_words8 * BITS_IN_WORD8 + 1 + BITS_IN_WORD64 - 1) / BITS_IN_BLOCK + 1;

    block blocks[nrof_blocks];

    for (uint32_t i = 0; i < nrof_blocks; i++) {
        for (uint32_t j = 0; j < WORDS32_IN_BLOCK; j++) {
            blocks[i][j] = 0;
            for (uint32_t k = 0; k < WORDS8_IN_WORD32; k++) {
                uint32_t uint8_t_index = i * WORDS8_IN_BLOCK + j * WORDS8_IN_WORD32 + k;
                if (uint8_t_index < nrof_words8) {
                    blocks[i][j] |= (((uint32_t) message[uint8_t_index])
                            << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - k - 1)));
                }
            }
        }
    }

    uint32_t temp = (((uint32_t) 0x80) << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - (nrof_words8 % 4) - 1)));
    blocks[nrof_words8 / WORDS8_IN_BLOCK][nrof_words8 / 4] |= temp;
    blocks[nrof_blocks - 1][WORDS32_IN_BLOCK - 2] = (uint32_t) (((uint64_t) (nrof_words8 * BITS_IN_WORD8))
            >> BITS_IN_WORD32);
    blocks[nrof_blocks - 1][WORDS32_IN_BLOCK - 1] = (uint32_t) (nrof_words8 * BITS_IN_WORD8);

#ifdef DEBUG
    // prints blocks
    for (uint32_t i = 0; i < nrof_blocks; i++) {
        printf("preprocessed hexadecimal improvement (%d):\n", i);
        for (uint32_t n = 0; n < WORDS32_IN_BLOCK; n++) {
            printf("%08x ", blocks[i][n]);
            if ((n + 1) % (WORDS32_IN_BLOCK / 2) == 0) printf("\n");
        }
    }
#endif

    /*
     * Processing
     */
    const uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    hash[0] = H[0];
    hash[1] = H[1];
    hash[2] = H[2];
    hash[3] = H[3];
    hash[4] = H[4];
    hash[5] = H[5];
    hash[6] = H[6];
    hash[7] = H[7];

    uint32_t a, b, c, d, e, f, g, h;

    for (uint64_t t = 0; t < nrof_blocks; t++) {
        // prepare block
        uint32_t W[WORDS32_IN_M_BLOCK];
        for (uint32_t i = 0; i < WORDS32_IN_BLOCK; i++) {
            W[i] = blocks[t][i];
        }
        for (uint32_t i = WORDS32_IN_BLOCK; i < WORDS32_IN_M_BLOCK; i++) {
            W[i] = sigma_1(W[i - 2]) + W[i - 7] + sigma_0(W[i - 15]) + W[i - 16];
        }

        // 64 rounds
        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];

        uint32_t T1, T2;
        for (uint32_t i = 0; i < 64; i++) {
            T1 = h + big_sigma_1(e) + ch(e, f, g) + K[i] + W[i];
            T2 = big_sigma_0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        hash[0] = hash[0] + a;
        hash[1] = hash[1] + b;
        hash[2] = hash[2] + c;
        hash[3] = hash[3] + d;
        hash[4] = hash[4] + e;
        hash[5] = hash[5] + f;
        hash[6] = hash[6] + g;
        hash[7] = hash[7] + h;
    }

    return hash;
}

void find_string(uint32_t index, const uint32_t MAX_LEN, uint8_t *data, const uint32_t *secret, uint32_t *done,
                 uint32_t *result) {
    if (!*done) {
        if (index >= MAX_LEN) {
            hash(result, data);
            *done = 1;
            for (int i = 0; i < WORDS32_IN_HASH; i++) {
                if (result[i] != secret[i]) {
                    *done = 0;
                    break;
                }
            }
            if (*done) {
                printf("secret found: %s\n", data);
            }
        } else {
#ifdef LETTERS_ONLY
            for (int i = FIRST_UPPER_LETTER_VALUE; i < LAST_UPPER_LETTER_VALUE + 1; i++) {
                data[index] = (uint8_t) i;
                find_string(index + 1, MAX_LEN, data, secret, done, result);
            }
            for (int i = FIRST_LOWER_LETTER_VALUE; i < LAST_LOWER_LETTER_VALUE + 1; i++) {
                data[index] = (uint8_t) i;
                find_string(index + 1, MAX_LEN, data, secret, done, result);
            }
#else
            for (int i = ASCII_VALUES_START; i < NROF_ASCII_VALUES; i++) {
                data[index] = (uint8_t) i;
                find_string(index + 1, MAX_LEN, data, secret, done, hash);
            }
#endif
        }
    }
}

void dehash(uint32_t MAX_LEN, const uint32_t *secret) {
    const uint32_t MIN_STRING_LEN = 1;
    uint8_t *data;
    uint32_t *hash = malloc(sizeof(uint32_t) * 8);
    uint32_t *done = malloc(sizeof(uint32_t));
    *done = 0;
    for (uint32_t i = MIN_STRING_LEN; i < MIN_STRING_LEN + MAX_LEN; i++) {
        data = (uint8_t *) malloc(i + 1);
        data[i] = (uint8_t) 0; // null terminator
        find_string(0, i, data, secret, done, hash);
        free(data);

        if (*done) {
            break;
        }

        printf("done with %u\n", i);
    }
    free(done);
    free(hash);
}

void print_hash(uint32_t *hash) {
    for (uint32_t i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (BITS_IN_WORD32 - n));
}

inline uint32_t sha(uint32_t x, uint32_t n) {
    return x >> n;
}

inline uint32_t sigma_0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ sha(x, 3);
}

inline uint32_t sigma_1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ sha(x, 10);
}

inline uint32_t big_sigma_0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t big_sigma_1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}