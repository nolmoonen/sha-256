#include <stdio.h> // printf
#include <stdint.h> // uint32_t and uint64_t
#include <mem.h> // strlen
#include <stdlib.h> // malloc

#define WORDS8_IN_WORD32 4

#define WORDS32_IN_M_BLOCK 64

#define BITS_IN_WORD8 8
#define BITS_IN_WORD32 32
#define BITS_IN_WORD64 64

#define WORDS8_IN_BLOCK 64
#define WORDS32_IN_BLOCK 16
#define BITS_IN_BLOCK 512

// first ascii character to try
#define ASCII_VALUES_START 33
#define NROF_ASCII_VALUES 128

//#define DEBUG 0

typedef uint8_t word8;
typedef uint32_t word32;
typedef uint64_t word64;

typedef word32 block[WORDS32_IN_BLOCK];

word32 rotr(word32 x, word32 n);

word32 sha(word32 x, word32 n);

word32 sigma_0(word32 x);

word32 sigma_1(word32 x);

word32 big_sigma_0(word32 x);

word32 big_sigma_1(word32 x);

word32 ch(word32 x, word32 y, word32 z);

word32 maj(word32 x, word32 y, word32 z);

/**
 * Find all strings up to a certain max_length.
 */
void find_all_strings(const word32 MAX_LEN, const word32 *secret);

/**
 * Finds all permutations of a string of a fixed length.
 */
void find_string(word32 index, const word32 MAX_LEN, word8 *data, const word32 *secret, word32 *done);

/**
 * ASCII hashing.
 */
word32 *hash_test(word32 *hash, word8 *message);

/**
 * Prints a hash.
 */
void print_hash(word32 *hash);

// abd
const word32 SEC0[] = {0xa52d159f, 0x262b2c6d, 0xdb724a61, 0x840befc3, 0x6eb30c88, 0x877a4030, 0xb65cbe86, 0x298449c9};
// ???
const word32 SEC1[] = {0x23D46EF4, 0x374DB1E8, 0x3A8ECB77, 0xA99BA9D1, 0x2835D911, 0xFF8915C4, 0xD20E4A71, 0xAE179DFD};

int main() {
    // brute force a string
    find_all_strings(10, SEC1);

//    // calculate a hash
//    word32 *hash = malloc(sizeof(int32_t) * 8);
//    print_hash(hash_test(hash, (word8 *) "abd"));
//    free(hash);
}

word32 *hash_test(word32 *hash, word8 *message) {
    /*
     * Pre processing
     */
    // append 0b10000000 to message
    word32 nrof_words8 = strlen((const char *) message);
    word8 *data = (word8 *) malloc(nrof_words8 + 1);

    for (int i = 0; i < nrof_words8; i++) {
        data[i] = (word8) message[i];
    }
    data[nrof_words8] = 0x80;

    // nrof_words8 includes the padded 0b10000000
    nrof_words8 = nrof_words8 + 1;

    // number of blocks required
    word64 nrof_blocks = (nrof_words8 * BITS_IN_WORD8 + BITS_IN_WORD64 - 1) / BITS_IN_BLOCK + 1;

    block blocks[nrof_blocks];

    for (word32 i = 0; i < nrof_blocks; i++) {
        for (word32 j = 0; j < WORDS32_IN_BLOCK; j++) {
            blocks[i][j] = 0;
            for (word32 k = 0; k < WORDS8_IN_WORD32; k++) {
                word32 word8_index = i * WORDS8_IN_BLOCK + j * WORDS8_IN_WORD32 + k;
                if (word8_index < nrof_words8) {
                    word32 value = data[word8_index];
                    word32 temp = (((word32) value) << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - k - 1)));
                    blocks[i][j] = blocks[i][j] | temp;
                }
            }
        }
    }

    blocks[nrof_blocks - 1][WORDS32_IN_BLOCK - 2] = (word32) (((word64) ((nrof_words8 - 1) * BITS_IN_WORD8))
            >> BITS_IN_WORD32);
    blocks[nrof_blocks - 1][WORDS32_IN_BLOCK - 1] = (word32) ((nrof_words8 - 1) * BITS_IN_WORD8);

#ifdef DEBUG
    // prints blocks
    for (word32 i = 0; i < nrof_blocks; i++) {
        printf("preprocessed hexadecimal improvement (%d):\n", i);
        for (word32 n = 0; n < WORDS32_IN_BLOCK; n++) {
            printf("%08x ", blocks[i][n]);
            if ((n + 1) % (WORDS32_IN_BLOCK / 2) == 0) printf("\n");
        }
    }
#endif

    /*
     * Processing
     */
    const word32 h_0_0 = 0x6a09e667;
    const word32 h_1_0 = 0xbb67ae85;
    const word32 h_2_0 = 0x3c6ef372;
    const word32 h_3_0 = 0xa54ff53a;
    const word32 h_4_0 = 0x510e527f;
    const word32 h_5_0 = 0x9b05688c;
    const word32 h_6_0 = 0x1f83d9ab;
    const word32 h_7_0 = 0x5be0cd19;

    const word32 K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    word32 h_0 = h_0_0;
    word32 h_1 = h_1_0;
    word32 h_2 = h_2_0;
    word32 h_3 = h_3_0;
    word32 h_4 = h_4_0;
    word32 h_5 = h_5_0;
    word32 h_6 = h_6_0;
    word32 h_7 = h_7_0;

    word32 a;
    word32 b;
    word32 c;
    word32 d;
    word32 e;
    word32 f;
    word32 g;
    word32 h;

    for (word32 t = 0; t < nrof_blocks; t++) {
        // prepare block
        word32 W[WORDS32_IN_M_BLOCK];
        for (word32 i = 0; i < WORDS32_IN_BLOCK; i++) {
            W[i] = blocks[t][i];
        }
        for (word32 i = WORDS32_IN_BLOCK; i < WORDS32_IN_M_BLOCK; i++) {
            W[i] = sigma_1(W[i - 2]) + W[i - 7] + sigma_0(W[i - 15]) + W[i - 16];
        }

        // 64 rounds
        a = h_0;
        b = h_1;
        c = h_2;
        d = h_3;
        e = h_4;
        f = h_5;
        g = h_6;
        h = h_7;

        for (word32 i = 0; i < 64; i++) {
            word32 T1 = h + big_sigma_1(e) + ch(e, f, g) + K[i] + W[i];
            word32 T2 = big_sigma_0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h_0 = h_0 + a;
        h_1 = h_1 + b;
        h_2 = h_2 + c;
        h_3 = h_3 + d;
        h_4 = h_4 + e;
        h_5 = h_5 + f;
        h_6 = h_6 + g;
        h_7 = h_7 + h;
    }

    hash[0] = h_0;
    hash[1] = h_1;
    hash[2] = h_2;
    hash[3] = h_3;
    hash[4] = h_4;
    hash[5] = h_5;
    hash[6] = h_6;
    hash[7] = h_7;

    free(data);

    return hash;
}

void find_string(word32 index, const word32 MAX_LEN, word8 *data, const word32 *secret, word32 *done) {
    if (!*done) {
        if (index >= MAX_LEN) {
            word32 *hash = malloc(sizeof(word32) * 8);
            hash_test(hash, data);
            *done = 1;
            for (int i = 0; i < 8; i++) {
                if (hash[i] != secret[i]) {
                    *done = 0;
                    break;
                }
            }
            if (*done) {
                printf("secret found: %s", data);
            }
            free(hash);
        } else {
            for (int i = ASCII_VALUES_START; i < NROF_ASCII_VALUES; i++) {
                data[index] = (word8) i;
                find_string(index + 1, MAX_LEN, data, secret, done);
            }
        }
    }
}

void find_all_strings(const word32 MAX_LEN, const word32 *secret) {
    const word32 MIN_STRING_LEN = 1;
    word8 *data;
    word32 *done = malloc(sizeof(word32));
    *done = 0;
    for (word32 i = MIN_STRING_LEN; i < MIN_STRING_LEN + MAX_LEN; i++) {
        data = (word8 *) malloc(i + 1);
        data[i] = (word8) 0; // null terminator
        find_string(0, i, data, secret, done);
        free(data);

        if (*done) {
            break;
        }

        printf("done with %u\n", i);
    }
}

void print_hash(word32 *hash) {
    for (int32_t i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }
    printf("\n");
}

inline word32 rotr(word32 x, word32 n) {
    return (x >> n) | (x << (BITS_IN_WORD32 - n));
}

inline word32 sha(word32 x, word32 n) {
    return x >> n;
}

inline word32 sigma_0(word32 x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ sha(x, 3);
}

inline word32 sigma_1(word32 x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ sha(x, 10);
}

inline word32 big_sigma_0(word32 x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline word32 big_sigma_1(word32 x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline word32 ch(word32 x, word32 y, word32 z) {
    return (x & y) ^ (~x & z);
}

inline word32 maj(word32 x, word32 y, word32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}