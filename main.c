#include <stdio.h> // printf
#include <stdint.h> // uint32_t and uint64_t
#include <mem.h> // strlen
#include <unistd.h> // atoi
#include <stdlib.h>

typedef int8_t word8;
typedef uint32_t word32;
typedef uint64_t word64;

word32 rotr(word32 x, word32 n);

word32 sha(word32 x, word32 n);

word32 sigma_0(word32 x);

word32 sigma_1(word32 x);

word32 big_sigma_0(word32 x);

word32 big_sigma_1(word32 x);

word32 ch(word32 x, word32 y, word32 z);

word32 maj(word32 x, word32 y, word32 z);

#define WORDS32_IN_BLOCK 16
#define WORDS32_IN_WORD64 2
#define WORDS8_IN_WORD32 (sizeof(word32) / sizeof(word8))

#define WORDS32_IN_M_BLOCK 64

#define BITS_IN_WORD8 8
#define BITS_IN_WORD32 32
#define BITS_IN_WORD64 64
#define BITS_IN_BLOCK 512

/**
 * ASCII hashing
 */
int main() {
    /*
     * preprocessing
     */
    word8 message[] = {"abca"};
    word64 nrof_words8 = strlen(message);
    printf("nrof_words8: %llu\n", nrof_words8);
    word64 nrof_words32 = nrof_words8 / (sizeof(word32) / sizeof(word8));
    printf("nrof_words32: %llu\n", nrof_words32);

    // l is nrof_bits
    word64 l = nrof_words8 * BITS_IN_WORD8;
    printf("l: %llu\n", l);

    word64 k = ((BITS_IN_BLOCK - BITS_IN_WORD64) - ((l + 1) % BITS_IN_BLOCK)) % BITS_IN_BLOCK;
    printf("k: %llu\n", k);

    word64 nrof_bits = l + k + 1 + BITS_IN_WORD64;
    printf("nrof_bits: %llu\n", nrof_bits);

    if (nrof_bits % BITS_IN_BLOCK != 0) {
        printf("something is wrong!\n");
    }

    word64 nrof_blocks = nrof_bits / BITS_IN_BLOCK;
    printf("nrof_blocks: %llu\n", nrof_blocks);

    // for all bits
//    word32 words[nrof_blocks * WORDS32_IN_BLOCK];
    word32 blocks[nrof_blocks][WORDS32_IN_BLOCK];
    word32 current_word8 = 0;
    for (word32 i = 0; i < nrof_blocks; i++) {
        word32 words_in_this_block = WORDS32_IN_BLOCK;
        if (i == nrof_blocks - 1) {
            // last block
            words_in_this_block = words_in_this_block - WORDS32_IN_WORD64;
        }

        for (word32 n = 0; n < words_in_this_block; n++) {
            word32 word = 0;
            if (current_word8 < nrof_words8) {
                for (word32 j = 0; j < WORDS8_IN_WORD32; j++) {
                    word32 temp;
                    temp = ((word32) message[i * WORDS8_IN_WORD32 + j]) << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - j - 1));
//                    printf("%u\n", temp);
                    printf("%08x\n", message[i * WORDS8_IN_WORD32 + j]);
                    word |= temp;
                    current_word8 = current_word8 + 1;
                }
            } else if (current_word8 >= nrof_words8 && current_word8 < nrof_words8 + WORDS8_IN_WORD32) {
                word = (word32) (1 << (BITS_IN_WORD32 - 1)); // l can be short tho
                current_word8 = current_word8 + WORDS8_IN_WORD32;
            }
            blocks[i][n] = word;
        }

        if (i == nrof_blocks - 1) {
            // last block
            blocks[i][WORDS32_IN_BLOCK - 2] = (word32) (l >> BITS_IN_WORD32);
            blocks[i][WORDS32_IN_BLOCK - 1] = (word32) l;
        }
    }

    // prints blocks
    for (word32 i = 0; i < nrof_blocks; i++) {
        printf("preprocessed hexadecimal (%d):\n", i);
        for (word32 n = 0; n < WORDS32_IN_BLOCK; n++) {
            printf("%08x ", blocks[i][n]);
        }
        printf("\n");
    }

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
        for (int x = 0; x < 64; x++) {
            printf("%08x", W[x]);
        }
        printf("\n");
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

        // print hash
        printf("processed hexadecimal (%d):\n", t);
        printf("%08x ", h_0);
        printf("%08x ", h_1);
        printf("%08x ", h_2);
        printf("%08x ", h_3);
        printf("%08x ", h_4);
        printf("%08x ", h_5);
        printf("%08x ", h_6);
        printf("%08x ", h_7);
        printf("\n");
    }

    return 0;
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