#include <stdio.h> // printf
#include <stdint.h> // uint32_t and uint64_t
#include <mem.h> // strlen
#include <unistd.h> // atoi
#include <stdlib.h>

typedef int8_t word8;
typedef uint32_t word32;
typedef uint64_t word64;

#define WORDS32_IN_BLOCK 16
#define WORDS32_IN_WORD64 2
#define WORDS8_IN_WORD32 (sizeof(word32) / sizeof(word8))

#define BITS_IN_WORD8 8
#define BITS_IN_WORD32 32
#define BITS_IN_WORD64 64
#define BITS_IN_BLOCK 512

/*
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * https://www.researchgate.net/file.PostFileLoader.html?id=534b393ad3df3e04508b45ad&assetKey=AS%3A273514844622849%401442222429260
 */

int main() {
    word8 *message = {"abcc"};
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
    word32 words[nrof_blocks * WORDS32_IN_BLOCK];
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
                    word |= temp;
                    current_word8 = current_word8 + 1;
                }
            } else if (current_word8 >= nrof_words8 && current_word8 < nrof_words8 + WORDS8_IN_WORD32) {
                word = (word32) ~0; // l can be short tho
                current_word8 = current_word8 + WORDS8_IN_WORD32;
            }
            words[n] = word;
        }

        if (i == nrof_blocks - 1) {
            // last block
            words[WORDS32_IN_BLOCK - 2] = (word32) (l >> BITS_IN_WORD32);
            words[WORDS32_IN_BLOCK - 1] = (word32) l;
        }
    }

    for (word32 i = 0; i < nrof_blocks; i++) {
        for (word32 n = 0; n < WORDS32_IN_BLOCK; n++) {
            printf("%u ", words[n]);
        }
        printf("\n");
    }

    return 0;
}