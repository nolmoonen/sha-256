#include <stdio.h> // printf
#include <stdint.h> // uint32_t and uint64_t
#include <mem.h> // strlen
#include <stdlib.h> // malloc
#include <time.h> // clock
#include <windows.h>

#define WORDS8_IN_WORD32 4

#define WORDS32_IN_M_BLOCK 64

#define BITS_IN_WORD8 8
#define BITS_IN_WORD32 32
#define BITS_IN_WORD64 64

#define WORDS8_IN_BLOCK 64
#define WORD32_IN_BLOCK 16
#define BITS_IN_BLOCK 512

#define WORD32_IN_HASH 8

//#define DEBUG
#define LETTERS_ONLY
#define USE_THREADS

#ifdef LETTERS_ONLY
#define NROF_LETTERS 26

#define FIRST_LOWER_LETTER_VALUE 97
#define LAST_LOWER_LETTER_VALUE 122

#define FIRST_UPPER_LETTER_VALUE 65
#define LAST_UPPER_LETTER_VALUE 90

#ifdef USE_THREADS
// should be a multiplicity of 2
#define NROF_THREADS 6  // SEC2 263586 173602 172989
//#define NROF_THREADS 12 // SEC2 198080 187788 186647
#endif
#else
// first ascii character to try
#define ASCII_VALUES_START 33
#define NROF_ASCII_VALUES 128
#endif


typedef uint8_t word8;
typedef uint32_t word32;
typedef uint64_t word64;

typedef word32 block[WORD32_IN_BLOCK];

word32 rotr(word32 x, word32 n);

word32 sha(word32 x, word32 n);

word32 sigma_0(word32 x);

word32 sigma_1(word32 x);

word32 big_sigma_0(word32 x);

word32 big_sigma_1(word32 x);

word32 ch(word32 x, word32 y, word32 z);

word32 maj(word32 x, word32 y, word32 z);

struct Parameters {
    uint32_t start_char; // decimal value of first ASCII character to try
    uint32_t nrof_chars; // number of characters to try
    word32 MAX_LEN; // maximum length of secret
    word32 MIN_LEN; // maximum length of secret
    const word32 *secret; // hashed secret
    uint32_t *done;
};

/**
 * Finds all permutations of a string of a fixed length.
 */
void find_string(word32 index, const word32 MAX_LEN, word8 *data, const word32 *secret, word32 *done, word32 *hash,
                 struct Parameters *params);

/**
 * ASCII hashing.
 */
word32 *hash_test(word32 *hash, word8 *message);

/**
 * Prints a hash.
 */
void print_hash(word32 *hash);

// abd
const word32 SEC_0[] = {0xa52d159f, 0x262b2c6d, 0xdb724a61, 0x840befc3, 0x6eb30c88, 0x877a4030, 0xb65cbe86, 0x298449c9};
// ???
const word32 SEC_1[] = {0x23D46EF4, 0x374DB1E8, 0x3A8ECB77, 0xA99BA9D1, 0x2835D911, 0xFF8915C4, 0xD20E4A71, 0xAE179DFD};
// zzzzz
const word32 SEC_2[] = {0x68a55e5b, 0x1e43c67f, 0x4ef34065, 0xa86c4c58, 0x3f532ae8, 0xe3cda7e3, 0x6cc79b61, 0x1802ac07};

int threaded_bruteforce(const word32 MIN_LEN, const word32 MAX_LEN, const word32 *secret);

int main() {
    clock_t start, end;
    start = clock();

    // brute force a string
    threaded_bruteforce(0, 8, SEC_0);

//    // calculate a hash
//    word32 *hash = malloc(sizeof(int32_t) * 8);
//    print_hash(hash_test(hash, (word8 *) "abcdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
//    free(hash);

    end = clock();
    printf("cycles: %li\n", end - start);
}

word32 *hash_test(word32 *hash, word8 *message) {
    /*
     * Pre processing
     */
    // length of message
    word32 nrof_words8 = strlen((const char *) message);

    // number of blocks required
    word64 nrof_blocks = (nrof_words8 * BITS_IN_WORD8 + 1 + BITS_IN_WORD64 - 1) / BITS_IN_BLOCK + 1;

    block blocks[nrof_blocks];

    for (word32 i = 0; i < nrof_blocks; i++) {
        for (word32 j = 0; j < WORD32_IN_BLOCK; j++) {
            blocks[i][j] = 0;
            for (word32 k = 0; k < WORDS8_IN_WORD32; k++) {
                word32 word8_index = i * WORDS8_IN_BLOCK + j * WORDS8_IN_WORD32 + k;
                if (word8_index < nrof_words8) {
                    blocks[i][j] |= (((word32) message[word8_index]) << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - k - 1)));
                }
            }
        }
    }

    word32 temp = (((word32) 0x80) << (BITS_IN_WORD8 * (WORDS8_IN_WORD32 - (nrof_words8 % 4) - 1)));
    blocks[nrof_words8 / WORDS8_IN_BLOCK][nrof_words8 / 4] |= temp;
    blocks[nrof_blocks - 1][WORD32_IN_BLOCK - 2] = (word32) (((word64) (nrof_words8 * BITS_IN_WORD8))
            >> BITS_IN_WORD32);
    blocks[nrof_blocks - 1][WORD32_IN_BLOCK - 1] = (word32) (nrof_words8 * BITS_IN_WORD8);

#ifdef DEBUG
    // prints blocks
    for (word32 i = 0; i < nrof_blocks; i++) {
        printf("preprocessed hexadecimal improvement (%d):\n", i);
        for (word32 n = 0; n < WORD32_IN_BLOCK; n++) {
            printf("%08x ", blocks[i][n]);
            if ((n + 1) % (WORD32_IN_BLOCK / 2) == 0) printf("\n");
        }
    }
#endif

    /*
     * Processing
     */
    const word32 H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

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

    hash[0] = H[0];
    hash[1] = H[1];
    hash[2] = H[2];
    hash[3] = H[3];
    hash[4] = H[4];
    hash[5] = H[5];
    hash[6] = H[6];
    hash[7] = H[7];

    word32 a, b, c, d, e, f, g, h;

    for (word32 t = 0; t < nrof_blocks; t++) {
        // prepare block
        word32 W[WORDS32_IN_M_BLOCK];
        for (word32 i = 0; i < WORD32_IN_BLOCK; i++) {
            W[i] = blocks[t][i];
        }
        for (word32 i = WORD32_IN_BLOCK; i < WORDS32_IN_M_BLOCK; i++) {
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

        word32 T1, T2;
        for (word32 i = 0; i < 64; i++) {
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

//    free(data);

    return hash;
}

void find_string(word32 index, const word32 MAX_LEN, word8 *data, const word32 *secret, word32 *done, word32 *hash,
                 struct Parameters *params) {
    if (!*done) {
        if (index >= MAX_LEN) {
            hash_test(hash, data);
            uint32_t local_done = 1;
            for (int i = 0; i < WORD32_IN_HASH; i++) {
                if (hash[i] != secret[i]) {
                    local_done = 0;
                    break;
                }
            }
            if (local_done) {
                printf("secret found: %s\n", data);
                *done = 1;
            }
        } else {
#ifdef LETTERS_ONLY
            for (int i = FIRST_UPPER_LETTER_VALUE; i < LAST_UPPER_LETTER_VALUE + 1; i++) {
                data[index] = (word8) i;
                find_string(index + 1, MAX_LEN, data, secret, done, hash, params);
            }
            for (int i = FIRST_LOWER_LETTER_VALUE; i < LAST_LOWER_LETTER_VALUE + 1; i++) {
                data[index] = (word8) i;
                find_string(index + 1, MAX_LEN, data, secret, done, hash, params);
            }
#else
            for (int i = ASCII_VALUES_START; i < NROF_ASCII_VALUES; i++) {
                data[index] = (word8) i;
                find_string(index + 1, MAX_LEN, data, secret, done, hash, params);
            }
#endif
        }
    }
}

DWORD WINAPI worker_thread(LPVOID params) {
    struct Parameters *parameters;

    // cast void pointer
    parameters = (struct Parameters *) params;

    printf("%u, %u, %p, %u\n", parameters->start_char, parameters->nrof_chars, parameters->secret, parameters->MAX_LEN);

    // do the work
    word32 MIN_STRING_LEN = 1;
    MIN_STRING_LEN = MIN_STRING_LEN < parameters->MIN_LEN ? parameters->MIN_LEN : MIN_STRING_LEN;
    word8 *data;
    word32 *hash = malloc(sizeof(word32) * 8);
    uint32_t *done = parameters->done;
    for (word32 i = MIN_STRING_LEN; i < MIN_STRING_LEN + parameters->MAX_LEN; i++) {
        data = (word8 *) malloc(i + 1);
        data[i] = (word8) 0; // null terminator
        for (int j = parameters->start_char; j < parameters->start_char + parameters->nrof_chars; j++) {
            data[0] = (word8) j;
            find_string(1, i, data, parameters->secret, done, hash, parameters);
            if (*done) {
                break;
            }
            if (i >= 7) {
                printf("worker is done with char: %u\n", j);
            }
        }
        free(data);

        if (*done) {
            break;
        }

        printf("worker is done with: %u (started with %u)\n", i, parameters->start_char);
    }
    free(hash);

    return 0;
}

int threaded_bruteforce(const word32 MIN_LEN, const word32 MAX_LEN, const word32 *secret) {
    struct Parameters *parameters[NROF_THREADS];
    DWORD thread_id[NROF_THREADS];
    HANDLE thread_handle[NROF_THREADS];
    uint32_t *done = malloc(sizeof(uint32_t));
    *done = 0;

    // create MAX_THREADS worker threads
    for (uint32_t i = 0; i < NROF_THREADS; i++) {
        // allocate memory for thread data.
        parameters[i] = (struct Parameters *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct Parameters));

        if (parameters[i] == NULL) {
            // memory allocation failed
            ExitProcess(2);
        }

        // fill data
        uint32_t range = NROF_LETTERS / (NROF_THREADS / 2);
        uint32_t last_range = NROF_LETTERS - (NROF_THREADS / 2 - 1) * range;
        if (i < NROF_THREADS / 2) {
            parameters[i]->start_char = FIRST_UPPER_LETTER_VALUE + i * range;
            // i is the last part of the upper characters
            if (i == NROF_THREADS / 2 - 1) {
                parameters[i]->nrof_chars = last_range;
            } else {
                parameters[i]->nrof_chars = range;
            }
        } else {
            parameters[i]->start_char = FIRST_LOWER_LETTER_VALUE + (i % (NROF_THREADS / 2)) * range;
            // i is the last part of the lower characters
            if (i == NROF_THREADS - 1) {
                parameters[i]->nrof_chars = last_range;
            } else {
                parameters[i]->nrof_chars = range;
            }
        }
        parameters[i]->MIN_LEN = MIN_LEN;
        parameters[i]->MAX_LEN = MAX_LEN;
        parameters[i]->secret = secret;
        parameters[i]->done = done;

        // create thread
        thread_handle[i] = CreateThread(NULL, 0, worker_thread, parameters[i], 0, &thread_id[i]);

        if (thread_handle[i] == NULL) {
            // thread could not be created
            ExitProcess(3);
        }
    }

    // wait untill all closed
    WaitForMultipleObjects(NROF_THREADS, thread_handle, TRUE, INFINITE);

    // close the threads
    for (int i = 0; i < NROF_THREADS; i++) {
        CloseHandle(thread_handle[i]);
        // free memory allocation
        if (parameters[i] != NULL) {
            HeapFree(GetProcessHeap(), 0, parameters[i]);
            parameters[i] = NULL;
        }
    }

    free(done);

    return 0;
}

void print_hash(word32 *hash) {
    for (word32 i = 0; i < 8; i++) {
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