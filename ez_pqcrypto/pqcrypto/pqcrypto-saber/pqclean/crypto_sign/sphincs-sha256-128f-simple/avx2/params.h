#ifndef PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_PARAMS_H
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_PARAMS_H

/* Hash output length in bytes. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N 16
/* Height of the hypertree. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FULL_HEIGHT 60
/* Number of subtree layer. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_D 20
/* FORS tree dimensions. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_HEIGHT 9
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_TREES 30
/* Winternitz parameter, */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_W 16

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_ADDR_BYTES 32

/* WOTS parameters. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LOGW 4

#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN1 (8 * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N / PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LOGW)

/* PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN2 3

#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN (PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN1 + PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN2)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_BYTES (PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_LEN * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_PK_BYTES PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_BYTES

/* Subtree size. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_TREE_HEIGHT (PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FULL_HEIGHT / PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_D)

/* FORS parameters. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_MSG_BYTES ((PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_HEIGHT * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_TREES + 7) / 8)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_BYTES ((PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_HEIGHT + 1) * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_TREES * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_PK_BYTES PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N

/* Resulting SPX sizes. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_BYTES (PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N + PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FORS_BYTES + PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_D * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_WOTS_BYTES +\
        PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_FULL_HEIGHT * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_PK_BYTES (2 * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N)
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_SK_BYTES (2 * PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_N + PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_OPTRAND_BYTES 32

#endif
