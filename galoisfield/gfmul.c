#include <stdint.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

typedef struct {
    uint64_t low;
    uint64_t high;
} uint128_t;

// Reduction polynomial x^128 + x^7 + x^2 + x + 1 according to intel whitepaper (page 17)
static inline void reduce_256_to_128(uint64_t *result_high, uint64_t *result_low,
                                   uint64_t X3, uint64_t X2, uint64_t X1, uint64_t X0) {
    uint64_t A = X3 >> 63;
    uint64_t B = X3 >> 62;
    uint64_t C = X3 >> 57;
    uint64_t D = X2 ^ A ^ B ^ C;

    uint64_t E1 = (X3 << 1) | (D >> 63);
    uint64_t E0 = D << 1;
    uint64_t F1 = (X3 << 2) | (D >> 62);
    uint64_t F0 = D << 2;
    uint64_t G1 = (X3 << 7) | (D >> 57);
    uint64_t G0 = D << 7;

    uint64_t H1 = X3 ^ E1 ^ F1 ^ G1;
    uint64_t H0 = D ^ E0 ^ F0 ^ G0;

    *result_high = X1 ^ H1;
    *result_low = X0 ^ H0;
}

// Source https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
EXPORT uint128_t gfmul(uint64_t a_low, uint64_t a_high, uint64_t b_low, uint64_t b_high) {
    // Create 128-bit values
    __m128i a = _mm_set_epi64x(a_high, a_low);
    __m128i b = _mm_set_epi64x(b_high, b_low);

    // Carry-less multiplication (just 4 multiplications)
    __m128i tmp0 = _mm_clmulepi64_si128(a, b, 0x00);  // low x low
    __m128i tmp1 = _mm_clmulepi64_si128(a, b, 0x10);  // high x low
    __m128i tmp2 = _mm_clmulepi64_si128(a, b, 0x01);  // low x high
    __m128i tmp3 = _mm_clmulepi64_si128(a, b, 0x11);  // high x high

    // Combine middle terms
    __m128i tmp4 = _mm_xor_si128(tmp1, tmp2);
    tmp1 = _mm_slli_si128(tmp4, 8);
    tmp2 = _mm_srli_si128(tmp4, 8);
    tmp0 = _mm_xor_si128(tmp0, tmp1);
    tmp3 = _mm_xor_si128(tmp3, tmp2);

    // Extract values for reduction
    uint64_t res[2], high[2];
    _mm_storeu_si128((__m128i*)res, tmp0);
    _mm_storeu_si128((__m128i*)high, tmp3);

    // Do explicit reduction
    uint128_t result;
    reduce_256_to_128(&result.high, &result.low,
                      high[1], high[0],
                      res[1], res[0]);

    return result;
}