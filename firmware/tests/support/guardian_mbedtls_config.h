// G22A, host only: the mbedtls configuration of the offer signature check
// (tests/tune_offer_check.cpp). RSA PKCS#1 v1.5 with SHA-256, plus key generation
// so the check makes its own throwaway key pair. The board uses ESP-IDF's own
// mbedtls configuration; this file is never part of the firmware image.
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_GENPRIME
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PLATFORM_C
