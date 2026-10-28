/*
 * chttp crypto - the primitives TLS 1.3 needs, implemented here so the
 * server keeps its zero-dependency promise.
 *
 * Profile: SHA-256/SHA-512, HMAC/HKDF, AES-128-GCM, X25519, Ed25519.
 * No dynamic allocation, no global state, no libcrypto.
 */
#ifndef CHTTP_CRYPTO_H
#define CHTTP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CH_SHA256_LEN 32
#define CH_SHA512_LEN 64
#define CH_AES128_KEY_LEN 16
#define CH_GCM_NONCE_LEN 12
#define CH_GCM_TAG_LEN 16

struct ch_sha256 {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

struct ch_sha512 {
    uint64_t state[8];
    uint64_t bits_hi;
    uint64_t bits_lo;
    uint8_t block[128];
    size_t used;
};

void ch_sha256_init(struct ch_sha256 *ctx);
void ch_sha256_update(struct ch_sha256 *ctx, const void *data, size_t len);
void ch_sha256_final(struct ch_sha256 *ctx, uint8_t out[CH_SHA256_LEN]);
void ch_sha256(const void *data, size_t len, uint8_t out[CH_SHA256_LEN]);

void ch_sha512_init(struct ch_sha512 *ctx);
void ch_sha512_update(struct ch_sha512 *ctx, const void *data, size_t len);
void ch_sha512_final(struct ch_sha512 *ctx, uint8_t out[CH_SHA512_LEN]);

void ch_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[CH_SHA256_LEN]);

void ch_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_len,
                            uint8_t out[CH_SHA256_LEN]);
void ch_hkdf_expand_sha256(const uint8_t prk[CH_SHA256_LEN],
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t out_len);
/* HKDF-Expand-Label from RFC 8446, with a SHA-256 transcript. */
void ch_hkdf_expand_label_sha256(const uint8_t secret[CH_SHA256_LEN],
                                 const char *label, size_t label_len,
                                 const uint8_t *context, size_t context_len,
                                 uint8_t *out, size_t out_len);

int ch_random(void *out, size_t len);

/* One-shot AES-128-GCM. Returns 0 on success, -1 if a tag check fails. */
void ch_aes128_gcm_encrypt(const uint8_t key[CH_AES128_KEY_LEN],
                           const uint8_t nonce[CH_GCM_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *cipher,
                           uint8_t tag[CH_GCM_TAG_LEN]);
int ch_aes128_gcm_decrypt(const uint8_t key[CH_AES128_KEY_LEN],
                          const uint8_t nonce[CH_GCM_NONCE_LEN],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *cipher, size_t cipher_len,
                          uint8_t *plain,
                          const uint8_t tag[CH_GCM_TAG_LEN]);

/* X25519(out, scalar, point); scalar is clamped internally. */
void ch_x25519(uint8_t out[32], const uint8_t scalar[32],
               const uint8_t point[32]);

/* Ed25519 from a 32-byte RFC 8032 seed. */
void ch_ed25519_public_key(uint8_t out[32], const uint8_t seed[32]);
void ch_ed25519_sign(uint8_t signature[64], const uint8_t *message,
                     size_t message_len, const uint8_t seed[32]);

#endif
