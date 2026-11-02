/*
 * This file is part of chttp.
 * Copyright (c) 2026 Dipanjan Patra <patraanjan23@users.noreply.github.com>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * chttp is free software: you may redistribute and/or modify it under the
 * terms of the GNU Affero General Public License, version 3, as published by
 * the Free Software Foundation. Offering this software, or anything built on
 * it, as a hosted or closed-source product without releasing your source
 * requires a commercial license from the author (see README, License).
 */

/*
 * chttp crypto - see crypto.h.
 *
 * The field and scalar arithmetic follows the compact public-domain
 * TweetNaCl construction: 16 limbs of 16 bits, constant-time conditional
 * swaps, no data-dependent table lookups. AES uses the same rule: the S-box
 * is computed arithmetically instead of read from a table, so cache timing
 * does not leak the key. That is slower than a table or hardware AES, which
 * is the right trade for a small server.
 */
#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha256_block(struct ch_sha256 *ctx, const uint8_t *block)
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | (uint32_t)block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18)
                    ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19)
                    ^ (w[i - 2] >> 10);

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void ch_sha256_init(struct ch_sha256 *ctx)
{
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bits = 0;
    ctx->used = 0;
}

void ch_sha256_update(struct ch_sha256 *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = data;

    ctx->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t room = sizeof ctx->block - ctx->used;
        size_t take = len < room ? len : room;

        memcpy(ctx->block + ctx->used, bytes, take);
        ctx->used += take;
        bytes += take;
        len -= take;
        if (ctx->used == sizeof ctx->block) {
            sha256_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

void ch_sha256_final(struct ch_sha256 *ctx, uint8_t out[CH_SHA256_LEN])
{
    uint64_t bits = ctx->bits;
    uint8_t pad[72];
    size_t pad_len;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof pad - 1);
    pad_len = ctx->used < 56 ? 56 - ctx->used : 120 - ctx->used;
    ch_sha256_update(ctx, pad, pad_len);
    for (size_t i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bits >> (56 - i * 8));
    ch_sha256_update(ctx, pad, 8);

    for (size_t i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

void ch_sha256(const void *data, size_t len, uint8_t out[CH_SHA256_LEN])
{
    struct ch_sha256 ctx;

    ch_sha256_init(&ctx);
    ch_sha256_update(&ctx, data, len);
    ch_sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* SHA-512                                                             */
/* ------------------------------------------------------------------ */

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
    0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
    0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
    0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
    0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
    0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
    0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull,
    0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
    0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
    0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull,
    0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static void sha512_block(struct ch_sha512 *ctx, const uint8_t *block)
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;

    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i * 8] << 56)
             | ((uint64_t)block[i * 8 + 1] << 48)
             | ((uint64_t)block[i * 8 + 2] << 40)
             | ((uint64_t)block[i * 8 + 3] << 32)
             | ((uint64_t)block[i * 8 + 4] << 24)
             | ((uint64_t)block[i * 8 + 5] << 16)
             | ((uint64_t)block[i * 8 + 6] << 8)
             | (uint64_t)block[i * 8 + 7];
    }
    for (size_t i = 16; i < 80; i++) {
        uint64_t s0 = ROTR64(w[i - 15], 1) ^ ROTR64(w[i - 15], 8)
                    ^ (w[i - 15] >> 7);
        uint64_t s1 = ROTR64(w[i - 2], 19) ^ ROTR64(w[i - 2], 61)
                    ^ (w[i - 2] >> 6);

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (size_t i = 0; i < 80; i++) {
        uint64_t s1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + s1 + ch + sha512_k[i] + w[i];
        uint64_t s0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void ch_sha512_init(struct ch_sha512 *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908ull;
    ctx->state[1] = 0xbb67ae8584caa73bull;
    ctx->state[2] = 0x3c6ef372fe94f82bull;
    ctx->state[3] = 0xa54ff53a5f1d36f1ull;
    ctx->state[4] = 0x510e527fade682d1ull;
    ctx->state[5] = 0x9b05688c2b3e6c1full;
    ctx->state[6] = 0x1f83d9abfb41bd6bull;
    ctx->state[7] = 0x5be0cd19137e2179ull;
    ctx->bits_hi = 0;
    ctx->bits_lo = 0;
    ctx->used = 0;
}

void ch_sha512_update(struct ch_sha512 *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = data;
    uint64_t add = (uint64_t)len << 3;

    ctx->bits_hi += (uint64_t)len >> 61;
    ctx->bits_lo += add;
    if (ctx->bits_lo < add)
        ctx->bits_hi++;
    while (len > 0) {
        size_t room = sizeof ctx->block - ctx->used;
        size_t take = len < room ? len : room;

        memcpy(ctx->block + ctx->used, bytes, take);
        ctx->used += take;
        bytes += take;
        len -= take;
        if (ctx->used == sizeof ctx->block) {
            sha512_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

void ch_sha512_final(struct ch_sha512 *ctx, uint8_t out[CH_SHA512_LEN])
{
    uint64_t bits_hi = ctx->bits_hi;
    uint64_t bits_lo = ctx->bits_lo;
    uint8_t pad[144];
    size_t pad_len;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof pad - 1);
    pad_len = ctx->used < 112 ? 112 - ctx->used : 240 - ctx->used;
    ch_sha512_update(ctx, pad, pad_len);
    for (size_t i = 0; i < 8; i++)
        pad[i] = (uint8_t)(bits_hi >> (56 - i * 8));
    for (size_t i = 0; i < 8; i++)
        pad[8 + i] = (uint8_t)(bits_lo >> (56 - i * 8));
    ch_sha512_update(ctx, pad, 16);

    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(ctx->state[i] >> (56 - j * 8));
    }
}

static void sha512_once(const void *data, size_t len,
                        uint8_t out[CH_SHA512_LEN])
{
    struct ch_sha512 ctx;

    ch_sha512_init(&ctx);
    ch_sha512_update(&ctx, data, len);
    ch_sha512_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* HMAC, HKDF                                                          */
/* ------------------------------------------------------------------ */

void ch_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[CH_SHA256_LEN])
{
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[CH_SHA256_LEN];
    struct ch_sha256 ctx;

    memset(k, 0, sizeof k);
    if (key_len > sizeof k)
        ch_sha256(key, key_len, k);
    else
        memcpy(k, key, key_len);
    for (size_t i = 0; i < sizeof k; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    ch_sha256_init(&ctx);
    ch_sha256_update(&ctx, ipad, sizeof ipad);
    ch_sha256_update(&ctx, data, data_len);
    ch_sha256_final(&ctx, inner);

    ch_sha256_init(&ctx);
    ch_sha256_update(&ctx, opad, sizeof opad);
    ch_sha256_update(&ctx, inner, sizeof inner);
    ch_sha256_final(&ctx, out);
}

void ch_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_len,
                            uint8_t out[CH_SHA256_LEN])
{
    static const uint8_t zero = 0;

    if (salt == NULL || salt_len == 0) {
        salt = &zero;
        salt_len = 0;
    }
    ch_hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

void ch_hkdf_expand_sha256(const uint8_t prk[CH_SHA256_LEN],
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t out_len)
{
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[CH_SHA256_LEN];
    uint8_t t[CH_SHA256_LEN];
    size_t t_len = 0;
    uint8_t counter = 1;

    memset(ipad, 0x36, sizeof ipad);
    memset(opad, 0x5c, sizeof opad);
    for (int i = 0; i < CH_SHA256_LEN; i++) {
        ipad[i] ^= prk[i];
        opad[i] ^= prk[i];
    }

    while (out_len > 0) {
        struct ch_sha256 ctx;
        size_t take;

        ch_sha256_init(&ctx);
        ch_sha256_update(&ctx, ipad, sizeof ipad);
        ch_sha256_update(&ctx, t, t_len);
        ch_sha256_update(&ctx, info, info_len);
        ch_sha256_update(&ctx, &counter, 1);
        ch_sha256_final(&ctx, inner);

        ch_sha256_init(&ctx);
        ch_sha256_update(&ctx, opad, sizeof opad);
        ch_sha256_update(&ctx, inner, sizeof inner);
        ch_sha256_final(&ctx, t);
        t_len = sizeof t;

        take = out_len < sizeof t ? out_len : sizeof t;
        memcpy(out, t, take);
        out += take;
        out_len -= take;
        counter++;
    }
}

void ch_hkdf_expand_label_sha256(const uint8_t secret[CH_SHA256_LEN],
                                 const char *label, size_t label_len,
                                 const uint8_t *context, size_t context_len,
                                 uint8_t *out, size_t out_len)
{
    uint8_t info[2 + 1 + 6 + 64 + 1 + 64];
    size_t pos = 0;

    if (label_len > 64)
        label_len = 64;
    if (context_len > 64)
        context_len = 64;

    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)out_len;
    info[pos++] = (uint8_t)(6 + label_len);
    memcpy(info + pos, "tls13 ", 6);
    pos += 6;
    memcpy(info + pos, label, label_len);
    pos += label_len;
    info[pos++] = (uint8_t)context_len;
    if (context_len > 0)
        memcpy(info + pos, context, context_len);
    pos += context_len;

    ch_hkdf_expand_sha256(secret, info, pos, out, out_len);
}

int ch_random(void *out, size_t len)
{
    uint8_t *bytes = out;
    ssize_t got;

    while (len > 0) {
        got = getrandom(bytes, len, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            /* getrandom can be unavailable in a very old sandbox. */
            int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

            if (fd < 0)
                return -1;
            got = read(fd, bytes, len);
            close(fd);
            if (got <= 0)
                return -1;
        }
        if (got == 0)
            return -1;
        bytes += got;
        len -= (size_t)got;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* AES-128, constant-time S-box, then GCM                              */
/* ------------------------------------------------------------------ */

static uint8_t aes_mul(uint8_t a, uint8_t b)
{
    uint8_t product = 0;

    for (int i = 0; i < 8; i++) {
        product ^= (uint8_t)(-(int)(b & 1u) & a);
        a = (uint8_t)((a << 1) ^ ((uint8_t)(-(int)(a >> 7) & 0x1bu)));
        b = (uint8_t)(b >> 1);
    }
    return product;
}

static uint8_t aes_inverse(uint8_t x)
{
    uint8_t result = 1;

    /* x^254 = x^-1 in GF(2^8), fixed square-and-multiply. */
    for (int bit = 7; bit >= 0; bit--) {
        result = aes_mul(result, result);
        if (((254u >> bit) & 1u) != 0)
            result = aes_mul(result, x);
    }
    return result;
}

static uint8_t aes_sbox(uint8_t x)
{
    uint8_t y = aes_inverse(x);
    uint8_t rotated = 0;

    rotated ^= (uint8_t)((y << 1) | (y >> 7));
    rotated ^= (uint8_t)((y << 2) | (y >> 6));
    rotated ^= (uint8_t)((y << 3) | (y >> 5));
    rotated ^= (uint8_t)((y << 4) | (y >> 4));
    return (uint8_t)(y ^ rotated ^ 0x63u);
}

static void aes128_expand(const uint8_t key[CH_AES128_KEY_LEN],
                          uint8_t round_keys[176])
{
    static const uint8_t rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    memcpy(round_keys, key, CH_AES128_KEY_LEN);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];

        memcpy(t, round_keys + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t first = t[0];

            t[0] = (uint8_t)(aes_sbox(t[1]) ^ rcon[i / 4 - 1]);
            t[1] = aes_sbox(t[2]);
            t[2] = aes_sbox(t[3]);
            t[3] = aes_sbox(first);
        }
        for (int j = 0; j < 4; j++)
            round_keys[i * 4 + j] = (uint8_t)(round_keys[(i - 4) * 4 + j]
                                              ^ t[j]);
    }
}

static void aes128_encrypt_block(const uint8_t round_keys[176],
                                 const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16];

    for (int i = 0; i < 16; i++)
        state[i] = (uint8_t)(in[i] ^ round_keys[i]);

    for (int round = 1; round <= 10; round++) {
        uint8_t mixed[16];

        /* SubBytes + ShiftRows: row r rotates left by r. */
        for (int column = 0; column < 4; column++) {
            for (int row = 0; row < 4; row++)
                mixed[column * 4 + row] =
                    aes_sbox(state[((column + row) & 3) * 4 + row]);
        }

        if (round != 10) {
            for (int column = 0; column < 4; column++) {
                uint8_t *c = mixed + column * 4;
                uint8_t a0 = c[0];
                uint8_t a1 = c[1];
                uint8_t a2 = c[2];
                uint8_t a3 = c[3];
                uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                uint8_t x01 = (uint8_t)(a0 ^ a1);
                uint8_t x12 = (uint8_t)(a1 ^ a2);
                uint8_t x23 = (uint8_t)(a2 ^ a3);
                uint8_t x30 = (uint8_t)(a3 ^ a0);

                /* xtime, kept branch-free. */
                x01 = (uint8_t)((x01 << 1)
                               ^ ((uint8_t)(-(int)(x01 >> 7) & 0x1bu)));
                x12 = (uint8_t)((x12 << 1)
                               ^ ((uint8_t)(-(int)(x12 >> 7) & 0x1bu)));
                x23 = (uint8_t)((x23 << 1)
                               ^ ((uint8_t)(-(int)(x23 >> 7) & 0x1bu)));
                x30 = (uint8_t)((x30 << 1)
                               ^ ((uint8_t)(-(int)(x30 >> 7) & 0x1bu)));
                c[0] = (uint8_t)(a0 ^ all ^ x01);
                c[1] = (uint8_t)(a1 ^ all ^ x12);
                c[2] = (uint8_t)(a2 ^ all ^ x23);
                c[3] = (uint8_t)(a3 ^ all ^ x30);
            }
        }

        for (int i = 0; i < 16; i++)
            state[i] = (uint8_t)(mixed[i] ^ round_keys[round * 16 + i]);
    }
    memcpy(out, state, 16);
}

static void ghash_mul(uint8_t value[16], const uint8_t h[16])
{
    uint8_t z[16];
    uint8_t v[16];

    memset(z, 0, sizeof z);
    memcpy(v, h, sizeof v);
    for (int i = 0; i < 128; i++) {
        uint8_t bit = (uint8_t)((value[i / 8] >> (7 - (i & 7))) & 1);
        uint8_t mask = (uint8_t)-(int)bit;
        uint8_t carry;

        for (int j = 0; j < 16; j++)
            z[j] ^= (uint8_t)(v[j] & mask);
        carry = (uint8_t)(v[15] & 1);
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] = (uint8_t)(v[0] >> 1);
        v[0] ^= (uint8_t)(-(int)carry & 0xe1u);
    }
    memcpy(value, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16],
                         const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t take = len < 16 ? len : 16;

        for (size_t i = 0; i < take; i++)
            y[i] ^= data[i];
        ghash_mul(y, h);
        data += take;
        len -= take;
    }
}

static void ghash_lengths(uint8_t y[16], const uint8_t h[16],
                          uint64_t aad_bits, uint64_t data_bits)
{
    uint8_t block[16];

    for (int i = 0; i < 8; i++) {
        block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        block[8 + i] = (uint8_t)(data_bits >> (56 - i * 8));
    }
    ghash_update(y, h, block, sizeof block);
}

static void gcm_ctr(const uint8_t round_keys[176], const uint8_t nonce[12],
                    uint32_t counter, const uint8_t *in, size_t len,
                    uint8_t *out)
{
    uint8_t block[16];
    uint8_t stream[16];

    memcpy(block, nonce, 12);
    for (size_t offset = 0; offset < len; offset += 16) {
        size_t take = len - offset < 16 ? len - offset : 16;

        block[12] = (uint8_t)(counter >> 24);
        block[13] = (uint8_t)(counter >> 16);
        block[14] = (uint8_t)(counter >> 8);
        block[15] = (uint8_t)counter;
        aes128_encrypt_block(round_keys, block, stream);
        for (size_t i = 0; i < take; i++)
            out[offset + i] = (uint8_t)(in[offset + i] ^ stream[i]);
        counter++;
    }
}

void ch_aes128_gcm_encrypt(const uint8_t key[CH_AES128_KEY_LEN],
                           const uint8_t nonce[CH_GCM_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *cipher,
                           uint8_t tag[CH_GCM_TAG_LEN])
{
    uint8_t round_keys[176];
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t y[16];
    uint8_t mask[16];

    aes128_expand(key, round_keys);
    memset(h, 0, sizeof h);
    aes128_encrypt_block(round_keys, h, h);

    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    memset(y, 0, sizeof y);
    ghash_update(y, h, aad, aad_len);
    gcm_ctr(round_keys, nonce, 2, plain, plain_len, cipher);
    ghash_update(y, h, cipher, plain_len);
    ghash_lengths(y, h, (uint64_t)aad_len * 8, (uint64_t)plain_len * 8);

    aes128_encrypt_block(round_keys, j0, mask);
    for (int i = 0; i < CH_GCM_TAG_LEN; i++)
        tag[i] = (uint8_t)(y[i] ^ mask[i]);
}

int ch_aes128_gcm_decrypt(const uint8_t key[CH_AES128_KEY_LEN],
                          const uint8_t nonce[CH_GCM_NONCE_LEN],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *cipher, size_t cipher_len,
                          uint8_t *plain,
                          const uint8_t tag[CH_GCM_TAG_LEN])
{
    uint8_t round_keys[176];
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t y[16];
    uint8_t mask[16];
    uint8_t expected[CH_GCM_TAG_LEN];
    uint8_t difference = 0;

    aes128_expand(key, round_keys);
    memset(h, 0, sizeof h);
    aes128_encrypt_block(round_keys, h, h);

    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    memset(y, 0, sizeof y);
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, cipher, cipher_len);
    ghash_lengths(y, h, (uint64_t)aad_len * 8, (uint64_t)cipher_len * 8);

    aes128_encrypt_block(round_keys, j0, mask);
    for (int i = 0; i < CH_GCM_TAG_LEN; i++)
        expected[i] = (uint8_t)(y[i] ^ mask[i]);
    for (int i = 0; i < CH_GCM_TAG_LEN; i++)
        difference |= (uint8_t)(expected[i] ^ tag[i]);
    if (difference != 0)
        return -1;

    gcm_ctr(round_keys, nonce, 2, cipher, cipher_len, plain);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Curve25519 field arithmetic (TweetNaCl construction)                */
/* ------------------------------------------------------------------ */

typedef int64_t ch_gf[16];

static const ch_gf ch_gf0;
static const ch_gf ch_gf1 = {1};
static const ch_gf ch_121665 = {0xDB41, 1};
static const ch_gf ch_D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const ch_gf ch_X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const ch_gf ch_Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};

static void gf_copy(ch_gf out, const ch_gf in)
{
    for (int i = 0; i < 16; i++)
        out[i] = in[i];
}

static void gf_carry(ch_gf out)
{
    int64_t carry;

    for (int i = 0; i < 16; i++) {
        out[i] += (int64_t)1 << 16;
        carry = out[i] >> 16;
        out[(i + 1) * (i < 15)] += carry - 1 + 37 * (carry - 1) * (i == 15);
        out[i] -= carry << 16;
    }
}

static void gf_select(ch_gf p, ch_gf q, int bit)
{
    int64_t mask = (int64_t)~(bit - 1);

    for (int i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);

        p[i] ^= t;
        q[i] ^= t;
    }
}

static void gf_pack(uint8_t out[32], const ch_gf n)
{
    ch_gf m;
    ch_gf t;
    int bit;

    gf_copy(t, n);
    gf_carry(t);
    gf_carry(t);
    gf_carry(t);
    for (int round = 0; round < 2; round++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        bit = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        gf_select(t, m, 1 - bit);
    }
    for (int i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t)(t[i] & 0xff);
        out[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void gf_unpack(ch_gf out, const uint8_t in[32])
{
    for (int i = 0; i < 16; i++)
        out[i] = (int64_t)in[2 * i] + ((int64_t)in[2 * i + 1] << 8);
    out[15] &= 0x7fff;
}

static void gf_add(ch_gf out, const ch_gf a, const ch_gf b)
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] + b[i];
}

static void gf_sub(ch_gf out, const ch_gf a, const ch_gf b)
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] - b[i];
}

static void gf_mul(ch_gf out, const ch_gf a, const ch_gf b)
{
    int64_t t[31];

    for (int i = 0; i < 31; i++)
        t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++)
        out[i] = t[i];
    gf_carry(out);
    gf_carry(out);
}

static void gf_square(ch_gf out, const ch_gf a)
{
    gf_mul(out, a, a);
}

static void gf_invert(ch_gf out, const ch_gf in)
{
    ch_gf c;

    gf_copy(c, in);
    for (int a = 253; a >= 0; a--) {
        gf_square(c, c);
        if (a != 2 && a != 4)
            gf_mul(c, c, in);
    }
    gf_copy(out, c);
}

void ch_x25519(uint8_t out[32], const uint8_t scalar[32],
               const uint8_t point[32])
{
    uint8_t z[32];
    int64_t x[80];
    ch_gf a, b, c, d, e, f;
    int64_t bit;

    memcpy(z, scalar, 32);
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;

    gf_unpack(x, point);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        c[i] = 0;
        d[i] = 0;
        a[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;

    for (int i = 254; i >= 0; i--) {
        bit = (z[i >> 3] >> (i & 7)) & 1;
        gf_select(a, b, (int)bit);
        gf_select(c, d, (int)bit);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_square(d, e);
        gf_square(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_square(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, ch_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_square(b, e);
        gf_select(a, b, (int)bit);
        gf_select(c, d, (int)bit);
    }

    for (int i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    gf_invert(x + 32, x + 32);
    gf_mul(x + 16, x + 16, x + 32);
    gf_pack(out, x + 16);
}

/* ------------------------------------------------------------------ */
/* Ed25519                                                             */
/* ------------------------------------------------------------------ */

static const int64_t ed_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
};

static uint8_t ed_parity(const ch_gf value)
{
    uint8_t packed[32];

    gf_pack(packed, value);
    return (uint8_t)(packed[0] & 1);
}

static void ed_pack(uint8_t out[32], ch_gf point[4])
{
    ch_gf tx, ty, zi;

    gf_invert(zi, point[2]);
    gf_mul(tx, point[0], zi);
    gf_mul(ty, point[1], zi);
    gf_pack(out, ty);
    out[31] ^= (uint8_t)(ed_parity(tx) << 7);
}

static void ed_add(ch_gf p[4], ch_gf q[4])
{
    ch_gf a, b, c, d, e, f, g, h, t;

    gf_sub(a, p[1], p[0]);
    gf_sub(t, q[1], q[0]);
    gf_mul(a, a, t);
    gf_add(b, p[0], p[1]);
    gf_add(t, q[0], q[1]);
    gf_mul(b, b, t);
    gf_mul(c, p[3], q[3]);
    gf_mul(c, c, ch_D2);
    gf_mul(d, p[2], q[2]);
    gf_add(d, d, d);
    gf_sub(e, b, a);
    gf_sub(f, d, c);
    gf_add(g, d, c);
    gf_add(h, b, a);

    gf_mul(p[0], e, f);
    gf_mul(p[1], h, g);
    gf_mul(p[2], g, f);
    gf_mul(p[3], e, h);
}

static void ed_cswap(ch_gf p[4], ch_gf q[4], uint8_t bit)
{
    for (int i = 0; i < 4; i++)
        gf_select(p[i], q[i], bit);
}

static void ed_scalarmult(ch_gf p[4], ch_gf q[4], const uint8_t *scalar)
{
    gf_copy(p[0], ch_gf0);
    gf_copy(p[1], ch_gf1);
    gf_copy(p[2], ch_gf1);
    gf_copy(p[3], ch_gf0);
    for (int i = 255; i >= 0; i--) {
        uint8_t bit = (uint8_t)((scalar[i / 8] >> (i & 7)) & 1);

        ed_cswap(p, q, bit);
        ed_add(q, p);
        ed_add(p, p);
        ed_cswap(p, q, bit);
    }
}

static void ed_scalarbase(ch_gf p[4], const uint8_t *scalar)
{
    ch_gf q[4];

    gf_copy(q[0], ch_X);
    gf_copy(q[1], ch_Y);
    gf_copy(q[2], ch_gf1);
    gf_mul(q[3], ch_X, ch_Y);
    ed_scalarmult(p, q, scalar);
}

static void ed_modL(uint8_t *out, int64_t x[64])
{
    int64_t carry;

    for (int i = 63; i >= 32; i--) {
        int j;

        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * ed_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (int j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * ed_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; j++)
        x[j] -= carry * ed_L[j];
    for (int i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        out[i] = (uint8_t)(x[i] & 255);
    }
}

static void ed_reduce(uint8_t *value)
{
    int64_t x[64];

    for (int i = 0; i < 64; i++)
        x[i] = value[i];
    memset(value, 0, 64);
    ed_modL(value, x);
}

void ch_ed25519_public_key(uint8_t out[32], const uint8_t seed[32])
{
    uint8_t d[64];
    ch_gf p[4];

    sha512_once(seed, 32, d);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    ed_scalarbase(p, d);
    ed_pack(out, p);
}

void ch_ed25519_sign(uint8_t signature[64], const uint8_t *message,
                     size_t message_len, const uint8_t seed[32])
{
    uint8_t d[64];
    uint8_t r[64];
    uint8_t h[64];
    uint8_t public_key[32];
    int64_t x[64];
    ch_gf p[4];
    struct ch_sha512 ctx;

    sha512_once(seed, 32, d);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    ed_scalarbase(p, d);
    ed_pack(public_key, p);

    ch_sha512_init(&ctx);
    ch_sha512_update(&ctx, d + 32, 32);
    ch_sha512_update(&ctx, message, message_len);
    ch_sha512_final(&ctx, r);
    ed_reduce(r);

    ed_scalarbase(p, r);
    ed_pack(signature, p);

    ch_sha512_init(&ctx);
    ch_sha512_update(&ctx, signature, 32);
    ch_sha512_update(&ctx, public_key, 32);
    ch_sha512_update(&ctx, message, message_len);
    ch_sha512_final(&ctx, h);
    ed_reduce(h);

    memset(x, 0, sizeof x);
    for (int i = 0; i < 32; i++)
        x[i] = r[i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i + j] += (int64_t)h[i] * d[j];
    ed_modL(signature + 32, x);
}
