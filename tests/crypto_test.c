/* Known-answer tests for the primitives TLS depends on. */
#include "../src/crypto.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void hex_decode(const char *text, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned value = 0;

        if (sscanf(text + i * 2, "%2x", &value) != 1) {
            fprintf(stderr, "bad test vector\n");
            failures++;
            return;
        }
        out[i] = (uint8_t)value;
    }
}

static void check(const char *name, const uint8_t *got, const char *expected,
                  size_t len)
{
    uint8_t want[128];

    if (len > sizeof want)
        return;
    hex_decode(expected, want, len);
    if (memcmp(got, want, len) != 0) {
        fprintf(stderr, "FAIL %s\n", name);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

static void test_sha256(void)
{
    static const char *const messages[] = {
        "",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };
    static const char *const digests[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    };
    uint8_t digest[32];

    for (size_t i = 0; i < 3; i++) {
        ch_sha256(messages[i], strlen(messages[i]), digest);
        check("SHA-256", digest, digests[i], sizeof digest);
    }
}

static void test_sha512(void)
{
    struct ch_sha512 ctx;
    uint8_t digest[64];

    ch_sha512_init(&ctx);
    ch_sha512_update(&ctx, "abc", 3);
    ch_sha512_final(&ctx, digest);
    check("SHA-512",
          digest,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          sizeof digest);
}

static void test_hmac_hkdf(void)
{
    static const uint8_t jefe[] = "Jefe";
    static const uint8_t data[] = "what do ya want for nothing?";
    uint8_t mac[32];
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[32];
    uint8_t okm[42];

    ch_hmac_sha256(jefe, sizeof jefe - 1, data, sizeof data - 1, mac);
    check("HMAC-SHA256", mac,
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          sizeof mac);

    memset(ikm, 0x0b, sizeof ikm);
    for (size_t i = 0; i < sizeof salt; i++)
        salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof info; i++)
        info[i] = (uint8_t)(0xf0 + i);

    ch_hkdf_extract_sha256(salt, sizeof salt, ikm, sizeof ikm, prk);
    check("HKDF-Extract", prk,
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
          sizeof prk);
    ch_hkdf_expand_sha256(prk, info, sizeof info, okm, sizeof okm);
    check("HKDF-Expand", okm,
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865", sizeof okm);
}

static void test_aes_gcm(void)
{
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[20];
    uint8_t plain[60];
    uint8_t cipher[60];
    uint8_t tag[16];
    uint8_t recovered[60];
    uint8_t broken[16];

    hex_decode("feffe9928665731c6d6a8f9467308308", key, sizeof key);
    hex_decode("cafebabefacedbaddecaf888", nonce, sizeof nonce);
    hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof aad);
    hex_decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
               "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
               plain, sizeof plain);

    ch_aes128_gcm_encrypt(key, nonce, aad, sizeof aad, plain, sizeof plain,
                          cipher, tag);
    check("AES-128-GCM ciphertext", cipher,
          "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
          "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
          sizeof cipher);
    check("AES-128-GCM tag", tag,
          "5bc94fbc3221a5db94fae95ae7121a47", sizeof tag);

    if (ch_aes128_gcm_decrypt(key, nonce, aad, sizeof aad, cipher,
                              sizeof cipher, recovered, tag) != 0
        || memcmp(recovered, plain, sizeof plain) != 0) {
        fprintf(stderr, "FAIL AES-128-GCM decrypt\n");
        failures++;
    } else {
        printf("ok: AES-128-GCM decrypt\n");
    }

    memcpy(broken, tag, sizeof broken);
    broken[0] ^= 1;
    if (ch_aes128_gcm_decrypt(key, nonce, aad, sizeof aad, cipher,
                              sizeof cipher, recovered, broken) == 0) {
        fprintf(stderr, "FAIL AES-128-GCM accepted a bad tag\n");
        failures++;
    } else {
        printf("ok: AES-128-GCM rejects a bad tag\n");
    }
}

static void test_x25519(void)
{
    uint8_t alice_private[32];
    uint8_t bob_private[32];
    uint8_t alice_public[32];
    uint8_t bob_public[32];
    uint8_t shared[32];
    static const uint8_t basepoint[32] = {9};

    hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
               alice_private, sizeof alice_private);
    hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
               bob_private, sizeof bob_private);

    ch_x25519(alice_public, alice_private, basepoint);
    ch_x25519(bob_public, bob_private, basepoint);
    check("X25519 Alice public", alice_public,
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
          sizeof alice_public);
    check("X25519 Bob public", bob_public,
          "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          sizeof bob_public);

    ch_x25519(shared, alice_private, bob_public);
    check("X25519 shared secret", shared,
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
          sizeof shared);
}

static void test_ed25519(void)
{
    uint8_t seed[32];
    uint8_t public_key[32];
    uint8_t signature[64];
    uint8_t message[1] = {0x72};

    hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
               seed, sizeof seed);
    ch_ed25519_public_key(public_key, seed);
    check("Ed25519 public key (1)", public_key,
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
          sizeof public_key);
    ch_ed25519_sign(signature, (const uint8_t *)"", 0, seed);
    check("Ed25519 signature (1)", signature,
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
          sizeof signature);

    hex_decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
               seed, sizeof seed);
    ch_ed25519_public_key(public_key, seed);
    check("Ed25519 public key (2)", public_key,
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
          sizeof public_key);
    ch_ed25519_sign(signature, message, sizeof message, seed);
    check("Ed25519 signature (2)", signature,
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
          sizeof signature);
}

int main(void)
{
    test_sha256();
    test_sha512();
    test_hmac_hkdf();
    test_aes_gcm();
    test_x25519();
    test_ed25519();
    if (failures != 0) {
        fprintf(stderr, "%d crypto test(s) failed\n", failures);
        return 1;
    }
    printf("all crypto tests passed\n");
    return 0;
}
