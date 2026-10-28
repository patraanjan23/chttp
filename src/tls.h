/*
 * chttp TLS 1.3 server side.
 *
 * Deliberately one profile, chosen because it is the smallest interoperable
 * subset: TLS 1.3 only, X25519 key exchange, Ed25519 certificates,
 * TLS_AES_128_GCM_SHA256, no resumption, no 0-RTT, no renegotiation.
 * A client that offers anything else is rejected during the handshake.
 */
#ifndef CHTTP_TLS_H
#define CHTTP_TLS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define TLS_MAX_CERTIFICATES 4
#define TLS_MAX_CERTIFICATE_BYTES (16 * 1024)

struct tls_credentials {
    uint8_t *certificates[TLS_MAX_CERTIFICATES];
    size_t certificate_lens[TLS_MAX_CERTIFICATES];
    size_t certificate_count;
    size_t certificate_bytes;
    uint8_t private_key[32];
    uint8_t public_key[32];
};

struct tls_conn;

/* Loads a PEM or DER certificate chain and an unencrypted PKCS#8 Ed25519
 * key. Returns 0 on success; on failure writes a message into error. */
int tls_load_credentials(const char *certificate_path, const char *key_path,
                         struct tls_credentials *credentials, char *error,
                         size_t error_size);
void tls_free_credentials(struct tls_credentials *credentials);

struct tls_conn *tls_conn_new(int fd, const struct tls_credentials *credentials);
void tls_conn_free(struct tls_conn *conn);

/* Runs the server handshake. The deadline is start + timeout_ms. */
int tls_handshake(struct tls_conn *conn, const struct timespec *start,
                  int timeout_ms);
const char *tls_error(const struct tls_conn *conn);
int tls_error_is_timeout(const struct tls_conn *conn);

/* Application data. tls_read returns bytes, 0 on close_notify, -1 on error. */
ssize_t tls_read(struct tls_conn *conn, void *data, size_t len,
                 const struct timespec *start, int timeout_ms);
long tls_write_all(struct tls_conn *conn, const void *data, size_t len,
                   const struct timespec *start, int timeout_ms);
void tls_shutdown(struct tls_conn *conn, const struct timespec *start,
                  int timeout_ms);

#endif
