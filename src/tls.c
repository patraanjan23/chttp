/*
 * chttp TLS 1.3 - see tls.h.
 *
 * The record layer and handshake state machine are written here; the
 * primitives live in crypto.c. Every length is checked before use, every
 * read is bounded, and the handshake runs against a wall-clock deadline.
 */
#include "tls.h"

#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TLS_RECORD_MAX 16384
#define TLS_RECORD_SLACK 256
#define TLS_HS_MAX 32768
#define TLS_CERT_MAX TLS_MAX_CERTIFICATE_BYTES
#define TLS_ALERT_MAX 64

#define TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_ALERT 21
#define TLS_CONTENT_HANDSHAKE 22
#define TLS_CONTENT_APPLICATION 23

#define TLS_HS_CLIENT_HELLO 1
#define TLS_HS_SERVER_HELLO 2
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_HS_CERTIFICATE 11
#define TLS_HS_CERTIFICATE_VERIFY 15
#define TLS_HS_FINISHED 20
#define TLS_HS_KEY_UPDATE 24
#define TLS_HS_MESSAGE_HASH 254

#define TLS_EXT_SERVER_NAME 0
#define TLS_EXT_SUPPORTED_GROUPS 10
#define TLS_EXT_SIGNATURE_ALGORITHMS 13
#define TLS_EXT_ALPN 16
#define TLS_EXT_SUPPORTED_VERSIONS 43
#define TLS_EXT_KEY_SHARE 51

#define TLS_GROUP_X25519 0x001d
#define TLS_VERSION_1_3 0x0304
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_ED25519 0x0807

#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_MISSING_EXTENSION 109

struct tls_keys {
    uint8_t key[CH_AES128_KEY_LEN];
    uint8_t iv[CH_GCM_NONCE_LEN];
    uint64_t sequence;
};

struct tls_conn {
    int fd;
    const struct tls_credentials *credentials;
    int active;      /* record protection installed */
    int established; /* handshake finished */
    int closed;      /* close_notify sent or received */
    int timed_out;
    char error[TLS_ALERT_MAX + 128];

    struct tls_keys read_keys;
    struct tls_keys write_keys;

    struct ch_sha256 transcript;

    uint8_t handshake[TLS_HS_MAX];
    size_t handshake_len;
    size_t handshake_offset;

    uint8_t record[5 + TLS_RECORD_MAX + TLS_RECORD_SLACK];
    uint8_t outgoing[5 + TLS_RECORD_MAX + 1 + CH_GCM_TAG_LEN];

    size_t application_len;
    size_t application_offset;

    uint8_t client_handshake_secret[CH_SHA256_LEN];
    uint8_t server_handshake_secret[CH_SHA256_LEN];
    uint8_t client_application_secret[CH_SHA256_LEN];
    uint8_t server_application_secret[CH_SHA256_LEN];
};

/* ------------------------------------------------------------------ */
/* Diagnostics and time                                                */
/* ------------------------------------------------------------------ */

static int tls_ms_since(const struct timespec *start)
{
    struct timespec now;
    long long elapsed;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return 0;
    elapsed = (long long)(now.tv_sec - start->tv_sec) * 1000
            + (now.tv_nsec - start->tv_nsec) / 1000000;
    if (elapsed < 0)
        return 0;
    return elapsed > 2147483647LL ? 2147483647 : (int)elapsed;
}

static int tls_fail(struct tls_conn *conn, const char *fmt, ...)
{
    va_list args;

    if (conn->error[0] == '\0') {
        va_start(args, fmt);
        vsnprintf(conn->error, sizeof conn->error, fmt, args);
        va_end(args);
    }
    return -1;
}

const char *tls_error(const struct tls_conn *conn)
{
    return conn->error[0] != '\0' ? conn->error : "tls error";
}

int tls_error_is_timeout(const struct tls_conn *conn)
{
    return conn->timed_out;
}

/* ------------------------------------------------------------------ */
/* Raw socket I/O under the connection deadline                        */
/* ------------------------------------------------------------------ */

static int raw_read(struct tls_conn *conn, void *data, size_t length,
                    const struct timespec *start, int timeout_ms)
{
    uint8_t *bytes = data;

    while (length > 0) {
        ssize_t got;

        if (tls_ms_since(start) >= timeout_ms) {
            conn->timed_out = 1;
            return tls_fail(conn, "handshake deadline exceeded");
        }
        got = recv(conn->fd, bytes, length, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn->timed_out = 1;
                return tls_fail(conn, "socket timeout");
            }
            return tls_fail(conn, "receive failed: %s", strerror(errno));
        }
        if (got == 0)
            return tls_fail(conn, "connection closed during handshake");
        bytes += got;
        length -= (size_t)got;
    }
    return 0;
}

static int raw_write(struct tls_conn *conn, const void *data, size_t length,
                     const struct timespec *start, int timeout_ms)
{
    const uint8_t *bytes = data;

    while (length > 0) {
        ssize_t sent;

        if (tls_ms_since(start) >= timeout_ms) {
            conn->timed_out = 1;
            return tls_fail(conn, "write deadline exceeded");
        }
        sent = send(conn->fd, bytes, length, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn->timed_out = 1;
                return tls_fail(conn, "socket timeout");
            }
            return tls_fail(conn, "send failed: %s", strerror(errno));
        }
        if (sent == 0)
            return tls_fail(conn, "send returned zero");
        bytes += sent;
        length -= (size_t)sent;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* PEM / DER credential loading                                        */
/* ------------------------------------------------------------------ */

static int file_read(const char *path, size_t limit, uint8_t **out,
                     size_t *out_len, char *error, size_t error_size)
{
    uint8_t *buffer;
    size_t used = 0;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(error, error_size, "cannot open %s: %s", path,
                 strerror(errno));
        return -1;
    }
    buffer = malloc(limit + 1);
    if (buffer == NULL) {
        close(fd);
        snprintf(error, error_size, "out of memory reading %s", path);
        return -1;
    }
    for (;;) {
        ssize_t got = read(fd, buffer + used, limit + 1 - used);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            snprintf(error, error_size, "cannot read %s: %s", path,
                     strerror(errno));
            free(buffer);
            close(fd);
            return -1;
        }
        if (got == 0)
            break;
        used += (size_t)got;
        if (used > limit) {
            snprintf(error, error_size, "%s is larger than %zu bytes", path,
                     limit);
            free(buffer);
            close(fd);
            return -1;
        }
    }
    close(fd);
    *out = buffer;
    *out_len = used;
    return 0;
}

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int base64_decode(const uint8_t *text, size_t length, uint8_t **out,
                         size_t *out_len, char *error, size_t error_size)
{
    uint8_t *buffer = malloc(length / 4 * 3 + 3);
    size_t used = 0;
    int group[4];
    int count = 0;

    if (buffer == NULL) {
        snprintf(error, error_size, "out of memory decoding PEM");
        return -1;
    }
    for (size_t i = 0; i < length; i++) {
        unsigned char c = text[i];
        int value;

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        if (c == '=') {
            value = -2;
        } else {
            value = base64_value(c);
            if (value < 0) {
                snprintf(error, error_size, "invalid base64 in PEM block");
                free(buffer);
                return -1;
            }
        }
        group[count++] = value;
        if (count == 4) {
            if (group[0] < 0 || group[1] < 0) {
                snprintf(error, error_size, "invalid base64 padding");
                free(buffer);
                return -1;
            }
            buffer[used++] = (uint8_t)((group[0] << 2) | (group[1] >> 4));
            if (group[2] >= 0) {
                buffer[used++] = (uint8_t)(((group[1] & 15) << 4)
                                           | (group[2] >> 2));
                if (group[3] >= 0)
                    buffer[used++] = (uint8_t)(((group[2] & 3) << 6)
                                               | group[3]);
            }
            count = 0;
        }
    }
    if (count != 0) {
        snprintf(error, error_size, "truncated base64 in PEM block");
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_len = used;
    return 0;
}

/* Finds one "-----BEGIN <label>-----" ... "-----END <label>-----" block
 * starting at *cursor, decodes it, and advances *cursor past it. */
static int pem_next(const uint8_t *data, size_t data_len, const char *label,
                    size_t *cursor, uint8_t **out, size_t *out_len,
                    char *error, size_t error_size)
{
    char begin[64];
    char end[64];
    size_t begin_len;
    size_t end_len;
    const uint8_t *begin_at;
    const uint8_t *end_at;
    size_t body_start;

    snprintf(begin, sizeof begin, "-----BEGIN %s-----", label);
    snprintf(end, sizeof end, "-----END %s-----", label);
    begin_len = strlen(begin);
    end_len = strlen(end);

    begin_at = memmem(data + *cursor, data_len - *cursor, begin, begin_len);
    if (begin_at == NULL) {
        snprintf(error, error_size, "no %s PEM block found", label);
        return -1;
    }
    body_start = (size_t)(begin_at - data) + begin_len;
    end_at = memmem(data + body_start, data_len - body_start, end, end_len);
    if (end_at == NULL) {
        snprintf(error, error_size, "unterminated %s PEM block", label);
        return -1;
    }
    if (base64_decode(data + body_start, (size_t)(end_at - (data + body_start)),
                      out, out_len, error, error_size) < 0)
        return -1;
    *cursor = (size_t)(end_at - data) + end_len;
    return 0;
}

struct der {
    const uint8_t *data;
    size_t length;
};

static int der_next(struct der *input, uint8_t *tag, struct der *value)
{
    size_t length;
    size_t header = 2;
    uint8_t first;

    if (input->length < 2)
        return -1;
    first = input->data[1];
    if ((first & 0x80) != 0) {
        size_t count = first & 0x7f;

        if (count == 0 || count > 2 || input->length < 2 + count)
            return -1;
        length = 0;
        for (size_t i = 0; i < count; i++)
            length = (length << 8) | input->data[2 + i];
        header += count;
    } else {
        length = first;
    }
    if (length > input->length - header)
        return -1;
    *tag = input->data[0];
    value->data = input->data + header;
    value->length = length;
    input->data += header + length;
    input->length -= header + length;
    return 0;
}

static int der_expect(struct der *input, uint8_t expected, struct der *value)
{
    uint8_t tag;

    if (der_next(input, &tag, value) < 0 || tag != expected)
        return -1;
    return 0;
}

static int der_skip(struct der *input)
{
    uint8_t tag;
    struct der ignored;

    return der_next(input, &tag, &ignored);
}

static int oid_is_ed25519(const struct der *oid)
{
    static const uint8_t ed25519[] = {0x2b, 0x65, 0x70};

    return oid->length == sizeof ed25519
        && memcmp(oid->data, ed25519, sizeof ed25519) == 0;
}

static int parse_private_key(const uint8_t *data, size_t length,
                             uint8_t seed[32], char *error, size_t error_size)
{
    struct der file = {data, length};
    struct der outer;
    struct der version;
    struct der algorithm;
    struct der oid;
    struct der wrapped;
    struct der inner;

    if (der_expect(&file, 0x30, &outer) < 0
        || der_expect(&outer, 0x02, &version) < 0
        || der_expect(&outer, 0x30, &algorithm) < 0
        || der_expect(&algorithm, 0x06, &oid) < 0
        || der_expect(&outer, 0x04, &wrapped) < 0
        || der_expect(&wrapped, 0x04, &inner) < 0
        || inner.length != 32 || !oid_is_ed25519(&oid)) {
        snprintf(error, error_size,
                 "key is not an unencrypted PKCS#8 Ed25519 private key");
        return -1;
    }
    memcpy(seed, inner.data, 32);
    return 0;
}

/* Extracts the Ed25519 public key from the leaf certificate's SPKI. */
static int parse_certificate_public_key(const uint8_t *data, size_t length,
                                        uint8_t public_key[32], char *error,
                                        size_t error_size)
{
    struct der file = {data, length};
    struct der certificate;
    struct der tbs;
    struct der spki;
    struct der algorithm;
    struct der oid;
    struct der bits;

    if (der_expect(&file, 0x30, &certificate) < 0
        || der_expect(&certificate, 0x30, &tbs) < 0) {
        snprintf(error, error_size, "certificate is not valid DER");
        return -1;
    }
    if (tbs.length > 0 && tbs.data[0] == 0xa0 && der_skip(&tbs) < 0)
        goto bad_certificate;
    if (der_skip(&tbs) < 0 /* serialNumber */
        || der_skip(&tbs) < 0 /* signature algorithm */
        || der_skip(&tbs) < 0 /* issuer */
        || der_skip(&tbs) < 0 /* validity */
        || der_skip(&tbs) < 0 /* subject */
        || der_expect(&tbs, 0x30, &spki) < 0
        || der_expect(&spki, 0x30, &algorithm) < 0
        || der_expect(&algorithm, 0x06, &oid) < 0
        || der_expect(&spki, 0x03, &bits) < 0
        || bits.length != 33 || bits.data[0] != 0
        || !oid_is_ed25519(&oid))
        goto bad_certificate;

    memcpy(public_key, bits.data + 1, 32);
    return 0;

bad_certificate:
    snprintf(error, error_size,
             "leaf certificate does not contain an Ed25519 public key");
    return -1;
}

void tls_free_credentials(struct tls_credentials *credentials)
{
    for (size_t i = 0; i < credentials->certificate_count; i++) {
        free(credentials->certificates[i]);
        credentials->certificates[i] = NULL;
        credentials->certificate_lens[i] = 0;
    }
    credentials->certificate_count = 0;
    credentials->certificate_bytes = 0;
    memset(credentials->private_key, 0, sizeof credentials->private_key);
    memset(credentials->public_key, 0, sizeof credentials->public_key);
}

int tls_load_credentials(const char *certificate_path, const char *key_path,
                         struct tls_credentials *credentials, char *error,
                         size_t error_size)
{
    uint8_t *certificate_file = NULL;
    uint8_t *key_file = NULL;
    size_t certificate_file_len = 0;
    size_t key_file_len = 0;
    int result = -1;

    memset(credentials, 0, sizeof *credentials);
    error[0] = '\0';

    if (file_read(certificate_path, 64 * 1024, &certificate_file,
                  &certificate_file_len, error, error_size) < 0)
        return -1;
    if (file_read(key_path, 8 * 1024, &key_file, &key_file_len, error,
                  error_size) < 0) {
        free(certificate_file);
        return -1;
    }

    if (memmem(certificate_file, certificate_file_len, "-----BEGIN", 10)
        != NULL) {
        size_t cursor = 0;

        while (credentials->certificate_count < TLS_MAX_CERTIFICATES) {
            uint8_t *der = NULL;
            size_t der_len = 0;
            char pem_error[128];

            if (pem_next(certificate_file, certificate_file_len, "CERTIFICATE",
                         &cursor, &der, &der_len, pem_error,
                         sizeof pem_error) < 0) {
                if (credentials->certificate_count == 0) {
                    snprintf(error, error_size, "%s", pem_error);
                    goto out;
                }
                break;
            }
            if (der_len > TLS_MAX_CERTIFICATE_BYTES
                || credentials->certificate_bytes + der_len
                   > TLS_MAX_CERTIFICATE_BYTES) {
                snprintf(error, error_size,
                         "certificate chain exceeds %d bytes",
                         TLS_MAX_CERTIFICATE_BYTES);
                free(der);
                goto out;
            }
            credentials->certificates[credentials->certificate_count] = der;
            credentials->certificate_lens[credentials->certificate_count]
                = der_len;
            credentials->certificate_count++;
            credentials->certificate_bytes += der_len;
        }
        if (credentials->certificate_count == 0) {
            snprintf(error, error_size, "no certificate found in %s",
                     certificate_path);
            goto out;
        }
    } else {
        if (certificate_file_len > TLS_MAX_CERTIFICATE_BYTES) {
            snprintf(error, error_size, "certificate is larger than %d bytes",
                     TLS_MAX_CERTIFICATE_BYTES);
            goto out;
        }
        credentials->certificates[0] = certificate_file;
        credentials->certificate_lens[0] = certificate_file_len;
        credentials->certificate_count = 1;
        credentials->certificate_bytes = certificate_file_len;
        certificate_file = NULL;
    }

    {
        uint8_t *key_der = key_file;
        size_t key_der_len = key_file_len;
        uint8_t decoded[32];

        if (memmem(key_file, key_file_len, "-----BEGIN", 10) != NULL) {
            size_t cursor = 0;

            key_der = NULL;
            if (pem_next(key_file, key_file_len, "PRIVATE KEY", &cursor,
                         &key_der, &key_der_len, error, error_size) < 0) {
                key_der = NULL;
                goto out;
            }
        }
        if (parse_private_key(key_der, key_der_len, decoded, error,
                              error_size) < 0) {
            if (key_der != key_file)
                free(key_der);
            goto out;
        }
        memcpy(credentials->private_key, decoded, 32);
        if (key_der != key_file)
            free(key_der);
        memset(decoded, 0, sizeof decoded);
    }

    ch_ed25519_public_key(credentials->public_key,
                          credentials->private_key);

    {
        uint8_t certificate_key[32];

        if (parse_certificate_public_key(credentials->certificates[0],
                                         credentials->certificate_lens[0],
                                         certificate_key, error,
                                         error_size) < 0)
            goto out;
        if (memcmp(certificate_key, credentials->public_key, 32) != 0) {
            snprintf(error, error_size,
                     "certificate public key does not match the private key");
            goto out;
        }
    }

    result = 0;

out:
    free(certificate_file);
    free(key_file);
    if (result < 0)
        tls_free_credentials(credentials);
    return result;
}

/* ------------------------------------------------------------------ */
/* Record layer                                                        */
/* ------------------------------------------------------------------ */

static void make_nonce(uint8_t nonce[CH_GCM_NONCE_LEN],
                       const uint8_t iv[CH_GCM_NONCE_LEN], uint64_t sequence)
{
    memcpy(nonce, iv, CH_GCM_NONCE_LEN);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (uint8_t)(sequence >> (56 - 8 * i));
}

static int send_record(struct tls_conn *conn, int type, const uint8_t *data,
                       size_t length, const struct timespec *start,
                       int timeout_ms)
{
    uint8_t nonce[CH_GCM_NONCE_LEN];
    uint8_t tag[CH_GCM_TAG_LEN];
    size_t total;

    if (length > TLS_RECORD_MAX)
        return tls_fail(conn, "record too large to send");

    if (!conn->active) {
        total = 5 + length;
        conn->outgoing[0] = (uint8_t)type;
        conn->outgoing[1] = 0x03;
        conn->outgoing[2] = 0x03;
        conn->outgoing[3] = (uint8_t)(length >> 8);
        conn->outgoing[4] = (uint8_t)length;
        memcpy(conn->outgoing + 5, data, length);
        return raw_write(conn, conn->outgoing, total, start, timeout_ms);
    }

    total = length + 1 + CH_GCM_TAG_LEN;
    conn->outgoing[0] = TLS_CONTENT_APPLICATION;
    conn->outgoing[1] = 0x03;
    conn->outgoing[2] = 0x03;
    conn->outgoing[3] = (uint8_t)(total >> 8);
    conn->outgoing[4] = (uint8_t)total;

    memmove(conn->outgoing + 5, data, length);
    conn->outgoing[5 + length] = (uint8_t)type;

    make_nonce(nonce, conn->write_keys.iv, conn->write_keys.sequence);
    ch_aes128_gcm_encrypt(conn->write_keys.key, nonce, conn->outgoing, 5,
                          conn->outgoing + 5, length + 1,
                          conn->outgoing + 5, tag);
    memcpy(conn->outgoing + 5 + length + 1, tag, sizeof tag);
    conn->write_keys.sequence++;
    return raw_write(conn, conn->outgoing, 5 + total, start, timeout_ms);
}

static int read_record(struct tls_conn *conn, int *type, uint8_t **data,
                       size_t *length, const struct timespec *start,
                       int timeout_ms)
{
    for (;;) {
        uint8_t header[5] = {0};
        size_t record_length;

        if (raw_read(conn, header, sizeof header, start, timeout_ms) < 0)
            return -1;
        if (header[0] < TLS_CONTENT_CHANGE_CIPHER_SPEC
            || header[0] > TLS_CONTENT_APPLICATION)
            return tls_fail(conn, "invalid record type %u", header[0]);
        if (header[1] != 0x03)
            return tls_fail(conn, "invalid record version");
        record_length = ((size_t)header[3] << 8) | header[4];
        if (record_length > TLS_RECORD_MAX + TLS_RECORD_SLACK)
            return tls_fail(conn, "record larger than %d bytes",
                            TLS_RECORD_MAX + TLS_RECORD_SLACK);
        if (raw_read(conn, conn->record + 5, record_length, start,
                     timeout_ms) < 0)
            return -1;

        /* Middlebox-compatibility ChangeCipherSpec: allowed during the
         * handshake, ignored; after the handshake it is a protocol error. */
        if (header[0] == TLS_CONTENT_CHANGE_CIPHER_SPEC) {
            if (conn->established)
                return tls_fail(conn, "unexpected ChangeCipherSpec");
            if (record_length != 1 || conn->record[5] != 1)
                return tls_fail(conn, "malformed ChangeCipherSpec");
            continue;
        }

        if (!conn->active) {
            *type = header[0];
            *data = conn->record + 5;
            *length = record_length;
            return 0;
        }

        if (header[0] != TLS_CONTENT_APPLICATION)
            return tls_fail(conn, "unprotected record after handshake keys");
        if (record_length < 1 + CH_GCM_TAG_LEN)
            return tls_fail(conn, "protected record is too short");

        {
            size_t cipher_length = record_length - CH_GCM_TAG_LEN;
            uint8_t nonce[CH_GCM_NONCE_LEN];
            int inner;

            make_nonce(nonce, conn->read_keys.iv, conn->read_keys.sequence);
            if (ch_aes128_gcm_decrypt(conn->read_keys.key, nonce, header, 5,
                                      conn->record + 5, cipher_length,
                                      conn->record + 5,
                                      conn->record + 5 + cipher_length) < 0)
                return tls_fail(conn, "record authentication failed");
            conn->read_keys.sequence++;

            while (cipher_length > 0
                   && conn->record[5 + cipher_length - 1] == 0)
                cipher_length--;
            if (cipher_length == 0)
                return tls_fail(conn, "record has no content type");
            inner = conn->record[5 + cipher_length - 1];
            cipher_length--;
            if (inner < TLS_CONTENT_CHANGE_CIPHER_SPEC
                || inner > TLS_CONTENT_APPLICATION)
                return tls_fail(conn, "invalid inner content type");

            *type = inner;
            *data = conn->record + 5;
            *length = cipher_length;
            return 0;
        }
    }
}

static void send_alert(struct tls_conn *conn, int level, int description,
                       const struct timespec *start, int timeout_ms)
{
    uint8_t alert[2];

    if (conn->closed)
        return;
    alert[0] = (uint8_t)level;
    alert[1] = (uint8_t)description;
    (void)send_record(conn, TLS_CONTENT_ALERT, alert, sizeof alert, start,
                      timeout_ms);
    if (description == TLS_ALERT_CLOSE_NOTIFY)
        conn->closed = 1;
}

/* ------------------------------------------------------------------ */
/* Handshake reader                                                    */
/* ------------------------------------------------------------------ */

static int next_handshake(struct tls_conn *conn, uint8_t **message,
                          size_t *message_len, const struct timespec *start,
                          int timeout_ms)
{
    for (;;) {
        size_t need;

        if (conn->handshake_offset > 0) {
            memmove(conn->handshake,
                    conn->handshake + conn->handshake_offset,
                    conn->handshake_len - conn->handshake_offset);
            conn->handshake_len -= conn->handshake_offset;
            conn->handshake_offset = 0;
        }
        if (conn->handshake_len >= 4) {
            need = 4 + (((size_t)conn->handshake[1] << 16)
                        | ((size_t)conn->handshake[2] << 8)
                        | conn->handshake[3]);
            if (need > sizeof conn->handshake)
                return tls_fail(conn, "handshake message too large");
            if (conn->handshake_len >= need) {
                *message = conn->handshake;
                *message_len = need;
                conn->handshake_offset = need;
                return 0;
            }
        }

        {
            int type;
            uint8_t *data;
            size_t length;

            if (read_record(conn, &type, &data, &length, start, timeout_ms) < 0)
                return -1;
            if (type == TLS_CONTENT_ALERT) {
                if (length == 2 && data[1] == TLS_ALERT_CLOSE_NOTIFY) {
                    conn->closed = 1;
                    return tls_fail(conn, "peer closed during handshake");
                }
                return tls_fail(conn, "peer sent an alert");
            }
            if (type != TLS_CONTENT_HANDSHAKE)
                return tls_fail(conn, "expected a handshake record");
            if (conn->handshake_len + length > sizeof conn->handshake)
                return tls_fail(conn, "handshake data too large");
            memcpy(conn->handshake + conn->handshake_len, data, length);
            conn->handshake_len += length;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Transcript, key schedule, small writers                             */
/* ------------------------------------------------------------------ */

static void transcript_add(struct tls_conn *conn, const void *data,
                           size_t length)
{
    ch_sha256_update(&conn->transcript, data, length);
}

static void transcript_hash(struct tls_conn *conn, uint8_t out[CH_SHA256_LEN])
{
    struct ch_sha256 copy = conn->transcript;

    ch_sha256_final(&copy, out);
}

static void derive_secret(const uint8_t secret[CH_SHA256_LEN],
                          const char *label, const uint8_t context[CH_SHA256_LEN],
                          uint8_t out[CH_SHA256_LEN])
{
    ch_hkdf_expand_label_sha256(secret, label, strlen(label), context,
                                CH_SHA256_LEN, out, CH_SHA256_LEN);
}

static void install_read_keys(struct tls_conn *conn,
                              const uint8_t secret[CH_SHA256_LEN])
{
    ch_hkdf_expand_label_sha256(secret, "key", 3, NULL, 0,
                                conn->read_keys.key, CH_AES128_KEY_LEN);
    ch_hkdf_expand_label_sha256(secret, "iv", 2, NULL, 0,
                                conn->read_keys.iv, CH_GCM_NONCE_LEN);
    conn->read_keys.sequence = 0;
}

static void install_write_keys(struct tls_conn *conn,
                               const uint8_t secret[CH_SHA256_LEN])
{
    ch_hkdf_expand_label_sha256(secret, "key", 3, NULL, 0,
                                conn->write_keys.key, CH_AES128_KEY_LEN);
    ch_hkdf_expand_label_sha256(secret, "iv", 2, NULL, 0,
                                conn->write_keys.iv, CH_GCM_NONCE_LEN);
    conn->write_keys.sequence = 0;
}

struct writer {
    uint8_t *data;
    size_t capacity;
    size_t length;
    int failed;
};

static void w_bytes(struct writer *w, const void *data, size_t length)
{
    if (w->failed || length > w->capacity - w->length) {
        w->failed = 1;
        return;
    }
    memcpy(w->data + w->length, data, length);
    w->length += length;
}

static void w_u8(struct writer *w, uint8_t value)
{
    w_bytes(w, &value, 1);
}

static void w_u16(struct writer *w, uint16_t value)
{
    uint8_t bytes[2] = {(uint8_t)(value >> 8), (uint8_t)value};

    w_bytes(w, bytes, sizeof bytes);
}

static void w_u24(struct writer *w, size_t value)
{
    uint8_t bytes[3] = {(uint8_t)(value >> 16), (uint8_t)(value >> 8),
                        (uint8_t)value};

    w_bytes(w, bytes, sizeof bytes);
}

static void patch_u16(uint8_t *data, size_t at, size_t value)
{
    data[at] = (uint8_t)(value >> 8);
    data[at + 1] = (uint8_t)value;
}

static void patch_u24(uint8_t *data, size_t at, size_t value)
{
    data[at] = (uint8_t)(value >> 16);
    data[at + 1] = (uint8_t)(value >> 8);
    data[at + 2] = (uint8_t)value;
}

static int send_handshake(struct tls_conn *conn, int type,
                          const uint8_t *body, size_t body_len,
                          const struct timespec *start, int timeout_ms)
{
    uint8_t message[TLS_RECORD_MAX + 512];
    size_t message_len = 4 + body_len;
    size_t offset = 0;

    if (message_len > sizeof message)
        return tls_fail(conn, "handshake message too large to send");
    message[0] = (uint8_t)type;
    message[1] = (uint8_t)(body_len >> 16);
    message[2] = (uint8_t)(body_len >> 8);
    message[3] = (uint8_t)body_len;
    memcpy(message + 4, body, body_len);
    transcript_add(conn, message, message_len);

    while (offset < message_len) {
        size_t chunk = message_len - offset;

        if (chunk > TLS_RECORD_MAX)
            chunk = TLS_RECORD_MAX;
        if (send_record(conn, TLS_CONTENT_HANDSHAKE, message + offset, chunk,
                        start, timeout_ms) < 0)
            return -1;
        offset += chunk;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* ClientHello                                                         */
/* ------------------------------------------------------------------ */

struct hello {
    uint8_t session_id[32];
    size_t session_id_len;
    int has_tls13;
    int has_aes128gcm;
    int has_ed25519;
    int has_x25519_group;
    int has_x25519_share;
    uint8_t x25519_share[32];
};

static int take_bytes(const uint8_t **cursor, size_t *left, size_t count,
                      const uint8_t **out)
{
    if (count > *left)
        return -1;
    *out = *cursor;
    *cursor += count;
    *left -= count;
    return 0;
}

static int take_u8(const uint8_t **cursor, size_t *left, uint8_t *out)
{
    const uint8_t *bytes;

    if (take_bytes(cursor, left, 1, &bytes) < 0)
        return -1;
    *out = bytes[0];
    return 0;
}

static int take_u16(const uint8_t **cursor, size_t *left, uint16_t *out)
{
    const uint8_t *bytes;

    if (take_bytes(cursor, left, 2, &bytes) < 0)
        return -1;
    *out = (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
    return 0;
}

static int parse_extensions(const uint8_t *data, size_t length,
                            struct hello *hello)
{
    const uint8_t *cursor = data;
    size_t left = length;

    while (left > 0) {
        uint16_t type;
        uint16_t ext_len;
        const uint8_t *body;
        size_t body_left;

        if (take_u16(&cursor, &left, &type) < 0
            || take_u16(&cursor, &left, &ext_len) < 0
            || take_bytes(&cursor, &left, ext_len, &body) < 0)
            return -1;
        body_left = ext_len;

        if (type == TLS_EXT_SUPPORTED_VERSIONS) {
            uint8_t list_len;
            const uint8_t *list;

            if (take_u8(&body, &body_left, &list_len) < 0
                || take_bytes(&body, &body_left, list_len, &list) < 0)
                return -1;
            for (size_t i = 0; i + 1 < list_len; i += 2) {
                uint16_t version = (uint16_t)(((uint16_t)list[i] << 8)
                                              | list[i + 1]);

                if (version == TLS_VERSION_1_3)
                    hello->has_tls13 = 1;
            }
        } else if (type == TLS_EXT_SUPPORTED_GROUPS) {
            uint16_t list_len;
            const uint8_t *list;

            if (take_u16(&body, &body_left, &list_len) < 0
                || take_bytes(&body, &body_left, list_len, &list) < 0)
                return -1;
            for (size_t i = 0; i + 1 < list_len; i += 2) {
                uint16_t group = (uint16_t)(((uint16_t)list[i] << 8)
                                            | list[i + 1]);

                if (group == TLS_GROUP_X25519)
                    hello->has_x25519_group = 1;
            }
        } else if (type == TLS_EXT_SIGNATURE_ALGORITHMS) {
            uint16_t list_len;
            const uint8_t *list;

            if (take_u16(&body, &body_left, &list_len) < 0
                || take_bytes(&body, &body_left, list_len, &list) < 0)
                return -1;
            for (size_t i = 0; i + 1 < list_len; i += 2) {
                uint16_t scheme = (uint16_t)(((uint16_t)list[i] << 8)
                                             | list[i + 1]);

                if (scheme == TLS_ED25519)
                    hello->has_ed25519 = 1;
            }
        } else if (type == TLS_EXT_KEY_SHARE) {
            uint16_t shares_len;
            const uint8_t *shares;

            const uint8_t *share_cursor;
            size_t share_left;

            if (take_u16(&body, &body_left, &shares_len) < 0
                || take_bytes(&body, &body_left, shares_len, &shares) < 0)
                return -1;
            share_cursor = shares;
            share_left = shares_len;
            while (share_left > 0) {
                uint16_t group;
                uint16_t key_len;
                const uint8_t *key;

                if (take_u16(&share_cursor, &share_left, &group) < 0
                    || take_u16(&share_cursor, &share_left, &key_len) < 0
                    || take_bytes(&share_cursor, &share_left, key_len,
                                  &key) < 0)
                    return -1;
                if (group == TLS_GROUP_X25519 && key_len == 32) {
                    memcpy(hello->x25519_share, key, 32);
                    hello->has_x25519_share = 1;
                }
            }
        }
    }
    return 0;
}

static int parse_client_hello(const uint8_t *message, size_t length,
                              struct hello *hello)
{
    const uint8_t *cursor;
    size_t left;
    const uint8_t *body;
    uint16_t legacy_version;
    uint16_t suites_len;
    uint8_t compression_len;
    const uint8_t *compression;

    memset(hello, 0, sizeof *hello);
    if (length < 4 + 2 + 32 + 1 || message[0] != TLS_HS_CLIENT_HELLO)
        return -1;
    cursor = message + 4;
    left = length - 4;

    if (take_u16(&cursor, &left, &legacy_version) < 0
        || legacy_version < 0x0301 || legacy_version > 0x0303)
        return -1;
    if (take_bytes(&cursor, &left, 32, &body) < 0)
        return -1;
    if (take_u8(&cursor, &left, &compression_len) < 0
        || compression_len > 32)
        return -1;
    hello->session_id_len = compression_len;
    if (take_bytes(&cursor, &left, compression_len, &body) < 0)
        return -1;
    memcpy(hello->session_id, body, compression_len);

    if (take_u16(&cursor, &left, &suites_len) < 0
        || suites_len < 2 || (suites_len & 1) != 0)
        return -1;
    if (take_bytes(&cursor, &left, suites_len, &body) < 0)
        return -1;
    for (size_t i = 0; i < suites_len; i += 2) {
        uint16_t suite = (uint16_t)(((uint16_t)body[i] << 8) | body[i + 1]);

        if (suite == TLS_AES_128_GCM_SHA256)
            hello->has_aes128gcm = 1;
    }

    if (take_u8(&cursor, &left, &compression_len) < 0
        || compression_len < 1)
        return -1;
    if (take_bytes(&cursor, &left, compression_len, &compression) < 0)
        return -1;
    {
        int has_null = 0;

        for (size_t i = 0; i < compression_len; i++) {
            if (compression[i] == 0)
                has_null = 1;
        }
        if (!has_null)
            return -1;
    }

    if (left == 0)
        return 0;
    {
        uint16_t extensions_len;

        if (take_u16(&cursor, &left, &extensions_len) < 0
            || extensions_len != left)
            return -1;
        if (parse_extensions(cursor, left, hello) < 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Handshake                                                           */
/* ------------------------------------------------------------------ */

static const uint8_t hello_retry_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

static int build_server_hello(uint8_t *out, size_t capacity,
                              const struct hello *hello,
                              const uint8_t random[32],
                              const uint8_t public_key[32], int retry)
{
    struct writer w = {out, capacity, 0, 0};
    size_t extensions_length_at;
    size_t extensions_start;

    w_u16(&w, 0x0303);
    w_bytes(&w, random, 32);
    w_u8(&w, (uint8_t)hello->session_id_len);
    w_bytes(&w, hello->session_id, hello->session_id_len);
    w_u16(&w, TLS_AES_128_GCM_SHA256);
    w_u8(&w, 0);

    extensions_length_at = w.length;
    w_u16(&w, 0);
    extensions_start = w.length;

    w_u16(&w, TLS_EXT_SUPPORTED_VERSIONS);
    w_u16(&w, 2);
    w_u16(&w, TLS_VERSION_1_3);

    w_u16(&w, TLS_EXT_KEY_SHARE);
    if (retry) {
        w_u16(&w, 2);
        w_u16(&w, TLS_GROUP_X25519);
    } else {
        w_u16(&w, 36);
        w_u16(&w, TLS_GROUP_X25519);
        w_u16(&w, 32);
        w_bytes(&w, public_key, 32);
    }

    if (w.failed)
        return -1;
    patch_u16(out, extensions_length_at, w.length - extensions_start);
    return (int)w.length;
}

static int send_certificate_message(struct tls_conn *conn,
                                    const struct tls_credentials *credentials,
                                    const struct timespec *start,
                                    int timeout_ms)
{
    uint8_t body[TLS_MAX_CERTIFICATE_BYTES + 64];
    struct writer w = {body, sizeof body, 0, 0};
    size_t list_length_at;
    size_t list_start;

    w_u8(&w, 0); /* certificate_request_context */
    list_length_at = w.length;
    w_u24(&w, 0);
    list_start = w.length;
    for (size_t i = 0; i < credentials->certificate_count; i++) {
        w_u24(&w, credentials->certificate_lens[i]);
        w_bytes(&w, credentials->certificates[i],
                credentials->certificate_lens[i]);
        w_u16(&w, 0); /* no certificate extensions */
    }
    if (w.failed)
        return tls_fail(conn, "certificate chain too large for one message");
    patch_u24(body, list_length_at, w.length - list_start);
    return send_handshake(conn, TLS_HS_CERTIFICATE, body, w.length, start,
                          timeout_ms);
}

static int send_certificate_verify(struct tls_conn *conn,
                                   const struct tls_credentials *credentials,
                                   const struct timespec *start,
                                   int timeout_ms)
{
    static const char context[] = "TLS 1.3, server CertificateVerify";
    uint8_t content[64 + sizeof context - 1 + 1 + CH_SHA256_LEN];
    uint8_t signature[64];
    uint8_t body[2 + 2 + 64];
    struct writer w = {body, sizeof body, 0, 0};

    memset(content, 0x20, 64);
    memcpy(content + 64, context, sizeof context - 1);
    content[64 + sizeof context - 1] = 0;
    transcript_hash(conn, content + 64 + sizeof context);
    ch_ed25519_sign(signature, content, sizeof content,
                    credentials->private_key);

    w_u16(&w, TLS_ED25519);
    w_u16(&w, sizeof signature);
    w_bytes(&w, signature, sizeof signature);
    return send_handshake(conn, TLS_HS_CERTIFICATE_VERIFY, body, w.length,
                          start, timeout_ms);
}

static int send_finished(struct tls_conn *conn, int server,
                         const struct timespec *start, int timeout_ms)
{
    const uint8_t *secret = server ? conn->server_handshake_secret
                                   : conn->client_handshake_secret;
    uint8_t finished_key[CH_SHA256_LEN];
    uint8_t verify_data[CH_SHA256_LEN];
    uint8_t hash[CH_SHA256_LEN];

    transcript_hash(conn, hash);
    ch_hkdf_expand_label_sha256(secret, "finished", 8, NULL, 0,
                                finished_key, sizeof finished_key);
    ch_hmac_sha256(finished_key, sizeof finished_key, hash, sizeof hash,
                   verify_data);
    return send_handshake(conn, TLS_HS_FINISHED, verify_data,
                          sizeof verify_data, start, timeout_ms);
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b,
                               size_t length)
{
    uint8_t difference = 0;

    for (size_t i = 0; i < length; i++)
        difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0;
}

int tls_handshake(struct tls_conn *conn, const struct timespec *start,
                  int timeout_ms)
{
    uint8_t *message = NULL;
    size_t message_len = 0;
    struct hello hello;
    uint8_t empty_hash[CH_SHA256_LEN];
    uint8_t early_secret[CH_SHA256_LEN];
    uint8_t derived[CH_SHA256_LEN];
    uint8_t handshake_secret[CH_SHA256_LEN];
    uint8_t master_secret[CH_SHA256_LEN];
    uint8_t private_key[32];
    uint8_t public_key[32];
    uint8_t shared_secret[32];
    uint8_t server_random[32];
    uint8_t hash[CH_SHA256_LEN];
    uint8_t body[512];
    struct writer w = {body, sizeof body, 0, 0};
    int handshake_length;
    static const uint8_t basepoint[32] = {9};
    static const uint8_t zeros[32];

#define TLS_ABORT(code, ...)                                                 \
    do {                                                                     \
        tls_fail(conn, __VA_ARGS__);                                         \
        send_alert(conn, 2, (code), start, timeout_ms);                      \
        return -1;                                                           \
    } while (0)

    conn->error[0] = '\0';
    conn->timed_out = 0;
    conn->active = 0;
    conn->established = 0;
    conn->closed = 0;
    conn->handshake_len = 0;
    conn->handshake_offset = 0;
    conn->application_len = 0;
    conn->application_offset = 0;
    ch_sha256_init(&conn->transcript);
    ch_sha256("", 0, empty_hash);

    if (next_handshake(conn, &message, &message_len, start, timeout_ms) < 0)
        return -1;
    transcript_add(conn, message, message_len);
    if (parse_client_hello(message, message_len, &hello) < 0)
        TLS_ABORT(TLS_ALERT_DECODE_ERROR, "malformed ClientHello");

    if (!hello.has_tls13)
        TLS_ABORT(TLS_ALERT_PROTOCOL_VERSION,
                  "client did not offer TLS 1.3");
    if (!hello.has_aes128gcm)
        TLS_ABORT(TLS_ALERT_HANDSHAKE_FAILURE,
                  "client did not offer TLS_AES_128_GCM_SHA256");
    if (!hello.has_ed25519)
        TLS_ABORT(TLS_ALERT_HANDSHAKE_FAILURE,
                  "client did not offer the Ed25519 signature scheme");

    if (!hello.has_x25519_share) {
        if (!hello.has_x25519_group)
            TLS_ABORT(TLS_ALERT_HANDSHAKE_FAILURE,
                      "client does not support X25519");

        /* The client sent a key share for another group (common with the
         * post-quantum hybrids). Ask it to retry with X25519. */
        transcript_hash(conn, hash);
        ch_sha256_init(&conn->transcript);
        {
            uint8_t message_hash[4] = {TLS_HS_MESSAGE_HASH, 0, 0, 32};

            transcript_add(conn, message_hash, sizeof message_hash);
            transcript_add(conn, hash, sizeof hash);
        }
        handshake_length = build_server_hello(body, sizeof body, &hello,
                                              hello_retry_random, NULL, 1);
        if (handshake_length < 0
            || send_handshake(conn, TLS_HS_SERVER_HELLO, body,
                              (size_t)handshake_length, start, timeout_ms) < 0)
            return -1;

        if (next_handshake(conn, &message, &message_len, start, timeout_ms) < 0)
            return -1;
        transcript_add(conn, message, message_len);
        if (parse_client_hello(message, message_len, &hello) < 0)
            TLS_ABORT(TLS_ALERT_DECODE_ERROR, "malformed second ClientHello");
        if (!hello.has_tls13)
            TLS_ABORT(TLS_ALERT_PROTOCOL_VERSION,
                      "client did not offer TLS 1.3");
        if (!hello.has_aes128gcm || !hello.has_ed25519)
            TLS_ABORT(TLS_ALERT_HANDSHAKE_FAILURE,
                      "client changed its TLS 1.3 offer");
        if (!hello.has_x25519_share)
            TLS_ABORT(TLS_ALERT_HANDSHAKE_FAILURE,
                      "client did not send an X25519 key share");
    }

    if (ch_random(private_key, sizeof private_key) < 0
        || ch_random(server_random, sizeof server_random) < 0)
        TLS_ABORT(TLS_ALERT_INTERNAL_ERROR, "no system randomness");
    ch_x25519(public_key, private_key, basepoint);
    ch_x25519(shared_secret, private_key, hello.x25519_share);
    {
        static const uint8_t zero_secret[32];
        uint8_t difference = 0;

        for (int i = 0; i < 32; i++)
            difference |= (uint8_t)(shared_secret[i] ^ zero_secret[i]);
        if (difference == 0)
            TLS_ABORT(TLS_ALERT_ILLEGAL_PARAMETER,
                      "client sent an unusable X25519 share");
    }

    handshake_length = build_server_hello(body, sizeof body, &hello,
                                          server_random, public_key, 0);
    if (handshake_length < 0
        || send_handshake(conn, TLS_HS_SERVER_HELLO, body,
                          (size_t)handshake_length, start, timeout_ms) < 0)
        return -1;

    /* Handshake key schedule (RFC 8446 section 7.1). */
    ch_hkdf_extract_sha256(NULL, 0, zeros, sizeof zeros, early_secret);
    derive_secret(early_secret, "derived", empty_hash, derived);
    ch_hkdf_extract_sha256(derived, sizeof derived, shared_secret,
                           sizeof shared_secret, handshake_secret);
    transcript_hash(conn, hash);
    derive_secret(handshake_secret, "c hs traffic", hash,
                  conn->client_handshake_secret);
    derive_secret(handshake_secret, "s hs traffic", hash,
                  conn->server_handshake_secret);
    derive_secret(handshake_secret, "derived", empty_hash, derived);
    ch_hkdf_extract_sha256(derived, sizeof derived, zeros, sizeof zeros,
                           master_secret);

    install_read_keys(conn, conn->client_handshake_secret);
    install_write_keys(conn, conn->server_handshake_secret);
    conn->active = 1;

    w_u16(&w, 0); /* EncryptedExtensions: no extensions */
    if (w.failed
        || send_handshake(conn, TLS_HS_ENCRYPTED_EXTENSIONS, body, w.length,
                          start, timeout_ms) < 0)
        return -1;

    if (send_certificate_message(conn, conn->credentials, start,
                                 timeout_ms) < 0)
        return -1;
    if (send_certificate_verify(conn, conn->credentials, start,
                                timeout_ms) < 0)
        return -1;
    if (send_finished(conn, 1, start, timeout_ms) < 0)
        return -1;

    /* Application traffic secrets, with the transcript through the server
     * Finished. The server can send application data immediately. */
    transcript_hash(conn, hash);
    derive_secret(master_secret, "c ap traffic", hash,
                  conn->client_application_secret);
    derive_secret(master_secret, "s ap traffic", hash,
                  conn->server_application_secret);
    install_write_keys(conn, conn->server_application_secret);

    if (next_handshake(conn, &message, &message_len, start, timeout_ms) < 0)
        return -1;
    if (message[0] != TLS_HS_FINISHED || message_len != 4 + CH_SHA256_LEN)
        TLS_ABORT(TLS_ALERT_UNEXPECTED_MESSAGE,
                  "expected the client Finished");
    {
        uint8_t finished_key[CH_SHA256_LEN];
        uint8_t expected[CH_SHA256_LEN];

        transcript_hash(conn, hash);
        ch_hkdf_expand_label_sha256(conn->client_handshake_secret,
                                    "finished", 8, NULL, 0, finished_key,
                                    sizeof finished_key);
        ch_hmac_sha256(finished_key, sizeof finished_key, hash, sizeof hash,
                       expected);
        if (!constant_time_equal(expected, message + 4, CH_SHA256_LEN))
            TLS_ABORT(TLS_ALERT_DECRYPT_ERROR,
                      "client Finished verification failed");
    }
    transcript_add(conn, message, message_len);
    install_read_keys(conn, conn->client_application_secret);
    conn->established = 1;

    memset(private_key, 0, sizeof private_key);
    memset(shared_secret, 0, sizeof shared_secret);
    return 0;

#undef TLS_ABORT
}

/* ------------------------------------------------------------------ */
/* Application data                                                    */
/* ------------------------------------------------------------------ */

static int handle_post_handshake(struct tls_conn *conn, const uint8_t *data,
                                 size_t length, const struct timespec *start,
                                 int timeout_ms)
{
    size_t body_len;

    if (length < 4 || data[0] != TLS_HS_KEY_UPDATE)
        return tls_fail(conn, "unexpected post-handshake message");
    body_len = ((size_t)data[1] << 16) | ((size_t)data[2] << 8) | data[3];
    if (body_len != 1 || length != 5)
        return tls_fail(conn, "malformed KeyUpdate");
    if (data[4] > 1)
        return tls_fail(conn, "invalid KeyUpdate request value");

    ch_hkdf_expand_label_sha256(conn->client_application_secret,
                                "traffic upd", 10, NULL, 0,
                                conn->client_application_secret,
                                CH_SHA256_LEN);
    install_read_keys(conn, conn->client_application_secret);

    if (data[4] == 1) {
        uint8_t update[5] = {TLS_HS_KEY_UPDATE, 0, 0, 1, 0};

        if (send_record(conn, TLS_CONTENT_HANDSHAKE, update, sizeof update,
                        start, timeout_ms) < 0)
            return -1;
        ch_hkdf_expand_label_sha256(conn->server_application_secret,
                                    "traffic upd", 10, NULL, 0,
                                    conn->server_application_secret,
                                    CH_SHA256_LEN);
        install_write_keys(conn, conn->server_application_secret);
    }
    return 0;
}

ssize_t tls_read(struct tls_conn *conn, void *data, size_t length,
                 const struct timespec *start, int timeout_ms)
{
    uint8_t *bytes = data;

    if (length == 0)
        return 0;
    while (conn->application_offset >= conn->application_len) {
        int type = 0;
        uint8_t *payload = NULL;
        size_t payload_len = 0;

        if (read_record(conn, &type, &payload, &payload_len, start,
                        timeout_ms) < 0)
            return -1;
        if (type == TLS_CONTENT_APPLICATION) {
            conn->application_offset = 0;
            conn->application_len = payload_len;
        } else if (type == TLS_CONTENT_ALERT) {
            if (payload_len == 2
                && payload[1] == TLS_ALERT_CLOSE_NOTIFY) {
                conn->closed = 1;
                return 0;
            }
            return tls_fail(conn, "peer sent alert %u",
                            payload_len == 2 ? payload[1] : 255u);
        } else if (type == TLS_CONTENT_HANDSHAKE) {
            if (handle_post_handshake(conn, payload, payload_len, start,
                                      timeout_ms) < 0)
                return -1;
        } else {
            return tls_fail(conn, "unexpected record type %d", type);
        }
    }

    {
        size_t available = conn->application_len - conn->application_offset;
        size_t take = length < available ? length : available;

        memcpy(bytes, conn->record + 5 + conn->application_offset, take);
        conn->application_offset += take;
        return (ssize_t)take;
    }
}

long tls_write_all(struct tls_conn *conn, const void *data, size_t length,
                   const struct timespec *start, int timeout_ms)
{
    const uint8_t *bytes = data;
    size_t remaining = length;

    if (conn->closed)
        return -1;
    while (remaining > 0) {
        size_t chunk = remaining < TLS_RECORD_MAX ? remaining
                                                  : TLS_RECORD_MAX;

        if (send_record(conn, TLS_CONTENT_APPLICATION, bytes, chunk, start,
                        timeout_ms) < 0)
            return -1;
        bytes += chunk;
        remaining -= chunk;
    }
    return (long)length;
}

void tls_shutdown(struct tls_conn *conn, const struct timespec *start,
                  int timeout_ms)
{
    if (conn->established && !conn->closed)
        send_alert(conn, 1, TLS_ALERT_CLOSE_NOTIFY, start, timeout_ms);
}

struct tls_conn *tls_conn_new(int fd, const struct tls_credentials *credentials)
{
    struct tls_conn *conn = calloc(1, sizeof *conn);

    if (conn == NULL)
        return NULL;
    conn->fd = fd;
    conn->credentials = credentials;
    return conn;
}

void tls_conn_free(struct tls_conn *conn)
{
    free(conn);
}
