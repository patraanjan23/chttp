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
 * chttp - a minimal, production-hardened HTTP/1.1 server.
 *
 * One listening process accepts a connection and forks a child that serves
 * a bounded number of requests. Concurrency is bounded, every wait has a
 * deadline, and shutdown drains in-flight requests before exiting.
 *
 * Serves GET, HEAD, and bounded POST echoes over plaintext or TLS 1.3. No
 * configuration files; configuration is flags plus environment
 * variables.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tls.h"

#define CHTTP_VERSION "1.0"

#define DEFAULT_PORT         8080
#define DEFAULT_BIND         "127.0.0.1"
#define DEFAULT_MAX_CONNS    64
#define MAX_CONNS_LIMIT      1024
#define DEFAULT_TIMEOUT_SECS 5
#define MAX_TIMEOUT_SECS     300

#define REQUEST_MAX 8192 /* whole request head, including CRLF CRLF */
#define BODY_MAX    8192
#define URI_MAX     1024 /* request-target, including '/' */
#define KEEPALIVE_MAX_REQUESTS 100

#define DRAIN_MS      5000 /* let in-flight requests finish after SIGTERM */
#define TERM_GRACE_MS 1000 /* then ask them to stop */
#define KILL_GRACE_MS 2000 /* then kill them */

#define RESP_ALLOW       0x1u
#define RESP_RETRY_AFTER 0x2u

struct config {
    const char *bind_addr;
    int port;
    int max_connections;
    int timeout_secs;
    const char *tls_certificate;
    const char *tls_key;
};

struct connection {
    int fd;
    struct tls_conn *tls;
    const struct timespec *start;
    int timeout_ms;
};

struct response {
    int status;
    const char *reason;
    const char *content_type;
    const char *body;
    size_t body_len;
    unsigned flags;
};

struct request_info {
    const char *method;
    const char *target;
    const char *version;
    int include_body;
};

struct request_framing {
    size_t content_length;
    int has_content_length;
    int chunked;
};

struct server {
    struct config cfg;
    int listen_fd;
    pid_t *pids;
    int active;
};

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t child_reaped = 0;

static void request_stop(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static void note_child(int sig)
{
    (void)sig;
    child_reaped = 1;
}

static void install_handler(int sig, void (*handler)(int))
{
    struct sigaction action;

    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0; /* no SA_RESTART: accept/recv must return EINTR */
    if (sigaction(sig, &action, NULL) < 0) {
        fprintf(stderr, "chttp: sigaction(%d): %s\n", sig, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void install_ignore(int sig)
{
    struct sigaction action;

    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(sig, &action, NULL) < 0) {
        fprintf(stderr, "chttp: sigaction(%d): %s\n", sig, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void log_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void log_msg(const char *fmt, ...)
{
    char buf[2048];
    va_list args;
    int written;
    size_t length;
    size_t offset = 0;

    va_start(args, fmt);
    written = vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    if (written <= 0)
        return;

    length = (size_t)written < sizeof buf ? (size_t)written : sizeof buf - 1;
    while (offset < length) {
        ssize_t sent = write(STDERR_FILENO, buf + offset, length - offset);

        if (sent <= 0)
            break;
        offset += (size_t)sent;
    }
}

static int ms_since(const struct timespec *start)
{
    struct timespec now;
    long elapsed;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return 0;
    elapsed = (now.tv_sec - start->tv_sec) * 1000
            + (now.tv_nsec - start->tv_nsec) / 1000000;
    if (elapsed < 0)
        return 0;
    return elapsed > INT_MAX ? INT_MAX : (int)elapsed;
}

static void sleep_ms(int milliseconds)
{
    struct timespec request;

    request.tv_sec = milliseconds / 1000;
    request.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    while (nanosleep(&request, &request) < 0 && errno == EINTR)
        ;
}

static void format_http_date(char *out, size_t capacity)
{
    static const char *const days[7] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char *const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    time_t now = time(NULL);
    struct tm broken;

    if (now == (time_t)-1 || gmtime_r(&now, &broken) == NULL) {
        snprintf(out, capacity, "Thu, 01 Jan 1970 00:00:00 GMT");
        return;
    }
    snprintf(out, capacity, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             days[broken.tm_wday], broken.tm_mday, months[broken.tm_mon],
             broken.tm_year + 1900, broken.tm_hour, broken.tm_min,
             broken.tm_sec);
}

static void format_log_time(char *out, size_t capacity)
{
    time_t now = time(NULL);
    struct tm broken;

    if (now == (time_t)-1 || gmtime_r(&now, &broken) == NULL) {
        snprintf(out, capacity, "1970-01-01T00:00:00Z");
        return;
    }
    snprintf(out, capacity, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             broken.tm_year + 1900, broken.tm_mon + 1, broken.tm_mday,
             broken.tm_hour, broken.tm_min, broken.tm_sec);
}

/* Copy an untrusted string into a log field: quotes/backslashes escaped,
 * control and non-ASCII bytes replaced, output truncated to the buffer. */
static void log_escape(const char *input, char *out, size_t capacity)
{
    size_t used = 0;

    for (const unsigned char *p = (const unsigned char *)input;
         *p != '\0' && used + 2 < capacity; p++) {
        unsigned char c = *p;

        if (c == '"' || c == '\\') {
            out[used++] = '\\';
            out[used++] = (char)c;
        } else if (c < 0x20 || c > 0x7e) {
            out[used++] = '?';
        } else {
            out[used++] = (char)c;
        }
    }
    out[used] = '\0';
}

static void log_access(const char *peer, const char *method,
                       const char *target, const char *version,
                       int status, long bytes, int elapsed_ms)
{
    char timestamp[32];
    char method_safe[32];
    char target_safe[300];
    char version_safe[32];

    format_log_time(timestamp, sizeof timestamp);
    log_escape(method != NULL ? method : "-", method_safe, sizeof method_safe);
    log_escape(target != NULL ? target : "-", target_safe, sizeof target_safe);
    log_escape(version != NULL ? version : "-", version_safe,
               sizeof version_safe);
    log_msg("%s %s \"%s %s %s\" %d %ld %dms\n", timestamp, peer,
            method_safe, target_safe, version_safe, status, bytes, elapsed_ms);
}

static int parse_int(const char *text, int minimum, int maximum, int *out)
{
    char *end = NULL;
    long value;

    if (text == NULL || *text == '\0')
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
        || value < minimum || value > maximum)
        return -1;
    *out = (int)value;
    return 0;
}

static const char usage_text[] =
    "usage: chttp [OPTIONS] [PORT]\n"
    "\n"
    "  --bind ADDR             address to bind (default 127.0.0.1)\n"
    "  --port PORT             TCP port (default 8080)\n"
    "  --max-connections N     concurrent connections (default 64)\n"
    "  --timeout SECONDS       per-request I/O deadline (default 5)\n"
    "  --tls-cert FILE         certificate chain (PEM/DER); enables TLS 1.3\n"
    "  --tls-key FILE          Ed25519 private key (PEM/DER, PKCS#8)\n"
    "  -h, --help              show this help\n"
    "  -V, --version           show the version\n"
    "\n"
    "Environment (flags win): CHTTP_BIND, CHTTP_PORT,\n"
    "  CHTTP_MAX_CONNECTIONS, CHTTP_TIMEOUT, CHTTP_TLS_CERT, CHTTP_TLS_KEY\n";

static void usage_error(const char *message, const char *detail)
{
    if (detail != NULL)
        log_msg("chttp: %s: %s\n", message, detail);
    else
        log_msg("chttp: %s\n", message);
    log_msg("%s", usage_text);
}

/* Returns 0 on success, 1 if the caller should exit successfully (help or
 * version), and -1 on a configuration error. */
static int parse_args(int argc, char **argv, struct config *cfg)
{
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            ssize_t ignored = write(STDOUT_FILENO, usage_text,
                                    sizeof usage_text - 1);
            (void)ignored;
            return 1;
        }
        if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
            char version[32];
            int length = snprintf(version, sizeof version, "chttp %s\n",
                                  CHTTP_VERSION);
            ssize_t ignored;

            if (length > 0)
                ignored = write(STDOUT_FILENO, version, (size_t)length);
            else
                ignored = -1;
            (void)ignored;
            return 1;
        }
        if (strcmp(arg, "--bind") == 0 || strcmp(arg, "--port") == 0
            || strcmp(arg, "--max-connections") == 0
            || strcmp(arg, "--timeout") == 0
            || strcmp(arg, "--tls-cert") == 0
            || strcmp(arg, "--tls-key") == 0) {
            if (i + 1 >= argc) {
                usage_error("missing value for", arg);
                return -1;
            }
            value = argv[++i];
            if (strcmp(arg, "--bind") == 0) {
                if (*value == '\0') {
                    usage_error("empty bind address", NULL);
                    return -1;
                }
                cfg->bind_addr = value;
            } else if (strcmp(arg, "--port") == 0) {
                if (parse_int(value, 1, 65535, &cfg->port) < 0) {
                    usage_error("invalid port", value);
                    return -1;
                }
            } else if (strcmp(arg, "--max-connections") == 0) {
                if (parse_int(value, 1, MAX_CONNS_LIMIT,
                              &cfg->max_connections) < 0) {
                    usage_error("invalid max-connections", value);
                    return -1;
                }
            } else if (strcmp(arg, "--timeout") == 0) {
                if (parse_int(value, 1, MAX_TIMEOUT_SECS,
                              &cfg->timeout_secs) < 0) {
                    usage_error("invalid timeout", value);
                    return -1;
                }
            } else if (strcmp(arg, "--tls-cert") == 0) {
                if (*value == '\0') {
                    usage_error("empty TLS certificate path", NULL);
                    return -1;
                }
                cfg->tls_certificate = value;
            } else {
                if (*value == '\0') {
                    usage_error("empty TLS key path", NULL);
                    return -1;
                }
                cfg->tls_key = value;
            }
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            usage_error("unknown option", arg);
            return -1;
        }
        if (parse_int(arg, 1, 65535, &cfg->port) < 0) {
            usage_error("invalid port", arg);
            return -1;
        }
    }
    return 0;
}

static int apply_env(const char *name, int minimum, int maximum, int *target)
{
    const char *value = getenv(name);

    if (value == NULL || *value == '\0')
        return 0;
    if (parse_int(value, minimum, maximum, target) < 0) {
        log_msg("chttp: invalid %s=%s\n", name, value);
        return -1;
    }
    return 0;
}

static int config_from_env(struct config *cfg)
{
    const char *bind_addr = getenv("CHTTP_BIND");

    if (bind_addr != NULL) {
        if (*bind_addr == '\0') {
            log_msg("chttp: CHTTP_BIND is empty\n");
            return -1;
        }
        cfg->bind_addr = bind_addr;
    }
    if (apply_env("CHTTP_PORT", 1, 65535, &cfg->port) < 0)
        return -1;
    if (apply_env("CHTTP_MAX_CONNECTIONS", 1, MAX_CONNS_LIMIT,
                  &cfg->max_connections) < 0)
        return -1;
    if (apply_env("CHTTP_TIMEOUT", 1, MAX_TIMEOUT_SECS,
                  &cfg->timeout_secs) < 0)
        return -1;
    {
        const char *certificate = getenv("CHTTP_TLS_CERT");
        const char *key = getenv("CHTTP_TLS_KEY");

        if (certificate != NULL) {
            if (*certificate == '\0') {
                log_msg("chttp: CHTTP_TLS_CERT is empty\n");
                return -1;
            }
            cfg->tls_certificate = certificate;
        }
        if (key != NULL) {
            if (*key == '\0') {
                log_msg("chttp: CHTTP_TLS_KEY is empty\n");
                return -1;
            }
            cfg->tls_key = key;
        }
    }
    return 0;
}

static int bind_listener(const struct config *cfg, const char *scheme,
                         char *description, size_t description_size)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    char port_text[8];
    int listener = -1;
    int saved_errno = 0;
    int gai;

    snprintf(port_text, sizeof port_text, "%d", cfg->port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    gai = getaddrinfo(cfg->bind_addr, port_text, &hints, &results);
    if (gai != 0) {
        log_msg("chttp: cannot resolve %s: %s\n", cfg->bind_addr,
                gai_strerror(gai));
        return -1;
    }

    for (struct addrinfo *entry = results; entry != NULL;
         entry = entry->ai_next) {
        int reuse = 1;

        listener = socket(entry->ai_family,
                          entry->ai_socktype | SOCK_CLOEXEC,
                          entry->ai_protocol);
        if (listener < 0) {
            saved_errno = errno;
            continue;
        }
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                       &reuse, sizeof reuse) < 0) {
            saved_errno = errno;
            close(listener);
            listener = -1;
            continue;
        }
        if (bind(listener, entry->ai_addr, entry->ai_addrlen) == 0) {
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];

            if (getnameinfo(entry->ai_addr, entry->ai_addrlen,
                            host, sizeof host, service, sizeof service,
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                snprintf(description, description_size,
                         strchr(host, ':') != NULL ? "%s://[%s]:%s"
                                                   : "%s://%s:%s",
                         scheme, host, service);
            else
                snprintf(description, description_size, "%s:%d",
                         cfg->bind_addr, cfg->port);
            break;
        }
        saved_errno = errno;
        close(listener);
        listener = -1;
    }
    freeaddrinfo(results);

    if (listener < 0)
        log_msg("chttp: cannot bind %s:%d: %s\n", cfg->bind_addr, cfg->port,
                strerror(saved_errno != 0 ? saved_errno : EINVAL));
    return listener;
}

static const char index_html[] =
    "<!doctype html>\n"
    "<html lang=\"en\">\n"
    "<head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>chttp</title>\n"
    "<style>\n"
    "  :root { color-scheme: light dark; }\n"
    "  body { font-family: system-ui, sans-serif; margin: 3rem auto;\n"
    "         max-width: 40rem; padding: 0 1rem; line-height: 1.5; }\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<h1>hello from Fil-C</h1>\n"
    "<p>This page is served by a memory-safe C program.</p>\n"
    "<p><a href=\"/health\">/health</a></p>\n"
    "</body>\n"
    "</html>\n";

static const struct response RESP_INDEX = {
    200, "OK", "text/html; charset=utf-8", index_html,
    sizeof index_html - 1, 0
};
static const struct response RESP_HEALTH = {
    200, "OK", "text/plain; charset=utf-8", "ok\n", sizeof "ok\n" - 1, 0
};
static const struct response RESP_400 = {
    400, "Bad Request", "text/plain; charset=utf-8",
    "bad request\n", sizeof "bad request\n" - 1, 0
};
static const struct response RESP_404 = {
    404, "Not Found", "text/plain; charset=utf-8",
    "not found\n", sizeof "not found\n" - 1, 0
};
static const struct response RESP_405 = {
    405, "Method Not Allowed", "text/plain; charset=utf-8",
    "method not allowed\n", sizeof "method not allowed\n" - 1, RESP_ALLOW
};
static const struct response RESP_408 = {
    408, "Request Timeout", "text/plain; charset=utf-8",
    "request timeout\n", sizeof "request timeout\n" - 1, 0
};
static const struct response RESP_413 = {
    413, "Content Too Large", "text/plain; charset=utf-8",
    "content too large\n", sizeof "content too large\n" - 1, 0
};
static const struct response RESP_414 = {
    414, "URI Too Long", "text/plain; charset=utf-8",
    "uri too long\n", sizeof "uri too long\n" - 1, 0
};
static const struct response RESP_431 = {
    431, "Request Header Fields Too Large", "text/plain; charset=utf-8",
    "request headers too large\n", sizeof "request headers too large\n" - 1, 0
};
static const struct response RESP_503 = {
    503, "Service Unavailable", "text/plain; charset=utf-8",
    "server busy\n", sizeof "server busy\n" - 1, RESP_RETRY_AFTER
};
static const struct response RESP_505 = {
    505, "HTTP Version Not Supported", "text/plain; charset=utf-8",
    "http version not supported\n", sizeof "http version not supported\n" - 1, 0
};

static long send_all(int fd, const void *data, size_t length)
{
    const char *bytes = data;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t sent = send(fd, bytes, remaining, MSG_NOSIGNAL);

        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;
        bytes += sent;
        remaining -= (size_t)sent;
    }
    return (long)length;
}

static int build_header(const struct response *response, char *buffer,
                        size_t capacity, int secure, int keep_alive)
{
    char date[40];
    const char *allow = (response->flags & RESP_ALLOW) != 0
                      ? "Allow: GET, HEAD\r\n" : "";
    const char *retry = (response->flags & RESP_RETRY_AFTER) != 0
                      ? "Retry-After: 1\r\n" : "";
    const char *hsts = secure
                     ? "Strict-Transport-Security: max-age=31536000\r\n" : "";
    const char *connection = keep_alive ? "keep-alive" : "close";
    int written;

    format_http_date(date, sizeof date);
    written = snprintf(buffer, capacity,
                       "HTTP/1.1 %d %s\r\n"
                       "Date: %s\r\n"
                       "Content-Type: %s\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: %s\r\n"
                       "Cache-Control: no-store\r\n"
                       "X-Content-Type-Options: nosniff\r\n"
                       "%s%s%s"
                       "\r\n",
                       response->status, response->reason, date,
                       response->content_type, response->body_len,
                       connection, hsts, allow, retry);
    if (written < 0 || (size_t)written >= capacity)
        return -1;
    return written;
}

static ssize_t connection_read(struct connection *conn, void *buffer,
                               size_t length)
{
    if (conn->tls != NULL)
        return tls_read(conn->tls, buffer, length, conn->start,
                        conn->timeout_ms);
    return recv(conn->fd, buffer, length, 0);
}

static long connection_write_all(struct connection *conn, const void *data,
                                 size_t length)
{
    if (conn->tls != NULL)
        return tls_write_all(conn->tls, data, length, conn->start,
                             conn->timeout_ms);
    return send_all(conn->fd, data, length);
}

static long respond(struct connection *conn, const struct response *response,
                    int include_body, int secure, int keep_alive)
{
    char buffer[2048];
    int header_length = build_header(response, buffer, sizeof buffer, secure,
                                     keep_alive);
    size_t total;

    if (header_length < 0)
        return -1;
    total = (size_t)header_length;

    if (include_body && response->body_len > 0) {
        if (response->body_len <= sizeof buffer - total) {
            /* One write: no header/body split, no Nagle interaction. */
            memcpy(buffer + total, response->body, response->body_len);
            total += response->body_len;
            return connection_write_all(conn, buffer, total);
        }
        {
            long header_sent = connection_write_all(conn, buffer, total);
            long body_sent;

            if (header_sent < 0)
                return -1;
            body_sent = connection_write_all(conn, response->body,
                                             response->body_len);
            if (body_sent < 0)
                return -1;
            return header_sent + body_sent;
        }
    }
    return connection_write_all(conn, buffer, total);
}

static void reject_busy(int fd, const char *peer, int tls_enabled)
{
    char buffer[1024];
    int header_length;
    long sent = -1;

    if (tls_enabled) {
        /* A TLS client cannot parse a plaintext 503. Close instead; the
         * connection cap exists to protect the listener, not to chat. */
        log_access(peer, "-", "-", "-", RESP_503.status, -1, 0);
        return;
    }
    header_length = build_header(&RESP_503, buffer, sizeof buffer, 0, 0);
    if (header_length > 0
        && (size_t)header_length + RESP_503.body_len <= sizeof buffer) {
        ssize_t written;

        memcpy(buffer + header_length, RESP_503.body, RESP_503.body_len);
        written = send(fd, buffer,
                       (size_t)header_length + RESP_503.body_len,
                       MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written > 0)
            sent = (long)written;
    }
    log_access(peer, "-", "-", "-", RESP_503.status, sent, 0);
}

static int is_token(const char *text)
{
    if (*text == '\0')
        return 0;
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        unsigned char c = *p;

        if (c <= 0x20 || c >= 0x7f)
            return 0;
        if (strchr("()<>@,;:\\\"/[]?={}", (int)c) != NULL)
            return 0;
    }
    return 1;
}

static int valid_target(const char *target)
{
    if (target[0] != '/')
        return 0;
    for (const unsigned char *p = (const unsigned char *)target; *p != '\0';
         p++) {
        if (*p < 0x21 || *p > 0x7e)
            return 0;
    }
    return 1;
}

static int path_is(const char *target, const char *path)
{
    size_t length = strlen(path);

    if (strncmp(target, path, length) != 0)
        return 0;
    return target[length] == '\0' || target[length] == '?';
}

static void route_request(char *request, struct request_info *info,
                          struct response *response)
{
    char *line_end = strstr(request, "\r\n");
    char *method;
    char *target;
    char *version;
    char *first_space;
    char *second_space;

    if (line_end == NULL) {
        *response = RESP_400;
        return;
    }
    *line_end = '\0';

    method = request;
    first_space = strchr(method, ' ');
    if (first_space == NULL) {
        *response = RESP_400;
        return;
    }
    *first_space = '\0';
    target = first_space + 1;
    second_space = strchr(target, ' ');
    if (second_space == NULL) {
        *response = RESP_400;
        return;
    }
    *second_space = '\0';
    version = second_space + 1;
    if (*version == '\0' || strchr(version, ' ') != NULL) {
        *response = RESP_400;
        return;
    }

    info->method = method;
    info->target = target;
    info->version = version;

    if (!is_token(method) || *target == '\0') {
        *response = RESP_400;
        return;
    }

    /* HEAD never carries a body, including on error responses. */
    info->include_body = strcmp(method, "HEAD") != 0;

    if (strcmp(version, "HTTP/1.1") != 0
        && strcmp(version, "HTTP/1.0") != 0) {
        *response = strncmp(version, "HTTP/", 5) == 0 ? RESP_505 : RESP_400;
        return;
    }
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0
        && strcmp(method, "POST") != 0) {
        *response = RESP_405;
        return;
    }
    if (strlen(target) >= URI_MAX) {
        *response = RESP_414;
        return;
    }
    if (!valid_target(target)) {
        *response = RESP_400;
        return;
    }

    if (strcmp(method, "POST") == 0)
        *response = path_is(target, "/") ? RESP_405 : RESP_404;
    else if (path_is(target, "/"))
        *response = RESP_INDEX;
    else if (path_is(target, "/health"))
        *response = RESP_HEALTH;
    else
        *response = RESP_404;
}

enum read_result {
    READ_OK,
    READ_EMPTY,
    READ_ABORT,
    READ_TIMEOUT,
    READ_TOO_LARGE,
    READ_BAD
};

static enum read_result read_headers(struct connection *conn, char *buffer,
                                     size_t capacity, size_t *used_out,
                                     char *carry, size_t *pending)
{
    size_t used = *pending;
    if (used != 0)
        memcpy(buffer, carry, used);
    *pending = 0;

    for (;;) {
        ssize_t received;
        char *end = memmem(buffer, used, "\r\n\r\n", 4);
        if (end != NULL) {
            size_t header = (size_t)(end - buffer) + 4;
            *pending = used - header;
            if (*pending != 0)
                memcpy(carry, buffer + header, *pending);
            *used_out = header;
            return READ_OK;
        }
        if (used == capacity)
            return READ_TOO_LARGE;
        if (ms_since(conn->start) >= conn->timeout_ms)
            return READ_TIMEOUT;

        received = connection_read(conn, buffer + used, capacity - used);
        if (received < 0) {
            if (conn->tls != NULL)
                return tls_error_is_timeout(conn->tls) ? READ_TIMEOUT
                                                       : READ_ABORT;
            if (errno == EINTR) {
                if (stop_requested)
                    return READ_ABORT;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return READ_TIMEOUT;
            return READ_ABORT;
        }
        if (received == 0)
            return used == 0 ? READ_EMPTY : READ_BAD;
        if (memchr(buffer + used, '\0', (size_t)received) != NULL)
            return READ_BAD;

        used += (size_t)received;
        {
            char *end = memmem(buffer, used, "\r\n\r\n", 4);
            if (end != NULL) {
                size_t header = (size_t)(end - buffer) + 4;
                *pending = used - header;
                if (*pending != 0)
                    memcpy(carry, buffer + header, *pending);
                *used_out = header;
                return READ_OK;
            }
        }
    }
}

static void finish_response(struct connection *conn, const char *peer,
                            const struct response *response, int include_body,
                            const struct request_info *info,
                            const struct timespec *start, int secure,
                            int keep_alive)
{
    long bytes = respond(conn, response, include_body, secure, keep_alive);

    log_access(peer, info->method, info->target, info->version,
               response->status, bytes, ms_since(start));
}

/* Parse connection policy and bounded request framing. The worker consumes
 * every accepted body before parsing the next pipelined request. */
static int request_keep_alive(char *request, int *keep_alive,
                              struct request_framing *framing)
{
    char *line = strstr(request, "\r\n");
    int close_seen = 0, keep_seen = 0, content_length_seen = 0;
    int host_seen = 0, transfer_encoding_seen = 0;
    int is_http11;

    memset(framing, 0, sizeof *framing);
    if (line == NULL)
        return -1;
    {
        char *last = line;
        while (last > request && last[-1] != ' ')
            last--;
        if (last == request)
            return -1;
        last--;
        is_http11 = (size_t)(line - last - 1) == 8
                 && memcmp(last + 1, "HTTP/1.1", 8) == 0;
    }
    line += 2;
    while (*line != '\0' && !(line[0] == '\r' && line[1] == '\n')) {
        char *end = strstr(line, "\r\n");
        char *colon;
        if (end == NULL)
            return -1;
        *end = '\0';
        colon = strchr(line, ':');
        if (colon == NULL || colon == line)
            return -1;
        *colon++ = '\0';
        if (!is_token(line))
            return -1;
        while (*colon == ' ' || *colon == '\t') colon++;
        {
            char *value_end = colon + strlen(colon);
            while (value_end > colon
                   && (value_end[-1] == ' ' || value_end[-1] == '\t'))
                *--value_end = '\0';
        }
        for (const unsigned char *value = (const unsigned char *)colon;
             *value != '\0'; value++) {
            if ((*value < 0x20 && *value != '\t') || *value == 0x7f)
                return -1;
        }
        if (strcasecmp(line, "Host") == 0) {
            if (host_seen++ || *colon == '\0')
                return -1;
        } else if (strcasecmp(line, "Connection") == 0) {
            char *save = NULL;
            char *token = strtok_r(colon, ",", &save);
            if (token == NULL)
                return -1;
            do {
                char *tail;
                while (*token == ' ' || *token == '\t') token++;
                tail = token + strlen(token);
                while (tail > token && (tail[-1] == ' ' || tail[-1] == '\t'))
                    *--tail = '\0';
                if (!is_token(token))
                    return -1;
                if (strcasecmp(token, "close") == 0) close_seen = 1;
                if (strcasecmp(token, "keep-alive") == 0) keep_seen = 1;
                token = strtok_r(NULL, ",", &save);
            } while (token != NULL);
        } else if (strcasecmp(line, "Content-Length") == 0) {
            char *tail;
            unsigned long long length;
            if (content_length_seen++ || *colon == '\0')
                return -1;
            for (const unsigned char *digit = (const unsigned char *)colon;
                 *digit != '\0'; digit++)
                if (*digit < '0' || *digit > '9')
                    return -1;
            errno = 0;
            length = strtoull(colon, &tail, 10);
            if (errno != 0 || *tail != '\0')
                return -1;
            framing->content_length = length > BODY_MAX
                                    ? BODY_MAX + 1 : (size_t)length;
            framing->has_content_length = 1;
        } else if (strcasecmp(line, "Transfer-Encoding") == 0) {
            if (transfer_encoding_seen++ || strcasecmp(colon, "chunked") != 0)
                return -1;
            framing->chunked = 1;
        }
        line = end + 2;
    }
    if (is_http11 && host_seen != 1)
        return -1;
    if (framing->chunked && (framing->has_content_length || !is_http11))
        return -1;
    *keep_alive = !close_seen && (is_http11 || keep_seen);
    return 0;
}

static enum read_result read_exact(struct connection *conn, void *output,
                                   size_t length, char *carry,
                                   size_t *pending)
{
    unsigned char *out = output;
    size_t used = 0;

    if (*pending != 0) {
        used = *pending < length ? *pending : length;
        memcpy(out, carry, used);
        *pending -= used;
        if (*pending != 0)
            memmove(carry, carry + used, *pending);
    }
    while (used < length) {
        ssize_t received;
        if (ms_since(conn->start) >= conn->timeout_ms)
            return READ_TIMEOUT;
        received = connection_read(conn, out + used, length - used);
        if (received < 0) {
            if (conn->tls != NULL)
                return tls_error_is_timeout(conn->tls) ? READ_TIMEOUT
                                                       : READ_ABORT;
            if (errno == EINTR) {
                if (stop_requested)
                    return READ_ABORT;
                continue;
            }
            return (errno == EAGAIN || errno == EWOULDBLOCK)
                 ? READ_TIMEOUT : READ_ABORT;
        }
        if (received == 0)
            return READ_BAD;
        used += (size_t)received;
    }
    return READ_OK;
}

static enum read_result read_crlf_line(struct connection *conn, char *line,
                                       size_t capacity, char *carry,
                                       size_t *pending)
{
    size_t used = 0;
    while (used + 1 < capacity) {
        enum read_result result = read_exact(conn, line + used, 1, carry,
                                             pending);
        if (result != READ_OK)
            return result;
        if (used != 0 && line[used - 1] == '\r' && line[used] == '\n') {
            line[used - 1] = '\0';
            return READ_OK;
        }
        used++;
    }
    return READ_TOO_LARGE;
}

static enum read_result read_chunked_body(struct connection *conn,
                                          unsigned char *body,
                                          size_t *body_length, char *carry,
                                          size_t *pending)
{
    size_t total = 0, trailer_bytes = 0;
    for (int chunks = 0; chunks < 512; chunks++) {
        char line[128], *end;
        unsigned long long chunk_size;
        enum read_result result = read_crlf_line(conn, line, sizeof line,
                                                  carry, pending);
        if (result != READ_OK)
            return result;
        {
            char *semi = strchr(line, ';');
            char *digits_end = semi != NULL ? semi : line + strlen(line);
            if (digits_end == line)
                return READ_BAD;
            for (char *digit = line; digit < digits_end; digit++)
                if (!((*digit >= '0' && *digit <= '9')
                      || (*digit >= 'a' && *digit <= 'f')
                      || (*digit >= 'A' && *digit <= 'F')))
                    return READ_BAD;
            if (semi != NULL)
                for (const unsigned char *ext =
                         (const unsigned char *)semi + 1; *ext != '\0'; ext++)
                    if (*ext < 0x20 || *ext > 0x7e)
                        return READ_BAD;
            errno = 0;
            chunk_size = strtoull(line, &end, 16);
            if (errno != 0 || end != digits_end)
                return READ_BAD;
        }
        if (chunk_size == 0) {
            for (;;) {
                result = read_crlf_line(conn, line, sizeof line, carry,
                                        pending);
                if (result != READ_OK)
                    return result;
                trailer_bytes += strlen(line) + 2;
                if (trailer_bytes > REQUEST_MAX)
                    return READ_TOO_LARGE;
                if (line[0] == '\0') {
                    *body_length = total;
                    return READ_OK;
                }
                {
                    char *colon = strchr(line, ':');
                    if (colon == NULL || colon == line)
                        return READ_BAD;
                    *colon++ = '\0';
                    if (!is_token(line)
                        || strcasecmp(line, "Content-Length") == 0
                        || strcasecmp(line, "Transfer-Encoding") == 0
                        || strcasecmp(line, "Host") == 0
                        || strcasecmp(line, "Connection") == 0)
                        return READ_BAD;
                    for (const unsigned char *value =
                             (const unsigned char *)colon; *value != '\0'; value++)
                        if ((*value < 0x20 && *value != '\t') || *value == 0x7f)
                            return READ_BAD;
                }
            }
        }
        if (chunk_size > BODY_MAX - total)
            return READ_TOO_LARGE;
        result = read_exact(conn, body + total, (size_t)chunk_size, carry,
                            pending);
        if (result != READ_OK)
            return result;
        total += (size_t)chunk_size;
        {
            char ending[2];
            result = read_exact(conn, ending, sizeof ending, carry, pending);
            if (result != READ_OK)
                return result;
            if (ending[0] != '\r' || ending[1] != '\n')
                return READ_BAD;
        }
    }
    return READ_TOO_LARGE;
}

static void handle_client(int fd, const char *peer, const struct config *cfg,
                          const struct tls_credentials *credentials)
{
    struct request_info info = { "-", "-", "-", 1 };
    struct response response;
    struct timespec start;
    struct connection conn;
    char request[REQUEST_MAX + 1];
    char carry[REQUEST_MAX];
    size_t pending = 0;
    size_t used = 0;
    enum read_result result;
    int secure = credentials != NULL;

    clock_gettime(CLOCK_MONOTONIC, &start);
    conn.fd = fd;
    conn.tls = NULL;
    conn.start = &start;
    conn.timeout_ms = cfg->timeout_secs * 1000;

    if (credentials != NULL) {
        conn.tls = tls_conn_new(fd, credentials);
        if (conn.tls == NULL) {
            log_msg("chttp: out of memory for a TLS connection\n");
            return;
        }
        if (tls_handshake(conn.tls, &start, conn.timeout_ms) < 0) {
            log_msg("chttp: tls handshake from %s failed after %dms: %s\n",
                    peer, ms_since(&start), tls_error(conn.tls));
            /* Signal EOF before freeing the connection state: allocation
             * cleanup must not delay the client's view of the close. */
            shutdown(fd, SHUT_WR);
            tls_conn_free(conn.tls);
            return;
        }
    }

    for (int count = 0; count < KEEPALIVE_MAX_REQUESTS; count++) {
        int keep_alive = 0;
        struct request_framing framing;
        unsigned char body[BODY_MAX];
        size_t body_length = 0;
        info = (struct request_info){ "-", "-", "-", 1 };
        clock_gettime(CLOCK_MONOTONIC, &start);
        result = read_headers(&conn, request, REQUEST_MAX, &used, carry,
                              &pending);
        switch (result) {
        case READ_EMPTY:
            goto out;
        case READ_ABORT:
            log_access(peer, "-", "-", "-", 499, 0, ms_since(&start));
            goto out;
        case READ_TIMEOUT:
            finish_response(&conn, peer, &RESP_408, 1, &info, &start,
                            secure, 0);
            goto out;
        case READ_TOO_LARGE:
            finish_response(&conn, peer, &RESP_431, 1, &info, &start,
                            secure, 0);
            goto out;
        case READ_BAD:
            finish_response(&conn, peer, &RESP_400, 1, &info, &start,
                            secure, 0);
            goto out;
        case READ_OK:
            break;
        }
        request[used] = '\0';
        if (request_keep_alive(request, &keep_alive, &framing) < 0) {
            finish_response(&conn, peer, &RESP_400, 1, &info, &start,
                            secure, 0);
            goto out;
        }
        route_request(request, &info, &response);
        if (framing.content_length > BODY_MAX) {
            finish_response(&conn, peer, &RESP_413, 1, &info, &start,
                            secure, 0);
            goto out;
        }
        if (framing.chunked || framing.content_length != 0) {
            enum read_result body_result;
            if (strcmp(info.method, "POST") != 0) {
                finish_response(&conn, peer, &RESP_400, 1, &info, &start,
                                secure, 0);
                goto out;
            }
            if (framing.chunked)
                body_result = read_chunked_body(&conn, body, &body_length,
                                                carry, &pending);
            else {
                body_length = framing.content_length;
                body_result = read_exact(&conn, body, body_length, carry,
                                         &pending);
            }
            if (body_result != READ_OK) {
                const struct response *error = body_result == READ_TIMEOUT
                                             ? &RESP_408
                                             : body_result == READ_TOO_LARGE
                                               ? &RESP_413 : &RESP_400;
                finish_response(&conn, peer, error, 1, &info, &start,
                                secure, 0);
                goto out;
            }
            if (strcmp(info.target, "/") == 0) {
                response = (struct response){
                    200, "OK", "text/plain; charset=utf-8",
                    (const char *)body, body_length, 0
                };
            }
        }
        if (response.status == 400 || response.status == 408
            || response.status == 414 || response.status == 431
            || response.status == 505)
            keep_alive = 0;
        if (count + 1 == KEEPALIVE_MAX_REQUESTS)
            keep_alive = 0;
        finish_response(&conn, peer, &response, info.include_body, &info,
                        &start, secure, keep_alive);
        if (!keep_alive)
            goto out;
    }

out:
    if (conn.tls != NULL) {
        tls_shutdown(conn.tls, &start, conn.timeout_ms);
        /* The close_notify is on the wire; make the TCP close visible before
         * tearing down the (large) TLS buffers. */
        shutdown(fd, SHUT_WR);
        tls_conn_free(conn.tls);
    }
}

static void set_client_timeouts(int fd, int seconds)
{
    struct timeval timeout;

    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        log_msg("chttp: SO_RCVTIMEO: %s\n", strerror(errno));
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
        log_msg("chttp: SO_SNDTIMEO: %s\n", strerror(errno));
}

static void reap_children(struct server *srv, int quiet)
{
    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0)
            return;
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            if (errno != ECHILD && !quiet)
                log_msg("chttp: waitpid: %s\n", strerror(errno));
            return;
        }

        for (int i = 0; i < srv->cfg.max_connections; i++) {
            if (srv->pids[i] == pid) {
                srv->pids[i] = 0;
                srv->active--;
                break;
            }
        }
        if (quiet)
            continue;
        if (WIFSIGNALED(status))
            log_msg("chttp: connection process %ld terminated by signal %d\n",
                    (long)pid, WTERMSIG(status));
        else if (WEXITSTATUS(status) != 0)
            log_msg("chttp: connection process %ld exited with status %d\n",
                    (long)pid, WEXITSTATUS(status));
    }
}

static void drain_connections(struct server *srv)
{
    struct timespec phase;

    if (srv->active == 0)
        return;
    log_msg("chttp: draining %d connection(s)\n", srv->active);

    clock_gettime(CLOCK_MONOTONIC, &phase);
    while (srv->active > 0 && ms_since(&phase) < DRAIN_MS) {
        reap_children(srv, 1);
        if (srv->active == 0)
            break;
        sleep_ms(20);
    }

    if (srv->active > 0) {
        log_msg("chttp: terminating %d connection(s) with SIGTERM\n",
                srv->active);
        for (int i = 0; i < srv->cfg.max_connections; i++) {
            if (srv->pids[i] > 0)
                kill(srv->pids[i], SIGTERM);
        }
        clock_gettime(CLOCK_MONOTONIC, &phase);
        while (srv->active > 0 && ms_since(&phase) < TERM_GRACE_MS) {
            reap_children(srv, 1);
            if (srv->active > 0)
                sleep_ms(20);
        }
    }

    if (srv->active > 0) {
        log_msg("chttp: killing %d connection(s)\n", srv->active);
        for (int i = 0; i < srv->cfg.max_connections; i++) {
            if (srv->pids[i] > 0)
                kill(srv->pids[i], SIGKILL);
        }
        clock_gettime(CLOCK_MONOTONIC, &phase);
        while (srv->active > 0 && ms_since(&phase) < KILL_GRACE_MS) {
            reap_children(srv, 1);
            if (srv->active > 0)
                sleep_ms(20);
        }
    }

    if (srv->active > 0)
        log_msg("chttp: %d connection process(es) still running; exiting\n",
                srv->active);
}

int main(int argc, char **argv)
{
    struct config cfg = {
        DEFAULT_BIND, DEFAULT_PORT, DEFAULT_MAX_CONNS, DEFAULT_TIMEOUT_SECS,
        NULL, NULL
    };
    struct server srv;
    struct tls_credentials credentials;
    char listen_description[128];
    int exit_code = EXIT_SUCCESS;
    int arguments;
    int tls_enabled = 0;

    if (config_from_env(&cfg) < 0)
        return EXIT_FAILURE;
    arguments = parse_args(argc, argv, &cfg);
    if (arguments > 0)
        return EXIT_SUCCESS;
    if (arguments < 0)
        return EXIT_FAILURE;

    if (cfg.tls_certificate != NULL || cfg.tls_key != NULL) {
        char tls_problem[256];

        if (cfg.tls_certificate == NULL || cfg.tls_key == NULL) {
            log_msg("chttp: --tls-cert and --tls-key must be used together\n");
            return EXIT_FAILURE;
        }
        if (tls_load_credentials(cfg.tls_certificate, cfg.tls_key,
                                 &credentials, tls_problem,
                                 sizeof tls_problem) < 0) {
            log_msg("chttp: tls: %s\n", tls_problem);
            return EXIT_FAILURE;
        }
        tls_enabled = 1;
    }

    install_ignore(SIGPIPE);
    install_ignore(SIGHUP); /* no config reload: restart to change settings */
    install_handler(SIGINT, request_stop);
    install_handler(SIGTERM, request_stop);
    install_handler(SIGCHLD, note_child);

    memset(&srv, 0, sizeof srv);
    srv.cfg = cfg;
    srv.listen_fd = bind_listener(&cfg, tls_enabled ? "https" : "http",
                                  listen_description,
                                  sizeof listen_description);
    if (srv.listen_fd < 0) {
        if (tls_enabled)
            tls_free_credentials(&credentials);
        return EXIT_FAILURE;
    }
    if (listen(srv.listen_fd, SOMAXCONN) < 0) {
        log_msg("chttp: listen: %s\n", strerror(errno));
        close(srv.listen_fd);
        if (tls_enabled)
            tls_free_credentials(&credentials);
        return EXIT_FAILURE;
    }

    srv.pids = calloc((size_t)cfg.max_connections, sizeof(pid_t));
    if (srv.pids == NULL) {
        log_msg("chttp: out of memory\n");
        close(srv.listen_fd);
        if (tls_enabled)
            tls_free_credentials(&credentials);
        return EXIT_FAILURE;
    }

    log_msg("chttp %s listening on %s (%d max connections, %ds request "
            "deadline, %s, pid %ld)\n",
            CHTTP_VERSION, listen_description, cfg.max_connections,
            cfg.timeout_secs,
            tls_enabled ? "tls 1.3" : "plaintext", (long)getpid());

    while (!stop_requested) {
        struct sockaddr_storage client_address;
        socklen_t client_length = sizeof client_address;
        char peer[NI_MAXHOST] = "unknown";
        int client;
        int slot = -1;
        pid_t pid;

        if (child_reaped) {
            child_reaped = 0;
            reap_children(&srv, 0);
        }

        client = accept4(srv.listen_fd, (struct sockaddr *)&client_address,
                         &client_length, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS
                || errno == ENOMEM) {
                log_msg("chttp: accept: %s (retrying)\n", strerror(errno));
                sleep_ms(100);
                continue;
            }
            log_msg("chttp: accept: %s\n", strerror(errno));
            exit_code = EXIT_FAILURE;
            break;
        }

        if (getnameinfo((struct sockaddr *)&client_address, client_length,
                        peer, sizeof peer, NULL, 0, NI_NUMERICHOST) != 0)
            snprintf(peer, sizeof peer, "unknown");

        if (srv.active >= cfg.max_connections) {
            /* A child may have just exited without its SIGCHLD being
             * delivered yet; reap before declaring the server busy. */
            reap_children(&srv, 0);
            if (srv.active >= cfg.max_connections) {
                reject_busy(client, peer, tls_enabled);
                close(client);
                continue;
            }
        }

        for (int i = 0; i < cfg.max_connections; i++) {
            if (srv.pids[i] == 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            reject_busy(client, peer, tls_enabled);
            close(client);
            continue;
        }

        set_client_timeouts(client, cfg.timeout_secs);

        pid = fork();
        if (pid == 0) {
            struct sigaction default_action;

            close(srv.listen_fd);
            memset(&default_action, 0, sizeof default_action);
            default_action.sa_handler = SIG_DFL;
            sigemptyset(&default_action.sa_mask);
            default_action.sa_flags = 0;
            sigaction(SIGCHLD, &default_action, NULL);

            handle_client(client, peer, &cfg,
                          tls_enabled ? &credentials : NULL);
            close(client);
            _exit(EXIT_SUCCESS);
        }
        if (pid < 0) {
            log_msg("chttp: fork: %s\n", strerror(errno));
            reject_busy(client, peer, tls_enabled);
            close(client);
            sleep_ms(20);
            continue;
        }

        srv.pids[slot] = pid;
        srv.active++;
        close(client);
    }

    close(srv.listen_fd);
    drain_connections(&srv);
    free(srv.pids);
    if (tls_enabled)
        tls_free_credentials(&credentials);
    log_msg("chttp: stopped\n");
    return exit_code;
}
