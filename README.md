# chttp - a minimal HTTP server in Fil-C

A dependency-free HTTP/1.1 and TLS 1.3 server written from first principles. It
uses POSIX sockets directly, speaks HTTP by writing bytes, and implements the
TLS handshake and its crypto in the same tree, so HTTPS adds no library or
package. The only unusual thing is the compiler: Fil-C checks every pointer
access, so the code is memory-safe at run time.

**Status: experimental.** chttp is an experiment in building a small,
dependency-free, memory-safe HTTP/1.1 + TLS 1.3 server on Fil-C, written from
first principles. The scope is deliberately fixed — bounded concurrency, hard
per-request deadlines, strict parsing, access logs, backpressure, a graceful
drain on `SIGTERM`, and an opt-in TLS 1.3 profile — and everything, including
the interfaces, is subject to change.

```
src/main.c            listener, HTTP parsing, routing
src/tls.c             TLS 1.3 records and handshake
src/crypto.c          SHA-256/512, HMAC/HKDF, AES-128-GCM, X25519, Ed25519
Makefile              build, test, install
tests/crypto_test.c   known-answer vectors
tests/smoke.sh        HTTP integration checks
tests/tls.sh          TLS integration checks
deploy/chttp.service  hardened systemd unit
```

## Project philosophy

The guiding rule is: **every line, library and parser you add is attack surface
you have to defend forever. Keep the trusted core small, and make the places
where it grows narrow and obvious.**

Three properties follow from that, and they are constraints on changes, not
aspirations:

**Minimal.** Three C files, one build file, up to 100 requests per connection,
and a bounded number of short-lived single-threaded worker processes. The
protocol surface is exactly what the routes need: an 8 KiB bounded header
read, a first-line parse, a status line, a fixed set of response headers, a
body. There is no config language, no plugin loader, no template engine, no logging
framework, no event loop, no HTTP library, and no crypto library. Anything that
can be deleted is deleted, because code that does not exist cannot be
exploited, patched, or misconfigured. TLS is opt-in rather than the default:
a deployment that does not need it compiles the same binary but never enters
the TLS code path.

**Robust.** The server fails closed and never trusts the client: an 8 KiB
request cap, a 1 KiB target cap, a hard wall-clock deadline per request,
partial `send` loops, `EPIPE`/`EINTR`/`EAGAIN` handled explicitly, `SIGPIPE`
ignored, and a connection cap that rejects excess load with `503`.
`SIGINT`/`SIGTERM` stop acceptance, drain in-flight work, then exit 0. Every
pointer access is checked by Fil-C at run time, so an out-of-bounds read is a
panic with a line number, not silent corruption. It binds to loopback by
default; exposing it is a deliberate flag, not a default.

**Dependencyless.** Zero third-party libraries at build or run time, and a
static-pie binary with no `NEEDED` entries and no interpreter. No dependency
means no transitive tree to audit, no version drift, no package manager at
deploy time, and no supply-chain path into the server. The TLS primitives are
implemented here for the same reason: linking OpenSSL would replace a small,
reviewable state machine with a large dependency and its own release cadence.
Fil-C itself is the one build-time tool, and it is pinned by version in this
document (see [Dependencies](#dependencies)).

Those goals pull against extensibility, so extensibility lives in **seams, not
in frameworks**. The core exposes three:

| Seam | Where | What it is for |
|------|-------|----------------|
| Router | `route_request` in `src/main.c` | new endpoints; add a branch, or replace it with a `struct route` table |
| Responses | the `RESP_*` constants and `respond(conn, resp, include_body, secure)` | any status, content type, or body without touching socket code |
| Lifecycle | accept/fork/cap/drain in `main` | limits, policy, auth checks, counters |
| Transport | `struct connection` in `src/main.c` and the `tls_*` API in `src/tls.h` | plaintext or TLS behind the same read/write calls |

Adding a route is a local change and needs no new dependency:

```c
static const struct response RESP_VERSION = {
    200, "OK", "text/plain; charset=utf-8", "chttp 1.0\n",
    sizeof "chttp 1.0\n" - 1, 0
};

/* in route_request, before the 404 fallback: */
else if (path_is(target, "/version"))
    *response = RESP_VERSION;
```

The extension rule is simple: **a feature may add code, never a parser or a
dependency it does not need.** Keep new work inside these seams, keep buffers
bounded and every wait deadlined, and the server stays auditable after it
grows. If a feature genuinely needs a dependency, that is a signal it belongs
in a different program in front of this one (reverse proxy, supervisor), not in
the trusted core. TLS was added under that rule: it is code in the tree, behind
the transport seam, with no new library.

Non-goals, deliberately: TLS 1.2 and below, session resumption, 0-RTT,
renegotiation, client certificates, ALPN/HTTP/2, unbounded concurrency or
thread pools, dynamic config reload, plugins. Each is a large
state machine or a large dependency; each would multiply the surface this
design exists to keep small. Concurrency is bounded on purpose: one forked,
single-threaded process per connection, capped by `--max-connections`.

## What it does

- Listens on `127.0.0.1:8080` by default. Bind address, port, concurrency,
  timeout, and TLS credentials come from flags or `CHTTP_*` environment
  variables.
- Speaks HTTP/1.1 or TLS 1.3 on the same listener. TLS is enabled only when
  both `--tls-cert` and `--tls-key` are supplied; without them the server is
  plaintext exactly as before.
- Serves connections concurrently: the listener forks one child per
  connection, up to `--max-connections` (default 64). A child serves at most
  100 requests on that connection. Beyond the cap a plaintext
  client gets `503 Service Unavailable` with `Retry-After: 1`; a TLS client
  cannot parse a plaintext error, so the connection is closed instead of
  queueing forever.
- Reads each bounded request head with a hard per-request deadline (default
  5 s). HTTP/1.1 connections persist by default; HTTP/1.0 requires
  `Connection: keep-alive`. `Connection: close` ends persistence. A client that
  stalls while a request is incomplete gets `408`; an idle persistent
  connection is closed after the same timeout.
- Bounded `POST /` bodies are echoed (maximum 8 KiB), using either
  `Content-Length` or chunked transfer encoding. Conflicting framing, malformed
  chunks, and oversized bodies are rejected; pipelined bytes remain buffered
  for the next request.
- Routes:

  | Request          | Response                          |
  |------------------|-----------------------------------|
  | `GET /`          | 200, a small HTML page            |
  | `GET /health`    | 200, `ok` (query string ignored)  |
  | `HEAD` on either | same headers, no body             |
  | `POST /`         | 200, echoes the bounded body      |
  | other path       | 404                               |
  | other method     | 405 with `Allow: GET, HEAD`       |
  | malformed        | 400 / 414 / 431 / 505 as appropriate |

- Sends `Date`, `Content-Type`, `Content-Length`, the appropriate `Connection`
  header, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`, so
  every response is complete and the client knows exactly where it ends. TLS
  responses add `Strict-Transport-Security: max-age=31536000`.
- Logs one access line per request to `stderr` (method, path, status, bytes,
  duration). Failed TLS handshakes are logged separately, without request data,
  with the handshake duration and the reason. `SIGINT`/`SIGTERM` drain
  in-flight requests and exit 0.

## TLS

TLS 1.3 is implemented in `src/tls.c` and `src/crypto.c` and is opt-in.
Supplying both credentials is the entire configuration:

```sh
openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=example.com" \
    -addext "subjectAltName=DNS:example.com,IP:127.0.0.1"

./build/chttp --port 8443 --tls-cert cert.pem --tls-key key.pem
curl --cacert cert.pem https://127.0.0.1:8443/health
```

Without `--tls-cert` and `--tls-key` the listener is plaintext and the TLS code
is never entered. Giving only one of the two is a startup error.

The profile is deliberately a single point, chosen for the smallest
interoperable surface:

| Aspect | Choice |
|--------|--------|
| Protocol | TLS 1.3 only, `TLS_AES_128_GCM_SHA256` |
| Key exchange | X25519 |
| Certificate key | Ed25519 only |
| Certificate chain | up to 4 certificates, 16 KiB total, PEM or DER |
| Private key | unencrypted PKCS#8, PEM or DER |
| Resumption, 0-RTT, renegotiation | not implemented |
| Client certificates | not supported |
| ALPN | ignored; HTTP/1.1 only |

A client that offers anything outside this set is rejected during the
handshake with the matching alert: `protocol_version` for TLS 1.2-only clients,
`handshake_failure` when the required cipher suite or signature scheme is
missing, `illegal_parameter` for an unusable X25519 share. If the client's first
key share is for another group (OpenSSL 3.5 defaults to the post-quantum
`X25519MLKEM768`), the server sends a `HelloRetryRequest` for X25519, so modern
clients interoperate without special flags.

Credentials are read and checked at startup, before the listener binds: both
files must parse, the leaf must contain an Ed25519 public key, and that key must
match the private key. If they do not, the process prints the reason and exits
1. A PEM certificate file may contain a chain; `cat leaf.pem intermediate.pem`
is enough. At the connection cap, TLS clients are closed rather than sent a
plaintext `503`, because a plaintext status line mid-TLS is not a response they
can parse.

### Security notes

**This cryptography is written here and has not been externally audited.**
That is the cost of the zero-dependency rule, and it should be a conscious
choice, not a footnote. What is true today:

- Every primitive is checked against public known-answer vectors in
  `tests/crypto_test.c`: SHA-256/512, HMAC, HKDF (RFC 5869), AES-128-GCM (NIST),
  X25519 (RFC 7748), and Ed25519 (RFC 8032).
- The field, scalar, and point arithmetic follows the compact public-domain
  TweetNaCl construction, with constant-time conditional swaps and no
  secret-indexed tables. AES computes its S-box arithmetically instead of
  reading one, trading speed for cache-timing resistance.
- The profile is narrow on purpose. Fewer suites, one group, one signature
  scheme, and no resumption mean less code and fewer downgrade paths.
- The implementation does not use hardware AES, does not wipe every stack
  buffer on every path, and makes no formal side-channel claims. Fil-C gives it
  memory safety, not cryptographic safety.

For a high-value public deployment, a reviewed TLS terminator in front of
`chttp` remains the conservative choice. What this implementation buys is a
self-contained HTTPS server whose entire trusted computing base is the code in
this repository.

Certificate validation, revocation checking, SNI-based certificate selection,
and client authentication are deliberately absent. The server presents exactly
one identity; the client still verifies its chain and hostname. `chttp` does
not fetch OCSP or CRLs. The server sends `Strict-Transport-Security:
max-age=31536000` only on TLS responses.

## First principles

An HTTP server is a byte pipeline with one required loop:

1. **Create a socket** - `socket(AF_INET, SOCK_STREAM, 0)` gives a TCP endpoint.
2. **Claim an address** - `bind` to an address; `SO_REUSEADDR` lets you restart
   without waiting for `TIME_WAIT`.
3. **Mark it listening** - `listen` turns the socket into an accept queue.
4. **Block in `accept`** - each call returns a new connected socket.
5. **Read the request** - HTTP is text until `\r\n\r\n` (end of headers). The
   first line is `METHOD SP TARGET SP VERSION`, so a bounded parse of that line
   is enough for routing. Bounded `POST /` bodies are read according to
   `Content-Length` or chunked framing before a pipelined request is parsed.
6. **Write the response** - status line, headers, blank line, body. The client
   finds the body end via `Content-Length`; a persistent connection may then
   carry another bounded request.
7. **Close and loop.**

That is the whole protocol surface this server needs. Everything beyond that
loop is bounded defensive work:

- a fixed 8 KiB request cap and a 1 KiB target cap (`431`, `414`);
- a total request deadline, not just per-`recv` socket timeouts, so a slowloris
  client cannot hold a slot indefinitely (`408`);
- one forked worker per connection, capped at 64, handling at most 100
  requests with `SIGCHLD` reaping;
- `503` + `Retry-After` when the cap is reached, rather than unbounded forks;
- signal-driven drain with a deadline, so deploys do not cut responses off;
- one structured access-log line per request, with client-controlled fields
  escaped before they reach the log.

## Operations

### Configuration

Flags override environment variables, which override defaults. Invalid values
fail at startup with a message and exit status 1.

| Flag | Environment | Default | Range |
|------|-------------|---------|-------|
| `--bind ADDR` | `CHTTP_BIND` | `127.0.0.1` | IPv4/IPv6 literal or name |
| `--port N`, or positional `N` | `CHTTP_PORT` | `8080` | 1-65535 |
| `--max-connections N` | `CHTTP_MAX_CONNECTIONS` | `64` | 1-1024 |
| `--timeout SECONDS` | `CHTTP_TIMEOUT` | `5` | 1-300 |
| `--tls-cert FILE` | `CHTTP_TLS_CERT` | none | PEM chain or DER certificate |
| `--tls-key FILE` | `CHTTP_TLS_KEY` | none | Ed25519 PKCS#8 key, PEM or DER |

TLS is enabled only when both certificate and key are set. The same flags work
from the environment, which is convenient for a unit file:

```sh
./build/chttp 9000                                  # loopback:9000
./build/chttp --bind 0.0.0.0 --port 8080            # all interfaces
CHTTP_BIND=::1 CHTTP_PORT=8080 ./build/chttp        # IPv6 loopback
./build/chttp --port 8443 \
    --tls-cert /etc/chttp/cert.pem --tls-key /etc/chttp/key.pem
```

`--bind` accepts names via `getaddrinfo`, so `localhost` works and binds the
first address that succeeds. Binding `::` on Linux normally accepts IPv4 too;
the OS default for `IPV6_V6ONLY` is left alone.

### Process model and limits

- The parent accepts, enforces the connection cap, forks, and reaps. It never
  parses a request or touches TLS state; each child runs its own handshake.
- Each child serves up to 100 requests on one connection, then `_exit`s. A
  crash in a child cannot take down the listener; the parent logs a non-zero
  exit.
- At the cap, new plaintext connections get `503` + `Retry-After: 1`, then
  close. TLS connections are closed without a response. The parent reaps
  first, so a just-finished request frees its slot immediately.
- Worker stack buffers are bounded: 8 KiB request head, 8 KiB pipelined input,
  and an 8 KiB request body, plus the Fil-C runtime. During a TLS handshake the
  child also holds about 66 KiB of record,
  handshake, and output buffers, which are freed when it exits. Total worker
  memory is bounded by `--max-connections`. On the test aarch64 build a held
  worker measured about 2.4 MB RSS including shared pages, so lower the cap on
  memory-constrained hosts.
- `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` on `accept` are retried after 100 ms;
  only unexpected accept errors are fatal.
- Socket receive/send timeouts are set as a backstop, but the wall-clock
  deadline is authoritative; a client sending one byte every few seconds still
  gets `408` at the deadline.

### Signals and exit status

| Signal | Behavior |
|--------|----------|
| `SIGTERM`, `SIGINT` | Stop accepting; drain for up to 5 s; `SIGTERM` stragglers for 1 s; `SIGKILL` them for 2 s; exit 0. |
| `SIGCHLD` | Reap finished workers (no zombies). |
| `SIGPIPE` | Ignored; a vanished client is a write error, not a signal death. |
| `SIGHUP` | Ignored. There is no config reload; restart to apply changes. |

Exit status is 0 for a clean or drained shutdown and 1 for configuration,
resolution, bind, listen, or unexpected accept failures.

### Responses and logs

| Status | Meaning |
|--------|---------|
| 200 | `/` or `/health` (also for `HEAD`) |
| 400 | malformed request line or NUL byte in the head |
| 404 | unknown path |
| 405 | method other than `GET`/`HEAD`; includes `Allow` |
| 408 | request deadline expired |
| 414 | target of 1 KiB or more (1023 chars max) |
| 431 | head larger than 8 KiB |
| 499 | log-only: client vanished before a response |
| 503 | connection cap reached; includes `Retry-After` |
| 505 | unsupported `HTTP/x.y` version |

Each request appends one line to `stderr`, which systemd captures in the
journal:

```
2026-10-27T10:54:58Z 127.0.0.1 "GET /health HTTP/1.1" 200 196 0ms
2026-10-27T10:54:59Z 127.0.0.1 "GET / HTTP/9.9" 505 245 0ms
```

Fields: UTC timestamp, peer, escaped request line, status, bytes written, and
duration. Bytes `-1` means the response could not be written. When no request
line was parsed (over-cap rejection, client abort, oversized head), the line
shows `"- - -"`. Client-supplied text is escaped and truncated before logging,
so it cannot forge log lines. Request bodies and headers are never logged.
Handshake failures use a separate line with no request data:

```
chttp: tls handshake from 127.0.0.1 failed after 1003ms: handshake deadline exceeded
```

### Deployment

```sh
make install                # /usr/local/bin/chttp
sudo make install-systemd   # /etc/systemd/system/chttp.service
sudo systemctl daemon-reload
sudo systemctl enable --now chttp
curl -fsS http://127.0.0.1:8080/health
```

The unit runs with `DynamicUser`, `NoNewPrivileges`, `ProtectSystem=strict`,
`PrivateTmp`, and a restricted address-family set. It listens on 8080; for a
port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`. `TimeoutStopSec`
is 10 s, above the server's 8 s worst-case stop budget.

For TLS, keep the key out of the unit file and let systemd stage it. The unit
contains a commented example:

```
# ExecStart=/usr/local/bin/chttp --bind 127.0.0.1 --port 8443 \
#     --tls-cert %d/tls-cert --tls-key %d/tls-key
# LoadCredential=tls-cert:/etc/chttp/cert.pem
# LoadCredential=tls-key:/etc/chttp/key.pem
```

`%d` is systemd's credentials directory; the files are copied into it with
owner-only permissions for the dynamic user, so `/etc/chttp` can stay
unreadable to everyone else. Because the service uses `DynamicUser`, do not
chown the key to a fixed account.

For containers or other supervisors, run `chttp` in the foreground, send
`SIGTERM` to the process, and probe `/health`. The static binary needs no
runtime files, so with a numeric `--bind` the container image can be
`FROM scratch` plus the binary (and, for TLS, the two credential files).

## Dependencies

**Build time:** Fil-C 0.687+ (one tarball: compiler, runtime, musl). `make
check` needs `bash`, `curl`, basic coreutils (the suites use bash's `/dev/tcp`
for raw requests), and `openssl` for the TLS suite, which generates throwaway
Ed25519 credentials and probes the handshake with `s_client`. OpenSSL is a
test tool only; it is never linked into the server. Valgrind and strace are
needed only by their targets; the clang static analyzer ships inside Fil-C. No
system clang, no libc-dev packages, no package manager for the build itself.

**Run time:** none. The default build uses `-static`, which produces a
static-pie ELF with no `NEEDED` libraries and no program interpreter:

```sh
readelf -d build/chttp | grep NEEDED        # nothing
readelf -l build/chttp | grep interpreter   # nothing
```

Copy `build/chttp` (about 11 MB) to another Linux aarch64 machine and run it.
No Fil-C tree, no libc package, no config file, and no OpenSSL. For a ~250 KB
dynamically linked build during development, use `make LDFLAGS=`.

**Third-party libraries:** zero. The program calls POSIX sockets and
`read`/`write`-family functions only; there is no HTTP library, event loop,
JSON parser, config file, or crypto library. SHA-256/SHA-512, HMAC, HKDF,
AES-128-GCM, X25519, and Ed25519 are implemented in `src/crypto.c`; the TLS 1.3
record layer and handshake are in `src/tls.c`.

## Can it be libc-free?

No, not while remaining a Fil-C program. "No libc" and "Fil-C's memory safety"
are mutually exclusive in practice: Fil-C implements safety by instrumenting
every pointer operation and linking a runtime that checks capabilities.

The compiler injects calls to that runtime even for a freestanding `_start`
program. Compiling a raw-syscall server with `filcc -nostdlib -ffreestanding`
reaches the linker and fails with:

```
undefined reference to `pizlonated_main'
undefined reference to `filc_start_program'
undefined reference to `filc_error'
undefined reference to `filc_stack_overflow_failure'
undefined reference to `filc_global_initialization_start'
undefined reference to `filc_global_initialization_end'
```

Those symbols come from `libpizlo` (garbage collector, capability checks) and
Fil-C's instrumented libc, both of which ship as static archives
(`libpizlo.a`, `libc.a`) and are bundled by `-static`. Dropping them drops the
checks: you would have an ordinary unsafe binary, buildable with
`gcc -nostdlib -static` and `svc #0`, but it would no longer be this project.

So the strongest honest claim is: **zero third-party dependencies and a
self-contained runtime artifact**, not zero libc.

## Quick start

```sh
# 1. Download Fil-C (pick the archive for your CPU)
curl -LO https://github.com/pizlonator/fil-c/releases/download/v0.687/filc-0.687-linux-aarch64.tar.xz
tar -xJf filc-0.687-linux-aarch64.tar.xz

# 2. Put the compiler on PATH
export PATH="$PWD/filc-0.687-linux-aarch64/build/bin:$PATH"

# 3. Build and serve
make
make run                 # http://127.0.0.1:8080
./build/chttp 9000       # or choose a port
```

Or without changing `PATH`:

```sh
make CC=/path/to/fil-c/build/bin/filcc
```

Expected startup line:

```
chttp 1.0 listening on http://127.0.0.1:8080 (64 max connections, 5s request deadline, plaintext, pid 4242)
```

Add `--tls-cert`/`--tls-key` and the same line says `https://... (tls 1.3)`.

Try it:

```sh
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/nope
curl -i -X POST http://127.0.0.1:8080/
```

`make check` builds the server and runs three suites: `tests/crypto_test.c`
checks the primitives against RFC/NIST vectors; `tests/smoke.sh` covers the
HTTP surface, `HEAD`, malformed requests, bounded POST/chunked bodies,
414/431 limits, timeout enforcement, 16-way concurrency, 503 backpressure,
graceful drain, and configuration;
`tests/tls.sh` generates Ed25519 credentials with `openssl` and covers
interoperability (`curl`, `s_client`, the PQ-hybrid HelloRetryRequest), HSTS,
TLS 1.2 rejection, DER and chained credentials, startup validation, handshake
deadlines, and the TLS connection cap. The smoke suite also covers pipelining,
HTTP/1.0 persistence, body/framing validation, and the 100-request connection cap.

For additional HTTP parser coverage, the external [h1spec](https://github.com/uNetworking/h1spec)
smoke suite was run against plaintext HTTP and all 33 checks passed. h1spec
is not vendored and is not part of `make check`; clone its repository, start
the server, then run this from the h1spec checkout with Deno:

```sh
deno run --allow-net http_test.ts 127.0.0.1 8080
```

## Tooling

Fil-C is the primary memory-safety checker; the tools below inspect things it
does not (leaks, syscalls, dataflow) or double-check the program from outside.

```sh
make analyze       # clang static analyzer (ships with Fil-C)
make perf          # informational HTTP throughput/latency benchmark
make valgrind      # dynamic build under Valgrind, scripted HTTP smoke test
make valgrind-tls  # the same, plus one TLS handshake (slow)
make trace         # skip optional ptrace-based tracing by default
make trace TRACE=1 # strace one exchange (Linux host; writes build/strace.log)
```

Valgrind and strace are optional external tools. Install them only if you
intend to use those targets:

```sh
apt-get install -y --no-install-recommends valgrind strace
```

**`make analyze`** runs `filcc --analyze` with the analyzer's text output. It
found a deliberately planted null dereference in testing and is clean on this
server. It needs no extra dependencies.

**`make valgrind`** builds `build/chttp-dyn` (dynamic, not the default static
image), starts it, fetches `/health` and `/`, sends `SIGTERM`, and requires
`ERROR SUMMARY: 0 errors` from `build/valgrind.log`. The server forks per
request; `--child-silent-after-fork=yes` keeps the report focused on the
listener, while the children are still instrumented and exit through `_exit`:

```
definitely lost: 0 bytes in 0 blocks
still reachable: ~1.3 KB in ~35 blocks   # runtime, not a leak
ERROR SUMMARY: 0 errors from 0 contexts
```

**`make valgrind-tls`** does the same over HTTPS, generating a throwaway
Ed25519 certificate and allowing a 20 s handshake deadline. A handshake under
Valgrind is thousands of interpreted field operations, so it is slow; the
target is opt-in for that reason. It writes `build/valgrind-tls.log`.

Two limits are real, not papered over:

- Valgrind cannot start the default **static-pie** Fil-C image. It aborts with
  `mmap(0x108000, ...) failed in UME with error 22`. That is why the target
  builds the dynamic variant.
- Valgrind also cannot tolerate Fil-C's **guarded `ioctl`** path: musl's
  `printf` checks `TIOCGWINSZ` via `ioctl`, and Fil-C's syscall wrapper panics
  under Valgrind (`filc_call_syscall_with_guarded_ptr` assertion). The server
  therefore logs to `stderr`, which is unbuffered and skips that path. Do not
  put stdout `printf` in code you intend to run under Valgrind.

**`make trace TRACE=1`** runs `strace -f -e trace=network` around the static
server, makes one request, and stops it. `-f` follows the per-connection fork,
so the log contains both the listener and the worker. Tracing is opt-in because
it uses ptrace and may be unsupported or noisy inside Android/TermFold's PRoot
environment. Plain `make trace` skips it. It works on the static binary because
strace observes syscalls, not the Fil-C ABI:

```
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
setsockopt(3, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
bind(3, {sa_family=AF_INET, sin_port=htons(...), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
listen(3, 128) = 0
accept4(3, {sa_family=AF_INET, ...}, [16], SOCK_CLOEXEC) = 4
setsockopt(4, SOL_SOCKET, SO_RCVTIMEO, ...) = 0
setsockopt(4, SOL_SOCKET, SO_SNDTIMEO, ...) = 0
```

### Sanitizers

Do not add `-fsanitize=address` or `-fsanitize=undefined`: Fil-C does not ship
the clang sanitizer runtimes, and linking fails with
`cannot find .../libclang_rt.asan.a`. Fil-C itself is the sanitizer here; ASan
would only check machine addresses, not Fil-C's capabilities.

### What Valgrind can and cannot tell you

Valgrind sees the machine code after Fil-C's checks and the runtime's own
allocation. It is useful for leaks and uninitialized data, but a clean
Valgrind run says nothing about capability violations; those are Fil-C's job,
and Fil-C catches them before Valgrind would. Treat the tools as complements,
not substitutes.

## Notes and limits

- HTTP/1.1 keep-alive (HTTP/1.0 opt-in), served by a forked, single-threaded
  child per connection. Each child handles at most 100 requests. Concurrency is
  capped by `--max-connections` (64 by default); there is no thread pool or
  event loop.
- Small and deliberate, not a general web server: no request-body support
  beyond the bounded `POST /` echo, compression, virtual hosts, range requests,
  or dynamic content. It serves two built-in routes and the echo endpoint.
- TLS is a narrow, opt-in profile: TLS 1.3, X25519, Ed25519 certificates,
  AES-128-GCM only. Clients that cannot offer that exact combination cannot
  connect. There is no certificate hot-reload (restart to rotate), no SNI
  selection, no client authentication, and no HTTP-to-HTTPS redirect; bind a
  TLS listener, or put a redirect in front. See [TLS](#tls).
- The crypto is in-tree and unaudited; read the
  [security notes](#security-notes) before using it for high-value traffic.
- Binds to loopback by default; use `--bind` or `CHTTP_BIND` deliberately.
  There is no in-process privilege drop: run it as a non-root user or under
  the provided unit (which uses `DynamicUser=yes`).
- No per-IP rate limiting or authentication; the global connection cap is the
  backstop. Put a reverse proxy in front if you need auth, per-client quotas,
  or a broader TLS policy than the profile above.
- Compile everything with Fil-C, including libraries you link in. Mixing in
  objects built with a normal compiler defeats the safety guarantees.
- `make` produces the static binary by default (`-static`). Use `make LDFLAGS=`
  for a small, dynamically linked build that needs the Fil-C tree at run time.
- Logs requests to `stderr`; `SIGINT`/`SIGTERM` drain in-flight requests and
  exit 0 (which also lets the Valgrind target get a clean report).
- Changes are expected to preserve the [project philosophy](#project-philosophy):
  bounded buffers, no new parser, no new dependency, and growth inside the
  router/response/lifecycle seams.

## Fil-C catches memory bugs

Fil-C turns out-of-bounds and use-after-free into a panic instead of silent
corruption:

```sh
cat > /tmp/oob.c <<'EOF'
#include <stdlib.h>
int main(void) {
    int *p = malloc(4);
    p[10] = 42;         /* out of bounds */
    free(p);
    return 0;
}
EOF
filcc -O2 -g -o /tmp/oob /tmp/oob.c && /tmp/oob
```

The process aborts with a `filc safety error` naming the source line and the
heap object. (The allocator has a 16-byte minimum block, so a small `p[1]`
overrun on a 4-byte object can land inside that block; `p[10]` is caught.)

## License

Copyright (c) 2026 Dipanjan Patra.

chttp is free software, licensed under the **GNU Affero General Public License
v3.0** (`LICENSE`). You may use, study, modify, and redistribute it under AGPLv3
terms; if you offer modified versions as a network service, AGPLv3 requires you
to offer your source to those users.

If you want to use chttp in a closed-source product, or under terms that do not
require copyleft (including hosted-service terms), a commercial license is
available from the author: contact `patraanjan23@users.noreply.github.com`.

The software is provided without warranty and without any liability on the
author's part, as stated in `LICENSE` §15 and §16.
