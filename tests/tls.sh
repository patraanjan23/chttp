#!/usr/bin/env bash
# Integration checks for the in-tree TLS 1.3 stack: the opt-in profile,
# OpenSSL/curl interoperability, credential loading, the protocol boundary,
# timeouts, the connection cap, and plaintext/HSTS behaviour.
set -euo pipefail

BIN=${BIN:-./build/chttp}
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 20000))}
WORK=$(mktemp -d)
SERVER_PID=""
SERVER_PORT=""
CERT=""
KEY=""
CA=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    if [ -f "$WORK/server.log" ]; then
        echo "--- server log ---" >&2
        tail -40 "$WORK/server.log" >&2
    fi
    exit 1
}

ok() { echo "ok: $*"; }

command -v openssl >/dev/null 2>&1 || fail "openssl is required for the TLS suite"

wait_ready_tls() {
    local port=$1
    for _ in $(seq 1 100); do
        if curl -fsS --max-time 2 --cacert "$CA" -o /dev/null \
            "https://127.0.0.1:$port/health" 2>/dev/null; then
            return 0
        fi
        if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
    done
    return 1
}

wait_ready_plain() {
    local port=$1
    for _ in $(seq 1 100); do
        if curl -fsS --max-time 1 -o /dev/null \
            "http://127.0.0.1:$port/health" 2>/dev/null; then
            return 0
        fi
        if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
    done
    return 1
}

start_tls_server() {
    local tries=0
    while [ "$tries" -lt 25 ]; do
        SERVER_PORT=$((BASE_PORT + tries))
        "$BIN" --port "$SERVER_PORT" --timeout 2 \
            --tls-cert "$CERT" --tls-key "$KEY" "$@" \
            >>"$WORK/server.log" 2>&1 &
        SERVER_PID=$!
        if wait_ready_tls "$SERVER_PORT"; then
            return 0
        fi
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        tries=$((tries + 1))
    done
    fail "could not start $BIN with TLS"
}

start_plain_server() {
    local tries=0
    while [ "$tries" -lt 25 ]; do
        SERVER_PORT=$((BASE_PORT + tries))
        "$BIN" --port "$SERVER_PORT" --timeout 2 "$@" \
            >>"$WORK/server.log" 2>&1 &
        SERVER_PID=$!
        if wait_ready_plain "$SERVER_PORT"; then
            return 0
        fi
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        tries=$((tries + 1))
    done
    fail "could not start $BIN without TLS"
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        terminate_server "$SERVER_PID" || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

# The server forks one child per accepted connection; child counts make the
# cap and drain tests independent of scheduling delays.
count_children() {
    { pgrep -P "$SERVER_PID" 2>/dev/null || true; } | wc -l
}

wait_children() {
    local want=$1
    for _ in $(seq 1 200); do
        if [ "$(count_children)" -ge "$want" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

wait_no_children() {
    for _ in $(seq 1 200); do
        if [ "$(count_children)" -eq 0 ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

# A signal can occasionally be lost between the proot layer and the server,
# so teardown retries SIGTERM before forcing the process down. Polling the
# process state (rather than kill -0) also treats a zombie as exited.
pid_gone() {
    local state
    state=$(ps -o stat= -p "$1" 2>/dev/null || true)
    state=${state// /}
    if [ -z "$state" ]; then
        return 0
    fi
    case "$state" in
        Z*) return 0 ;;
        *) return 1 ;;
    esac
}

wait_exit() {
    local pid=$1
    local tries=${2:-150}
    for _ in $(seq 1 "$tries"); do
        if pid_gone "$pid"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

terminate_server() {
    local pid=$1
    kill -TERM "$pid" 2>/dev/null || true
    if wait_exit "$pid" 150; then
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    if wait_exit "$pid" 50; then
        return 0
    fi
    kill -KILL "$pid" 2>/dev/null || true
    wait_exit "$pid" 50 || true
    return 1
}

expect_startup_failure() {
    local label=$1
    local pattern=$2
    shift 2
    local log="$WORK/startup.log"
    local rc=0

    # A process that fails validation must exit on its own; a running server
    # is stopped by timeout, so rc 124 means the configuration was accepted.
    timeout 30 "$BIN" --port "$((BASE_PORT + 900))" "$@" >"$log" 2>&1 \
        || rc=$?
    [ "$rc" -ne 124 ] || fail "$label: server started with invalid TLS configuration"
    [ "$rc" -ne 0 ] || fail "$label: server exited 0"
    grep -qi -- "$pattern" "$log" || fail "$label: expected '$pattern'"
    ok "$label"
}

# --- credentials ---------------------------------------------------------

mkdir -p "$WORK/tls"
ED_KEY="$WORK/tls/key.pem"
ED_CERT="$WORK/tls/cert.pem"
openssl req -x509 -newkey ed25519 -keyout "$ED_KEY" -out "$ED_CERT" \
    -days 2 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate an Ed25519 certificate"
ok "generated an Ed25519 self-signed certificate"

openssl x509 -in "$ED_CERT" -outform DER -out "$WORK/tls/cert.der" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not convert the certificate to DER"
openssl pkcs8 -topk8 -nocrypt -in "$ED_KEY" -outform DER \
    -out "$WORK/tls/key.der" >>"$WORK/openssl.log" 2>&1 \
    || fail "could not convert the key to PKCS#8 DER"
ok "generated DER credentials"

openssl genpkey -algorithm ed25519 -out "$WORK/tls/other-key.pem" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate a second key"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls/rsa-key.pem" \
    -out "$WORK/tls/rsa-cert.pem" -days 2 -nodes -subj "/CN=localhost" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate an RSA certificate"

openssl genpkey -algorithm ed25519 -out "$WORK/tls/ca-key.pem" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate the CA key"
openssl req -x509 -new -key "$WORK/tls/ca-key.pem" \
    -out "$WORK/tls/ca-cert.pem" -days 2 -subj "/CN=chttp test CA" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate the CA certificate"
openssl genpkey -algorithm ed25519 -out "$WORK/tls/leaf-key.pem" \
    >>"$WORK/openssl.log" 2>&1 || fail "could not generate the leaf key"
openssl req -new -key "$WORK/tls/leaf-key.pem" -out "$WORK/tls/leaf.csr" \
    -subj "/CN=localhost" >>"$WORK/openssl.log" 2>&1 \
    || fail "could not generate the leaf CSR"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' \
    >"$WORK/tls/leaf.ext"
openssl x509 -req -in "$WORK/tls/leaf.csr" \
    -CA "$WORK/tls/ca-cert.pem" -CAkey "$WORK/tls/ca-key.pem" \
    -CAcreateserial -out "$WORK/tls/leaf-cert.pem" -days 2 \
    -extfile "$WORK/tls/leaf.ext" >>"$WORK/openssl.log" 2>&1 \
    || fail "could not sign the leaf certificate"
cat "$WORK/tls/leaf-cert.pem" "$WORK/tls/ca-cert.pem" \
    >"$WORK/tls/chain.pem"
ok "generated a CA-signed certificate chain"

# --- interoperability ----------------------------------------------------

CERT=$ED_CERT
KEY=$ED_KEY
CA=$ED_CERT
start_tls_server --max-connections 16

echo "== interoperability =="
body=$(curl -fsS --max-time 10 --cacert "$CA" \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$body" = "ok" ] || fail "HTTPS GET /health returned '$body'"
ok "curl verifies the Ed25519 certificate and gets /health"

headers=$(curl -fsS --max-time 10 --cacert "$CA" -D - -o /dev/null \
    "https://127.0.0.1:$SERVER_PORT/")
status=${headers%%$'\n'*}
case "${status%$'\r'}" in
    "HTTP/1.1 200 "*) ;;
    *) fail "HTTPS GET / was not 200" ;;
esac
grep -qi '^Strict-Transport-Security: max-age=31536000' <<<"$headers" \
    || fail "TLS response is missing HSTS"
ok "TLS responses carry HSTS"

code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/nope")
[ "$code" = 404 ] || fail "HTTPS GET /nope returned $code"
ok "HTTPS 404"

code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    -X POST "https://127.0.0.1:$SERVER_PORT/")
[ "$code" = 405 ] || fail "HTTPS POST returned $code"
ok "HTTPS 405"

curl -sS --max-time 10 --cacert "$CA" -I \
    "https://127.0.0.1:$SERVER_PORT/" >"$WORK/head.txt" 2>&1 \
    || fail "HTTPS HEAD failed"
grep -q '^HTTP/1.1 200 ' "$WORK/head.txt" || fail "HTTPS HEAD was not 200"
ok "HTTPS HEAD"

response=$(printf 'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
    | timeout 15 openssl s_client -quiet -connect "127.0.0.1:$SERVER_PORT" \
        -CAfile "$CA" 2>/dev/null || true)
case "$response" in
    *"HTTP/1.1 200 OK"*) ;;
    *) fail "openssl s_client did not receive a response" ;;
esac
grep -q 'ok' <<<"$response" || fail "s_client response has no body"
ok "openssl s_client exchanges an HTTP request"

probe=$(timeout 20 openssl s_client -connect "127.0.0.1:$SERVER_PORT" \
    -tls1_3 -CAfile "$CA" -verify_return_error -brief </dev/null 2>&1 || true)
grep -q 'Verification: OK' <<<"$probe" \
    || fail "s_client did not verify the certificate"
grep -qi 'Signature type: ed25519' <<<"$probe" \
    || fail "s_client did not report an Ed25519 signature"
grep -qi 'Peer Temp Key: X25519' <<<"$probe" \
    || fail "s_client did not report an X25519 key"
ok "openssl s_client verifies the chain and negotiates the profile"

direct=$(timeout 20 openssl s_client -connect "127.0.0.1:$SERVER_PORT" \
    -tls1_3 -groups X25519 -CAfile "$CA" -msg </dev/null 2>&1 \
    | grep -c '], ClientHello' || true)
[ "$direct" = 1 ] || fail "X25519 key share unexpectedly needed $direct ClientHellos"
ok "an X25519 key share is accepted without HelloRetryRequest"

retry=$(timeout 20 openssl s_client -connect "127.0.0.1:$SERVER_PORT" \
    -tls1_3 -groups X25519MLKEM768:X25519 -CAfile "$CA" -msg </dev/null 2>&1 \
    | grep -c '], ClientHello' || true)
[ "$retry" -ge 2 ] || fail "a post-quantum key share did not trigger HelloRetryRequest"
ok "a PQ-hybrid key share triggers HelloRetryRequest"

echo "== protocol boundary =="
if curl -sS --max-time 10 --cacert "$CA" --tlsv1.2 --tls-max 1.2 \
    -o /dev/null "https://127.0.0.1:$SERVER_PORT/health" 2>/dev/null; then
    fail "a TLS 1.2-only client was accepted"
fi
ok "TLS 1.2-only clients are rejected"

legacy=$(timeout 15 openssl s_client -connect "127.0.0.1:$SERVER_PORT" \
    -tls1_2 -CAfile "$CA" </dev/null 2>&1 || true)
grep -qi 'alert protocol version' <<<"$legacy" \
    || fail "TLS 1.2 rejection did not send protocol_version"
ok "TLS 1.2 rejection sends a protocol_version alert"

if timeout 15 openssl s_client -connect "127.0.0.1:$SERVER_PORT" -tls1_3 \
    -ciphersuites TLS_AES_256_GCM_SHA384 -CAfile "$CA" -brief \
    </dev/null >"$WORK/aes256.txt" 2>&1; then
    fail "a client offering only TLS_AES_256_GCM_SHA384 was accepted"
fi
grep -qi 'alert handshake failure\|alert number 40' "$WORK/aes256.txt" \
    || fail "AES-256-only rejection did not send handshake_failure"
ok "clients without TLS_AES_128_GCM_SHA256 are rejected"

if curl -sS --max-time 6 -o /dev/null \
    "http://127.0.0.1:$SERVER_PORT/health" 2>/dev/null; then
    fail "a plaintext HTTP request was served by the TLS listener"
fi
ok "plaintext HTTP on the TLS port is refused"

echo "== input handling =="
exec 9<>"/dev/tcp/127.0.0.1/$SERVER_PORT" || fail "could not open a TCP connection"
printf 'not a tls record\r\n\r\n' >&9
read_rc=0
IFS= read -r -n 1 -t 5 -u 9 || read_rc=$?
exec 9<&-
[ "$read_rc" -ne 0 ] || fail "garbage input produced a byte instead of a close"
[ "$read_rc" -eq 1 ] || fail "garbage input left the connection open"
code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "server did not survive garbage input ($code)"
ok "garbage input closes the connection without killing the server"

echo "== concurrency =="
pids=""
for _ in $(seq 1 16); do
    curl -fsS --max-time 15 --cacert "$CA" -o /dev/null \
        "https://127.0.0.1:$SERVER_PORT/health" &
    pids="$pids $!"
done
succeeded=0
for pid in $pids; do
    if wait "$pid"; then
        succeeded=$((succeeded + 1))
    fi
done
[ "$succeeded" -eq 16 ] || fail "only $succeeded/16 concurrent TLS requests succeeded"
ok "16 concurrent TLS requests succeeded"

# --- handshake deadline --------------------------------------------------

echo "== deadlines and backpressure =="
stop_server
CERT=$ED_CERT
KEY=$ED_KEY
CA=$ED_CERT
start_tls_server --timeout 1 --max-connections 4

exec 8<>"/dev/tcp/127.0.0.1/$SERVER_PORT" || fail "could not hold a connection"
log_before=$(wc -l <"$WORK/server.log")
failure=""
for _ in $(seq 1 100); do
    failure=$(tail -n +$((log_before + 1)) "$WORK/server.log" \
        | grep 'tls handshake from .* failed after ' | tail -n 1 || true)
    [ -n "$failure" ] && break
    sleep 0.1
done
exec 8<&-
[ -n "$failure" ] || fail "an idle handshake was not abandoned within 10s"
elapsed_ms=$(printf '%s' "$failure" \
    | sed -E 's/.*failed after ([0-9]+)ms.*/\1/')
case "$elapsed_ms" in
    ''|*[!0-9]*) fail "could not read the handshake duration from: $failure" ;;
esac
[ "$elapsed_ms" -ge 800 ] || fail "handshake deadline fired too early (${elapsed_ms}ms)"
[ "$elapsed_ms" -lt 5000 ] || fail "handshake deadline did not fire (${elapsed_ms}ms)"
ok "an idle TLS handshake is abandoned after ${elapsed_ms}ms"
code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "server did not recover from an idle handshake ($code)"
ok "the server still serves after an idle handshake"

stop_server
start_tls_server --timeout 30 --max-connections 1
wait_no_children || fail "the server kept a child after startup checks"
exec 6<>"/dev/tcp/127.0.0.1/$SERVER_PORT" || fail "could not hold the only slot"
wait_children 1 || fail "the only slot was not taken"
exec 5<>"/dev/tcp/127.0.0.1/$SERVER_PORT" || fail "could not open a second connection"
read_rc=0
IFS= read -r -n 1 -t 10 -u 5 || read_rc=$?
exec 5<&-
[ "$read_rc" -ne 0 ] || fail "the TLS listener answered over the cap in plaintext"
[ "$read_rc" -eq 1 ] || fail "the over-cap connection was not closed"
ok "connections over the TLS cap are closed without a plaintext 503"
exec 6<&-
code=""
for _ in $(seq 1 50); do
    code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:$SERVER_PORT/health" 2>/dev/null || true)
    [ "$code" = 200 ] && break
    sleep 0.1
done
[ "$code" = 200 ] || fail "TLS server did not recover after the cap freed ($code)"
ok "TLS server recovers after a slot frees"

# --- alternate credentials ----------------------------------------------

echo "== credentials =="
stop_server
CERT="$WORK/tls/cert.der"
KEY="$WORK/tls/key.der"
CA=$ED_CERT
start_tls_server
code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "DER credentials returned $code"
ok "DER certificate and PKCS#8 DER key are accepted"

stop_server
CERT="$WORK/tls/chain.pem"
KEY="$WORK/tls/leaf-key.pem"
CA="$WORK/tls/ca-cert.pem"
start_tls_server
code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "CA-signed chain returned $code"
ok "a two-certificate PEM chain is served and verified"

stop_server
PORT_ENV=$((BASE_PORT + 1000))
CHTTP_TLS_CERT=$ED_CERT CHTTP_TLS_KEY=$ED_KEY \
    "$BIN" --port "$PORT_ENV" --timeout 2 >>"$WORK/server.log" 2>&1 &
SERVER_PID=$!
CA=$ED_CERT
SERVER_PORT=$PORT_ENV
wait_ready_tls "$PORT_ENV" || fail "environment-configured TLS server did not start"
code=$(curl -sS --max-time 10 --cacert "$CA" -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "environment-configured TLS server returned $code"
ok "CHTTP_TLS_CERT/CHTTP_TLS_KEY enable TLS"

stop_server

expect_startup_failure "--tls-cert without --tls-key" \
    'must be used together' --tls-cert "$ED_CERT"
expect_startup_failure "--tls-key without --tls-cert" \
    'must be used together' --tls-key "$ED_KEY"
expect_startup_failure "a mismatched key" \
    'does not match the private key' \
    --tls-cert "$ED_CERT" --tls-key "$WORK/tls/other-key.pem"
expect_startup_failure "an RSA certificate" \
    'Ed25519' --tls-cert "$WORK/tls/rsa-cert.pem" --tls-key "$ED_KEY"
expect_startup_failure "a missing certificate file" \
    'cannot open' --tls-cert "$WORK/tls/nope.pem" --tls-key "$ED_KEY"
(
    CHTTP_TLS_CERT= exec "$BIN" --port "$((BASE_PORT + 901))" \
        >"$WORK/startup.log" 2>&1
) || true
if ! grep -q 'CHTTP_TLS_CERT is empty' "$WORK/startup.log"; then
    fail "an empty CHTTP_TLS_CERT was not rejected"
fi
ok "an empty CHTTP_TLS_CERT is rejected"

# --- plaintext stays plaintext ------------------------------------------

echo "== plaintext mode =="
start_plain_server
headers=$(curl -fsS --max-time 5 -D - -o /dev/null \
    "http://127.0.0.1:$SERVER_PORT/")
grep -qi '^Strict-Transport-Security:' <<<"$headers" \
    && fail "plaintext response advertises HSTS"
ok "plaintext responses do not advertise HSTS"
stop_server

if grep -q "terminated by signal" "$WORK/server.log"; then
    fail "a connection process crashed"
fi
ok "no connection process crashed"

echo "all TLS tests passed"
