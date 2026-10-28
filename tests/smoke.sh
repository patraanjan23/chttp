#!/usr/bin/env bash
# Integration checks for chttp: protocol surface, limits, timeouts,
# concurrency, backpressure, graceful shutdown, and configuration.
set -euo pipefail

BIN=${BIN:-./build/chttp}
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 20000))}
WORK=$(mktemp -d)
SERVER_PID=""
SERVER_PORT=""

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
        tail -30 "$WORK/server.log" >&2
    fi
    exit 1
}

ok() { echo "ok: $*"; }

wait_ready() {
    local port=$1
    for _ in $(seq 1 100); do
        if curl -fsS --max-time 2 -o /dev/null \
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

start_server() {
    local tries=0
    while [ "$tries" -lt 25 ]; do
        SERVER_PORT=$((BASE_PORT + tries))
        "$BIN" --port "$SERVER_PORT" --timeout 1 "$@" \
            >>"$WORK/server.log" 2>&1 &
        SERVER_PID=$!
        if wait_ready "$SERVER_PORT"; then
            return 0
        fi
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        tries=$((tries + 1))
    done
    fail "could not start $BIN"
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        terminate_server "$SERVER_PID" || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

# The server forks one child per accepted connection. Waiting for the child
# count to change is a reliable way to tell that an accepted connection has
# been accounted for, without racing on fixed sleeps.
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

raw() {
    local request=$1
    local response

    exec 9<>"/dev/tcp/127.0.0.1/$SERVER_PORT" || return 1
    printf '%b' "$request" >&9 || true
    response=$(cat <&9 2>/dev/null || true)
    exec 9<&-
    printf '%s' "$response"
}

status_line() {
    local line=${1%%$'\n'*}
    printf '%s' "${line%$'\r'}"
}

expect_code() {
    local response=$1
    local code=$2
    local name=$3
    local line

    line=$(status_line "$response")
    case "$line" in
        "HTTP/1.1 $code "*) ok "$name" ;;
        *) fail "$name: expected $code, got '${line:-<empty>}'" ;;
    esac
}

expect_header() {
    local response=$1
    local pattern=$2
    local name=$3

    grep -qiE "$pattern" <<<"$response" \
        || fail "$name: missing header /$pattern/"
    ok "$name"
}

start_server

echo "== protocol =="
body=$(curl -fsS "http://127.0.0.1:$SERVER_PORT/")
grep -q "hello from Fil-C" <<<"$body" || fail "GET / body"
ok "GET / returns the index page"

headers=$(curl -fsS -D - -o /dev/null "http://127.0.0.1:$SERVER_PORT/")
expect_code "$headers" 200 "GET / is 200"
expect_header "$headers" '^Date: ' "Date header present"
expect_header "$headers" '^Content-Length: [0-9]+' "Content-Length present"
expect_header "$headers" '^Connection: keep-alive' "HTTP/1.1 persistence advertised"

response=$(raw 'GET /health HTTP/1.1\r\nHost: test\r\n\r\nGET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n')
[ "$(grep -c '^HTTP/1.1 200' <<<"$response")" -eq 2 ] \
    || fail "pipelined keep-alive requests were not both served"
ok "pipelined requests share one connection and close is honored"

response=$(raw 'GET /health HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /health HTTP/1.0\r\n\r\n')
[ "$(grep -c '^HTTP/1.1 200' <<<"$response")" -eq 2 ] \
    || fail "HTTP/1.0 keep-alive opt-in was not honored"
ok "HTTP/1.0 persistence requires explicit opt-in"

requests=$(for _ in $(seq 1 99); do
    printf 'GET /health HTTP/1.1\r\nHost: test\r\n\r\n'
done
printf 'GET /health HTTP/1.1\r\nHost: test\r\n\r\nX')
response=$(raw "$requests")
[ "$(grep -c '^HTTP/1.1 200' <<<"$response")" -eq 100 ] \
    || fail "connection request cap did not serve exactly 100 requests"
grep -q '^Connection: close' <<<"${response##*HTTP/1.1}" \
    || fail "100th response did not advertise close"
ok "connection is closed after the bounded 100-request limit"

response=$(raw 'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx')
expect_code "$response" 400 "request bodies are rejected safely"

body=$(curl -fsS "http://127.0.0.1:$SERVER_PORT/health?probe=1")
[ "$body" = "ok" ] || fail "GET /health?probe=1 returned '$body'"
ok "GET /health ignores the query string"

code=$(curl -sS -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$SERVER_PORT/nope")
[ "$code" = 404 ] || fail "GET /nope returned $code"
ok "unknown path is 404"

headers=$(curl -sS -D - -o /dev/null -X POST \
    "http://127.0.0.1:$SERVER_PORT/")
expect_code "$headers" 405 "POST is 405"
expect_header "$headers" '^Allow: GET, HEAD' "405 advertises Allow"

response=$(raw 'HEAD / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n')
expect_code "$response" 200 "HEAD / is 200"
case "$response" in
    *"hello from Fil-C"*) fail "HEAD / returned a body" ;;
esac
ok "HEAD / has no body"

response=$(raw 'HEAD /health HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n')
expect_code "$response" 200 "HEAD /health is 200"
case "$response" in
    *$'\r\n\r\nok'*) fail "HEAD /health returned a body" ;;
esac
ok "HEAD /health has no body"

response=$(raw 'NOT A REQUEST\r\n\r\n')
expect_code "$response" 400 "malformed request line is 400"

response=$(raw 'GET / HTTP/9.9\r\nHost: test\r\nConnection: close\r\n\r\n')
expect_code "$response" 505 "unsupported HTTP version is 505"

response=$(raw 'GET / HTTP/1.1\r\nConnection: close\r\n\r\n')
expect_code "$response" 400 "HTTP/1.1 requires Host"

response=$(raw 'GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\nConnection: close\r\n\r\n')
expect_code "$response" 400 "duplicate Host headers are rejected"

response=$(raw $'GET / HTTP/1.1\r\nHost: test\r\nX-Bad: value\a\r\nConnection: close\r\n\r\n')
expect_code "$response" 400 "control characters in header values are rejected"

echo "== limits =="
long_path="/$(head -c 2000 /dev/zero | tr '\0' 'a')"
response=$(raw "GET $long_path HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
expect_code "$response" 414 "oversized URI is 414"

padding=$(head -c 9000 /dev/zero | tr '\0' 'A')
response=$(raw "GET / HTTP/1.1\r\nX-Pad: $padding\r\n\r\n")
expect_code "$response" 431 "oversized headers are 431"

exec 8<>"/dev/tcp/127.0.0.1/$SERVER_PORT"
printf 'GET / HTTP/1.1\r\nHost: test\r\n' >&8
started=$(date +%s)
response=$(cat <&8 || true)
exec 8<&-
elapsed=$(( $(date +%s) - started ))
expect_code "$response" 408 "incomplete request times out"
[ "$elapsed" -ge 1 ] || fail "timeout fired too early (${elapsed}s)"
ok "timeout enforced after ${elapsed}s"

echo "== concurrency =="
exec 7<>"/dev/tcp/127.0.0.1/$SERVER_PORT"
printf 'GET /health HTTP/1.1\r\nHost: slow\r\n' >&7
pids=""
for _ in $(seq 1 16); do
    curl -fsS --max-time 5 -o /dev/null \
        "http://127.0.0.1:$SERVER_PORT/health" &
    pids="$pids $!"
done
succeeded=0
for pid in $pids; do
    if wait "$pid"; then
        succeeded=$((succeeded + 1))
    fi
done
exec 7<&-
[ "$succeeded" -eq 16 ] \
    || fail "only $succeeded/16 concurrent requests succeeded"
ok "16 requests served while one connection was held open"

echo "== backpressure =="
stop_server
start_server --max-connections 1 --timeout 30
wait_no_children || fail "the server kept a child after startup checks"
exec 6<>"/dev/tcp/127.0.0.1/$SERVER_PORT"
printf 'GET /health HTTP/1.1\r\nHost: held\r\n' >&6
wait_children 1 || fail "the held connection was not accepted"
headers=$(curl -sS -D - -o /dev/null --max-time 5 \
    "http://127.0.0.1:$SERVER_PORT/health")
expect_code "$headers" 503 "connection over the cap is rejected"
expect_header "$headers" '^Retry-After: 1' "503 advertises Retry-After"
exec 6<&-

code=""
for _ in $(seq 1 30); do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:$SERVER_PORT/health" 2>/dev/null || true)
    [ "$code" = 200 ] && break
    sleep 0.1
done
[ "$code" = 200 ] || fail "server did not recover after the cap freed ($code)"
ok "server recovers after a slot frees"

echo "== shutdown =="
stop_server
start_server
kill -HUP "$SERVER_PID"
sleep 0.1
kill -0 "$SERVER_PID" || fail "SIGHUP killed the server"
ok "SIGHUP is ignored (no config reload)"
wait_no_children || fail "the server kept a child after startup checks"
exec 5<>"/dev/tcp/127.0.0.1/$SERVER_PORT"
printf 'GET /health HTTP/1.1\r\nHost: drain\r\n' >&5
wait_children 1 || fail "the drain connection was not accepted"
kill -TERM "$SERVER_PID"
response=$(cat <&5 || true)
exec 5<&-
expect_code "$response" 408 "in-flight request completes during drain"
if ! terminate_server "$SERVER_PID"; then
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    fail "server did not exit after SIGTERM"
fi
wait "$SERVER_PID" || fail "server did not exit cleanly"
SERVER_PID=""
ok "SIGTERM drains in-flight connections and exits 0"

echo "== configuration =="
PORT_ENV=$((BASE_PORT + 1000))
CHTTP_PORT=$PORT_ENV CHTTP_BIND=127.0.0.1 CHTTP_TIMEOUT=2 \
    "$BIN" >>"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_ready "$PORT_ENV" || fail "environment-configured server did not start"
SERVER_PORT=$PORT_ENV
code=$(curl -sS -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$SERVER_PORT/health")
[ "$code" = 200 ] || fail "environment-configured server returned $code"
ok "CHTTP_PORT/CHTTP_BIND/CHTTP_TIMEOUT configure the server"

if CHTTP_PORT=notaport "$BIN" >/dev/null 2>&1; then
    fail "invalid environment configuration was accepted"
fi
ok "invalid configuration fails fast"

stop_server

if grep -q "terminated by signal" "$WORK/server.log"; then
    fail "a connection process crashed"
fi
ok "no connection process crashed"

echo "all smoke tests passed"
