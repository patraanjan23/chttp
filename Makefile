# Minimal Fil-C HTTP server.
#
#   make            build build/chttp (static)
#   make run        build and serve on http://127.0.0.1:8080
#   make check      build and run the crypto, HTTP, and TLS suites
#   make analyze    clang static analyzer
#   make valgrind   dynamic build under Valgrind (needs valgrind + curl)
#   make trace      strace one exchange (needs strace + curl)
#   make install    install to $(PREFIX)/bin (default /usr/local)
#   make clean      remove build artifacts

# The Fil-C C driver. Override for a different path with:
#   make CC=/path/to/fil-c/build/bin/filcc
CC      := filcc
CFLAGS  ?= -O2 -g -Wall -Wextra
# -static gives a self-contained binary: no external libc/pkg deps at run time.
# For a small dynamically linked dev build: make LDFLAGS=
LDFLAGS ?= -static
TARGET  := build/chttp
DYNBIN  := build/chttp-dyn
CRYPTOTEST := build/crypto_test
SRC     := src/main.c src/tls.c src/crypto.c
HEADERS := src/tls.h src/crypto.h

ifeq ($(shell command -v $(firstword $(CC)) 2>/dev/null),)
$(error $(CC) not found - install Fil-C and put its build/bin on PATH, or run make CC=/path/to/fil-c/build/bin/filcc)
endif

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS) | build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

build:
	mkdir -p build

# Known-answer tests for the primitives TLS depends on.
$(CRYPTOTEST): tests/crypto_test.c src/crypto.c src/crypto.h | build
	$(CC) $(CFLAGS) -Werror -o $@ tests/crypto_test.c src/crypto.c

# Dynamic build, used by valgrind (Valgrind cannot start the static-pie image).
$(DYNBIN): $(SRC) $(HEADERS) | build
	$(CC) $(CFLAGS) -o $@ $(SRC)

# Clang static analyzer, shipped with the Fil-C compiler.
analyze:
	$(CC) --analyze $(CFLAGS) -Xanalyzer -analyzer-output=text $(SRC)

# Valgrind on the dynamic build: fetch pages and exercise both body framings.
# Children are silent after fork; the parent's report is the one we inspect.
valgrind: $(DYNBIN)
	@set -e; \
	port=$$((20000 + $$$$ % 20000)); \
	valgrind --leak-check=full --errors-for-leak-kinds=definite \
		--child-silent-after-fork=yes \
		--error-exitcode=99 --log-file=build/valgrind.log \
		./$(DYNBIN) --port $$port --timeout 2 --max-connections 4 \
		>/dev/null 2>&1 & \
	vpid=$$!; \
	trap 'kill $$vpid 2>/dev/null || true' EXIT INT TERM; \
	for i in $$(seq 1 100); do \
		curl -fsS --max-time 1 "http://127.0.0.1:$$port/health" >/dev/null 2>&1 && break; \
		sleep 0.2; \
	done; \
	curl -fsS "http://127.0.0.1:$$port/" | grep -q "hello from Fil-C"; \
	curl -fsS --data-binary hello "http://127.0.0.1:$$port/" | grep -qx hello; \
	curl -fsS -H 'Transfer-Encoding: chunked' --data-binary hello \
		"http://127.0.0.1:$$port/" | grep -qx hello; \
	kill -TERM $$vpid; \
	wait $$vpid; \
	grep -q "ERROR SUMMARY: 0 errors" build/valgrind.log; \
	echo "ok: valgrind found no errors (build/valgrind.log)"

# The same request/body coverage over TLS. Slow on purpose: a handshake under
# Valgrind is thousands of interpreted big-integer operations.
valgrind-tls: $(DYNBIN)
	@set -e; \
	dir=$$(mktemp -d); \
	port=$$((20000 + $$$$ % 20000)); \
	trap 'rm -rf $$dir; kill $${vpid:-0} 2>/dev/null || true' EXIT INT TERM; \
	openssl req -x509 -newkey ed25519 -keyout $$dir/key.pem \
		-out $$dir/cert.pem -days 1 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		>/dev/null 2>&1; \
	valgrind --leak-check=full --errors-for-leak-kinds=definite \
		--child-silent-after-fork=yes \
		--error-exitcode=99 --log-file=build/valgrind-tls.log \
		./$(DYNBIN) --port $$port --timeout 20 --max-connections 4 \
		--tls-cert $$dir/cert.pem --tls-key $$dir/key.pem \
		>/dev/null 2>&1 & \
	vpid=$$!; \
	for i in $$(seq 1 200); do \
		curl -fsS --max-time 3 --cacert $$dir/cert.pem \
			"https://127.0.0.1:$$port/health" >/dev/null 2>&1 && break; \
		sleep 0.5; \
	done; \
	curl -fsS --max-time 20 --cacert $$dir/cert.pem \
		"https://127.0.0.1:$$port/" | grep -q "hello from Fil-C"; \
	curl -fsS --max-time 20 --cacert $$dir/cert.pem --data-binary hello \
		"https://127.0.0.1:$$port/" | grep -qx hello; \
	curl -fsS --max-time 20 --cacert $$dir/cert.pem \
		-H 'Transfer-Encoding: chunked' --data-binary hello \
		"https://127.0.0.1:$$port/" | grep -qx hello; \
	kill -TERM $$vpid; \
	wait $$vpid; \
	grep -q "ERROR SUMMARY: 0 errors" build/valgrind-tls.log; \
	echo "ok: TLS valgrind found no errors (build/valgrind-tls.log)"

# Syscall-level trace of one request/response exchange.
trace: $(TARGET)
	@set -e; \
	port=$$((20000 + $$$$ % 20000)); \
	strace -f -e trace=network -o build/strace.log \
		./$(TARGET) --port $$port --timeout 2 --max-connections 4 \
		>/dev/null 2>&1 & \
	spid=$$!; \
	trap 'pkill -KILL -P $$spid 2>/dev/null || true; kill -KILL $$spid 2>/dev/null || true' EXIT INT TERM; \
	for i in $$(seq 1 100); do \
		curl -fsS --max-time 1 "http://127.0.0.1:$$port/health" >/dev/null 2>&1 && break; \
		sleep 0.2; \
	done; \
	curl -fsS "http://127.0.0.1:$$port/" >/dev/null; \
	child=$$(pgrep -P $$spid | head -1); \
	kill -TERM $$child; \
	wait $$spid; \
	echo "ok: network syscalls in build/strace.log"

run: $(TARGET)
	./$(TARGET)

check: $(TARGET) $(CRYPTOTEST)
	./$(CRYPTOTEST)
	BIN=./$(TARGET) ./tests/smoke.sh
	BIN=./$(TARGET) ./tests/tls.sh

PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/chttp

install-systemd:
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	install -m 0644 deploy/chttp.service \
		$(DESTDIR)$(SYSCONFDIR)/systemd/system/chttp.service

clean:
	rm -rf build

.PHONY: all run check clean analyze valgrind valgrind-tls trace install install-systemd
