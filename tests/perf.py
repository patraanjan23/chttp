#!/usr/bin/env python3
"""Repeatable HTTP/1.1 throughput/latency benchmark for chttp and peers."""
import argparse
import concurrent.futures
import socket
import statistics
import subprocess
import time


def worker(port, count, keep_alive):
    latencies = []
    while count:
        batch = min(count, 100) if keep_alive else 1
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.settimeout(5)
            stream = sock.makefile("rb")
            for _ in range(batch):
                start = time.perf_counter()
                connection = b"keep-alive" if keep_alive else b"close"
                sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: "
                             + connection + b"\r\n\r\n")
                status = stream.readline()
                headers = {}
                while True:
                    line = stream.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    key, _, value = line.partition(b":")
                    headers[key.lower()] = value.strip()
                length = int(headers.get(b"content-length", b"0"))
                body = stream.read(length)
                if not status.startswith(b"HTTP/1.1 200") or len(body) != length:
                    raise RuntimeError(f"unexpected response: {status!r}")
                latencies.append(time.perf_counter() - start)
        count -= batch
    return latencies


def run_round(port, requests, concurrency, keep_alive):
    counts = [requests // concurrency] * concurrency
    for i in range(requests % concurrency):
        counts[i] += 1
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        groups = pool.map(lambda n: worker(port, n, keep_alive), counts)
        latencies = [value for group in groups for value in group]
    elapsed = time.perf_counter() - start
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * .95))]
    return requests / elapsed, statistics.mean(latencies) * 1000, p95 * 1000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="path to server executable")
    parser.add_argument("--requests", type=int, default=3000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--mode", choices=("keepalive", "close"), default="keepalive")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if min(args.requests, args.concurrency, args.rounds) < 1:
        parser.error("requests, concurrency, and rounds must be positive")

    port = args.port
    if port == 0:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
    server = subprocess.Popen([args.binary, "--bind", "127.0.0.1", "--port",
                               str(port), "--max-connections", str(args.concurrency + 4)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    break
            except OSError:
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("server failed to start")
                time.sleep(.05)

        keep_alive = args.mode == "keepalive"
        run_round(port, min(args.concurrency, args.requests), args.concurrency,
                  keep_alive)  # warm-up
        samples = []
        for index in range(args.rounds):
            result = run_round(port, args.requests, args.concurrency, keep_alive)
            samples.append(result)
            print(f"round {index + 1}: {result[0]:.1f} req/s, "
                  f"mean={result[1]:.2f} ms, p95={result[2]:.2f} ms")
        rates = [sample[0] for sample in samples]
        means = [sample[1] for sample in samples]
        p95s = [sample[2] for sample in samples]
        print(f"median ({args.rounds} rounds, {args.mode}): "
              f"{statistics.median(rates):.1f} req/s, "
              f"mean latency={statistics.median(means):.2f} ms, "
              f"p95 latency={statistics.median(p95s):.2f} ms; "
              f"throughput range={min(rates):.1f}–{max(rates):.1f} req/s")
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    main()
