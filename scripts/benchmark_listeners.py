"""Benchmark utility to measure decoy listener handshake latency and connection capacity.
"""

import time
import socket
import sys


def benchmark_tcp_port(host="127.0.0.1", port=8050, attempts=5):
    """Measures average TCP handshake latency for specified decoy listener port."""
    latencies = []
    print(f"[*] Benchmarking listener at {host}:{port} ({attempts} probes)...")

    for i in range(attempts):
        t0 = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)
            s.close()
        except Exception as e:
            print(f"[-] Probe {i+1} failed: {e}")
            continue

    if latencies:
        avg_lat = sum(latencies) / len(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        print(f"[+] Success: {len(latencies)}/{attempts} probes connected.")
        print(f"    Avg Latency: {avg_lat:.2f} ms (Min: {min_lat:.2f} ms, Max: {max_lat:.2f} ms)")
        return avg_lat
    else:
        print(f"[-] Could not establish connection to {host}:{port}.")
        return None


if __name__ == "__main__":
    port_to_test = int(sys.argv[1]) if len(sys.argv) > 1 else 8050
    benchmark_tcp_port(port=port_to_test)
