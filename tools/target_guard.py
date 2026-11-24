"""Strict loopback-only URL validation for local lab clients."""

import argparse
import ipaddress
import sys
from urllib.parse import urlsplit


class TargetRejected(ValueError):
    pass


def validate_loopback_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise TargetRejected("Malformed URL") from exc

    if parsed.scheme not in ("http", "https"):
        raise TargetRejected("Only HTTP and HTTPS are accepted")

    if not parsed.netloc or host is None:
        raise TargetRejected("An explicit host is required")

    if parsed.username is not None or parsed.password is not None:
        raise TargetRejected("URL credentials are forbidden")

    if host.lower() == "localhost":
        return value

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise TargetRejected(
            "Use localhost or a literal loopback IP only"
        ) from exc

    if not address.is_loopback:
        raise TargetRejected("Non-loopback destination rejected")

    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    try:
        print("ACCEPTED:", validate_loopback_url(args.url))
        return 0
    except TargetRejected as exc:
        print("REJECTED:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
