#!/usr/bin/env python3

"""Build and run the local CVE-2026-126714 session corruption lab."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "cve-2026-126714"

CASES = {
    "session-vulnerable": {
        "version": "8.5.12",
        "directory": ARTIFACTS / "vulnerable",
        "expected": "OBJECT_RESTORED",
    },
    "session-patched": {
        "version": "8.5.13",
        "directory": ARTIFACTS / "patched",
        "expected": "NO_OBJECT",
    },
}


def execute(command, env=None):
    print("\n$", " ".join(map(str, command)), flush=True)
    result = subprocess.run(
        list(map(str, command)),
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)

    return result


def compose_run(service, args, extra_env=None):
    command = [
        "docker", "compose", "--profile", "session-lab",
        "run", "--rm", "--no-deps",
    ]

    for key, value in (extra_env or {}).items():
        command += ["-e", f"{key}={value}"]

    command.append(service)
    command.extend(args)

    return execute(command)



def read_session_file(service):
    """Read private session bytes as the container owner, without chmod."""
    php_code = (
        "echo 'SESSION_B64=' . "
        "base64_encode(file_get_contents('/sessions/sess_lab126714'));"
    )

    command = [
        "docker", "compose", "--profile", "session-lab",
        "run", "--rm", "--no-deps", "-T",
        service, "-r", php_code,
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Could not read session inside {service}: "
            f"{result.stderr}"
        )

    encoded = next(
        (
            line.split("=", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("SESSION_B64=")
        ),
        None,
    )

    if encoded is None:
        raise RuntimeError("Session reader did not return encoded data")

    return base64.b64decode(encoded, validate=True)

def image_identity(image):
    result = execute([
        "docker", "image", "inspect", image,
        "--format", "{{.Id}}",
    ])
    return result.stdout.strip()


def prepare_directories():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    for case in CASES.values():
        path = case["directory"].resolve()
        if ARTIFACTS.resolve() not in path.parents:
            raise RuntimeError("Refusing to clean a path outside lab artifacts")

        if path.exists():
            shutil.rmtree(path)

        path.mkdir(parents=True, mode=0o777)
        path.chmod(0o777)


def run_case(service, case, repetition):
    print(
        f"\n========== {service} / repetition {repetition} ==========",
        flush=True,
    )

    seed = compose_run(service, ["/lab/seed.php"])
    if seed.returncode != 0 or "SEED_OK" not in seed.stdout:
        raise RuntimeError("Session seeding failed")

    old_file = read_session_file(service)
    if len(old_file) == 0:
        raise RuntimeError("Seed session file is empty")

    writer = compose_run(
        service,
        ["/lab/interrupt.php"],
        {
            "LD_PRELOAD": "/usr/local/lib/libsession_interrupt.so",
            "LAB_INTERRUPT_SESSION_WRITE": "1",
        },
    )

    if writer.returncode != 86:
        raise RuntimeError(
            "Controlled interrupted write did not fire "
            f"(exit={writer.returncode})"
        )

    if "LAB_INJECTOR: partial session write" not in writer.stderr:
        raise RuntimeError("Missing failpoint evidence")

    after_write = read_session_file(service)

    # The writer reports the exact offset at which its write was interrupted.
    cut_line = next(
        (line for line in writer.stdout.splitlines()
         if line.startswith("CUT_BYTES=")),
        None,
    )
    if cut_line is None:
        raise RuntimeError("Writer did not report CUT_BYTES")

    try:
        cut_bytes = int(cut_line.split("=", 1)[1])
    except ValueError as exc:
        raise RuntimeError("Invalid CUT_BYTES value") from exc

    if not 0 < cut_bytes < len(old_file):
        raise RuntimeError(
            f"Invalid interruption offset: {cut_bytes}; "
            f"original file size: {len(old_file)}"
        )

    # Compare the exact pre-existing bytes after the interrupted write offset.
    expected_old_tail = old_file[cut_bytes:]

    suffix_survived = (
        len(after_write) == len(old_file)
        and after_write.endswith(expected_old_tail)
    )

    preserved_tail_bytes = (
        len(expected_old_tail) if suffix_survived else 0
    )

    reader = compose_run(service, ["/lab/read.php"])
    if reader.returncode != 0:
        raise RuntimeError("Session reader failed")

    restored = "OBJECT_RESTORED" in reader.stdout
    absent = "NO_OBJECT" in reader.stdout

    print(f"Old session bytes: {len(old_file)}")
    print(f"Interrupted file bytes: {len(after_write)}")
    print(f"Write interruption offset: {cut_bytes}")
    print(f"Expected old tail bytes: {len(expected_old_tail)}")
    print(f"Old tail bytes preserved exactly: {preserved_tail_bytes}")
    print(f"Exact old tail survived: {suffix_survived}")
    print(f"Object restored: {restored}")

    if case["expected"] == "OBJECT_RESTORED":
        passed = (
            len(after_write) == len(old_file)
            and suffix_survived
            and restored
            and not absent
        )
    else:
        passed = (
            len(after_write) == cut_bytes
            and not suffix_survived
            and absent
            and not restored
        )

    print("CASE RESULT:", "PASS" if passed else "FAIL")
    return passed, len(old_file), len(after_write), cut_bytes, preserved_tail_bytes, restored


def main():
    if not (ROOT / "docker-compose.yml").exists():
        print("Run this script from the repository.", file=sys.stderr)
        return 2

    prepare_directories()

    config = execute([
        "docker", "compose", "--profile", "session-lab", "config", "-q"
    ])
    if config.returncode != 0:
        return 2

    build = execute([
        "docker", "compose", "--profile", "session-lab",
        "build", "--pull",
        "session-vulnerable", "session-patched",
    ])
    if build.returncode != 0:
        return 2

    identities = {
        "PHP 8.5.12": image_identity("php-session-lab:8.5.12"),
        "PHP 8.5.13": image_identity("php-session-lab:8.5.13"),
    }

    results = {name: [] for name in CASES}

    for repetition in range(1, 4):
        for service, case in CASES.items():
            # Reset the session file before every independent trial.
            session_file = case["directory"] / "sess_lab126714"
            if session_file.exists():
                session_file.unlink()

            outcome = run_case(service, case, repetition)
            results[service].append(outcome)

    print("\n========== FINAL RESULTS ==========")

    all_passed = True

    for service, case in CASES.items():
        successful = sum(1 for row in results[service] if row[0])
        print(
            f"{case['version']}: {successful}/3 successful reproductions"
        )
        all_passed = all_passed and successful == 3

    if all_passed:
        lines = [
            "# CVE-2026-126714 — Local reproduction evidence",
            "",
            "Date: 2026-11-25",
            "Method: controlled partial pwrite followed by session reload",
            "",
            "## Runtime image identities",
            "",
        ]

        for name, identity in identities.items():
            lines.append(f"- {name}: `{identity}`")

        vulnerable_trial = results["session-vulnerable"][0]
        patched_trial = results["session-patched"][0]

        lines += [
            "",
            "## Results",
            "",
            "| Runtime | Trials | File size after interruption | Cutoff | Old tail retained | Deserialization |",
            "|---|---:|---:|---:|---:|---|",
            f"| PHP 8.5.12 | 3/3 | {vulnerable_trial[1]} → {vulnerable_trial[2]} bytes | {vulnerable_trial[3]} bytes | {vulnerable_trial[4]} bytes | Inert object restored |",
            f"| PHP 8.5.13 | 3/3 | {patched_trial[1]} → {patched_trial[2]} bytes | {patched_trial[3]} bytes | {patched_trial[4]} bytes | No object restored |",
            "",
            "## Interpretation",
            "",
            "The test used PHP's built-in files session handler and a controlled",
            "local pwrite failpoint. It demonstrated the stale-suffix behavior",
            "on the vulnerable build and its removal on the fixed build.",
            "",
            "The LabMarker class has no magic methods. No framework gadget chain,",
            "command execution, remote callback, or arbitrary payload was used.",
            "This demonstrates the session corruption/object restoration",
            "primitive, not remote code execution.",
            "",
            "Primary advisory:",
            "https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp",
            "",
            "Upstream fix:",
            "https://github.com/php/php-src/commit/e2d3cee9ad4b0b739f4a8ebe6a69c938399b7da6",
        ]

        evidence = ROOT / "evidence" / "CVE-2026-126714-session-reproduction.md"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text("\n".join(lines) + "\n")

        print("\nPASS: evidence written to", evidence.relative_to(ROOT))
        return 0

    print("\nINCONCLUSIVE: inspect the first failed stage and session artifacts.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
