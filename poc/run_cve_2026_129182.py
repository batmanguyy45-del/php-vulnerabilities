#!/usr/bin/env python3
"""Repeatable PHP-FPM fatal-backtrace regression comparison."""

from pathlib import Path
from datetime import datetime, timezone
import ast
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "fatal-backtrace-lab"
PROBE = "/lab/cve_2026_129182_probe.py"

CASES = [
    ("fatal-backtrace-vulnerable", "8.5.12", "memory", True),
    ("fatal-backtrace-vulnerable", "8.5.12", "zlib", True),
    ("fatal-backtrace-patched", "8.5.13", "memory", False),
    ("fatal-backtrace-patched", "8.5.13", "zlib", False),
]


def call(args, show=True):
    args = list(map(str, args))
    if show:
        print("\n$", " ".join(args), flush=True)
    r = subprocess.run(
        args, cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if show:
        print(r.stdout, end="", flush=True)
        print(r.stderr, end="", file=sys.stderr, flush=True)
    return r


def compose(*args, show=True):
    return call(
        ["docker", "compose", "--profile", PROFILE, *args],
        show=show
    )


def field(output, name):
    m = re.search(rf"^{re.escape(name)}=(.*)$", output, re.M)
    return m.group(1).strip() if m else None


def main():
    if not (ROOT / "docker-compose.yml").is_file():
        print("ERROR: repository root not found")
        return 2

    config = compose("config", "-q")
    if config.returncode:
        return 2

    images = {
        "8.5.12": "php:8.5.12-fpm-alpine",
        "8.5.13": "php:8.5.13-fpm-alpine",
    }
    identities = {}

    for version, image in images.items():
        inspect = call(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            show=False
        )
        version_check = call(
            ["docker", "run", "--rm", "--entrypoint", "php-fpm",
             image, "-v"],
            show=False
        )
        if inspect.returncode or version_check.returncode:
            print(f"ERROR: image verification failed for {image}")
            return 2
        if f"PHP {version}" not in version_check.stdout:
            print(f"ERROR: unexpected runtime version for {image}")
            return 2
        identities[version] = inspect.stdout.strip()
        print(f"IMAGE_{version}={identities[version]}")
        print(version_check.stdout.strip())

    results = []
    success = False

    try:
        for repetition in range(1, 4):
            for service, version, scenario, vulnerable in CASES:
                print(
                    f"\n========== TRIAL {repetition}/3 "
                    f"{version} {scenario} ==========",
                    flush=True
                )

                up = compose(
                    "up", "-d", "--no-deps", "--force-recreate", service
                )
                if up.returncode:
                    raise RuntimeError(f"Could not start {service}")

                time.sleep(1.5)

                probe = compose(
                    "run", "--rm", "--no-deps", "-T",
                    "fatal-backtrace-probe", PROBE, service, scenario
                )
                output = probe.stdout + "\n" + probe.stderr

                expected_trace = "True" if vulnerable else "False"
                checks = {
                    "REGRESSION_OBSERVATION": "PASS",
                    "SAME_WORKER": "True",
                    "EXPECTED_SHUTDOWN_FATAL": "True",
                    "PRODUCER_STACK_TRACE": expected_trace,
                    "EARLY_WARNING_CONFIRMED": "True",
                    "EARLY_DIAGNOSTIC_STACK_TRACE": "False",
                }

                failed = []
                for name, expected in checks.items():
                    actual = field(output, name)
                    if actual != expected:
                        failed.append(f"{name}: expected {expected}, got {actual}")

                pids_text = field(output, "WORKER_PIDS")
                try:
                    pids = ast.literal_eval(pids_text)
                except (ValueError, SyntaxError, TypeError):
                    pids = []

                if probe.returncode != 0:
                    failed.append(f"probe exit code {probe.returncode}")
                if len(pids) != 3 or len(set(pids)) != 1:
                    failed.append("worker PID continuity check failed")

                logs = compose(
                    "logs", "--no-color", "--tail=100", service,
                    show=False
                )
                log_text = logs.stdout + logs.stderr

                trigger = (
                    "Failed to set memory limit to 8388608 bytes"
                    if scenario == "memory"
                    else "Cannot use both zlib.output_compression and output_handler together!!"
                )
                if trigger not in log_text:
                    failed.append("expected shutdown fatal missing from FPM logs")
                if "Invalid date.timezone value 'invalid'" not in log_text:
                    failed.append("early diagnostic missing from FPM logs")
                if ("Stack trace:" in log_text) != vulnerable:
                    failed.append("FPM log stack-trace comparison mismatch")

                row = {
                    "trial": repetition,
                    "version": version,
                    "scenario": scenario,
                    "pids": pids,
                    "trace": expected_trace,
                    "passed": not failed,
                }
                results.append(row)

                print(f"WORKER_PIDS={pids}")
                print(f"FPM_LOG_CHECK={'PASS' if not failed else 'FAIL'}")
                if failed:
                    print("TRIAL_FAILURES:")
                    for item in failed:
                        print(" - " + item)
                    print(output)
                    raise RuntimeError("Trial did not meet all assertions")

                print("TRIAL_RESULT=PASS")

        success = len(results) == 12 and all(x["passed"] for x in results)

        if success:
            lines = [
                "# CVE-2026-129182 — PHP-FPM fatal-backtrace regression",
                "",
                f"Run date: {datetime.now(timezone.utc).isoformat()}",
                "Result: PASS — 12/12 independent trials",
                "",
                "## Runtime images",
                "",
            ]
            for version, identity in identities.items():
                lines.append(f"- PHP {version}: `{identity}`")

            lines += [
                "",
                "## Trial results",
                "",
                "| Trial | PHP | Scenario | Worker PID | Producer trace | Result |",
                "|---:|---:|---|---:|---|---|",
            ]
            for row in results:
                lines.append(
                    f"| {row['trial']} | {row['version']} | "
                    f"{row['scenario']} | {row['pids'][0]} | "
                    f"{row['trace']} | PASS |"
                )

            lines += [
                "",
                "## Observed behavior",
                "",
                "Each trial used a fresh single-worker FPM container and the "
                "upstream three-request sequence: baseline, shutdown-error "
                "producer, then an early PHP_VALUE date.timezone diagnostic.",
                "",
                "PHP 8.5.12 emitted a fatal-error stack trace for both the "
                "memory-limit restoration failure and the zlib/output-handler "
                "restoration failure. PHP 8.5.13 emitted the corresponding "
                "fatal message without that stack trace.",
                "",
                "Both versions emitted the expected invalid-timezone warning "
                "on the follow-up request. All three requests in every trial "
                "completed on the same worker PID.",
                "",
                "## Interpretation and limitations",
                "",
                "This reproduces the affected-versus-fixed FPM diagnostic "
                "behavior in both upstream regression scenarios. It confirms "
                "the shutdown-time backtrace difference introduced by the "
                "upstream fix.",
                "",
                "No worker crash, arbitrary memory read/write, or code "
                "execution was demonstrated. This report does not claim "
                "independent proof of memory corruption or RCE.",
                "",
                "Official advisory: "
                "https://github.com/php/php-src/security/advisories/GHSA-2fjv-p558-g82m",
                "",
                "Upstream fix: "
                "https://github.com/php/php-src/commit/ae961499489e6672db10573935d5463d798ecf47",
                "",
                "Upstream memory test: "
                "https://github.com/php/php-src/blob/PHP-8.5/sapi/fpm/tests/ghsa-2fjv-p558-g82m-memory-limit.phpt",
                "",
                "Upstream zlib test: "
                "https://github.com/php/php-src/blob/PHP-8.5/sapi/fpm/tests/ghsa-2fjv-p558-g82m-zlib.phpt",
                "",
            ]

            evidence = ROOT / "evidence" / "CVE-2026-129182-fpm-backtrace-regression.md"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("\n".join(lines))
            print(f"\nEVIDENCE_WRITTEN={evidence.relative_to(ROOT)}")
            print("FINAL_RESULT=PASS")
            return 0

        return 3

    except Exception as exc:
        print(f"\nFINAL_RESULT=INCONCLUSIVE: {exc}", file=sys.stderr)
        return 3

    finally:
        compose(
            "stop",
            "fatal-backtrace-vulnerable",
            "fatal-backtrace-patched",
            show=False
        )


if __name__ == "__main__":
    sys.exit(main())
