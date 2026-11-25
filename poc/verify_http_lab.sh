#!/bin/sh
# Run with: bash poc/verify_http_lab.sh
# This child script never changes the caller's interactive shell.

cd "$(dirname "$0")/.." || {
    echo "Could not enter project directory."
}

echo "===== RECREATING CLEAN TEST ENVIRONMENT ====="

docker compose --profile http-lab up -d --force-recreate \
    php-pre-november-fix \
    php-november-fixed \
    php-old-mitigated \
    nginx-http-lab

UP_RC=$?

if [ "$UP_RC" -eq 0 ]; then
    sleep 3

    echo "===== RUNNING HTTP PROBE ====="

    docker compose --profile http-lab run --rm \
        fpm-poc-runner /lab/poc/cve_2026_129289_http.py

    HTTP_RC=$?

    echo "===== READING VULNERABLE FPM ACCESS LOG ====="
    VULN_LOG=$(docker compose logs --no-color --tail=100 php-pre-november-fix 2>&1)
    printf '%s\n' "$VULN_LOG" | grep -F 'lab-marker-cve-2026-129289.php' || true

    echo "===== READING PATCHED FPM ACCESS LOG ====="
    PATCH_LOG=$(docker compose logs --no-color --tail=100 php-november-fixed 2>&1)
    printf '%s\n' "$PATCH_LOG" | grep -F 'lab-marker-cve-2026-129289.php' || true

    echo "===== READING MITIGATION FPM ACCESS LOG ====="
    MIT_LOG=$(docker compose logs --no-color --tail=100 php-old-mitigated 2>&1)
    printf '%s\n' "$MIT_LOG" | grep -F 'lab-marker-cve-2026-129289.php' || true

    VULN_MARKER=NO
    PATCH_MARKER=NO
    MIT_MARKER=NO

    case "$VULN_LOG" in
        *"GET /lab-marker-cve-2026-129289.php 200"*) VULN_MARKER=YES ;;
    esac

    case "$PATCH_LOG" in
        *"GET /lab-marker-cve-2026-129289.php 200"*) PATCH_MARKER=YES ;;
    esac

    case "$MIT_LOG" in
        *"GET /lab-marker-cve-2026-129289.php 200"*) MIT_MARKER=YES ;;
    esac

    echo "========== BACKEND EXECUTION MATRIX =========="
    echo "PHP 8.5.12 persistent: $VULN_MARKER"
    echo "PHP 8.5.13 persistent: $PATCH_MARKER"
    echo "PHP 8.5.12 mitigation: $MIT_MARKER"
    echo "HTTP probe exit code: $HTTP_RC"

    if [ "$HTTP_RC" -eq 0 ] &&
       [ "$VULN_MARKER" = YES ] &&
       [ "$PATCH_MARKER" = NO ] &&
       [ "$MIT_MARKER" = NO ]; then

        echo "RESULT: HTTP-TO-FPM MARKER DISPATCH REPRODUCED"

        cat > evidence/CVE-2026-129289-http-integration.md <<'EOF'
# CVE-2026-129289 HTTP-to-FPM Integration Evidence

Date: 2026-11-25

## Architecture

- Nginx HTTP frontend
- PHP 8.5.12 persistent FastCGI candidate
- PHP 8.5.13 patched candidate
- Independent PHP 8.5.12 keep-connection-disabled mitigation candidate
- Internal Docker network; no published host ports

## Oracle

The PHP-FPM access log is the authoritative oracle. The marker
is a fixed, benign request path handled by the pre-existing
local target.php script. Its response is not required to appear
in the original HTTP response.

## Expected differential

- Vulnerable backend: GET /lab-marker-cve-2026-129289.php 200
- Patched backend: no marker request
- Mitigation backend: no marker request

## Interpretation

A marker request in the vulnerable FPM access log, absent from
the patched and mitigation logs, demonstrates that the HTTP
request caused an additional FastCGI request to be processed
by the vulnerable local worker.

This demonstrates request dispatch using a harmless fixed marker.
It does not demonstrate arbitrary attacker-controlled PHP code
execution or the PHP_ADMIN_VALUE / auto_prepend_file chain.

See the terminal run and the original direct FastCGI evidence
for complementary protocol-level reproduction.
EOF

        echo "Evidence written to evidence/CVE-2026-129289-http-integration.md"
    else
        echo "RESULT: INCONCLUSIVE — do not claim HTTP reproduction."
        echo "Inspect the three FPM logs above."
    fi
else
    echo "Container recreation failed. No test was run."
fi

echo "===== FINAL STATUS ====="
docker compose ps
echo "===== GIT STATUS ====="
git status --short
echo "===== VERIFICATION FINISHED ====="
