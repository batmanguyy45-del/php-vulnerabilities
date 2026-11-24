# PHP Vulnerability Research Lab

Local-only PHP security research, debugging and vulnerable-versus-patched testing.

## Safety
All vulnerable services must stay inside an isolated Docker network.
No public targets, external callbacks, arbitrary shell payloads or host mounts.
A CVE is not considered reproduced merely because its version range matches.

## Requirements
- Kali Linux
- Python 3
- Docker Engine and Docker Compose v2

## Initial checks
```bash
python3 -m unittest discover -s tests -v
docker compose config -q
```

## Baseline environments
```bash
docker compose --profile baseline pull
docker compose --profile baseline up -d
docker compose ps
docker compose --profile baseline down
```

No vulnerable service ports are published to the host.

## Research workflow
1. Read the primary PHP advisory.
2. Verify affected versions and configuration prerequisites.
3. Build a disposable reproducer.
4. Record observable behavior and logs.
5. Repeat against the patched version.
6. Document limitations and evidence.

See docs/advisory-register.md and docs/poc-standard.md.
