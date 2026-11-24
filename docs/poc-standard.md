# PoC and Evidence Standard

Each CVE module must document:

1. Original PHP advisory and source references.
2. Exact affected and fixed releases.
3. Required runtime configuration.
4. Minimal reproducible laboratory environment.
5. Local reproduction procedure.
6. Observable evidence and logs.
7. Patched-version comparison.
8. Limitations and false-positive considerations.

Proof levels:

- Version match: affected version appears present.
- Prerequisite match: required configuration is present.
- Behavior reproduced: documented behavior was observed.
- Impact demonstrated: bounded proof establishes the relevant impact.
- Patch regression passed: the same test no longer reproduces on the fixed build.

Never equate a crash with RCE. Keep generated evidence local by default.
