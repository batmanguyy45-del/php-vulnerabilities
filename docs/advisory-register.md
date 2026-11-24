# Advisory Register

Research snapshot: 24 November 2026.

Primary PHP project advisories are linked below. Brotli is tracked separately because it is a dependency issue, not a PHP-core CVE.

| CVE | Research topic | Primary reference |
|---|---|---|
| CVE-2026-109618 | PHP request initialization memory corruption | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) |
| CVE-2026-109619 | PHP stale request state | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |
| CVE-2026-115560 | PHP session serializer mismatch | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) |
| CVE-2026-126714 | Partially overwritten PHP session files | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp) |
| CVE-2026-129182 | PHP fatal-error backtrace use-after-free | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-2fjv-p558-g82m) |
| CVE-2026-129289 | PHP-FPM request smuggling | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-qc49-hpvq-g2w6) |
| CVE-2026-129291 | PHP-FPM epoll use-after-free | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-jm4m-qfqx-967m) |
| CVE-2026-129474 | PHP magic-method backtrace use-after-free | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-8mjj-2r7p-4hg2) |
| CVE-2026-129481 | PHP interrupted session shutdown use-after-free | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-g3vh-838c-65v7) |
| CVE-2026-129496 | PHP timezone-cache use-after-free | [Advisory](https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv) |
| CVE-2026-111497 | Brotli decoder dependency vulnerability | [Advisory](https://www.php.net/archive/2026.php) |

## Patch baseline

PHP 8.5.13 was released on 19 November 2026. PHP 8.5.12 is used as a pre-November-fix comparison candidate, not as proof that every listed issue affects that build. Confirm each advisory's exact version range and configuration before attempting reproduction.

Do not infer vulnerability or exploitability from a version string alone. Distribution packages may backport fixes.
