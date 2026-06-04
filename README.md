# MadeYouReset Checker

A lightweight Python script to detect whether a web server is potentially vulnerable to the **MadeYouReset** HTTP/2 denial-of-service vulnerability — tracked as **CVE-2025-8671** (CVSS 7.5 High).

---

## Background

**MadeYouReset** is an HTTP/2 DoS vulnerability disclosed in August 2025 by researchers at Tel Aviv University and Imperva. It exploits a mismatch between HTTP/2 stream accounting and internal backend processing in many popular server implementations.

The attack sends deliberately malformed HTTP/2 control frames (e.g. a `WINDOW_UPDATE` with `increment=0`, which is illegal per RFC 9113 §6.9.1) to coerce the **server itself** into issuing `RST_STREAM` frames. Because the server treats the stream as closed at the protocol level while continuing to process the request in the backend, an attacker can bypass the `MAX_CONCURRENT_STREAMS` limit and exhaust server resources — without sending a single client-side `RST_STREAM`.

This makes it a bypass of mitigations introduced for the earlier **Rapid Reset** attack (CVE-2023-44487).

**Known affected software:**

| Product | CVE |
|---|---|
| Apache Tomcat 9.x / 10.x / 11.x | CVE-2025-48989 |
| Netty < 4.1.124.Final / 4.2.4.Final | CVE-2025-55163 |
| F5 BIG-IP | CVE-2025-54500 |
| IBM WebSphere Application Server Liberty | CVE-2025-36047 |
| Varnish, Fastly, Jetty, SUSE, Wind River | CVE-2025-8671 |

---

## How the Checker Works

1. Opens a TCP connection to the target host.
2. Performs a TLS handshake negotiating `h2` via ALPN.
3. Sends the HTTP/2 client preface and a `SETTINGS` frame.
4. Opens a request stream with a `HEADERS` frame.
5. Sends a malformed `WINDOW_UPDATE` frame (`increment=0`) on the open stream.
6. Analyses the server response:
   - **`RST_STREAM` on the stream (no `GOAWAY`)** → likely vulnerable.
   - **`GOAWAY`** → correct RFC behaviour; likely patched.
   - **No response / inconclusive** → manual follow-up recommended.

> The script performs a **read-only passive probe** — it does not attempt to exploit or stress-test the server.

---

## Requirements

- Python **3.7+**
- No external packages — pure standard library only.

---

## Installation

```bash
git clone https://github.com/ayushghatkar8080/MadeYouReset_Tester.git
cd MadeYouReset_Tester
# No pip install needed — no dependencies
```

---

## Usage

```bash
python3 main.py <url> [OPTIONS]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--timeout SECONDS` | `8` | Socket read timeout |
| `--no-color` | off | Disable ANSI colour output |

### Examples

```bash
# Basic check
python3 main.py https://example.com

# Custom port and longer timeout
python3 main.py https://example.com:8443 --timeout 15

# CI-friendly (no colour)
python3 main.py https://example.com --no-color
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Not vulnerable — server responded with `GOAWAY` (correct RFC behaviour) |
| `1` | **Likely vulnerable** — server sent `RST_STREAM` on the stream but no `GOAWAY` |
| `2` | Inconclusive — no HTTP/2, connection error, or ambiguous response |

Exit codes make it straightforward to integrate into CI pipelines or automation scripts.

---

## Sample Output

```
========================================================
  MadeYouReset (CVE-2025-8671) Checker
========================================================
  Target  : https://vulnerable-server.example.com
  Host    : vulnerable-server.example.com:443
  Path    : /
  Timeout : 8.0s
────────────────────────────────────────────────────────

[*] Connecting to vulnerable-server.example.com:443 ...
  ✓ TCP connection established

[*] Performing TLS handshake (ALPN: h2, http/1.1) ...
  → Negotiated protocol : h2
  ✓ HTTP/2 (h2) negotiated via ALPN

[*] Sending HTTP/2 client preface ...
  ✓ Preface + SETTINGS sent

[*] Waiting for server SETTINGS ...
  ← Frame type=0x04 stream=0 length=18
  ✓ Server SETTINGS received
  ✓ Sent SETTINGS ACK

[*] Opening HTTP/2 stream 1 (HEADERS frame) ...
  ✓ HEADERS sent on stream 1

[*] Sending malformed WINDOW_UPDATE (increment=0) on stream 1 ...
    RFC 9113 §6.9.1: increment=0 is a stream-level FLOW_CONTROL_ERROR
  ✓ Malformed WINDOW_UPDATE sent

[*] Analysing server response (timeout=8.0s) ...
  ← RST_STREAM  stream=1  error_code=0x00000003

────────────────────────────────────────────────────────
  RESULT
────────────────────────────────────────────────────────
  [LIKELY VULNERABLE]
  Server responded with RST_STREAM on stream 1
  (error_code=0x00000003) but did NOT send GOAWAY.

  Recommended actions:
  • Patch: Apache Tomcat ≥10.1.44/11.0.10/9.0.108,
           Netty ≥4.1.124.Final / 4.2.4.Final,
           and other vendor advisories for CVE-2025-8671.
  • Interim: disable HTTP/2 or deploy a WAF/proxy that
             validates HTTP/2 frames before forwarding.
========================================================
```

---

## Remediation

| Action | Details |
|---|---|
| **Patch** | Apply the latest vendor update for your HTTP/2 stack (see table above) |
| **Disable HTTP/2** | Fall back to HTTP/1.1 as a temporary mitigation |
| **WAF / Proxy** | Deploy a reverse proxy or WAF that validates HTTP/2 frames at the edge |
| **Rate limiting** | Enforce per-client connection caps and RST_STREAM rate limits |

---

## Disclaimer

> This tool is intended for **authorized security testing and research only**.  
> Do **not** run this script against systems you do not own or have explicit written permission to test.  
> The authors accept no liability for misuse.

---

## References

- [CERT/CC VU#767506](https://kb.cert.org/vuls/id/767506)
- [Netty Security Advisory — GHSA-prj3-ccx8-p6x4](https://github.com/netty/netty/security/advisories/GHSA-prj3-ccx8-p6x4)
- [Jetty Security Advisory — GHSA-mmxm-8w33-wc4h](https://github.com/jetty/jetty.project/security/advisories/GHSA-mmxm-8w33-wc4h)
- [NVD — CVE-2025-8671](https://nvd.nist.gov/vuln/detail/CVE-2025-8671)
- [RFC 9113 — HTTP/2 §6.9.1 Flow Control](https://www.rfc-editor.org/rfc/rfc9113#section-6.9.1)