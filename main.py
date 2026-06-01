#!/usr/bin/env python3
"""
MadeYouReset (CVE-2025-8671) Vulnerability Checker
====================================================
Checks whether a target URL's HTTP/2 server is potentially vulnerable to the
MadeYouReset DoS attack by probing its response to a deliberately malformed
WINDOW_UPDATE control frame on an open stream.

How it works:
  1. Perform a TLS handshake negotiating HTTP/2 (h2) via ALPN.
  2. Send the HTTP/2 client preface + SETTINGS frame.
  3. Open a new request stream (HEADERS frame).
  4. Send a malformed WINDOW_UPDATE frame (increment = 0, which is illegal per RFC 9113 §6.9.1).
  5. A vulnerable server will issue a RST_STREAM for the stream (treating it as
     a stream error) while continuing to process the request in the background
     — the accounting mismatch at the heart of MadeYouReset.
  6. A patched / correct server will either close the whole connection with a
     GOAWAY (connection error) or send no RST_STREAM at all.

Disclaimer:
  This script is for authorized security testing and research ONLY.
  Do NOT run it against systems you do not own or have explicit permission to test.

Usage:
  python3 madeyoureset_check.py <url> [--timeout SECONDS] [--no-color]

Examples:
  python3 madeyoureset_check.py https://example.com
  python3 madeyoureset_check.py https://example.com:8443 --timeout 10
"""

import argparse
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from typing import Optional

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def c(text: str, colour: str, use_colour: bool) -> str:
    return f"{colour}{text}{RESET}" if use_colour else text


# ── HTTP/2 frame helpers ───────────────────────────────────────────────────────
# Frame format: 3-byte length | 1-byte type | 1-byte flags | 4-byte stream-id
FRAME_SETTINGS       = 0x4
FRAME_HEADERS        = 0x1
FRAME_WINDOW_UPDATE  = 0x8
FRAME_RST_STREAM     = 0x3
FRAME_GOAWAY         = 0x7
FRAME_PING           = 0x6

HTTP2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def build_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    header = struct.pack(">I", length)[1:]          # 3-byte big-endian length
    header += struct.pack("BB", frame_type, flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def build_settings_frame() -> bytes:
    """Empty SETTINGS (acknowledge server settings or send defaults)."""
    return build_frame(FRAME_SETTINGS, 0x0, 0, b"")


def build_settings_ack() -> bytes:
    return build_frame(FRAME_SETTINGS, 0x1, 0, b"")


def build_headers_frame(host: str, path: str, stream_id: int) -> bytes:
    """
    Minimal HPACK-encoded HEADERS for a GET request.
    Uses literal header field without indexing (no Huffman) for simplicity.
    """
    def literal_header(name: bytes, value: bytes) -> bytes:
        # 0x00 = literal without indexing, new name
        return (bytes([0x00]) +
                bytes([len(name)]) + name +
                bytes([len(value)]) + value)

    # Use indexed representations for common pseudo-headers where possible.
    # :method GET  -> index 2
    # :scheme https -> index 7
    # :path /      -> index 5 (if path == "/") else literal
    hpack = bytes([0x82])  # :method GET  (index 2)
    hpack += bytes([0x87]) # :scheme https (index 7)
    if path == "/":
        hpack += bytes([0x85])  # :path / (index 5)
    else:
        hpack += literal_header(b":path", path.encode())
    hpack += literal_header(b":authority", host.encode())
    hpack += literal_header(b"user-agent", b"MadeYouReset-Checker/1.0")

    # END_HEADERS (0x4) flag; END_STREAM not set — we want the stream open
    return build_frame(FRAME_HEADERS, 0x4, stream_id, hpack)


def build_malformed_window_update(stream_id: int) -> bytes:
    """
    RFC 9113 §6.9.1: a WINDOW_UPDATE with increment=0 on a stream MUST be
    treated as a stream error of type FLOW_CONTROL_ERROR.  A vulnerable server
    responds with RST_STREAM (stream error) and keeps processing; a correct
    server may send GOAWAY (connection error).
    """
    payload = struct.pack(">I", 0)  # increment = 0  ← illegal
    return build_frame(FRAME_WINDOW_UPDATE, 0x0, stream_id, payload)


def parse_frame(data: bytes, offset: int):
    """Parse one HTTP/2 frame from `data` at `offset`. Returns (frame_dict, next_offset)."""
    if offset + 9 > len(data):
        return None, offset
    length = struct.unpack(">I", b"\x00" + data[offset:offset+3])[0]
    frame_type  = data[offset + 3]
    flags       = data[offset + 4]
    stream_id   = struct.unpack(">I", data[offset+5:offset+9])[0] & 0x7FFFFFFF
    end         = offset + 9 + length
    if end > len(data):
        return None, offset   # incomplete frame
    payload = data[offset+9:end]
    return {"type": frame_type, "flags": flags, "stream_id": stream_id,
            "payload": payload, "length": length}, end


# ── Main checker ───────────────────────────────────────────────────────────────
def check(url: str, timeout: float, use_colour: bool) -> int:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    host   = parsed.hostname or ""
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if scheme not in ("https", "http"):
        print(c(f"[!] Unsupported scheme '{scheme}'. Use https:// or http://.", RED, use_colour))
        return 2

    port = parsed.port or (443 if scheme == "https" else 80)

    banner = f"MadeYouReset (CVE-2025-8671) Checker"
    print(c("=" * 56, DIM, use_colour))
    print(c(f"  {banner}", BOLD, use_colour))
    print(c("=" * 56, DIM, use_colour))
    print(f"  Target  : {c(url, CYAN, use_colour)}")
    print(f"  Host    : {host}:{port}")
    print(f"  Path    : {path}")
    print(f"  Timeout : {timeout}s")
    print(c("─" * 56, DIM, use_colour))

    # ── Step 1: TCP connect ──────────────────────────────────────────────────
    print(f"\n[*] Connecting to {host}:{port} ...")
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(c("  ✓ TCP connection established", GREEN, use_colour))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(c(f"  ✗ TCP connection failed: {e}", RED, use_colour))
        return 2

    # ── Step 2: TLS + ALPN negotiation ──────────────────────────────────────
    h2_negotiated = False
    sock: socket.socket = raw_sock

    if scheme == "https":
        print(f"\n[*] Performing TLS handshake (ALPN: h2, http/1.1) ...")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        except ssl.SSLError as e:
            print(c(f"  ✗ TLS handshake failed: {e}", RED, use_colour))
            raw_sock.close()
            return 2

        negotiated = tls_sock.selected_alpn_protocol()
        print(f"  → Negotiated protocol : {c(str(negotiated), CYAN, use_colour)}")
        if negotiated == "h2":
            h2_negotiated = True
            print(c("  ✓ HTTP/2 (h2) negotiated via ALPN", GREEN, use_colour))
        elif negotiated in ("http/1.1", None):
            print(c("  ✗ Server did not negotiate HTTP/2 via ALPN.", YELLOW, use_colour))
            print(c("  → Server is NOT vulnerable (no HTTP/2 support detected).", GREEN, use_colour))
            tls_sock.close()
            return 0
        sock = tls_sock
    else:
        print(c("\n[!] HTTP (plaintext) detected. Attempting HTTP/2 upgrade (h2c) ...", YELLOW, use_colour))
        print(c("    Note: Most modern servers require TLS for HTTP/2.", DIM, use_colour))
        h2_negotiated = True  # assume h2c; we'll know quickly if it fails

    # ── Step 3: Send HTTP/2 client preface + SETTINGS ───────────────────────
    print(f"\n[*] Sending HTTP/2 client preface ...")
    stream_id = 1

    try:
        sock.sendall(HTTP2_CLIENT_PREFACE)
        sock.sendall(build_settings_frame())
        print(c("  ✓ Preface + SETTINGS sent", GREEN, use_colour))
    except OSError as e:
        print(c(f"  ✗ Send error: {e}", RED, use_colour))
        sock.close()
        return 2

    # ── Step 4: Read server SETTINGS ────────────────────────────────────────
    print(f"\n[*] Waiting for server SETTINGS ...")
    buf = b""
    deadline = time.time() + timeout
    got_server_settings = False

    while time.time() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.time()))
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except (socket.timeout, ssl.SSLError):
            break

        offset = 0
        while True:
            frame, new_offset = parse_frame(buf, offset)
            if frame is None:
                break
            offset = new_offset
            ft = frame["type"]
            sid = frame["stream_id"]
            print(c(f"  ← Frame type=0x{ft:02x} stream={sid} length={frame['length']}", DIM, use_colour))
            if ft == FRAME_SETTINGS and not (frame["flags"] & 0x1):
                got_server_settings = True
                print(c("  ✓ Server SETTINGS received", GREEN, use_colour))
        buf = buf[offset:]

        if got_server_settings:
            break

    if not got_server_settings:
        print(c("  ✗ No SETTINGS frame received — server may not speak HTTP/2.", YELLOW, use_colour))
        sock.close()
        return 2

    # ACK the server's SETTINGS
    try:
        sock.sendall(build_settings_ack())
        print(c("  ✓ Sent SETTINGS ACK", GREEN, use_colour))
    except OSError as e:
        print(c(f"  ✗ Send error: {e}", RED, use_colour))
        sock.close()
        return 2

    # ── Step 5: Open a request stream ───────────────────────────────────────
    print(f"\n[*] Opening HTTP/2 stream {stream_id} (HEADERS frame) ...")
    try:
        sock.sendall(build_headers_frame(host, path, stream_id))
        print(c(f"  ✓ HEADERS sent on stream {stream_id}", GREEN, use_colour))
    except OSError as e:
        print(c(f"  ✗ Send error: {e}", RED, use_colour))
        sock.close()
        return 2

    # ── Step 6: Send malformed WINDOW_UPDATE (increment=0) ──────────────────
    print(f"\n[*] Sending malformed WINDOW_UPDATE (increment=0) on stream {stream_id} ...")
    print(c(f"    RFC 9113 §6.9.1: increment=0 is a stream-level FLOW_CONTROL_ERROR", DIM, use_colour))
    try:
        sock.sendall(build_malformed_window_update(stream_id))
        print(c("  ✓ Malformed WINDOW_UPDATE sent", GREEN, use_colour))
    except OSError as e:
        print(c(f"  ✗ Send error: {e}", RED, use_colour))
        sock.close()
        return 2

    # ── Step 7: Analyse server response ─────────────────────────────────────
    print(f"\n[*] Analysing server response (timeout={timeout}s) ...")
    buf = b""
    deadline = time.time() + timeout
    rst_stream_received  = False
    goaway_received      = False
    rst_on_our_stream    = False
    goaway_error_code: Optional[int] = None
    rst_error_code: Optional[int]    = None

    FLOW_CONTROL_ERROR = 0x3

    while time.time() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.time()))
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
        except (socket.timeout, ssl.SSLError):
            break

        offset = 0
        while True:
            frame, new_offset = parse_frame(buf, offset)
            if frame is None:
                break
            offset = new_offset
            ft  = frame["type"]
            sid = frame["stream_id"]
            pl  = frame["payload"]

            if ft == FRAME_RST_STREAM and len(pl) >= 4:
                error_code = struct.unpack(">I", pl[:4])[0]
                rst_stream_received = True
                if sid == stream_id:
                    rst_on_our_stream = True
                    rst_error_code = error_code
                print(c(f"  ← RST_STREAM  stream={sid}  error_code=0x{error_code:08x}", YELLOW, use_colour))

            elif ft == FRAME_GOAWAY and len(pl) >= 8:
                last_stream = struct.unpack(">I", pl[:4])[0] & 0x7FFFFFFF
                error_code  = struct.unpack(">I", pl[4:8])[0]
                goaway_received     = True
                goaway_error_code   = error_code
                print(c(f"  ← GOAWAY      last_stream={last_stream}  error_code=0x{error_code:08x}", YELLOW, use_colour))

            elif ft == FRAME_SETTINGS:
                print(c(f"  ← SETTINGS    stream={sid}", DIM, use_colour))
            elif ft == FRAME_PING:
                print(c(f"  ← PING        stream={sid}", DIM, use_colour))
            else:
                print(c(f"  ← Frame       type=0x{ft:02x} stream={sid} length={frame['length']}", DIM, use_colour))

        buf = buf[offset:]

    sock.close()

    # ── Step 8: Verdict ───────────────────────────────────────────────────────
    print(c("\n" + "─" * 56, DIM, use_colour))
    print(c("  RESULT", BOLD, use_colour))
    print(c("─" * 56, DIM, use_colour))

    if rst_on_our_stream and not goaway_received:
        print(c(f"  [LIKELY VULNERABLE]", RED + BOLD, use_colour))
        print(f"  Server responded with RST_STREAM on stream {stream_id}")
        print(f"  (error_code=0x{rst_error_code:08x}) but did NOT send GOAWAY.")
        print()
        print(f"  This behaviour matches CVE-2025-8671 (MadeYouReset):")
        print(f"  the server treated the malformed WINDOW_UPDATE as a stream")
        print(f"  error, freeing the stream at the protocol level while likely")
        print(f"  continuing to process the request in the backend — allowing")
        print(f"  an attacker to bypass MAX_CONCURRENT_STREAMS limits.")
        print()
        print(c("  Recommended actions:", BOLD, use_colour))
        print("  • Patch: Apache Tomcat ≥10.1.44/11.0.10/9.0.108,")
        print("           Netty ≥4.1.124.Final / 4.2.4.Final,")
        print("           and other vendor advisories for CVE-2025-8671.")
        print("  • Interim: disable HTTP/2 or deploy a WAF/proxy that")
        print("             validates HTTP/2 frames before forwarding.")
        result = 1

    elif goaway_received:
        print(c("  [LIKELY NOT VULNERABLE]", GREEN + BOLD, use_colour))
        print(f"  Server responded with GOAWAY (error_code=0x{goaway_error_code:08x}).")
        print(f"  This indicates a connection-level error response, which is the")
        print(f"  correct RFC behaviour for a FLOW_CONTROL_ERROR. A patched server")
        print(f"  terminates the entire connection rather than silently resetting")
        print(f"  just the stream.")
        result = 0

    elif rst_stream_received and not rst_on_our_stream:
        print(c("  [INCONCLUSIVE]", YELLOW + BOLD, use_colour))
        print(f"  RST_STREAM received but on a different stream (not stream {stream_id}).")
        print(f"  Manual inspection recommended.")
        result = 2

    else:
        print(c("  [INCONCLUSIVE]", YELLOW + BOLD, use_colour))
        print(f"  No RST_STREAM or GOAWAY received within {timeout}s.")
        print(f"  Possible explanations:")
        print(f"  • Server silently dropped the malformed frame.")
        print(f"  • Connection closed before we could read the response.")
        print(f"  • Firewall / load balancer absorbed the frame.")
        print(f"  Try increasing --timeout or testing from a different network.")
        result = 2

    print(c("\n" + "=" * 56, DIM, use_colour))
    print(c(f"  CVE Reference : CVE-2025-8671 (MadeYouReset)", DIM, use_colour))
    print(c(f"  CVSS Score    : 7.5 (High)", DIM, use_colour))
    print(c(f"  Affected      : Apache Tomcat, Netty, F5 BIG-IP, Varnish,", DIM, use_colour))
    print(c(f"                  Fastly, IBM WebSphere Liberty, Jetty, ...", DIM, use_colour))
    print(c("=" * 56 + "\n", DIM, use_colour))
    return result


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="MadeYouReset (CVE-2025-8671) HTTP/2 vulnerability checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="Socket timeout in seconds (default: 8)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour output")
    args = parser.parse_args()

    use_colour = not args.no_color and sys.stdout.isatty()
    try:
        sys.exit(check(args.url, args.timeout, use_colour))
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()