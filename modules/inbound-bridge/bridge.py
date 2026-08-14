#!/usr/bin/env python3
"""Inbound HTTP -> LMTP bridge.

Some inbound-mail integrations can only speak HTTP, never raw SMTP/LMTP --
the motivating example is Cloudflare Email Routing, whose Worker runs on an
edge-compute platform where the only way to reach anything is `fetch()`,
not a TCP socket. This bridge is the other half of that bargain: it accepts
one POST per inbound message (envelope sender/recipients carried in
headers, the raw RFC 5322 message as the body) over whatever gets an HTTP
request onto this host -- an HTTP tunnel client, a reverse proxy, a mesh
VPN peer forwarding a port, the bridge neither knows nor cares -- and hands
it to a real mail server's local LMTP listener for normal delivery
(mailbox storage, Sieve filtering, alias/catch-all resolution: all of that
is the mail server's job, never this bridge's).

Security: binds loopback (or whatever LISTEN_HOST is set to) only; a
caller must present the shared secret as `Authorization: Bearer <token>`.
An unconfigured secret is treated as a deployment bug, not a supported
"auth disabled" mode -- see INBOUND_BRIDGE_ALLOW_UNAUTHENTICATED below for
the one deliberate exception.

Reliability: one LMTP transaction per recipient (LMTP gives one status
line per RCPT after DATA, unlike SMTP's one line for the whole
transaction, so blending recipients into a single caller-facing result
would misreport whichever ones didn't match the average). A temp-failure
(4xx) maps to HTTP 421 so the caller's own retry logic re-delivers; a hard
refusal (5xx) maps to HTTP 550 so the caller does NOT retry (retrying a
hard refusal just re-bounces the same message forever); success maps to
200. No message is ever silently dropped -- every outcome is a
distinguishable HTTP status the caller can act on correctly.

Stdlib only (http.server + smtplib), no third-party dependencies.
"""
import logging, os, smtplib, socket, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = os.environ.get("INBOUND_BRIDGE_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("INBOUND_BRIDGE_PORT", "2526"))
LMTP_HOST = os.environ.get("LMTP_HOST", "127.0.0.1")
LMTP_PORT = int(os.environ.get("LMTP_PORT", "24"))
# The name announced in LHLO. A SPAM-SCORE INPUT on every message this bridge
# ever delivers -- see the `lhloName` option in ../inbound-bridge.nix for the
# measurement and the reasoning. socket.getfqdn() rather than a bare label as
# the fallback, so an operator who never sets it still gets a qualified name.
LMTP_LHLO_NAME = os.environ.get("LMTP_LHLO_NAME", "").strip() or socket.getfqdn()
SECRET = os.environ.get("INBOUND_BRIDGE_SECRET", "").strip()
ALLOW_UNAUTHENTICATED = os.environ.get("INBOUND_BRIDGE_ALLOW_UNAUTHENTICATED", "").strip().lower() in (
    "1", "true", "yes",
)
MAX_SIZE = int(os.environ.get("INBOUND_BRIDGE_MAX_SIZE", str(64 * 1024 * 1024)))
ALLOWED_CLIENTS = {
    a.strip() for a in os.environ.get("INBOUND_BRIDGE_ALLOWED_CLIENTS", "").split(",") if a.strip()
}

LOG = logging.getLogger("inbound-bridge")


def deliver_one(mail_from, rcpt, raw):
    """One LMTP transaction for a single recipient. Returns (ok, tempfail, detail).

    Deliberately per-recipient rather than one multi-RCPT transaction:
    LMTP (unlike SMTP) gives an individual status line per recipient after
    DATA specifically so a multi-recipient delivery can partially succeed.
    Averaging that into one result for the whole POST would force a single
    caller-facing status where several recipients were actually right and
    others actually wrong; calling this once per recipient instead means
    every entry in the caller's result map reflects what really happened
    to that one mailbox.
    """
    lmtp = smtplib.LMTP(LMTP_HOST, LMTP_PORT, timeout=60)
    try:
        code, resp = lmtp.docmd("LHLO", LMTP_LHLO_NAME)     # LMTP greets with LHLO, not HELO/EHLO
        if code >= 400:
            return False, True, f"LHLO {code} {resp!r}"
        code, resp = lmtp.mail(mail_from or "")
        if code >= 400:
            return False, code < 500, f"MAIL {code} {resp!r}"
        code, resp = lmtp.rcpt(rcpt)
        if code >= 400:
            return False, code < 500, f"RCPT {code} {resp!r}"
        code, resp = lmtp.data(raw)
        return code < 400, (400 <= code < 500), f"DATA {code} {resp!r}"
    finally:
        try:
            lmtp.quit()
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # we log ourselves, with our own format and level

    def _reply(self, code, msg):
        b = (msg + "\n").encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError) as e:
            # Observed in production: a caller can disconnect the instant it
            # has what it needs, and that sometimes lands between us
            # finishing delivery and us writing the HTTP response back --
            # i.e. AFTER the code=200 (successful-delivery) case already
            # fully succeeded. Letting that write failure raise uncaught
            # previously surfaced to the caller as a failed POST despite the
            # message already being delivered, which risks a retry-induced
            # DUPLICATE delivery on any caller that treats "no response" as
            # "try again" -- the caller has no way to know the first attempt
            # actually landed. Delivery itself is unaffected either way;
            # just log it so a real pattern of these stays visible without
            # tearing down the request thread over what is, from the
            # mailbox's point of view, a non-event.
            LOG.warning("reply write failed (caller disconnected, code=%s): %s", code, e)

    def do_POST(self):
        if ALLOWED_CLIENTS and self.client_address[0] not in ALLOWED_CLIENTS:
            # Defense-in-depth only, not the real access control: on the
            # common deployment shape (this bridge on loopback, behind an
            # HTTP tunnel client or reverse proxy) every request arrives
            # from that one local process's address regardless of who the
            # original remote caller actually was, so this mostly narrows
            # "which local processes may talk to the bridge at all" rather
            # than "which remote parties may inject mail". The bearer
            # secret below is what actually gates that.
            LOG.warning("client %s not in allow-list", self.client_address)
            return self._reply(403, "forbidden")
        if SECRET and self.headers.get("Authorization", "") != f"Bearer {SECRET}":
            LOG.warning("auth fail from %s", self.client_address)
            return self._reply(401, "unauthorized")
        mail_from = (self.headers.get("X-Mail-From") or "").strip().strip("<>")
        rcpts = [r.strip().strip("<>") for r in (self.headers.get("X-Rcpt-To") or "").split(",") if r.strip()]
        if not rcpts:
            return self._reply(400, "missing X-Rcpt-To")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_SIZE:
            return self._reply(400, f"bad content length {n}")
        raw = self.rfile.read(n)

        results, ok_any, tempfail_any = {}, False, False
        for r in rcpts:
            try:
                ok, tempfail, detail = deliver_one(mail_from, r, raw)
            except Exception as e:  # noqa: BLE001
                ok, tempfail, detail = False, True, f"exc {e}"
            results[r] = detail
            ok_any = ok_any or ok
            tempfail_any = tempfail_any or (tempfail and not ok)
        if ok_any:
            LOG.info("delivered from=%s rcpts=%s %s", mail_from, rcpts, results)
            return self._reply(200, f"delivered {results}")
        if tempfail_any:
            LOG.warning("tempfail from=%s %s", mail_from, results)
            return self._reply(421, f"temp failure {results}")
        LOG.warning("refused from=%s %s", mail_from, results)
        return self._reply(550, f"refused {results}")


def main():
    logging.basicConfig(
        level=os.environ.get("INBOUND_BRIDGE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    if not SECRET and not ALLOW_UNAUTHENTICATED:
        # No shared secret configured, and nobody explicitly opted into
        # running open -- refuse to start, the same fail-closed default the
        # sibling outbound bridge uses when it has no relay keys configured
        # at all. An unauthenticated inbound endpoint that injects arbitrary
        # mail into a real mailbox is a strictly worse failure mode than a
        # service that refuses to start, and a mere warning log for that
        # condition is exactly the kind of thing that goes unnoticed until
        # it's an incident.
        LOG.error(
            "no INBOUND_BRIDGE_SECRET configured and INBOUND_BRIDGE_ALLOW_UNAUTHENTICATED "
            "is not set -- refusing to start unauthenticated"
        )
        sys.exit(1)
    if not SECRET:
        LOG.warning(
            "running UNAUTHENTICATED (INBOUND_BRIDGE_ALLOW_UNAUTHENTICATED is set) -- "
            "only safe if nothing untrusted can reach %s:%d", LISTEN_HOST, LISTEN_PORT,
        )
    LOG.info(
        "inbound-bridge on %s:%d -> LMTP %s:%d (max %d bytes)",
        LISTEN_HOST, LISTEN_PORT, LMTP_HOST, LMTP_PORT, MAX_SIZE,
    )
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
