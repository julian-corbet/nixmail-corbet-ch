#!/usr/bin/env python3
"""
SMTP -> HTTP-API outbound mail bridge.

Why this exists: many small self-hosted mail servers run on a host that
cannot reach a transactional-email provider's SMTP submission endpoint
directly -- most commonly an IPv6-only host talking to a provider whose
SMTP submission host has no AAAA record, but the same shape applies to
any environment where outbound SMTP is blocked or otherwise unusable.
Providers overwhelmingly still expose an HTTPS API, and HTTPS usually
works wherever plain SMTP does not. A mail server can only relay to a
"smarthost" over SMTP, though -- it has no notion of an HTTP-API
transport -- so this bridge sits in between: it listens for ordinary SMTP
from your own mail server, parses each message into a transport-neutral
form, and re-sends it through one of several providers' HTTP APIs, trying
each in turn until one accepts it (a failover chain -- see build_chain()
and the module's relayChain option). Whichever provider ends up sending
the message re-signs DKIM using its own, relay-verified view of the
sending domain, so DMARC still aligns via DKIM as long as your sending
domain is verified with that provider.

Security -- read this before deploying: this listener has NO
authentication of its own. SMTP has none built in, and this bridge does
not implement SMTP AUTH or STARTTLS. The only access control is
BRIDGE_ALLOWED_CLIENTS (default: loopback only), checked against the
connecting client's source address, plus whatever address you actually
bind (BRIDGE_HOST). Treat both as load-bearing: this bridge holds the
only credentials that can spend a paid provider account's sending quota,
and a listener with no source check at all is an open relay against that
account for anyone who can reach the socket. See the module's own
`bindHost`/`allowedClients` option docs for the incident this exists to
prevent.

Reliability: on total relay failure this returns an SMTP 4xx (temporary
failure), which tells a well-behaved MTA to keep the message queued and
retry later rather than bounce it. No message is ever silently dropped by
this bridge -- it is either handed to exactly one relay successfully, or
the calling MTA is told to try again. The chain-walking loop below
returns on the first success, which is what actually gives "at most one
relay per message" -- there is no separate lock or idempotency key
enforcing it structurally, so preserve that early-return if you ever
modify the loop.
"""
import asyncio
import base64
import ipaddress
import threading
import email
import logging
import os
import re
import sys
from email import policy
from email.utils import getaddresses, parseaddr

import httpx
from aiosmtpd.controller import Controller

LOG = logging.getLogger("mail-bridge")

# Loopback by default, deliberately. A previous, unpublished version of
# this exact script defaulted this to 0.0.0.0 -- meaning an operator who
# simply forgot to set BRIDGE_HOST got an open relay by default rather
# than a safe one. A security-relevant default must fail closed; only an
# operator who explicitly widens BRIDGE_HOST (and, just as importantly,
# BRIDGE_ALLOWED_CLIENTS below) can end up with a wider-than-loopback
# listener.
LISTEN_HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("BRIDGE_PORT", "2525"))
HTTP_TIMEOUT = float(os.environ.get("BRIDGE_HTTP_TIMEOUT", "30"))

# aiosmtpd has no message-size cap of its own by default, and the whole
# message is buffered in memory before handle_DATA ever runs -- without an
# explicit limit, one oversized (or malicious) message can push memory
# usage arbitrarily high. 25 MiB comfortably covers ordinary transactional
# mail (including a modest attachment, which this bridge base64-encodes
# in-memory -- see parse_message()) while still bounding worst case.
MAX_MESSAGE_SIZE = int(os.environ.get("BRIDGE_MAX_MESSAGE_SIZE", str(25 * 1024 * 1024)))

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "").strip()
MAILERSEND_API_KEY = os.environ.get("MAILERSEND_API_KEY", "").strip()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
SMTP2GO_API_KEY = os.environ.get("SMTP2GO_API_KEY", "").strip()
POSTMARK_API_KEY = os.environ.get("POSTMARK_API_KEY", "").strip()

# SMTP2GO's and Postmark's APIs are IPv4-only (no AAAA record). On an
# IPv6-only host, reach them anyway by resolving the API host's IPv4
# address through a public NAT64/DNS64 resolver and connecting to the
# synthesized IPv6 address instead -- keeping SNI and the Host header set
# to the real hostname so TLS certificate validation still passes (see
# _nat64_aaaa() and its two callers). The three defaults below are public
# anycast NAT64 resolvers (see nat64.net); override them if you run your
# own DNS64 service or these ever change ownership/routing. Any other
# provider whose API turns out to be IPv4-only needs the exact same
# treatment -- send_smtp2go()/send_postmark() are the pattern to copy.
NAT64_RESOLVERS = [
    r.strip()
    for r in os.environ.get(
        "BRIDGE_NAT64_RESOLVERS",
        "2a00:1098:2c::1,2a00:1098:2b::1,2a01:4f8:c2c:123f::1",
    ).split(",")
    if r.strip()
]


# --------------------------------------------------------------------------
# Source-client allowlist -- see the module docstring above. This is the
# ONE thing standing between "trusted internal relay" and "open relay
# against paid provider accounts"; there is no other authentication layer.
# --------------------------------------------------------------------------
def _parse_allowed_clients(raw: str):
    """Parse BRIDGE_ALLOWED_CLIENTS into a list of ip_network objects.

    Empty/unset means "loopback only" -- NOT "everyone". Accepts
    individual addresses (coerced to a /32 or /128) and CIDR ranges,
    comma-separated, e.g. "10.0.0.0/24,192.0.2.5,2001:db8::/32".
    """
    raw = (raw or "").strip()
    if not raw:
        return [ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128")]
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        nets.append(ipaddress.ip_network(part, strict=False))
    return nets


ALLOWED_CLIENT_NETS = _parse_allowed_clients(os.environ.get("BRIDGE_ALLOWED_CLIENTS", ""))


def _client_allowed(addr) -> bool:
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_CLIENT_NETS)


# --------------------------------------------------------------------------
# MIME -> neutral dict
# --------------------------------------------------------------------------
def _addrs(value):
    """Return [{'email':..,'name':..}] from a header value (or empty list)."""
    out = []
    for name, addr in getaddresses([value or ""]):
        if addr:
            out.append({"email": addr, "name": name or ""})
    return out


def parse_message(raw: bytes, envelope):
    """Parse the raw RFC822 message into a relay-neutral dict.

    Recipients come from the SMTP ENVELOPE (authoritative — includes Bcc), not
    from the To header. Sender, subject and bodies come from the message.
    """
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_name, from_email = parseaddr(msg.get("From", "") or envelope.mail_from or "")
    reply_to = None
    rt = _addrs(msg.get("Reply-To"))
    if rt:
        reply_to = rt[0]

    text_body = None
    html_body = None
    attachments = []
    try:
        body = msg.get_body(preferencelist=("plain",))
        if body is not None:
            text_body = body.get_content()
    except Exception:  # noqa: BLE001 - best effort
        pass
    try:
        body = msg.get_body(preferencelist=("html",))
        if body is not None:
            html_body = body.get_content()
    except Exception:  # noqa: BLE001
        pass

    for part in msg.iter_attachments():
        try:
            payload = part.get_content()
            if isinstance(payload, str):
                payload = payload.encode("utf-8", "replace")
            attachments.append(
                {
                    "filename": part.get_filename() or "attachment",
                    "content_type": part.get_content_type(),
                    "content_b64": base64.b64encode(payload).decode("ascii"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("skipping unparseable attachment: %s", exc)

    if not text_body and not html_body:
        # Fallback so the relay never rejects an empty body.
        text_body = msg.get_content() if not msg.is_multipart() else "(no text body)"

    return {
        "from_email": from_email,
        "from_name": from_name or "",
        # Deliver to the envelope recipients (authoritative).
        "rcpts": list(dict.fromkeys(envelope.rcpt_tos)),
        "reply_to": reply_to,
        "subject": msg.get("Subject", "") or "",
        "text": text_body,
        "html": html_body,
        "attachments": attachments,
        "message_id": msg.get("Message-ID", ""),
    }


# --------------------------------------------------------------------------
# Per-relay senders (each returns (ok: bool, detail: str))
# --------------------------------------------------------------------------
async def send_brevo(client: httpx.AsyncClient, m: dict):
    body = {
        "sender": {"email": m["from_email"], "name": m["from_name"] or m["from_email"]},
        "to": [{"email": r} for r in m["rcpts"]],
        "subject": m["subject"],
    }
    if m["html"]:
        body["htmlContent"] = m["html"]
    if m["text"]:
        body["textContent"] = m["text"]
    if m["reply_to"]:
        body["replyTo"] = {"email": m["reply_to"]["email"]}
    if m["attachments"]:
        body["attachment"] = [
            {"name": a["filename"], "content": a["content_b64"]} for a in m["attachments"]
        ]
    r = await client.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={"api-key": BREVO_API_KEY, "accept": "application/json"},
        json=body,
    )
    return (r.status_code in (200, 201), f"brevo {r.status_code}: {r.text[:200]}")


async def send_mailersend(client: httpx.AsyncClient, m: dict):
    body = {
        "from": {"email": m["from_email"], "name": m["from_name"] or m["from_email"]},
        "to": [{"email": r} for r in m["rcpts"]],
        "subject": m["subject"],
    }
    if m["text"]:
        body["text"] = m["text"]
    if m["html"]:
        body["html"] = m["html"]
    if m["reply_to"]:
        body["reply_to"] = {"email": m["reply_to"]["email"]}
    if m["attachments"]:
        body["attachments"] = [
            {"content": a["content_b64"], "filename": a["filename"], "disposition": "attachment"}
            for a in m["attachments"]
        ]
    r = await client.post(
        "https://api.mailersend.com/v1/email",
        headers={"Authorization": f"Bearer {MAILERSEND_API_KEY}"},
        json=body,
    )
    return (r.status_code in (200, 202), f"mailersend {r.status_code}: {r.text[:200]}")


async def send_resend(client: httpx.AsyncClient, m: dict):
    frm = f"{m['from_name']} <{m['from_email']}>" if m["from_name"] else m["from_email"]
    body = {"from": frm, "to": m["rcpts"], "subject": m["subject"]}
    if m["text"]:
        body["text"] = m["text"]
    if m["html"]:
        body["html"] = m["html"]
    if m["reply_to"]:
        body["reply_to"] = m["reply_to"]["email"]
    if m["attachments"]:
        body["attachments"] = [
            {"filename": a["filename"], "content": a["content_b64"]} for a in m["attachments"]
        ]
    r = await client.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
        json=body,
    )
    return (r.status_code in (200, 201), f"resend {r.status_code}: {r.text[:200]}")


async def _nat64_aaaa(host: str) -> str:
    """Resolve host's IPv4 to a NAT64-synthesized IPv6 via a public DNS64 resolver."""
    import dns.asyncresolver  # lazy: keeps the dep off bridge startup / the hot path

    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = NAT64_RESOLVERS
    res.lifetime = 8.0
    answer = await res.resolve(host, "AAAA")
    return str(answer[0])


async def send_smtp2go(client: httpx.AsyncClient, m: dict):
    host = "api.smtp2go.com"
    ipv6 = await _nat64_aaaa(host)  # IPv4-only API reached over IPv6 via NAT64
    body = {
        "sender": f"{m['from_name']} <{m['from_email']}>" if m["from_name"] else m["from_email"],
        "to": list(m["rcpts"]),
        "subject": m["subject"],
    }
    if m["text"]:
        body["text_body"] = m["text"]
    if m["html"]:
        body["html_body"] = m["html"]
    if m["reply_to"]:
        body["custom_headers"] = [{"header": "Reply-To", "value": m["reply_to"]["email"]}]
    if m["attachments"]:
        body["attachments"] = [
            {"filename": a["filename"], "fileblob": a["content_b64"], "mimetype": a["content_type"]}
            for a in m["attachments"]
        ]
    # Connect to the synthesized IPv6 literal but keep SNI + Host = the real name.
    r = await client.post(
        f"https://[{ipv6}]/v3/email/send",
        headers={"X-Smtp2go-Api-Key": SMTP2GO_API_KEY, "Host": host, "Accept": "application/json"},
        json=body,
        extensions={"sni_hostname": host},
    )
    try:
        ok = r.status_code == 200 and r.json().get("data", {}).get("succeeded", 0) >= 1
    except Exception:  # noqa: BLE001
        ok = False
    return (ok, f"smtp2go {r.status_code}: {r.text[:200]}")


async def send_postmark(client: httpx.AsyncClient, m: dict):
    # Postmark's API is IPv4-only (no AAAA), same as SMTP2GO — reach it over IPv6
    # through public NAT64, keeping SNI + Host = the real name so TLS validates.
    host = "api.postmarkapp.com"
    ipv6 = await _nat64_aaaa(host)
    frm = f"{m['from_name']} <{m['from_email']}>" if m["from_name"] else m["from_email"]
    body = {
        "From": frm,
        "To": ",".join(m["rcpts"]),
        "Subject": m["subject"],
        "MessageStream": "outbound",
    }
    if m["text"]:
        body["TextBody"] = m["text"]
    if m["html"]:
        body["HtmlBody"] = m["html"]
    if m["reply_to"]:
        body["ReplyTo"] = m["reply_to"]["email"]
    if m["attachments"]:
        body["Attachments"] = [
            {"Name": a["filename"], "Content": a["content_b64"], "ContentType": a["content_type"]}
            for a in m["attachments"]
        ]
    r = await client.post(
        f"https://[{ipv6}]/email",
        headers={
            "X-Postmark-Server-Token": POSTMARK_API_KEY,
            "Host": host,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=body,
        extensions={"sni_hostname": host},
    )
    try:
        ok = r.status_code == 200 and r.json().get("ErrorCode", -1) == 0
    except Exception:  # noqa: BLE001
        ok = False
    return (ok, f"postmark {r.status_code}: {r.text[:200]}")


# --------------------------------------------------------------------------
# Microsoft-recipient routing
# --------------------------------------------------------------------------
# Mail to Microsoft-hosted inboxes (consumer Outlook/Hotmail/Live AND any company
# on Office 365) lands far better through a reputation-focused relay than the
# bulk relays, so those messages are preferentially routed to a configurable
# "MS routing relay" first (see BRIDGE_MS_ROUTING_RELAY / build_chain() callers
# below — Postmark by default, since it's what this behaviour was originally
# built and verified against, but any configured relay can take that role).
# Detect by the consumer domain set OR an MX that points at Microsoft's mail
# infrastructure.
_MS_CONSUMER_DOMAINS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "passport.com", "windowslive.com",
    "outlook.co.uk", "hotmail.co.uk", "live.co.uk",
    "hotmail.fr", "outlook.fr", "live.fr",
    "hotmail.de", "outlook.de", "live.de",
    "hotmail.it", "hotmail.es",
}
_MS_MX_RE = re.compile(r"\.(?:mail|olc)\.protection\.outlook\.com\.?$", re.I)
_ms_domain_cache = {}


async def _domain_is_microsoft(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if not domain:
        return False
    if domain in _ms_domain_cache:
        return _ms_domain_cache[domain]
    result = domain in _MS_CONSUMER_DOMAINS
    if not result:
        try:
            import dns.asyncresolver  # lazy: same dep send_smtp2go already pulls in

            answer = await dns.asyncresolver.resolve(domain, "MX", lifetime=6.0)
            result = any(_MS_MX_RE.search(str(rr.exchange)) for rr in answer)
        except Exception:  # noqa: BLE001 - DNS failure => treat as non-Microsoft, use bulk chain
            result = False
    _ms_domain_cache[domain] = result
    return result


async def any_recipient_microsoft(rcpts) -> bool:
    for r in rcpts:
        domain = r.rsplit("@", 1)[-1] if "@" in r else ""
        if await _domain_is_microsoft(domain):
            return True
    return False


# --------------------------------------------------------------------------
# Relay registry + chain construction
# --------------------------------------------------------------------------
# name -> (send_fn, api_key). One dict is the single source of truth for
# "which relay names exist" and "is this one actually usable right now"
# (a non-empty api_key) — both build_chain() and the MS-routing lookup
# below read the exact same table, so there is nowhere left for the two to
# drift apart the way the base chain order and its own prose documentation
# once did (see DEFAULT_CHAIN_ORDER's comment).
RELAY_REGISTRY = {
    "brevo": (send_brevo, BREVO_API_KEY),
    "resend": (send_resend, RESEND_API_KEY),
    "mailersend": (send_mailersend, MAILERSEND_API_KEY),
    "smtp2go": (send_smtp2go, SMTP2GO_API_KEY),
    "postmark": (send_postmark, POSTMARK_API_KEY),
}

# Base failover order used when BRIDGE_RELAY_CHAIN is not set. This exact
# order is a real operational decision (a rough cost/deliverability
# trade-off across providers), not an arbitrary list. It previously lived
# ONLY as a hardcoded sequence of `if KEY: chain.append(...)` calls, with
# the order separately re-described in prose next to the systemd unit —
# and the two drifted: the prose fell out of date and started describing
# a different order that also omitted two of the four providers entirely,
# so the shipped documentation and the shipped behaviour disagreed about
# something operationally load-bearing. Keeping the order as one literal,
# consulted by both the code and (via BRIDGE_RELAY_CHAIN) by whoever wants
# to override it, means there is now exactly one place this order is
# decided.
DEFAULT_CHAIN_ORDER = ["brevo", "resend", "mailersend", "smtp2go"]


def build_chain():
    """Build the ordered list of (name, send_fn) to actually try, filtered
    to providers that have an API key configured.

    Order comes from BRIDGE_RELAY_CHAIN if set (a comma-separated list of
    relay names), else DEFAULT_CHAIN_ORDER. An unknown name in
    BRIDGE_RELAY_CHAIN is a hard failure at startup, not a silently
    dropped entry — a typo here should never quietly narrow your failover
    chain without telling you.
    """
    raw = os.environ.get("BRIDGE_RELAY_CHAIN", "").strip()
    if raw:
        order = [p.strip().lower() for p in raw.split(",") if p.strip()]
        unknown = [p for p in order if p not in RELAY_REGISTRY]
        if unknown:
            raise SystemExit(
                f"BRIDGE_RELAY_CHAIN names unknown relay(s): {', '.join(unknown)} "
                f"(known: {', '.join(RELAY_REGISTRY)})"
            )
    else:
        order = DEFAULT_CHAIN_ORDER
    return [(name, RELAY_REGISTRY[name][0]) for name in order if RELAY_REGISTRY[name][1]]


# --------------------------------------------------------------------------
# SMTP handler
# --------------------------------------------------------------------------
class BridgeHandler:
    def __init__(self):
        self.chain = build_chain()

        ms_relay = os.environ.get("BRIDGE_MS_ROUTING_RELAY", "postmark").strip().lower()
        if ms_relay not in RELAY_REGISTRY:
            raise SystemExit(
                f"BRIDGE_MS_ROUTING_RELAY names an unknown relay: {ms_relay} "
                f"(known: {', '.join(RELAY_REGISTRY)})"
            )
        ms_enable_raw = os.environ.get("BRIDGE_MS_ROUTING_ENABLE", "true").strip().lower()
        ms_enable = ms_enable_raw not in ("0", "false", "no", "off")

        self.ms_routing_name = ms_relay
        self.ms_routing_fn = RELAY_REGISTRY[ms_relay][0]
        # Only actually active when BOTH the feature is enabled AND that
        # relay's own API key is configured — enabling the feature with no
        # key for its target relay would otherwise "route" Microsoft-bound
        # mail into a relay call that can never succeed, silently falling
        # through to the base chain on every single message instead of
        # ever actually taking effect, which is a confusing way to
        # discover a config mistake.
        self.ms_routing_enabled = ms_enable and bool(RELAY_REGISTRY[ms_relay][1])

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        # Reject disallowed clients as early as the aiosmtpd Handler API
        # lets us: right after MAIL FROM, before any RCPT TO or message
        # body is ever read. A handler that implements handle_MAIL() is
        # responsible for populating envelope.mail_from/mail_options
        # itself (aiosmtpd's documented contract) — this isn't optional
        # bookkeeping, skipping it would silently break every delivery.
        peer = session.peer
        client_ip = peer[0] if peer else None
        if not _client_allowed(client_ip):
            LOG.warning("rejecting MAIL FROM from disallowed client %s", client_ip)
            return "550 5.7.1 relaying denied"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        # Defense in depth: handle_MAIL already rejects disallowed clients
        # before a session gets this far, but the check is repeated here
        # too rather than trusted to have fired correctly upstream — fail
        # closed at more than one point rather than relying on exactly one
        # check in exactly one method for a listener with zero other
        # authentication.
        peer = session.peer
        client_ip = peer[0] if peer else None
        if not _client_allowed(client_ip):
            LOG.warning("rejecting DATA from disallowed client %s", client_ip)
            return "550 5.7.1 relaying denied"

        try:
            m = parse_message(envelope.content, envelope)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("parse failure")
            return f"451 4.3.0 bridge parse error: {exc}"

        if not m["from_email"] or not m["rcpts"]:
            return "550 5.1.0 missing sender or recipient"

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            # Microsoft-hosted recipients deliver best through the
            # MS-routing relay's reputation: route them there first, still
            # failing over to the base chain on error or once that relay's
            # own quota/limits are exhausted. Duplicate the MS-routing
            # relay out of the base chain when merging, in case it's also
            # explicitly listed there via BRIDGE_RELAY_CHAIN — trying the
            # same relay twice wastes a round-trip and, more importantly,
            # this is exactly the loop that gives the "one relay per
            # message" guarantee described in the module docstring: it
            # must walk each distinct relay at most once and return on the
            # first success.
            chain = self.chain
            if self.ms_routing_enabled and await any_recipient_microsoft(m["rcpts"]):
                chain = [(self.ms_routing_name, self.ms_routing_fn)] + [
                    c for c in self.chain if c[0] != self.ms_routing_name
                ]
            last = "no relay configured"
            for name, fn in chain:
                try:
                    ok, detail = await fn(client, m)
                except Exception as exc:  # noqa: BLE001
                    ok, detail = False, f"{name} exception: {exc}"
                if ok:
                    LOG.info("delivered via %s: %s -> %s", name, m["from_email"], m["rcpts"])
                    return f"250 2.0.0 accepted via {name}"
                LOG.warning("relay %s failed: %s", name, detail)
                last = detail
        # All relays failed -> 4xx so the calling MTA keeps it queued and retries.
        LOG.error("all relays failed; deferring. last=%s", last)
        return "451 4.4.0 all relays failed, will retry"


def main():
    logging.basicConfig(
        level=os.environ.get("BRIDGE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    handler = BridgeHandler()
    if not handler.chain:
        LOG.error("no relay API keys configured — refusing to start")
        sys.exit(1)
    LOG.info(
        "mail-bridge listening on %s:%d (allowed clients: %s); relay chain: %s; "
        "MS-routing=%s (relay=%s)",
        LISTEN_HOST,
        LISTEN_PORT,
        ", ".join(str(n) for n in ALLOWED_CLIENT_NETS),
        ", ".join(n for n, _ in handler.chain),
        "on" if handler.ms_routing_enabled else "off",
        handler.ms_routing_name,
    )
    controller = Controller(
        handler,
        hostname=LISTEN_HOST,
        port=LISTEN_PORT,
        data_size_limit=MAX_MESSAGE_SIZE,
    )
    controller.start()
    try:
        # Python 3.14: asyncio.get_event_loop() no longer creates a loop in
        # MainThread (it RAISES) — a bridge relying on the old behaviour
        # here would crash-loop the instant a host upgrades past that
        # version. The aiosmtpd Controller runs its own event loop in a
        # separate thread anyway; the main thread only needs to park until
        # shutdown, which threading.Event().wait() does without touching
        # asyncio's loop machinery at all.
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
