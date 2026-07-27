# Experiments

Throwaway trials: spikes, one-off scripts, measurements not yet worth
writing up properly. Nothing here is guaranteed to work, be maintained, or
survive the next cleanup pass. If something in here turns out to matter,
distill the actual finding into [`../studies/`](../studies/README.md) and
let the experiment stay disposable (or delete it).

This is also the open-questions ledger for nixmail's own judgment calls --
every entry below corresponds to a default, a hardcoded constant, or a
documented "not yet" in `modules/*.nix` or the bridge scripts that is
reasoned, not measured. nixmail's whole reason to exist is a host that is
IPv6-only and sits behind an HTTP-only inbound route -- exactly the kind of
constraint that produces untested assumptions at the seams, which is why
most of the entries below sit in the two bridge daemons (`inbound-bridge`,
`outbound-bridge`) rather than in `stalwart.nix`/`bulwark.nix`, even though
a few of the strongest ones (the ones already flagged "not yet" or
"UNTESTED" in-source) live there too. Results feed back into the relevant
module's defaults as they close.

All open; nothing below has been run against a real deployment from inside
this repo -- the "proven end-to-end" claims in the main README describe a
production deployment that lives outside this repo, not anything exercised
by `nix flake check` or by anything in here.

## Table of contents

001. inbound-bridge: does the per-recipient 60s LMTP timeout, unbounded across recipients, fit inside the calling Worker's own HTTP timeout budget?
002. outbound-bridge: does the worst-case sequential relay-chain latency (~166s) fit inside Stalwart's own outbound relay patience?
003. outbound-bridge: does memoryHigh/memoryMax (96M/160M) actually cover peak memory for a maxMessageSize message with attachments?
004. outbound-bridge: are the default NAT64 resolvers actually reachable/fast from wherever this deploys?
005. both bridges: RestartSec = "5s" -- a hardcoded constant with no rationale recorded anywhere
006. outbound-bridge: DEFAULT_CHAIN_ORDER is called "a rough cost/deliverability trade-off," never a measured one
007. bulwark: `oidc.*` is explicitly flagged UNTESTED end-to-end against a real IdP
008. stalwart: LDAP directory client hardcodes `useTls = false` with no option surface -- "not yet needed, so not yet built"
009. stalwart: "NO AUTOMATED TEST YET EXERCISES THE APPLY-PLAN"

---

## 001 — inbound-bridge: does the per-recipient 60s LMTP timeout, unbounded across recipients, fit inside the calling Worker's own HTTP timeout budget?

**Question:** `modules/inbound-bridge/bridge.py`'s `deliver_one()` opens
`smtplib.LMTP(LMTP_HOST, LMTP_PORT, timeout=60)` -- a hardcoded 60-second
socket timeout, not exposed as a `nixmail.inboundBridge.*` option at all.
`do_POST()` calls `deliver_one()` once per recipient, **sequentially, in a
plain `for r in rcpts` loop**, with no overall per-request deadline
distinct from that per-recipient 60s. For a message to N recipients, the
worst case before the bridge sends any HTTP response back is N × 60s (if
the mail server's LMTP listener is merely slow rather than down at every
stage). The module's own docstring names the motivating caller explicitly:
"a Cloudflare Email Routing Worker, which never opens a raw socket."
Cloudflare Workers have their own subrequest/`fetch()` timeout budget
(materially shorter than minutes on most plans). Nothing in this module or
its tests checks whether the worst-case sequential-LMTP latency for a
multi-recipient message can ever exceed what the one caller this bridge was
actually built for is willing to wait.

**Hypothesis:** for the common case (one or two recipients, LMTP healthy)
this is a non-issue -- LMTP to a local, healthy mail server should complete
in milliseconds, and 60s only matters when something is already wrong. But
"a mail server briefly under load" is exactly the condition a retry-driven
design like this one is supposed to survive gracefully, and right now a
message to (say) 5 recipients during exactly that condition could hold the
HTTP connection open for minutes -- which the Worker may have already
abandoned, causing the caller to retry a message that inbound-bridge is
still in the middle of delivering (see the file's own documented
caller-disconnect handling for `_reply()`, which is the symptom of this
exact class of problem, not a fix for the underlying unbounded duration).

**Method sketch:** (a) send a POST with an artificial multi-recipient
`X-Rcpt-To` header against a deliberately slow/blackholed LMTP target and
time how long the bridge takes to reply; (b) separately, check Cloudflare's
current documented subrequest/fetch timeout for the plan the reference
deployment's Worker actually runs on, and compare. If the product of
recipient count × worst-case-per-recipient time can plausibly exceed that
budget, either the per-recipient timeout needs to shrink, the loop needs a
total deadline (return whatever's decided so far once a budget is hit,
rather than blocking on the last recipient), or recipients need to run
concurrently instead of sequentially.

**Status:** open.

## 002 — outbound-bridge: does the worst-case sequential relay-chain latency (~166s) fit inside Stalwart's own outbound relay patience?

**Question:** `nixmail.outboundBridge.httpTimeout` defaults to 30
(seconds), applied per relay HTTP call via `httpx.AsyncClient(timeout=...)`.
`handle_DATA()` walks the relay chain **sequentially in a `for name, fn in
chain` loop**, trying each configured relay until one succeeds; there is no
overall per-message deadline distinct from the sum of each relay's own
30s. With `msRouting.enable` at its default `true` and a Microsoft-hosted
recipient, the chain becomes `[postmark] + base_chain`, i.e. up to 5 relay
attempts (postmark, brevo, resend, mailersend, smtp2go) when all five have
keys configured. Two of those five (`smtp2go`, `postmark`) additionally
call `_nat64_aaaa()` first, which itself can take up to `res.lifetime = 8.0`
seconds to resolve or fail. Worst case, computed directly from these
defaults: 2 × (8s NAT64 + 30s HTTP) + 3 × 30s ≈ **166 seconds** before the
bridge finally replies `451 4.4.0 all relays failed, will retry` to the
calling mail server. Nothing in `modules/stalwart.nix`'s `smarthost` /
`forceOutboundThroughSmarthost` options exposes, documents, or discusses
any timeout for Stalwart's own outbound relay/DATA-phase patience against
this bridge -- so there is no visible cross-check anywhere in the repo that
Stalwart will actually still be waiting for a response 166 seconds after
handing this bridge a message.

**Hypothesis:** most messages resolve on the first or second relay in
well under a second, so this only bites the tail case where several
providers are degraded simultaneously -- but that is precisely the moment
outbound mail matters most (an ops incident, not routine traffic), and a
calling MTA that gives up before 166s would either bounce prematurely or
open a second concurrent delivery attempt against a message the bridge is
still actively working on, undermining the "at most one relay per message"
guarantee at the transport level even though the chain-walking logic itself
still enforces it internally.

**Method sketch:** instrument `handle_DATA()` (or wrap `chain`) to log a
per-relay elapsed time in a real deployment, and separately determine
Stalwart's actual client-side timeout for a smarthost DATA transaction
(check its own source/docs for the outbound SMTP client's configured
timeouts, since `stalwart.nix` doesn't expose one). Compare the two. If
Stalwart's patience is shorter than the worst-case chain-walk, either
`httpTimeout` needs to shrink, the chain needs a package-level deadline
budget instead of a per-relay one, or relays need to run with bounded
concurrency instead of pure sequential failover.

**Status:** open.

## 003 — outbound-bridge: does memoryHigh/memoryMax (96M/160M) actually cover peak memory for a maxMessageSize message with attachments?

**Question:** `nixmail.outboundBridge.maxMessageSize` defaults to
25 MiB, enforced by aiosmtpd's `data_size_limit`. `memoryHigh`/`memoryMax`
default to `"96M"`/`"160M"`, with the option doc reasoning "attachments are
held fully in memory, base64-encoded, for the duration of one relay
attempt" -- directional reasoning, not an arithmetic bound. Tracing
`bridge.py`'s actual data flow for a message near that 25 MiB ceiling: (1)
aiosmtpd buffers the raw ~25 MiB message; (2) `parse_message()`'s
`iter_attachments()` loop calls `base64.b64encode(payload)` per attachment,
producing a second, ~1.33×-larger in-memory copy stored in `m["attachments"]`
(~33 MiB); (3) every `send_*()` function re-embeds that same `content_b64`
string into a fresh `body` dict (a third reference/copy per relay attempt);
(4) `httpx`'s `json=body` serializes that dict to a JSON string and then to
bytes for the request body (a fourth copy, roughly attachment-sized again).
None of that arithmetic appears anywhere in the module or its comments --
the memory defaults were sized by intuition ("a bit higher than a bridge
with no attachment handling would need"), not by tracing what this
specific parsing/re-serialization path actually allocates for the
largest message the module itself will accept.

**Hypothesis:** stacking steps (1)-(4) for a message that is mostly one
attachment near the 25 MiB cap plausibly approaches or exceeds the 160M
hard `MemoryMax` before Python's own interpreter/GC overhead is even
counted -- in which case systemd SIGKILLs the process mid-relay-attempt.
That failure mode is worse than an ordinary relay failure: the bridge's own
docstring promises "no message is ever silently dropped... it is either
handed to exactly one relay successfully, or the calling MTA is told to try
again" -- a SIGKILL gives the calling MTA neither a 250 nor a clean 4xx, it
just gets a dropped connection, and how that's interpreted depends entirely
on the calling MTA's own connection-loss handling (untested, unconfirmed
here).

**Method sketch:** construct a synthetic ~24 MiB single-attachment message,
relay it through a real `outbound-bridge` instance, and watch
`systemctl status nixmail-outbound-bridge`'s `MemoryCurrent` (or
`/sys/fs/cgroup/system.slice/nixmail-outbound-bridge.service/memory.current`)
during the send. If peak usage approaches `memoryHigh`, either raise the
defaults, or cap `maxMessageSize` low enough (relative to the actual
per-relay-attempt working set the code allocates) that the two numbers are
provably compatible instead of independently guessed.

**Status:** open.

## 004 — outbound-bridge: are the default NAT64 resolvers actually reachable/fast from wherever this deploys?

**Question:** `nixmail.outboundBridge.nat64Resolvers` defaults to three
public anycast NAT64/DNS64 resolvers (`2a00:1098:2c::1`, `2a00:1098:2b::1`,
`2a01:4f8:c2c:123f::1` -- see nat64.net), used to reach the two currently
IPv4-only relay APIs (SMTP2GO, Postmark) from an IPv6-only host. The
option's own doc only says "override them if you operate your own DNS64
service, or if these ever change ownership/routing" -- an acknowledgment
that these are a third party's infrastructure, not a measurement of their
actual latency, uptime, or even current reachability from any real
deployment target. `_nat64_aaaa()`'s `res.lifetime = 8.0` bounds a single
resolve attempt, but nothing measures how often that 8s is actually
consumed in practice versus resolving near-instantly.

**Hypothesis:** public anycast resolvers are generally reliable, but "the
generalizable fix for any IPv4-only registry being unreachable from an
IPv6-only host" (this same NAT64 pattern, quoted from `bulwark.nix`'s
header) is exactly the kind of dependency that fails silently and
intermittently rather than outright -- worth at minimum confirming these
three resolvers are still operated by the same party and still respond
quickly from the actual network(s) nixmail deploys to, rather than trusting
a value baked in at authoring time indefinitely.

**Method sketch:** from an IPv6-only host (or a network namespace forced to
behave like one), time `dig AAAA api.smtp2go.com @2a00:1098:2c::1` (and the
other two resolvers, and `api.postmarkapp.com`) across a representative
sample of attempts, and separately confirm the synthesized addresses still
route to the real API and pass TLS validation end-to-end.

**Status:** open.

## 005 — both bridges: `RestartSec = "5s"` -- a hardcoded constant with no rationale recorded anywhere

**Question:** both `inbound-bridge.nix` and `outbound-bridge.nix` set
`Restart = "always"; RestartSec = "5s";` in their `serviceConfig`, with
zero surrounding comment or option -- a striking contrast with the rest of
these two modules, where nearly every other constant (`maxSizeBytes`,
`maxMessageSize`, `httpTimeout`, `memoryHigh`/`memoryMax`, the NAT64
resolver list) either has a real option a consumer can override, or a
comment explaining why the value was picked. `RestartSec` is neither: it's
not an option, and there's no reasoning for why 5 seconds beats 1 or 15.

**Hypothesis:** 5s is a plausible default for "don't hot-loop-restart a
crashing process, but also don't leave the mail path down for long" -- but
for `outbound-bridge` specifically, a crash-loop against a mail server that
is actively retrying delivery every `RestartSec` interval could matter for
how quickly the queue drains once the bridge recovers from a transient
fault (e.g. all relay keys temporarily unusable), and there's no evidence
this interval was chosen with that in mind rather than just being a common
systemd-config habit.

**Status:** open.

## 006 — outbound-bridge: `DEFAULT_CHAIN_ORDER` is called "a rough cost/deliverability trade-off," never a measured one

**Question:** `outbound-bridge.py`'s `DEFAULT_CHAIN_ORDER = ["brevo",
"resend", "mailersend", "smtp2go"]` (Postmark is deliberately excluded from
the base chain, reserved for `msRouting`). `outbound-bridge.nix`'s header
comment calls this "a real operational decision, not an arbitrary list...
a rough cost/deliverability trade-off across providers" -- explicitly
self-described as reasoned, and explicitly not described as measured
against any actual delivery-rate or cost data for these specific provider
accounts.

**Hypothesis:** the ordering is probably fine as a starting default (it's
clearly not arbitrary — someone thought about it), but "rough... trade-off"
is exactly the phrase the house convention flags as needing a ledger entry:
a design choice reasoned from experience/intuition rather than from
recorded per-provider delivery-success or cost numbers for this
deployment's own accounts.

**Method sketch:** once any real deployment sends production volume through
this bridge, per-relay success/failure counts are already implicit in each
relay's own dashboard (Brevo, Resend, MailerSend, SMTP2GO) — cross-reference
those against this chain's actual attempt order (visible in the bridge's
own logs, e.g. `"delivered via %s"` / `"relay %s failed"`) to check whether
the assumed cost/deliverability ranking matches what's actually happening.

**Status:** open.

## 007 — bulwark: `oidc.*` is explicitly flagged UNTESTED end-to-end against a real IdP

**Question:** `modules/bulwark.nix`'s file header states outright: "The
`oidc.*` option surface implements Bulwark's documented OIDC env-var
contract, but it has NOT been exercised end-to-end against a real OIDC
provider in the deployment this module was extracted from (confirmed live:
zero OAUTH_* environment variables present on that container — it runs
basic JMAP username+password auth only). Treat `oidc.enable = true` as an
unverified code path." The `oidc.enable` option description repeats this:
"UNTESTED end-to-end: see this module's file header before relying on it
in production." This is already a documented open question in the source,
not one this ledger is introducing.

**Hypothesis:** the option surface (`issuerUrl`, `clientId`, `onlySso`, plus
`OAUTH_CLIENT_SECRET` via `environmentFile`) faithfully mirrors Bulwark's
documented upstream env-var contract, so it's plausible it works as
written — but "documented contract, never actually exercised" is a real gap
for anything touching authentication, where the failure mode of a subtle
mismatch (wrong redirect URI shape, PKCE handled unexpectedly, a claim
mapping upstream expects that isn't obvious from the env-var names alone)
is a login that silently never completes, not a crash.

**Method sketch:** stand up any real OIDC provider (even a throwaway one),
register a client, set `nixmail.bulwark.oidc.enable = true` with real
values, and walk through an actual browser login -- confirming the redirect,
the code exchange, and (critically) that the resulting Bearer token the JMAP
server receives is one it actually accepts, per `oidc.onlySso`'s own
break-glass reasoning.

**Status:** open.

## 008 — stalwart: LDAP directory client hardcodes `useTls = false` with no option surface -- "not yet needed, so not yet built"

**Question:** `stalwart.nix`'s `directoryOp` sets `useTls = false;
allowInvalidCerts = false;` as fixed values, not options, with the comment:
"this object models a directory reached over a trusted local/loopback
path, matching every deployment this module has actually been run against.
A directory reached over an untrusted network would need `useTls`/
`allowInvalidCerts` exposed too -- not yet needed, so not yet built; raise
it if your deployment needs LDAP-over-TLS." This is a direct, in-source
"not yet solved" — the module cannot currently express LDAP-over-TLS at
all, and the assumption that every consumer's directory sits on a trusted
local/loopback path is asserted, not verified against anything but the one
reference deployment.

**Hypothesis:** fine for the one deployment this was extracted from, but
this is a real gap for any consumer whose LDAP directory is NOT local to
the mail server (the module's own "Scope" section in the README explicitly
invites "an unrelated external LDAP server" as a valid backend) -- plaintext
LDAP over a network path that isn't loopback would leak bind credentials
and directory contents in transit, and nothing in this module would warn a
consumer who wires up a remote directory that way.

**Status:** open.

## 009 — stalwart: "NO AUTOMATED TEST YET EXERCISES THE APPLY-PLAN"

**Question:** `stalwart.nix`'s file header states, verbatim: "NO AUTOMATED
TEST YET EXERCISES THE APPLY-PLAN. Before depending on this module, at
minimum hand-verify `stalwart-cli apply --dry-run --file <rendered-plan>`
against a throwaway instance; a NixOS VM test that boots a fresh database
and asserts the plan applies cleanly is the right long-term fix and does
not exist here yet." The main README's own `nix flake check` table
confirms this: `modules-evaluate` only checks that the four modules compose
under `evalModules` (a Nix-level type/eval check), not that the rendered
NDJSON plan is actually accepted by a real `stalwart-cli apply` against a
real Stalwart instance. Combined with entry 001 in `../studies/` below (the
registry schema was reverse-engineered, not documented upstream, and has
already changed meaning once between minor releases) — the one thing that
would catch a future silent schema drift is exactly the test that doesn't
exist yet.

**Hypothesis:** the plan is very likely correct for the pinned version pair
(0.16.10-0.16.13 / stalwart-cli 1.0.8) given it was built against a real
instance — but "correct for the pinned pair" and "will keep being correct
across a routine nixpkgs bump" are different claims, and only the second
one is currently unguarded by anything automated.

**Method sketch:** the fix is already scoped in the module's own comment
and in the README's "What's not shipped yet" section (a `nixosTest` that
boots a fresh database and asserts the plan applies cleanly) — this entry
exists so that gap is visible from the open-questions ledger too, not only
buried in a file header.

**Status:** open.
