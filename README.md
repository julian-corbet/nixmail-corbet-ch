# nixmail

A self-hosted mail stack for a single small NixOS box: Stalwart (unified
IMAP/JMAP/SMTP), a webmail frontend, and the two small glue daemons that
make outbound and inbound delivery work on an IPv6-only host sitting
behind an HTTP-only inbound mail route.

**Status: alpha.** Four NixOS modules, plus two bridge daemons that are real
programs rather than configuration — so the daemons get real tests and the
modules get an evaluation check. `nix flake check` runs three things:

| check | what it establishes |
|---|---|
| `inbound-bridge-tests` | 15 tests over the HTTP→LMTP bridge: the 4xx→421 / 5xx→550 status mapping, one LMTP transaction per recipient, partial success counting as success, an exception surfacing as retryable rather than a drop, and refusing to start unauthenticated |
| `outbound-bridge-tests` | 21 tests over the SMTP→HTTP bridge: the allow-list defaulting to loopback, at most one relay per message, total failure deferring instead of bouncing, and envelope recipients winning over header recipients |
| `modules-evaluate` | all four modules composed into one NixOS system, which is what catches a collision in the shared `services.nixmail.*` namespace |

Both suites are stdlib `unittest`, run offline, and send no mail.

What they pin is deliberately the set of behaviours that fail **silently**. A
status mapped the wrong way does not raise — it makes a caller retry a hard
refusal forever, or discard a message that only needed retrying. An allow-list
that widens by accident does not raise either: it turns a listener holding a paid
provider account's credentials into an open relay, which is the incident the
outbound bridge's own comments record from an earlier version that defaulted its
bind address to `0.0.0.0`. Both are proven in the failing direction — widen the
default and two tests fail, one of them by observing a rejected client reach the
relay chain.

An earlier version of this section claimed a `nix flake check` pass and a
standalone `evalModules` composition test at a time when the flake had no
`checks` output at all. That has been replaced by the table above rather than
quietly corrected.

Still stronger than any of it: all four modules run in a real production
deployment (a small single-node host, outside this repo), and outbound and
inbound mail have both been proven end to end with real messages through it.
What remains missing is a `nixosTest` exercising actual service startup — these
checks test units and daemons, not a booted machine. See "What's shipped" and
"Out of scope" below for the precise line.

## Scope

nixmail covers mail transport, webmail, and the two delivery bridges
ONLY. **Identity — an LDAP directory and OIDC/SSO — is explicitly out of
scope** and lives in a separate identity project. Nothing in this repo
ships, bundles, or requires a specific directory implementation:
Stalwart's `services.nixmail.stalwart.ldap.*` options (`url`, `baseDn`,
`bindDn`, `bindPasswordFile`, the search filters, the attribute
mappings) stand entirely on their own, so any LDAP-speaking directory
can back it — one from a separate identity project, or an unrelated
external LDAP server. This repo does not provide, and has never
provided, a directory server, an OIDC/SSO provider, or a password
manager.

## What this is

The mechanism behind a real, live self-hosted deployment: a mail server
authenticates every user against an LDAP directory it does not itself
provide (no internal user store), a webmail frontend talks to the mail
server's JMAP API directly, and two small Python bridges glue the mail
server to the outside world on a host that can't do plain inbound/outbound
SMTP the normal way:

- **outbound-bridge**: SMTP→HTTPS relay. The mail server relays outbound
  mail to this bridge as if it were an ordinary smarthost; the bridge
  re-sends each message through a configurable, ordered chain of
  HTTPS-based transactional-mail providers, trying each in turn and
  stopping at the first success — never delivering the same message twice.
- **inbound-bridge**: HTTP→LMTP relay. Something that can only speak HTTP
  (the motivating case: a Cloudflare Email Routing Worker, which never
  opens a raw socket) POSTs a raw message here; this bridge hands it to
  the mail server's local LMTP listener, one transaction per recipient,
  and maps the LMTP result back onto a retry-or-don't-retry HTTP status.

Every module wraps a specific real upstream (Stalwart, Bulwark) — none of
them hide behind an invented abstract role name. See each module's own
header comment for why: a generic interface with exactly one
implementation behind it documents a boundary that doesn't exist yet.

## What's shipped

All four live under `modules/` and are exported from `flake.nix` as
`nixosModules.<name>`. Each is independent — there is no shared "core" to
opt into first, unlike some sibling nix* repos (nixnet's engine+providers
shape doesn't apply here: these are four separate services, not one
engine with pluggable transports).

| `nixosModules.<name>` | Option namespace | Wraps | Notes |
|---|---|---|---|
| `stalwart` | `services.nixmail.stalwart` | Stalwart 0.16.x (own module, not nixpkgs' `services.stalwart`, which still targets Stalwart's abandoned 0.15 TOML config shape) | Renders Stalwart's post-0.15 registry-object config (domains, listeners, an LDAP directory client, TLS, MTA routing, CORS, webui, spam rules) as an NDJSON apply-plan applied once via `stalwart-cli`. The `ldap.*` options describe a directory *client* only — url, base DN, bind DN, bind-password file, search filters, attribute mappings — with no directory server bundled or assumed; point them at any LDAP-speaking directory (see "Scope" above). **Create-only, bootstrap-only — not a reconciler**: re-applying to an already-configured database is refused, not merged. Changing options after first boot does not reach a live server; reconcile by hand with `stalwart-cli`. DKIM is out of scope (manual step). `domains` is a real `attrsOf` submodule — every configured domain's `catchAll`/`subAddressing` reaches the rendered plan, checked directly in the eval test. |
| `bulwark` | `services.nixmail.bulwark` | [Bulwark](https://github.com/bulwark-app) webmail (JMAP client, shipped upstream only as an OCI image) | Runs it as a rootless podman container. Bakes the OCI image into the Nix store at *build* time (`dockerTools.pullImage`) instead of pulling at runtime — the generalizable fix for any IPv4-only registry being unreachable from an IPv6-only host. Documents the JMAP-session-returns-absolute-URLs trap that silently breaks attachments/EventSource behind a loopback backend URL. |
| `outbound-bridge` | `services.nixmail.outboundBridge` | in-repo (`outbound-bridge/bridge.py`, aiosmtpd) | No upstream equivalent exists — providers ship client libraries, not an SMTP-shaped protocol translator. `bindHost` is always itself permitted to relay, unconditionally, on top of whatever `allowedClients` adds — without that, setting `bindHost` to the host's own non-loopback address (as its own docs tell you to, when the mail server's anti-SSRF guard rejects a loopback relay target) while leaving `allowedClients` at its loopback-only default rejected every relay attempt. `bindHost` is hard-asserted non-wildcard (aiosmtpd's `Controller` takes exactly one bind address — "bind everywhere" replaces, not adds to, the loopback exposure). |
| `inbound-bridge` | `services.nixmail.inboundBridge` | in-repo (`inbound-bridge/bridge.py`, stdlib `http.server` + `smtplib`) | Deliberately dumb: no parsing, no Sieve, no alias resolution — all of that stays the mail server's job. Refuses to start with no secret configured unless `allowUnauthenticated` is explicitly set (a real gap in the deployment this was extracted from: an empty secret used to just log a warning and run open). Only ever declares soft (`after`) ordering on the mail server's unit, never `requires` — the relationship is a live, retried network call, not a boot-order dependency. |

Every module accepts secrets exclusively as `*File`/`*EnvFile` options
(an `EnvironmentFile` or a plain path) — none of them assume any
particular secrets-delivery backend (sops, cloud instance metadata,
anything else). None of them hardcode a domain, hostname, IP address, or
account identifier; every example in this README uses `example.org` /
`192.0.2.0/24`-style placeholders.

## What's not shipped yet

- **Cloudflare Workers** (inbound-routing worker, JMAP-CORS worker) —
  part of the reference deployment's mechanism but not part of this repo.
  Not started.
- **A real NixOS VM test** (`nixosTest`) exercising the modules against
  actual service startup, not just `evalModules`. Not started.
- **`docs/design.md`** — the option-surface-vs-runtime-state writeup
  nixnet has as `docs/providers.md`. Not started; each module's own
  header comment is the design doc for now.
- **`systemManagerModules`** — nixnet ships both `nixosModules` and
  `systemManagerModules` for the same files. Not evaluated for nixmail;
  several of these modules touch primitives (`users.users`, `boot.*`
  via `dockerTools`) that may not map cleanly onto system-manager's
  smaller surface. Unassessed, not attempted.

## Quickstart

```nix
{
  inputs.nixmail.url = "github:<owner>/<repo>"; # no public remote yet

  # host configuration.nix:
  imports = [
    inputs.nixmail.nixosModules.stalwart
    inputs.nixmail.nixosModules.bulwark
    inputs.nixmail.nixosModules."outbound-bridge"
    inputs.nixmail.nixosModules."inbound-bridge"
  ];

  # Bring your own LDAP directory -- this repo does not ship one (see
  # "Scope" above). `ldap.*` below just needs a directory that already
  # exists and answers on this URL/baseDn with a bind account it can use.
  services.nixmail.stalwart = {
    enable = true;
    domains."example.org" = { };
    defaultDomain = "example.org";
    publicHostname = "mail.example.org";
    httpPublicUrl = "https://mail.example.org";
    tls.certificateFile = "/run/secrets/tls-cert";
    tls.keyFile = "/run/secrets/tls-key";
    ldap = {
      url = "ldap://127.0.0.1:3890";
      baseDn = "dc=example,dc=org";
      bindDn = "uid=admin,ou=people,dc=example,dc=org";
      bindPasswordFile = "/run/secrets/ldap-bind";
    };
    recoveryAdmin = {
      enable = true;
      passwordFile = "/run/secrets/recovery-admin";
    };
  };

  services.nixmail.outboundBridge = {
    enable = true;
    keysEnvFile = "/run/secrets/relay-keys";   # BREVO_API_KEY=... etc.
  };

  services.nixmail.inboundBridge = {
    enable = true;
    secretFile = "/run/secrets/inbound-shared-secret";
  };

  services.nixmail.bulwark = {
    enable = true;
    jmapServerUrl = "https://mail.example.org";
    stateDir = "/var/lib/bulwark";
    environmentFile = "/run/secrets/bulwark-env";
  };
}
```

This is the shape a configuration takes, and the `modules-evaluate` check
verifies a placeholder version of exactly this shape — see
[examples/host](examples/host). A configuration of this shape (with real,
non-placeholder values) is what boots the live production deployment
mentioned above, which remains the stronger evidence; this repo
itself still has no automated `nixosTest` exercising real service
startup.

## Why this isn't a trivial extraction

A dedicated research pass against a live production reference deployment
surfaced several things that make a clean public/private split harder
than a straight copy:

1. **Two real config models coexist per service, and only one has a Nix
   representation.** Stalwart's declarative apply-plan is genuinely
   bootstrap-only — it never re-applies to an already-configured
   database. A real deployment's live domain list, catch-alls, DKIM
   keys, and MTA routing end up partly Nix-declared (at first boot) and
   partly runtime API state configured out-of-band with zero Nix
   representation. (Identity — the LDAP directory itself, any OIDC/SSO
   provider in front of it — is deliberately out of scope for this repo;
   see "Scope" above. A directory-sync-driven SSO provider's wiring is
   *entirely* runtime state in its own database, which is part of why
   identity was drawn as its own project boundary instead of one more
   module here.) Any module here has to be honest about which parts it
   actually manages declaratively and which remain a documented manual
   step, rather than pretend a create-only bootstrap is a live
   reconciler.
2. **The domain/mailbox topology is real, private data, not mechanism** —
   it belongs in whatever repo *consumes* this one (a private
   `manifest`-shaped file supplying real domains, catch-alls, and base
   DN), mirroring the nixnet/nixram/nixvps split. `stalwart.nix`'s
   `domains` option is a genuine `attrsOf` submodule for exactly this
   reason — every configured domain's settings reach the rendered plan
   (checked directly in this repo's own eval test), rather than a
   hardcoded single-domain assumption a consumer would have to work
   around.
3. **Two Cloudflare Workers are part of a full reference deployment's
   mechanism** (inbound routing, JMAP CORS) and would need the same
   public/private treatment as the NixOS modules if they're ever added
   here — not started (see "What's not shipped yet").
4. **Secrets delivery varies by deployment** (cloud instance metadata,
   sops, anything else) — every module stays delivery-mechanism-agnostic
   by accepting only `*File`/`*EnvFile` options, never assuming a
   specific backend.

## Repository layout

```
nixmail/
  flake.nix                    # nixosModules.{stalwart,bulwark,
                                #   outbound-bridge,inbound-bridge}
  modules/
    stalwart.nix
    bulwark.nix
    outbound-bridge.nix + outbound-bridge/bridge.py
    inbound-bridge.nix + inbound-bridge/bridge.py
```

## License

MIT.
