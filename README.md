# nixmail

A self-hosted mail + identity stack for a single small NixOS box: Stalwart
(unified IMAP/JMAP/SMTP), an LDAP directory, a webmail frontend, and the
two small glue daemons that make outbound and inbound delivery work on an
IPv6-only host sitting behind an HTTP-only inbound mail route.

**Status: alpha.** Five NixOS modules are extracted, wired into
`flake.nix`, and pass `nix flake check` plus a standalone `evalModules`
composition test (all five imported together against a placeholder
two-domain config, zero namespace collisions). None of this has run a
real NixOS VM test yet, and two pieces of the originally-planned stack —
an OIDC SSO provider and a password manager — have not been extracted at
all. See "What's shipped" and "What's not shipped yet" below for the
precise line.

## What this is

The mechanism behind a real, live self-hosted deployment: a mail server
authenticates every user against an LDAP directory (no internal user
store), a webmail frontend talks to the mail server's JMAP API directly,
and two small Python bridges glue the mail server to the outside world on
a host that can't do plain inbound/outbound SMTP the normal way:

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

Every module wraps a specific real upstream (Stalwart, lldap, Bulwark) —
none of them hide behind an invented abstract role name. See each
module's own header comment for why: a generic interface with exactly
one implementation behind it documents a boundary that doesn't exist yet.

## What's shipped

All five live under `modules/` and are exported from `flake.nix` as
`nixosModules.<name>`. Each is independent — there is no shared "core" to
opt into first, unlike some sibling nix* repos (nixnet's engine+providers
shape doesn't apply here: these are five separate services, not one
engine with pluggable transports).

| `nixosModules.<name>` | Option namespace | Wraps | Notes |
|---|---|---|---|
| `stalwart` | `services.nixmail.stalwart` | Stalwart 0.16.x (own module, not nixpkgs' `services.stalwart`, which still targets Stalwart's abandoned 0.15 TOML config shape) | Renders Stalwart's post-0.15 registry-object config (domains, listeners, LDAP directory, TLS, MTA routing, CORS, webui, spam rules) as an NDJSON apply-plan applied once via `stalwart-cli`. **Create-only, bootstrap-only — not a reconciler**: re-applying to an already-configured database is refused, not merged. Changing options after first boot does not reach a live server; reconcile by hand with `stalwart-cli`. DKIM is out of scope (manual step). `domains` is a real `attrsOf` submodule — every configured domain's `catchAll`/`subAddressing` reaches the rendered plan, checked directly in the eval test. |
| `lldap` | `services.nixmail.lldap` | [lldap](https://github.com/lldap/lldap) | Manages the server (process, listeners, unit) only. Deliberately exposes no options for declaring users/groups/passwords/alias values — those are live data, not configuration, and a real deployment lost data once to a declarative job that matched-and-overwrote existing directory entries by DN. Documents lldap's own attribute-name lowercasing behavior, which silently breaks case-sensitive lookups in anything that reads from it. |
| `bulwark` | `services.nixmail.bulwark` | [Bulwark](https://github.com/bulwark-app) webmail (JMAP client, shipped upstream only as an OCI image) | Runs it as a rootless podman container. Bakes the OCI image into the Nix store at *build* time (`dockerTools.pullImage`) instead of pulling at runtime — the generalizable fix for any IPv4-only registry being unreachable from an IPv6-only host. Documents the JMAP-session-returns-absolute-URLs trap that silently breaks attachments/EventSource behind a loopback backend URL. |
| `outbound-bridge` | `services.nixmail.outboundBridge` | in-repo (`outbound-bridge/bridge.py`, aiosmtpd) | No upstream equivalent exists — providers ship client libraries, not an SMTP-shaped protocol translator. `allowedClients` defaults to loopback-only and is hard-asserted non-empty; `bindHost` is hard-asserted non-wildcard (aiosmtpd's `Controller` takes exactly one bind address — "bind everywhere" replaces, not adds to, the loopback exposure). |
| `inbound-bridge` | `services.nixmail.inboundBridge` | in-repo (`inbound-bridge/bridge.py`, stdlib `http.server` + `smtplib`) | Deliberately dumb: no parsing, no Sieve, no alias resolution — all of that stays the mail server's job. Refuses to start with no secret configured unless `allowUnauthenticated` is explicitly set (a real gap in the deployment this was extracted from: an empty secret used to just log a warning and run open). Only ever declares soft (`after`) ordering on the mail server's unit, never `requires` — the relationship is a live, retried network call, not a boot-order dependency. |

Every module accepts secrets exclusively as `*File`/`*EnvFile` options
(an `EnvironmentFile` or a plain path) — none of them assume any
particular secrets-delivery backend (sops, cloud instance metadata,
anything else). None of them hardcode a domain, hostname, IP address, or
account identifier; every example in this README uses `example.org` /
`192.0.2.0/24`-style placeholders.

## What's not shipped yet

- **OIDC SSO provider** (`pocket-id` in the reference deployment) and
  **password manager** (`vaultwarden`) — not extracted. The reference
  deployment's SSO↔LDAP-sync wiring (bind DN, filters, attribute mapping)
  is *entirely* runtime state in the SSO provider's own database with no
  Nix representation at all today; a public module for it would have an
  honest, near-empty option surface, which needs its own design pass
  rather than a copy-paste.
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
    inputs.nixmail.nixosModules.lldap
    inputs.nixmail.nixosModules.bulwark
    inputs.nixmail.nixosModules."outbound-bridge"
    inputs.nixmail.nixosModules."inbound-bridge"
  ];

  services.nixmail.lldap = {
    enable = true;
    domain = "example.org";                     # placeholder — your real domain
    jwtSecretFile = "/run/secrets/lldap-jwt";
    adminPasswordFile = "/run/secrets/lldap-admin";
    keySeedEnvFile = "/run/secrets/lldap-seed";
  };

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

This is the exact shape checked by this repo's own composition test (all
five modules imported together, evaluated with `lib.evalModules`/
`nixosSystem` against placeholder values) — it type-checks and renders,
but has not been booted in a VM.

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
   representation. An SSO provider's LDAP-sync wiring is *entirely*
   runtime state in its own database — a module for it would have an
   empty option surface by design. Any module here has to be honest
   about which parts it actually manages declaratively and which remain
   a documented manual step, rather than pretend a create-only bootstrap
   is a live reconciler.
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
  flake.nix                    # nixosModules.{stalwart,lldap,bulwark,
                                #   outbound-bridge,inbound-bridge}
  modules/
    stalwart.nix
    lldap.nix
    bulwark.nix
    outbound-bridge.nix + outbound-bridge/bridge.py
    inbound-bridge.nix + inbound-bridge/bridge.py
```

## License

MIT.
