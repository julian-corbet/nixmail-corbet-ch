# nixmail

A self-hosted mail + identity stack for a single small NixOS box: Stalwart
(unified IMAP/JMAP/SMTP), an LDAP directory, OIDC SSO, a password manager, a
webmail frontend, and the two small glue daemons that make outbound and
inbound delivery work on an IPv6-only host behind Cloudflare Email Routing.

**Status: pre-alpha, scaffold only.** This repo captures the design derived
from a real, live production deployment (a 1 GB RAM GCE box handling real
mail for 5 domains since 2026-07-22) — but the module code itself has not
yet been extracted/genericized. See "Extraction plan" below for exactly
what that involves and why it isn't a quick copy-paste.

## What this is

The mechanism behind a real, live setup: Stalwart authenticates every user
via LDAP (no internal user store), pocket-id provides fleet-wide OIDC SSO,
vaultwarden is the one live relying party today (others — Forgejo, a
Kubernetes dashboard — are planned but not yet wired), a webmail frontend
talks to Stalwart's JMAP API directly, and two small Python bridges glue
Stalwart to the outside world on an IPv6-only host:

- **mail-bridge**: outbound SMTP→HTTPS relay. Stalwart can't reach the mail
  providers' IPv4-only SMTP submission hosts, so it relays locally to this
  bridge, which forwards over HTTPS (IPv6-reachable) through a fallback
  chain of providers (Brevo/Resend/MailerSend/SMTP2GO, with Postmark
  prepended for Microsoft-hosted recipients specifically).
- **inbound-bridge**: inbound HTTP→LMTP relay. A Cloudflare Email Routing
  Worker (running on Cloudflare's edge, catching all mail for the zone)
  POSTs raw messages here over a tunnel; this bridge hands them to
  Stalwart's local LMTP listener.

Every stateful service persists to a bind-mounted data disk so a
boot-disk-only rebuild never loses identity or mail state.

## Why this isn't a trivial extraction

A dedicated research pass (7 parallel investigations + 3 independent
adversarial verifiers, run 2026-07-25 against the live production system)
surfaced several things that make a clean public/private split harder than
the existing nixnet/nixram pattern:

1. **Two real config models coexist per service, and only one has a Nix
   representation.** Stalwart's declarative apply-plan is genuinely
   bootstrap-only — it never re-applies to an already-configured database.
   Its actual live domain list, catch-alls, DKIM keys, and MTA routing are
   partly Nix-declared (at first boot) and partly runtime API state that
   was configured out-of-band and has zero Nix representation at all.
   pocket-id's LDAP-sync wiring (bind DN, filters, attribute mapping) is
   *entirely* runtime state in its own encrypted SQLite DB — the module's
   Nix option surface for it is empty by design. A public module has to be
   honest about which parts it can actually manage declaratively and which
   parts remain a documented manual step.
2. **The domain/mailbox topology is real, private data**, not mechanism —
   it belongs in the *consuming* repo (infra), mirroring the
   nixnet/nixram/nixvps split: this repo ships the engine, a private
   `manifest/mail.nix`-shaped file supplies the actual domains, catch-alls,
   and base DN. That data model currently has its own bug (the consumer's
   catch-all values for 2 of 5 domains are declared but silently never
   applied) that needs fixing as part of making it a real, wired-up option
   rather than copying the drift forward.
3. **Two Cloudflare Workers are part of the mechanism** (inbound routing,
   JMAP CORS) and need the same public/private treatment as the NixOS
   modules — one already is fully generic (env-var driven), the other has
   three hardcoded real hostnames as JS constants that need to become
   configuration.
4. **Secrets delivery uses a completely different mechanism than the rest
   of the fleet** (GCE instance metadata, not sops) — the module needs to
   stay delivery-mechanism-agnostic (accept `*File` options like every
   other fleet module does) rather than assume any particular secrets
   backend.

None of this is a reason not to extract it — it's the reason to do it
properly rather than as a rushed copy. A full research pass against the
live reference deployment (service inventory, live dependency graph,
secrets inventory, external-dependency map) informed this plan; those
notes carry real deployment specifics and stay in the private consumer
repo rather than here.

## Planned shape (mirroring nixnet/nixram)

```
nixmail/
  flake.nix               # nixosModules.{core,stalwart,ldap-directory,
                           #   sso,password-manager,webmail,outbound-bridge,
                           #   inbound-bridge}; systemManagerModules mirror
                           #   where the underlying primitives allow it
  modules/
    stalwart.nix           # cfg.domains (real option, not a hardcoded list),
                           #   cfg.ldap.*, cfg.smarthost.*, bootstrap-vs-live
                           #   documented explicitly in-module
    ldap-directory.nix      # (today: a pinned lldap build)
    sso.nix                 # (today: pocket-id)
    password-manager.nix     # (today: vaultwarden)
    webmail.nix              # (today: bulwark)
    outbound-bridge.nix + outbound-bridge/bridge.py
    inbound-bridge.nix + inbound-bridge/bridge.py
  workers/
    inbound-router/          # Cloudflare Email Routing Worker (already generic)
    jmap-cors/                # needs its 3 hardcoded hostnames genericized
  docs/
    design.md                # option surface + what's declarative
                              #   vs runtime-only, once written
```

## License

MIT.
