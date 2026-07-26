# modules/outbound-bridge.nix
#
# SMTP -> HTTPS-API outbound mail bridge. Your mail server relays outbound
# mail to this bridge over plain SMTP, as if it were an ordinary smarthost;
# the bridge parses each message and re-sends it through one or more
# HTTPS-based transactional-mail providers, trying each configured relay in
# order and stopping at the first success, so a message is ever delivered
# via at most one relay and never silently duplicated. If every relay in
# the chain fails (or none has a key configured), the bridge returns an
# SMTP 4xx so your mail server keeps the message queued and retries -- no
# message is ever dropped at this layer.
#
# The motivating case: a mail server that cannot reach a provider's SMTP
# submission host directly for some environment-specific reason (an
# IPv4/IPv6 mismatch against that host, an outbound firewall rule, a NAT
# limitation, ...) while the same provider's HTTPS API remains reachable.
# That specific shape doesn't matter to this module -- it only needs
# *somewhere* to relay outbound mail that isn't a direct SMTP connection to
# the provider, and this bridge is that somewhere. There is no upstream
# equivalent: providers ship client libraries, not a protocol translator
# that lets an unmodified MTA relay to their API as if it were just another
# smarthost.
#
# Same overall shape and systemd hardening block as this repo's
# inbound-bridge.nix. Unlike that module, this one's `bindHost` has a real,
# common non-loopback use case -- which is exactly what makes the lessons
# below worth enforcing as mechanism, not just documenting in prose:
#
#   1. `bindHost` must be the box's own real, stable, non-loopback address
#      when it can't be loopback -- never a wildcard/any-interface address.
#      A mail server's own anti-SSRF guard commonly refuses a loopback
#      relay target (a sensible guard on its own: it stops the mail server
#      from being tricked into relaying to itself); binding all interfaces
#      to route around that restriction was tried once and found, in
#      production, to turn a "reachable from one intended caller" bridge
#      into a fully exposed relay reachable from every network the host is
#      attached to -- because aiosmtpd's `Controller` accepts exactly one
#      bind address, not a list. There is no "bind everywhere, trust one"
#      middle ground with this library; the assertion below refuses a
#      wildcard bind outright rather than let that mistake happen twice.
#   2. This listener has NO authentication of its own (no SMTP AUTH, no
#      STARTTLS) -- the client allowlist is the ONLY access control, which
#      is why it defaults to loopback-only rather than to "no check at
#      all". An earlier, unpublished version of this exact bridge shipped
#      with no client check whatsoever and relied entirely on its bind
#      address for isolation; the two mistakes compounded (a wide bind AND
#      no allowlist) into an open relay against paid provider accounts,
#      reachable by anyone who could route a TCP connection to the port,
#      with no error and no failed delivery to hint at it. Both defaults
#      in this module are closed; you have to widen both deliberately, and
#      the assertions below refuse the specific combinations already known
#      to be dangerous. `bindHost` itself is ALWAYS folded into the
#      effective allowlist alongside `allowedClients` (see
#      `effectiveAllowedClients` below) -- an earlier revision of this
#      module left that derivation out, so following lesson 1 above (set
#      `bindHost` to the box's real address) while leaving `allowedClients`
#      at its loopback-only default produced a bridge that rejected every
#      single relay attempt: the one address the docs told you to bind was
#      never itself in the allowlist. A module's default must not reject
#      the exact configuration its own docs tell you to use.
#   3. Secrets delivery must never be hardcoded to one mechanism. A public
#      module cannot assume sops-nix, agenix, a cloud-metadata fetcher, or
#      any other one convention -- `dependsOnUnits` below is an ordinary
#      list you fill in yourself with whatever unit actually provisions
#      `keysEnvFile`, wired into both `after` and `requires` so a slow or
#      failed secrets fetch is an ordinary retry rather than a silent
#      partial start.
#
# The base failover order (brevo -> resend -> mailersend -> smtp2go, with a
# configurable relay preferred for Microsoft-hosted recipients) is a real
# operational decision, not an arbitrary list -- see `relayChain`'s doc
# comment and bridge.py's own DEFAULT_CHAIN_ORDER comment for why it is
# deliberately declared in exactly one place instead of being re-described
# in this file's prose (that duplication is exactly what went stale here
# once already: the prose fell out of sync with the code and started
# describing a different, incomplete order).
#
# Wraps nothing -- there is no upstream "SMTP-to-HTTP-API bridge" package.
# The companion script lives at ./outbound-bridge/bridge.py.

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.nixmail.outboundBridge;

  bridge = ./outbound-bridge/bridge.py;

  relayNames = [ "brevo" "resend" "mailersend" "smtp2go" "postmark" ];

  # `bindHost` is ALWAYS itself permitted to relay, unconditionally, on top
  # of whatever `allowedClients` adds -- see the option docs on both for
  # why. Without this derivation, following this module's own `bindHost`
  # guidance (set it to the host's real, stable, non-loopback address) while
  # leaving `allowedClients` at its loopback-only default produced a bridge
  # that rejected every single relay attempt with "550 5.7.1 relaying
  # denied": the one address the docs told you to bind was never itself in
  # the allowlist. `unique` just avoids a harmless duplicate env var entry
  # when bindHost is already loopback (the common case, where it's already
  # covered by allowedClients' own default).
  effectiveAllowedClients = unique (cfg.allowedClients ++ [ cfg.bindHost ]);
in
{
  options.services.nixmail.outboundBridge = {
    enable = mkEnableOption ''
      the outbound SMTP-to-HTTP-API bridge: accepts mail from your mail
      server over local SMTP and re-sends it through one or more
      HTTPS-based relay providers, in an ordered failover chain, so a
      message is delivered via at most one relay and total failure across
      the chain queues-and-retries at the SMTP layer rather than dropping
      the message
    '';

    package = mkOption {
      type = types.package;
      default = pkgs.python3.withPackages (ps: with ps; [ aiosmtpd httpx dnspython ]);
      defaultText = literalExpression ''pkgs.python3.withPackages (ps: with ps; [ aiosmtpd httpx dnspython ])'';
      description = ''
        The Python interpreter and package set the bridge script runs
        under. `aiosmtpd` provides the local SMTP listener, `httpx` the
        outbound HTTPS calls to each relay's API, `dnspython` the NAT64
        and MX-based routing lookups (see `nat64Resolvers`). Override this
        to pin exact versions or vendor a patched build -- consumers are
        not stuck with whatever versions this module's own default happens
        to track.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 2525;
      description = ''
        SMTP port the bridge listens on, on `bindHost`. Point your mail
        server's outbound smarthost/relay setting at `bindHost:port` --
        this is a local relay target for your own mail server, not a
        service other hosts or end users are meant to talk to directly.
      '';
    };

    bindHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address the bridge's SMTP listener binds. If your mail server's own
        anti-SSRF guard refuses a loopback relay target (many do, on
        purpose), set this to the host's own stable non-loopback address
        instead, matching whatever address you configure as that server's
        smarthost.

        This address is ALWAYS itself permitted to relay through the
        bridge, unconditionally and automatically (see `allowedClients`
        below) -- you do not need to, and should not need to, also add it
        to `allowedClients` yourself. Only add entries to `allowedClients`
        for some OTHER source that also needs to reach this bridge (for
        example, your mail server's outbound connections arrive from a
        container/pod network address that differs from this host's own
        bind address because of NAT in between -- this happens routinely
        when the mail server and the bridge are on the same host but in
        different network namespaces).

        Do NOT set this to a wildcard/any-interface address ("0.0.0.0" or
        "::") to work around that restriction: aiosmtpd's `Controller`
        accepts exactly one bind address, not a list, so binding "all
        interfaces" doesn't add a fallback alongside loopback, it REPLACES
        a loopback-only exposure with exposure on every interface the host
        has -- including any of them your mail server never actually
        needed this reachable from. This bridge has no authentication
        beyond `allowedClients` below, so that difference is the whole
        ballgame: binding the box's own real address is both the fix for
        the anti-SSRF problem AND the only address your mail server needed
        reachable in the first place, no firewall rule required. See this
        file's header comment for the production incident that motivated
        the hard assertion on this below.
      '';
    };

    allowedClients = mkOption {
      type = types.listOf types.str;
      default = [ "127.0.0.1/32" "::1/128" ];
      example = [ "203.0.113.10" "203.0.113.0/24" ];
      description = ''
        ADDITIONAL source addresses (individual addresses or CIDRs) allowed
        to relay mail through this bridge, enforced by bridge.py itself at
        the SMTP protocol level -- this is the bridge's ONLY access control,
        since it implements no SMTP AUTH. Defaults to loopback only, which
        is deliberately NOT the same as "no check applied": an earlier,
        unpublished version of this bridge treated an unconfigured
        allowlist as "trust anyone who can connect", and that default is
        precisely what turned a bind-address mistake into an open relay
        against paid provider accounts (see this file's header comment).

        `bindHost` is ALWAYS permitted too, unconditionally, on top of
        whatever is listed here (see this option's use in `config` below) --
        this list only needs entries for sources OTHER than `bindHost`
        itself. It is safe to leave this at its default, or even set it to
        `[ ]`, once `bindHost` alone covers every source that actually needs
        to relay through this bridge.

        Narrow or widen this to match exactly what `bindHost` (and any
        NAT/firewall in front of it) actually exposes -- the two settings
        are independent, and getting only one of them right is not enough.
      '';
    };

    keysEnvFile = mkOption {
      type = types.path;
      description = ''
        An EnvironmentFile (`KEY=VALUE` per line) supplying each relay's API
        key -- `BREVO_API_KEY`, `RESEND_API_KEY`, `MAILERSEND_API_KEY`,
        `SMTP2GO_API_KEY`, `POSTMARK_API_KEY`, any subset. There is no
        default: a public module cannot assume any particular
        secrets-delivery convention, so you must point this at wherever
        your own mechanism actually renders it (see `dependsOnUnits`). It's
        read by systemd itself, as root, via `EnvironmentFile=` before the
        process drops to an unprivileged `DynamicUser` -- so the bridge's
        own runtime user never needs read access to the file on disk, only
        systemd does.

        A missing or key-less file is already fail-closed at the
        application layer, independent of anything here: bridge.py refuses
        to start at all if no provider ends up with a usable key. Unlike a
        bridge that silently disables a security check when a secret is
        absent, an empty relay chain here is a hard startup failure, not a
        quiet no-op.
      '';
    };

    dependsOnUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "my-secrets-render.service" ];
      description = ''
        Extra systemd units this bridge depends on -- typically whatever
        unit renders `keysEnvFile`. Wired into BOTH `after` AND `requires`
        for every unit listed here, deliberately: ordering alone only
        delays this service relative to those units, it does not make
        systemd verify they actually reached an active state first, and a
        secrets-rendering unit that starts late or fails is exactly the
        case where that distinction matters. This option exists
        specifically so the module never has to hardcode a dependency on
        any one secrets-delivery mechanism (see this file's header
        comment). Use it for a sops-nix/agenix activation unit, a
        systemd-credential-fetching oneshot, a cloud-metadata polling
        service, or leave it empty if `keysEnvFile` is simply present at
        boot with no unit of its own.
      '';
    };

    relayChain = mkOption {
      type = types.nullOr (types.listOf (types.enum relayNames));
      default = null;
      example = [ "resend" "brevo" "smtp2go" ];
      description = ''
        Explicit, ordered override of the failover chain. Only providers
        with a configured key in `keysEnvFile` are actually used, skipping
        the rest, in the order given here. Leave `null` to use the
        built-in default order (brevo, resend, mailersend, smtp2go) baked
        into bridge.py's own `DEFAULT_CHAIN_ORDER` -- that default
        previously lived ONLY as a hardcoded sequence of
        `if KEY: chain.append(...)` calls, separately re-described in this
        module's own prose, and the two silently drifted apart (the prose
        fell out of date and started describing a different order that
        also omitted two providers entirely). Setting this option
        explicitly, or reading bridge.py's own constant, are now the only
        two places this order is decided -- don't reintroduce a third,
        separately-maintained description of it anywhere else.
      '';
    };

    msRouting = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Route mail to Microsoft-hosted recipients (consumer
          Outlook/Hotmail/Live domains, or any domain whose MX points at
          Microsoft's mail infrastructure) through `msRouting.relay` first,
          before falling back to the ordinary chain. Deliverability into
          Microsoft-hosted mailboxes is disproportionately sensitive to
          sender reputation, and a relay with a stronger reputation there
          is worth preferring even if it's otherwise lower in your base
          chain. Only actually takes effect when `msRouting.relay` also has
          a configured key in `keysEnvFile` -- enabling this with no key
          for the target relay silently falls through to the base chain on
          every message instead of ever doing anything, so check both if
          this doesn't seem to be having an effect.
        '';
      };

      relay = mkOption {
        type = types.enum relayNames;
        default = "postmark";
        description = ''
          Which relay is preferred for Microsoft-hosted recipients (see
          `msRouting.enable`). Defaults to Postmark, since that's what this
          behaviour was originally built and verified against -- but the
          preference is a property of your own provider accounts'
          reputations, not a fact about the relays themselves, so any
          configured relay can take this role.
        '';
      };
    };

    maxMessageSize = mkOption {
      type = types.ints.positive;
      default = 25 * 1024 * 1024;
      description = ''
        Largest message, in bytes, the bridge will accept, enforced by
        aiosmtpd's own `data_size_limit`. aiosmtpd has no cap of its own by
        default, and the whole message is buffered in memory before
        delivery is even attempted (attachments are base64-encoded in
        memory too, in bridge.py's `parse_message()`) -- pick a value your
        mail server's own limit already agrees with, so rejection happens
        at one hop consistently rather than being silently relaxed here and
        hit later somewhere else.
      '';
    };

    httpTimeout = mkOption {
      type = types.numbers.positive;
      default = 30;
      description = "Per-request timeout, in seconds, for outbound HTTPS calls to a relay's API.";
    };

    logLevel = mkOption {
      type = types.enum [ "DEBUG" "INFO" "WARNING" "ERROR" ];
      default = "INFO";
      description = "Python `logging` level for the bridge process.";
    };

    nat64Resolvers = mkOption {
      type = types.listOf types.str;
      default = [ "2a00:1098:2c::1" "2a00:1098:2b::1" "2a01:4f8:c2c:123f::1" ];
      description = ''
        Public NAT64/DNS64 resolvers used to reach IPv4-only relay APIs
        (currently SMTP2GO and Postmark, neither of which publishes an
        AAAA record for their API host) over IPv6: the hostname is
        resolved against these resolvers for a synthesized IPv6 address,
        while TLS SNI and the HTTP Host header stay pointed at the real
        hostname so certificate validation still passes. The defaults are
        public anycast resolvers (see nat64.net) -- override them if you
        operate your own DNS64 service, or if you don't need this at all
        because your host already has native IPv4 connectivity to every
        relay you've configured.
      '';
    };

    memoryHigh = mkOption {
      type = types.str;
      default = "96M";
      description = ''
        systemd `MemoryHigh=` (soft throttle) for the service, as a size
        string (e.g. "96M", "1G"). Set a bit higher than a bridge with no
        attachment handling would need, since attachments are held fully in
        memory, base64-encoded, for the duration of one relay attempt --
        this is a second line of defense against a pathological message,
        not a tuning knob for normal traffic.
      '';
    };

    memoryMax = mkOption {
      type = types.str;
      default = "160M";
      description = "systemd `MemoryMax=` (hard kill) for the service. See `memoryHigh`.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(elem cfg.bindHost [ "0.0.0.0" "::" ]);
        message = ''
          services.nixmail.outboundBridge.bindHost must not be a
          wildcard/any-interface address ("0.0.0.0" or "::"). See that
          option's own description and this file's header comment: this
          bridge has no authentication beyond `allowedClients`, and
          aiosmtpd's `Controller` binds exactly one address, not a list --
          "all interfaces" is not a safe superset of "loopback plus one
          real address", it is a strictly worse exposure. Set `bindHost` to
          the one real address your mail server actually needs to reach
          this service from.
        '';
      }
      # There used to be an assertion here rejecting an empty
      # `allowedClients`. It no longer applies: `bindHost` is now always
      # folded into the effective allowlist (`effectiveAllowedClients`
      # above), so the "nothing can ever relay through this bridge" failure
      # mode that assertion existed to catch is now structurally
      # impossible -- `bindHost` is a required, always-non-empty address,
      # so the effective list sent to bridge.py can never be empty even
      # when `allowedClients` itself is deliberately set to `[ ]`.
      {
        assertion = cfg.relayChain == null || (length cfg.relayChain == length (unique cfg.relayChain));
        message = ''
          services.nixmail.outboundBridge.relayChain lists the same relay
          more than once. A relay is only ever tried once per message
          regardless (the chain-walking loop returns on first success), so
          a duplicate entry is always dead weight -- remove it rather than
          let it imply a retry that will never actually happen.
        '';
      }
    ];

    systemd.services.outbound-bridge = {
      description = "Outbound SMTP-to-HTTP-API mail bridge";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ] ++ cfg.dependsOnUnits;
      wants = [ "network-online.target" ];
      requires = cfg.dependsOnUnits;

      environment = {
        BRIDGE_HOST = cfg.bindHost;
        BRIDGE_PORT = toString cfg.port;
        BRIDGE_ALLOWED_CLIENTS = concatStringsSep "," effectiveAllowedClients;
        BRIDGE_RELAY_CHAIN = if cfg.relayChain == null then "" else concatStringsSep "," cfg.relayChain;
        BRIDGE_MS_ROUTING_RELAY = cfg.msRouting.relay;
        BRIDGE_MS_ROUTING_ENABLE = if cfg.msRouting.enable then "true" else "false";
        BRIDGE_MAX_MESSAGE_SIZE = toString cfg.maxMessageSize;
        BRIDGE_HTTP_TIMEOUT = toString cfg.httpTimeout;
        BRIDGE_LOG_LEVEL = cfg.logLevel;
        BRIDGE_NAT64_RESOLVERS = concatStringsSep "," cfg.nat64Resolvers;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/python3 ${bridge}";
        EnvironmentFile = cfg.keysEnvFile; # read by systemd as root before privilege drop
        DynamicUser = true;
        Restart = "always";
        RestartSec = "5s";

        # It only ever binds bindHost (an unprivileged port) and makes
        # outbound HTTPS calls -- there is no legitimate reason for it to
        # need anything this hardening block denies.
        MemoryHigh = cfg.memoryHigh;
        MemoryMax = cfg.memoryMax;
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = false; # CPython itself is JIT-less, but some C-extension wheels mmap their own code; keep false
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        UMask = "0077";
      };
    };
  };
}
