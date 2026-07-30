# modules/inbound-bridge.nix
#
# Bridges an inbound "we only speak HTTP" mail-routing integration (the
# motivating example: a Cloudflare Email Routing Worker, which can only
# `fetch()` -- it never opens a raw SMTP/LMTP socket) to a real mail
# server's local LMTP listener. The bridge itself is deliberately dumb: no
# mail parsing, no Sieve, no alias/catch-all resolution -- every one of
# those decisions belongs to whatever is listening on lmtpHost:lmtpPort,
# never to this bridge. All it does is turn "one HTTP POST, envelope in
# headers, raw RFC 5322 message as the body" into "one LMTP transaction per
# recipient", and turn the LMTP result back into an HTTP status the caller
# can act on correctly (retry vs. don't-retry).
#
# Deployment shape this assumes: something else -- an HTTP tunnel client, a
# reverse proxy, a mesh VPN peer forwarding a port -- terminates the actual
# public/remote connection and forwards to this bridge on loopback. This
# module has no opinion on what that something is and does not manage it.
#
# The live reference deployment this was extracted from treats every
# cross-service relationship here (this bridge <-> the mail server behind
# LMTP_HOST:LMTP_PORT) as a live network call with its own retry logic at
# request time, NOT a hard systemd boot-order dependency -- deliberately:
# whichever of the two processes starts first, the other's own retry
# handles it (an LMTP connection refused because the mail server isn't up
# yet just becomes a 421 the caller retries). That is why this module only
# ever adds soft ordering (`after`), never a hard `requires`, on the mail
# server's unit -- add one yourself in your own configuration if your
# deployment genuinely needs it.
#
# Wraps nothing: there is no upstream "HTTP-to-LMTP bridge" package.
# bridge.py is deliberately kept small and stdlib-only (http.server +
# smtplib) specifically so it stays readable in one sitting and never
# needs its own dependency-update treadmill.
{ config, lib, pkgs, ... }:

let
  cfg = config.nixmail.inboundBridge;
  bridgeScript = ./inbound-bridge/bridge.py;
in
{
  options.nixmail.inboundBridge = {
    enable = lib.mkEnableOption "the inbound HTTP -> LMTP mail bridge (hands HTTP-POSTed raw messages to a local LMTP listener)";

    listenHost = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Address the bridge's HTTP listener binds. Left at loopback by
        design: the expected deployment puts an HTTP tunnel client or
        reverse proxy in front of this bridge, terminating the actual
        remote connection and forwarding to loopback -- the bridge itself
        never needs to be, and should not be, reachable directly. Only
        widen this if you have a real reason the caller must reach the
        bridge without a local intermediary, and if you do, pair it with
        `allowedClientAddresses` below: the bearer secret is this
        service's real access control, but it was designed assuming a
        loopback-only listener, not as the sole defense on an
        internet-facing one.
      '';
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 2526;
      description = "Port the bridge's HTTP listener binds, on `listenHost`.";
    };

    lmtpHost = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address of the local mail server's LMTP listener this bridge delivers into.";
    };

    lmtpPort = lib.mkOption {
      type = lib.types.port;
      default = 24;
      description = ''
        Port of the local mail server's LMTP listener. Defaults to the
        IANA-assigned LMTP port; most mail servers let their own LMTP
        listener be pointed at any local port instead, so override this
        to match whatever your mail server is actually configured for.
      '';
    };

    maxSizeBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 64 * 1024 * 1024;
      description = ''
        Largest request body (the raw message, attachments included) the
        bridge will read before rejecting the POST with HTTP 400. A real
        option rather than a hardcoded constant so a deployment with
        legitimately large attachments isn't stuck editing the script to
        raise it -- keep it no larger than what your mail server itself
        will accept, or you just move the same rejection one hop later
        and make it harder to diagnose.
      '';
    };

    secretFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        `EnvironmentFile` containing `INBOUND_BRIDGE_SECRET=<bearer-token>`
        -- the shared secret the caller must present as
        `Authorization: Bearer <token>`. Deliberately just a path: this
        module has no opinion on how the file got there (sops-nix, a
        cloud provider's instance metadata, anything else) -- provision it
        with whatever secrets mechanism your deployment already uses and point
        this at the result. Read by systemd as root before the service
        drops privilege (`DynamicUser`), so the token is never embedded in
        the unit itself or readable by the service's own unprivileged
        user through any path other than its environment.

        Leaving this unset requires setting `allowUnauthenticated = true`
        (see below) -- the bridge refuses to start with neither, rather
        than come up quietly accepting unauthenticated mail into a real
        mailbox.
      '';
    };

    allowUnauthenticated = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow the bridge to start with no `secretFile` configured at all,
        accepting every POST unauthenticated. Default false: with neither
        this nor `secretFile` set, the bridge refuses to start rather than
        silently coming up open, because "an unauthenticated endpoint that
        injects arbitrary mail into a real mailbox" is a strictly worse
        failure mode than "a service that doesn't start", and a bare
        warning log for that condition is exactly the kind of thing that
        goes unnoticed until it is an incident. Only set this true on a
        network where every possible caller is already trusted by some
        OTHER mechanism (e.g. a fully closed test network) -- never on
        anything reachable through a public-facing tunnel or proxy.
      '';
    };

    allowedClientAddresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "127.0.0.1" "::1" ];
      description = ''
        Optional extra restriction: if non-empty, only these literal
        source addresses may even attempt the bearer-secret check (every
        other caller gets a bare 403 with no secret comparison at all).
        Honest caveat: on the common deployment shape (an HTTP tunnel
        client or reverse proxy in front of this bridge, both on
        loopback) every real request arrives from that one local
        process's address regardless of who the original remote caller
        was -- so in that shape this mostly restricts which LOCAL
        processes may talk to the bridge, not which remote parties may
        send mail. The bearer secret remains the actual access control;
        this is defense-in-depth layered on top of it, not a substitute
        for it.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "INFO";
      description = "Python `logging` level name for the bridge's own stdout logs (captured by the systemd journal).";
    };

    dependsOnUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "my-secrets-render.service" ];
      description = ''
        Extra systemd units this bridge depends on -- typically whatever
        unit renders `secretFile`. Wired into BOTH `after` AND `requires`
        for every unit listed here, deliberately: ordering alone only
        delays this service relative to those units, it does not make
        systemd verify they actually reached an active state first, and a
        secrets-rendering unit that starts late or fails is exactly the
        case where that distinction matters. This option exists
        specifically so the module never has to hardcode a dependency on
        any one secrets-delivery mechanism, mirroring
        outbound-bridge.nix's option of the same name. Use it for a
        sops-nix/agenix activation unit, a systemd-credential-fetching
        oneshot, a cloud-metadata polling service, or leave it empty if
        `secretFile` is simply present at boot with no unit of its own.

        This is unrelated to this module's soft-only ordering against the
        mail server's own LMTP-listening unit (see this file's header
        comment) -- that relationship stays soft-ordered by design; this
        option is only about whatever provisions `secretFile`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The one option combination this module treats as actively wrong,
        # not just unconventional -- worth catching at eval time rather
        # than leaving it to be discovered when the bridge exits at
        # service start (see bridge.py's own main() for that fail-closed
        # check; this assertion just surfaces the same decision earlier).
        assertion = cfg.secretFile != null || cfg.allowUnauthenticated;
        message = ''
          nixmail.inboundBridge.secretFile is not set and
          allowUnauthenticated is false. Either provide secretFile (an
          EnvironmentFile with INBOUND_BRIDGE_SECRET=<token>), or set
          allowUnauthenticated = true if you have deliberately decided
          this bridge should accept unauthenticated mail (see that
          option's description for when that is, and is not, reasonable).
        '';
      }
    ];

    systemd.services.nixmail-inbound-bridge = {
      description = "Inbound HTTP -> LMTP mail bridge";
      wantedBy = [ "multi-user.target" ];
      # Soft ordering only against the mail server's own unit -- see this
      # file's header comment for why this module never adds a hard
      # `requires` there. `dependsOnUnits` below is a separate concern
      # (whatever provisions `secretFile`) and DOES get a hard `requires`.
      after = [ "network-online.target" ] ++ cfg.dependsOnUnits;
      wants = [ "network-online.target" ];
      requires = cfg.dependsOnUnits;

      environment = {
        INBOUND_BRIDGE_HOST = cfg.listenHost;
        INBOUND_BRIDGE_PORT = toString cfg.listenPort;
        LMTP_HOST = cfg.lmtpHost;
        LMTP_PORT = toString cfg.lmtpPort;
        INBOUND_BRIDGE_MAX_SIZE = toString cfg.maxSizeBytes;
        INBOUND_BRIDGE_ALLOW_UNAUTHENTICATED = lib.boolToString cfg.allowUnauthenticated;
        INBOUND_BRIDGE_ALLOWED_CLIENTS = lib.concatStringsSep "," cfg.allowedClientAddresses;
        INBOUND_BRIDGE_LOG_LEVEL = cfg.logLevel;
      };

      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${bridgeScript}";
        DynamicUser = true;
        Restart = "always";
        RestartSec = "5s";

        # Loopback HTTP in, local LMTP out -- a small daemon that never
        # needs anything more than that, so it gets the tightest sandbox
        # this repo's bridge modules use.
        MemoryHigh = "64M";
        MemoryMax = "96M";
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
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        UMask = "0077";
      } // lib.optionalAttrs (cfg.secretFile != null) {
        EnvironmentFile = cfg.secretFile; # read by systemd as root, before privilege drop
      };
    };
  };
}
