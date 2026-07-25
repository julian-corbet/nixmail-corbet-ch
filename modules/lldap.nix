# modules/lldap.nix
#
# The LDAP identity directory backing this stack's authentication --
# implemented today by lldap specifically (a lightweight, LDAP-speaking
# user/group store with its own small web admin UI). Named after the actual
# upstream project rather than an abstract "ldap-directory" role, matching
# this repo's convention: a fake generic interface with exactly one
# implementation behind it documents a boundary that doesn't exist. If a
# second directory backend is ever added, it gets its own module.
#
# Non-goal, stated up front because it is easy to want the opposite: this
# module manages the lldap SERVER (the process, its listeners, its systemd
# unit) and nothing else. It deliberately exposes no options for declaring
# users, groups, group memberships, passwords, or alias VALUES -- the
# records living inside the directory are not configuration, they are data,
# and a real deployment this module was extracted from lost real user data
# once to a declarative bootstrap job that matched existing directory
# entries by DN and overwrote them on every apply. Provision identity
# out-of-band, through lldap's own admin UI/API or a restore from backup,
# and treat the running database as live state you back up -- never as
# something Nix should assert into existence. (The DIRECTORY SCHEMA --
# which group DNs and attribute names your other services expect to find --
# is legitimately configuration and belongs in whatever module consumes it,
# e.g. a mail server's LDAP-directory client config; the schema and the
# records inside it are different things.)
#
# Note for anyone writing a client against this directory: lldap lowercases
# every attribute name it returns over LDAP, regardless of how that
# attribute was created or named in lldap's own admin UI. A client that
# looks an attribute up by an exact, case-sensitive configured key (rather
# than case-insensitively) will silently miss a camelCase or PascalCase
# attribute name -- often in a way that only breaks HALF of a feature (e.g.
# inbound matching still works because a directory-side filter compares
# case-insensitively, while an outbound feature that indexes by the exact
# key comes up empty) rather than failing outright. This is lldap's own
# behavior, not a bug in any particular client, so it belongs in this
# module's documentation even though no option here is affected by it
# directly.
#
# Deviations from plain `services.lldap`, and why each one exists:
#
#   1. Static system user, uid/gid forced non-dynamic (see `uid` below for
#      the full failure chain this fixes -- upstream's own default broke a
#      real deployment in a way whose symptom pointed nowhere near its
#      cause). The correct long-term fix is a nixpkgs PR against
#      `services.lldap` itself; this module's override is a stopgap, not a
#      permanent home for the fix.
#   2. `StateDirectory=` dropped in favor of `ReadWritePaths=` when your
#      state directory is itself a bind mount rather than a plain directory
#      systemd is free to create (see `stateDirIsBindMount`).
#   3. `AmbientCapabilities`/`CapabilityBoundingSet` grant exactly the
#      capability needed to bind a privileged port, and only when
#      `ldapPort` actually is one -- mirroring nixnet's own pattern of
#      computing capabilities from what's actually configured rather than
#      granting them unconditionally.
#   4. The encryption key seed is wired via `EnvironmentFile`, because
#      lldap exposes no `_FILE`-suffixed variant for that one setting only
#      -- every other secret it takes has a normal `*_FILE` option this
#      module can point at a path instead.
#
# No pinned/patched lldap build ships here (a previous, unpublished version
# of this module carried one, version-coupled to a specific nixpkgs
# revision via an override argument name that nixpkgs itself renamed on an
# unrelated bump, breaking evaluation for days). `package` below is a plain
# `pkgs.lldap` by default; see that option for the one real caveat that
# survives the simplification.

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.nixmail.lldap;

  # Shared by `baseDn`'s default and (indirectly, via `domain`) `adminEmail`'s.
  # Not shared code with any other module yet -- there is no shared
  # `modules/core.nix` in this repo today. If a Stalwart-equivalent module
  # is ever extracted here, it will need this exact same base DN to talk to
  # this same directory; a small shared module (mirroring nixnet's
  # `core.nix`) is the right place for `domain`/`baseDn` to live at that
  # point, so the two option sets share one location instead of agreeing by
  # convention. Not done here because that consuming module doesn't exist
  # in this repo yet.
  domainToBaseDn = domain:
    concatMapStringsSep "," (p: "dc=${p}") (splitString "." domain);

  # Best-effort, boot-time-only check for `exposeOnInterfaces` -- see that
  # option's description for the real production incident this is trying
  # to catch a repeat of. Interface names are plain strings to the Nix
  # module system; nothing at build time can check they name a real,
  # live interface (many VPN/mesh overlay interfaces are created by a
  # userspace daemon at runtime and never appear in any static NixOS
  # network config at all), so this can only ever be a runtime, advisory
  # check -- never promote it to a hard failure, since a legitimately slow-
  # starting overlay network at boot would look identical to a genuinely
  # wrong name.
  interfaceCheckScript = pkgs.writeShellScript "nixmail-lldap-interface-check" ''
    set -euo pipefail
    ${concatMapStringsSep "\n" (ifn: ''
      if ! ${pkgs.iproute2}/bin/ip link show ${escapeShellArg ifn} >/dev/null 2>&1; then
        echo "nixmail lldap: exposeOnInterfaces names '${ifn}', but no such interface exists on this host (checked at boot)." >&2
        echo "  The firewall rule for it is harmless but INERT right now -- port ${toString cfg.ldapPort} is not actually reachable via '${ifn}'." >&2
        echo "  If this interface is brought up later by something else (a VPN client that starts after this check), this warning is stale; if it never appears, the name is wrong." >&2
      fi
    '') cfg.exposeOnInterfaces}
  '';
in
{
  options.services.nixmail.lldap = {
    enable = mkEnableOption ''
      the LDAP identity directory (implemented by lldap) backing this
      stack's authentication
    '';

    package = mkPackageOption pkgs "lldap" {
      extraDescription = ''
        lldap's on-disk SQLite schema is versioned, and a version jump can
        bump the schema; migrations are one-way. Pinning this to a
        version older than the one that last wrote an existing database
        will fail to open it (or, in some historical lldap releases,
        silently downgrade the schema) rather than reading it correctly.
        If you are restoring state from a backup or moving a database
        between hosts, match this package's lldap version to whichever
        version last wrote that database before changing anything else.
      '';
    };

    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "example.com";
      description = ''
        Organization/mail domain this directory serves. lldap itself has
        no concept of "domain" at all -- only a base DN and a set of
        attribute values -- so this option exists purely as a convenience
        default source for `baseDn` and `adminEmail` below, for the common
        case where a deployment's base DN and admin address both mirror
        its mail domain (`"example.com"` -> `"dc=example,dc=com"` and
        `"admin@example.com"`). If yours don't, or you would rather not
        derive anything from a single value, leave this unset and set
        `baseDn`/`adminEmail` explicitly instead -- this option then goes
        unused.
      '';
    };

    baseDn = mkOption {
      type = types.str;
      default =
        if cfg.domain == null then
          throw ''
            services.nixmail.lldap.baseDn has no default because
            services.nixmail.lldap.domain is not set. Either set `domain`
            (e.g. "example.com") so a base DN can be derived from it, or
            set `baseDn` explicitly (e.g. "dc=example,dc=com").
          ''
        else
          domainToBaseDn cfg.domain;
      description = ''
        LDAP base DN, e.g. `"dc=example,dc=com"`. Defaults to a derivation
        from `domain` (splitting it on `.` into `dc=` components), but is
        deliberately overridable on its own -- not every deployment's base
        DN mirrors its mail domain. Any other module in your configuration
        that talks to this directory (a mail server's LDAP directory
        client, an OIDC/SSO provider's LDAP sync) needs to agree on this
        exact value; if you run more than one such module, set this once
        and have the others reference `config.services.nixmail.lldap.baseDn`
        rather than repeating the literal string, so the two can never
        silently drift apart.
      '';
    };

    adminUser = mkOption {
      type = types.str;
      default = "admin";
      description = ''
        `ldap_user_dn`: the username component of lldap's own admin
        account, relative to `baseDn`. This is the identity lldap itself
        authenticates as for its own admin UI/API and the one every other
        service's LDAP bind DN is built from -- it is not a general user
        provisioning mechanism (see the module header's non-goal note).
      '';
    };

    adminEmail = mkOption {
      type = types.str;
      default =
        if cfg.domain == null then
          throw ''
            services.nixmail.lldap.adminEmail has no default because
            services.nixmail.lldap.domain is not set. Either set `domain`
            (e.g. "example.com"), or set `adminEmail` explicitly.
          ''
        else "admin@${cfg.domain}";
      description = "`ldap_user_email`: the email address recorded against the admin account above.";
    };

    ldapHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address lldap's LDAP listener binds. Defaults to loopback-only,
        the safe choice for a fresh install. If other hosts need to reach
        this directory at all (the entire point of running a shared
        identity store), lldap gives you exactly one address to bind --
        there is no per-interface bind list -- so the documented pattern
        here is to bind wide (typically `"0.0.0.0"`) and then scope who
        can actually reach it via `exposeOnInterfaces` below, rather than
        trying to pick one "right" interface address by hand.

        Whatever you choose: lldap speaks plain LDAP only on this listener
        -- there is no LDAPS here, upstream or in this module. Binding
        beyond loopback without some other layer of transport encryption
        already in front of it (a VPN/mesh overlay, an SSH tunnel, a
        reverse proxy doing STARTTLS/TLS termination) means directory
        contents and bind credentials cross the network in the clear.
      '';
    };

    ldapPort = mkOption {
      type = types.port;
      default = 389;
      description = ''
        LDAP listen port. Standard plain-LDAP port; see `ldapHost` for why
        this module never configures LDAPS and what to put in front of
        this port instead if it needs to leave loopback.
      '';
    };

    httpHost = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address lldap's admin web UI / REST API binds. Kept loopback-only
        by default -- the API and UI carry their own session/auth model,
        but there is no reason to expose them more widely than whatever
        actually needs to reach them; front this with your own reverse
        proxy (adding TLS and, ideally, an additional access boundary) if
        you need it reachable beyond this host.
      '';
    };

    httpPort = mkOption {
      type = types.port;
      default = 17170;
      description = "Port lldap's admin web UI / REST API binds, on `httpHost`.";
    };

    exposeOnInterfaces = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Interface names to open `ldapPort` on, via
        `networking.firewall.interfaces.<name>.allowedTCPPorts` -- the
        firewall-side half of the bind-wide-but-scoped pattern described
        on `ldapHost`. Left empty by default: NixOS's firewall does not
        open a port anywhere just because a service binds it, so an empty
        list here means the port stays closed on every interface
        regardless of what `ldapHost` is set to.

        This exists, and is checked at boot (see below), because of a
        real failure mode worth designing around: an earlier deployment
        of this exact pattern named a specific VPN/mesh overlay interface
        here, then migrated to a different VPN product entirely (a
        different interface name) without updating this setting. NixOS
        accepted the stale name without complaint -- interface names are
        just strings to the module system, nothing at build time checks
        they correspond to a real, live interface -- so the rule kept
        referencing an interface that no longer existed on the box, and
        this entire defense-in-depth firewall layer was silently absent
        for an unknown period, discovered only much later rather than at
        the time of the migration. Every listed interface is checked
        against what's actually live on the host at boot (a systemd
        oneshot, logged to the journal, never fatal -- see the module
        implementation); it cannot catch an interface that only comes up
        later at runtime, but it does catch exactly the "renamed and
        forgotten" case that went unnoticed for so long here.
      '';
    };

    jwtSecretFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing lldap's JWT signing secret (used to
        sign session tokens issued by the admin web UI / REST API). No
        default -- provisioning a real secret here is entirely your
        responsibility. Must exist and be readable before lldap's unit
        starts; list whatever provisions it in `dependsOnUnits` below.
      '';
    };

    adminPasswordFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing the admin account's password. Read once
        at first start (`silenceForceUserPassResetWarning` is set below
        because after that first start, the running directory -- not this
        file -- is the source of truth for the admin password; lldap's own
        upstream warning exists to flag exactly that kind of drift, which
        here is expected and accepted, not a misconfiguration). No default
        -- see `jwtSecretFile` for the same provisioning expectation.
      '';
    };

    keySeedEnvFile = mkOption {
      type = types.path;
      description = ''
        Path to an EnvironmentFile-format file containing exactly one
        line, `LLDAP_KEY_SEED=<seed>`. This is wired via `EnvironmentFile`
        rather than a `*_FILE`-style path option like the two above
        because lldap exposes no `_FILE` variant for this one setting --
        it is the sole exception among lldap's secrets. The seed is used
        to derive the private key that encrypts every user password
        stored in lldap's database.

        CRITICAL: this value MUST remain exactly what it was when the
        database was first created (or last had its passwords encrypted).
        Rotating it does not re-encrypt anything with a new key -- it
        makes every already-stored password hash permanently
        undecryptable, i.e. every user is locked out simultaneously with
        no in-place recovery short of resetting every password from
        scratch. Treat this file with at least as much care as the
        database itself: back it up alongside it, and never regenerate it
        as a matter of routine secret rotation.
      '';
    };

    uid = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = ''
        Fixed uid for the lldap system user, or `null` to let NixOS
        allocate one automatically. Either way, this module always
        creates a STATIC system user (`isSystemUser = true`) and
        explicitly forces `DynamicUser = false` on the service below --
        never left at upstream's own default.

        Why this matters, from a real production failure: `services.lldap`
        upstream defaults to `DynamicUser = true`. Under DynamicUser, the
        `lldap` user does not exist yet at the point `systemd-tmpfiles`
        runs at boot, so any tmpfiles rule that chowns lldap's data
        directory to that user (needed whenever the directory is, say, a
        pre-existing bind mount rather than something systemd creates
        itself) fails outright with "Unknown user 'lldap'". The directory
        is left `root:root 0700`, and lldap -- now running as some
        transient, per-boot uid -- cannot open its own SQLite database:
        `(code: 14) unable to open database file`. The failure then
        surfaces nowhere near its actual cause: every authenticated LDAP
        bind against the directory (an SSO service's sync job, anything
        else logging in) fails with LDAP code 49, "Invalid Credentials" --
        which reads exactly like a wrong-password problem and sends
        whoever's debugging it looking at credentials, not filesystem
        ownership, for however long it takes to notice the connection.

        Forcing a static user removes the ordering hazard entirely: the
        user exists before tmpfiles ever runs, so ownership is always
        correct regardless of boot order. Set a fixed number only if it
        needs to match whatever uid already owns files on disk (e.g.
        moving this same data to a different host); otherwise `null`
        (auto-allocated, but still static, never dynamic) is fine.

        The correct long-term fix is a nixpkgs PR making
        `services.lldap`'s own default a static user; this option is a
        working stopgap for consumers of this module in the meantime, not
        a claim that this is where the fix should permanently live.
      '';
    };

    gid = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = ''
        Fixed gid for the lldap system group, or `null` to auto-allocate.
        See `uid` for why this module forces a static (non-dynamic) user
        and group regardless of whether either number is pinned.
      '';
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "sqlite:///var/lib/lldap/users.db?mode=rwc";
      description = ''
        lldap's `database_url` setting. The default assumes `stateDir`
        is left at its own default; if you change `stateDir`, update this
        to match -- the two are not automatically kept in sync (lldap
        reads this as an opaque connection string; it has no notion of
        `stateDir` as a separate concept at all).
      '';
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/lldap";
      description = "Directory lldap keeps its SQLite database and other state in.";
    };

    stateDirIsBindMount = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Set true if `stateDir` is a bind mount from elsewhere (a separate
        data disk/dataset mounted at boot by something outside this
        module) rather than a plain directory systemd itself is free to
        create and own via `StateDirectory=`. The two cases need
        genuinely different systemd wiring, not just a different path
        string:

        - `false` (default, the common case): this module lets upstream's
          `StateDirectory=` mechanism create and own `stateDir` under
          systemd's normal `/var/lib` management, same as most services.
        - `true`: upstream's `ProtectSystem = "strict"` makes the whole
          `/var/lib` tree read-only to the service except for whatever
          `StateDirectory=` itself created. A directory that already
          existed before systemd got there (your bind mount) is not that
          -- so this module drops `StateDirectory=` entirely and grants
          `ReadWritePaths = [ stateDir ]` instead, which punches exactly
          one hole through the read-only tree for the path that's already
          there, without loosening anything else in the hardening
          profile. Get this flag backwards (`false` against a directory
          that is actually a bind mount) and `ProtectSystem = "strict"`
          simply makes that pre-existing directory read-only to the
          service, since nothing ever granted it the exemption --
          lldap fails to write its own database, the same
          "unable to open database file" symptom described on `uid`, for
          a completely different underlying reason.
      '';
    };

    dependsOnUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Extra systemd units lldap depends on -- typically whatever unit
        provisions `jwtSecretFile`, `adminPasswordFile`, and
        `keySeedEnvFile` at boot (a secrets-fetch service, a
        sops-nix/agenix activation, or anything else that writes those
        paths before this service starts). Wired into both `after` and
        `requires` below, deliberately: `after` alone only delays lldap
        relative to that unit, it does not verify the unit actually
        reached an active state first. Because `EnvironmentFile =
        keySeedEnvFile` makes a genuinely missing file a hard failure at
        start time (systemd refuses to start the unit at all) rather than
        a silent partial-config start, listing your secrets unit here
        turns "lldap fails and restarts in a loop right after every boot
        until secrets happen to show up" into "lldap correctly waits for
        secrets, then starts once".
      '';
    };
  };

  config = mkIf cfg.enable {
    services.lldap = {
      enable = true;
      package = cfg.package;

      # Admin password is (re)applied only on lldap's own first start; from
      # then on the running directory is the source of truth, since the UI
      # lets the admin change it. Silences upstream's warning about exactly
      # that drift, which here is expected, not a misconfiguration -- see
      # `adminPasswordFile`'s own description.
      silenceForceUserPassResetWarning = true;

      settings = {
        ldap_host = cfg.ldapHost;
        ldap_port = cfg.ldapPort;
        http_host = cfg.httpHost;
        http_port = cfg.httpPort;
        ldap_base_dn = cfg.baseDn;
        ldap_user_dn = cfg.adminUser;
        ldap_user_email = cfg.adminEmail;
        database_url = cfg.databaseUrl;
      };

      environment = {
        LLDAP_JWT_SECRET_FILE = cfg.jwtSecretFile;
        LLDAP_LDAP_USER_PASS_FILE = cfg.adminPasswordFile;
      };
    };

    # Static system user/group -- see `uid`'s description for the failure
    # chain this fixes. `isSystemUser = true` (as opposed to leaving
    # `DynamicUser = true`, upstream's own default) is what makes this a
    # real, static user that exists before systemd-tmpfiles runs, whether
    # or not a fixed number is pinned below.
    users.users.lldap = {
      isSystemUser = true;
      group = "lldap";
    } // optionalAttrs (cfg.uid != null) { uid = cfg.uid; };

    users.groups.lldap = optionalAttrs (cfg.gid != null) { gid = cfg.gid; };

    networking.firewall.interfaces = genAttrs cfg.exposeOnInterfaces (_: {
      allowedTCPPorts = [ cfg.ldapPort ];
    });

    # Best-effort warning for a stale/renamed entry in `exposeOnInterfaces`
    # -- see that option's description. Deliberately never fails the boot;
    # a wrong name here means a firewall rule is silently inert, not that
    # the service itself is broken.
    systemd.services.nixmail-lldap-interface-check = mkIf (cfg.exposeOnInterfaces != [ ]) {
      description = "Check that services.nixmail.lldap.exposeOnInterfaces names live interfaces";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${interfaceCheckScript}";
      };
    };

    systemd.services.lldap = {
      after = cfg.dependsOnUnits;
      requires = cfg.dependsOnUnits;

      serviceConfig = {
        DynamicUser = mkForce false;
        User = mkForce "lldap";
        Group = mkForce "lldap";
        # Bind capability granted only when actually binding a privileged
        # port -- mirrors nixnet's own pattern (see core.nix's
        # needsNetAdmin/needsNetRaw) of computing capabilities from what's
        # actually configured rather than granting them unconditionally.
        AmbientCapabilities = optional (cfg.ldapPort < 1024) "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = optional (cfg.ldapPort < 1024) "CAP_NET_BIND_SERVICE";
        # lldap has no `_FILE` variant for LLDAP_KEY_SEED -- see
        # `keySeedEnvFile`'s own description for why this is the one
        # secret wired this way instead of via `environment` above.
        EnvironmentFile = cfg.keySeedEnvFile;
      } // optionalAttrs cfg.stateDirIsBindMount {
        StateDirectory = mkForce "";
        ReadWritePaths = [ cfg.stateDir ];
      };
    };
  };
}
