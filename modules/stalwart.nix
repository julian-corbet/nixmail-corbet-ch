# modules/stalwart.nix
#
# Stalwart Mail Server (0.16.x): a custom module, NOT nixpkgs' own
# `services.stalwart`. Since 0.16, Stalwart abandoned static TOML config
# entirely -- the on-disk `config.json` names only the data store, and
# EVERYTHING else (listeners, the LDAP directory, MTA routing, TLS certs,
# domains, CORS, the admin webui, spam-filter rules) lives in the data
# store as "registry objects", applied over Stalwart's own JMAP management
# API via `stalwart-cli apply` (one JSON object per line -- NDJSON). This
# module renders that plan from ordinary Nix option values and drives it
# with a small bootstrap unit; nixpkgs' `services.stalwart` still targets
# the old, abandoned 0.15 TOML shape and cannot express any of this.
#
# TESTED VERSION PAIR: stalwart 0.16.10-0.16.13 against stalwart-cli 1.0.8.
# The registry object schema this module encodes is NOT a documented,
# stable upstream API -- it was reverse-engineered from `stalwart-cli
# describe` output and trial apply runs against a real instance. Treat any
# nixpkgs bump that changes either package as a "re-validate the whole
# plan" event, not a routine update: field shapes, especially the
# Map<T>-style attributes handled by `mkSet` below, have already changed
# meaning between minor releases once.
#
# STRUCTURAL LIMITATION -- READ BEFORE RELYING ON THIS MODULE FOR
# RECONFIGURATION: the rendered plan is CREATE-ONLY and is a FRESH-DATABASE
# BOOTSTRAP, not a reconciler. stalwart-cli 1.0.8 has no `upsert` verb, and
# a plain `create` against an object that already exists in the database
# both fails outright (primary-key violation) AND leaves any `#localId`
# cross-reference pointing at it dangling. So the bootstrap unit below
# applies the plan exactly once, to an empty database, and thereafter
# refuses to touch a database that already has the plan's domains in it
# (see the "SAFETY GUARD" comment on the unit itself for the concrete
# incident this prevents). Changing `nixmail.stalwart.*` options
# on an ALREADY-BOOTSTRAPPED system does NOT reach the live server -- you
# must reconcile the running database by hand with `stalwart-cli`
# (get/query/update/create/destroy/describe/apply --dry-run). Building an
# actual reconciler (query current state, diff against the desired plan,
# emit only the deltas) is real, separate design work this module does not
# attempt.
#
# DKIM is intentionally absent from the rendered plan. Stalwart 0.16
# auto-generates its own per-domain DKIM keypair at first init; the only
# Nix-representable part of that story would be a secret file path for a
# private key nothing in this module provisions, which is strictly worse
# than shipping nothing. Publish the auto-generated public key as a
# `_domainkey` TXT record by hand (`stalwart-cli` can dump it) for each
# domain you actually send mail from.
#
# NO AUTOMATED TEST YET EXERCISES THE APPLY-PLAN. Before depending on this
# module, at minimum hand-verify `stalwart-cli apply --dry-run --file
# <rendered-plan>` against a throwaway instance; a NixOS VM test that boots
# a fresh database and asserts the plan applies cleanly is the right
# long-term fix and does not exist here yet.

{ probeFact, collectProbes }:
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.nixmail.stalwart;

  # ── nixiam.posix: read through `lib.probeFact` ────────────────────────────
  # nixmail references nixiam nowhere else in this repo -- this is the one
  # place a name this module already owns (`user`/`group`) gets resolved
  # against the cross-host identity table nixiam.posix.identities/.groups
  # keeps, mirroring the precedent nixstorage/modules/reconciler.nix set for
  # reading that exact same table (which itself reads nixiam this same way).
  #
  # A bare `config.nixiam.posix.… or { }` degrades to an empty attrset both
  # when a host never imported nixiam's posix module at all (legitimate,
  # silent) AND when it did but `identities`/`groups` moved, was renamed, or
  # was rejected by its own type (a defect, silently indistinguishable from
  # the first case with a bare `or`) -- see nixhost's own `lib/facts.nix`
  # header (github:julian-corbet/nixhost-corbet-ch) for the full defect class
  # this family lost real weeks to elsewhere. `probeFact` tells the two
  # apart: `nsIdentities`/`nsGroups` still resolve to `{ }` either way (this
  # module keeps evaluating, `uid`/`gid` simply unresolved, exactly as
  # before), but `identitiesProbe.warnings`/`groupsProbe.warnings` (spliced
  # into `config.warnings` below) render ONLY for the composed-but-broken
  # case. nixmail never imports nixiam and never will; it only reads a value
  # if one happens to be there.
  # The OWNER is `nixiam.posix`, not `nixiam`, and the distinction is load-bearing rather than
  # stylistic. nixiam ships lldap, pocket-id, vaultwarden, users and posix as separately-composable
  # modules under one namespace, and a host may take some and not others -- the mail host takes
  # lldap and pocket-id and NOT posix. Probing `nixiam` sees the namespace present (lldap declared
  # it), finds `posix.identities` missing, and reports "the option moved or was renamed". Nothing
  # moved; posix was simply never composed. That was live here: two warnings on every evaluation of
  # the mail host, each pointing at a rename that does not exist. Naming the owner subtree puts the
  # composed-test on the actual module boundary.
  identitiesProbe = probeFact {
    inherit config;
    namespace = "nixiam.posix";
    path = "identities";
    fallback = { };
  };
  groupsProbe = probeFact {
    inherit config;
    namespace = "nixiam.posix";
    path = "allGroups";
    fallback = { };
  };
  nsIdentities = identitiesProbe.value;
  nsGroups = groupsProbe.value;

  # Duplicated rather than imported -- the same call nixstorage's reconciler
  # already made for this identical three-line function, for the same
  # reason: mirrors nixiam.posix's own private `resolvedGid` (modules/
  # posix.nix). An unset `gid` on an identity is a User Private Group,
  # numerically equal to that identity's own uid.
  identGid = ident: if ident.gid == null then ident.uid else ident.gid;

  # `user` is ALREADY the name this identity is known by across every host -- no
  # new "which identity" option to add here, unlike nixboot's
  # `esp.fromLayout` (which needed one because a single nixstorage host can
  # describe several media at once with no way to guess which one is
  # THIS host's). nixmail only ever runs one Stalwart identity per host,
  # already named by `cfg.user`, so that name IS the lookup key -- see the
  # `uid`/`gid` option descriptions below for why an explicit value there
  # still always wins over whatever this resolves to.
  stalwartIdentity = nsIdentities.${cfg.user} or null;

  # A group NAME can resolve two different ways in nixiam's own model (see
  # nixstorage/modules/reconciler.nix's `resolveOwnerGid`, the fuller,
  # non-defaulting form of this same lookup): a cross-host SHARED group
  # (nixiam.posix.groups, meant to be joined by more than one identity), or
  # one identity's own resolved primary gid (nixiam.posix.identities.<name>,
  # UPG-resolved). Check the shared-group table first -- it exists
  # specifically for names meant to cross identities -- then fall back to
  # treating the name as an identity of its own, which covers the shape
  # this module ships by default: `group` equal to `user`, one identity,
  # one UPG. Unlike the reconciler, this does NOT throw when a name exists
  # in both tables with disagreeing numbers: this is only ever a DEFAULT,
  # silently overridable by an explicit `gid = N;` (see that option below),
  # not a value anything gets chowned to on its say-so alone -- the
  # reconciler's ambiguity guard earns its keep guarding an action; nothing
  # here acts.
  stalwartGid =
    if nsGroups ? ${cfg.group} then nsGroups.${cfg.group}
    else if nsIdentities ? ${cfg.group} then identGid nsIdentities.${cfg.group}
    else null;

  # Only domains with `enable = true` ever reach the rendered plan -- see
  # the `domains.<name>.enable` option doc for why "disabled" and "not yet
  # created" are the only two states this module can express (it cannot
  # retract a domain already created in a live database; see the
  # module-level structural-limitation comment above).
  enabledDomains = filterAttrs (_: d: d.enable) cfg.domains;

  # The one and only place a Domain's `#localId` cross-reference name is
  # decided -- every other reference to a domain (SystemSettings.
  # defaultDomainId, in the future any other op that needs to point at a
  # specific domain) MUST go through this same function, or the two sides
  # silently stop matching.
  domainLocalId = name: "d-" + name;

  resolvedBindDn =
    if cfg.ldap.bindDn != null
    then cfg.ldap.bindDn
    else "uid=admin,ou=people,${cfg.ldap.baseDn}";

  # LDAP filter placeholders ({user}/{email}) are Stalwart's own syntax.
  # Both the login filter and the mailbox (recipient-acceptance) filter OR
  # in one clause per configured alias attribute, so a principal can
  # authenticate or receive mail under any of their secondary addresses,
  # not just their primary `mail` value.
  aliasLoginOrs = concatMapStrings (a: "(${a}={user})") cfg.ldap.attrEmailAlias;
  aliasEmailOrs = concatMapStrings (a: "(${a}={email})") cfg.ldap.attrEmailAlias;

  # Stalwart's 0.16 registry schema represents several attributes (LDAP
  # attribute-name mappings, listener `bind` addresses, URL prefix sets) as
  # a `Map<T>` that this module's original reverse-engineering found
  # deserializes from a boolean-valued JSON OBJECT (`{"item": true, ...}`),
  # not a JSON array -- exactly one example in upstream's own docs showed
  # array form instead. This is the ONLY place that decision is made: if
  # `stalwart-cli apply --dry-run` rejects the object form against the
  # version you're running, changing this one function to `items: items`
  # (array form) flips the entire rendered plan at once. Re-verify this
  # against `stalwart-cli describe` whenever you bump either package.
  mkSet = items: builtins.listToAttrs (map (i: nameValuePair i true) items);

  # Regex-escape a literal domain name for use inside the bootstrap guard's
  # `grep -E` pattern below (only `.` needs it -- domain names don't
  # otherwise contain ERE metacharacters).
  escapeDotsForRegex = s: replaceStrings [ "." ] [ "\\." ] s;
  domainGuardPattern = concatStringsSep "|" (map escapeDotsForRegex (attrNames enabledDomains));

  # ── Offline "Application" resources ─────────────────────────────────────
  # Stalwart's admin/account webui and its spam-filter ruleset are shipped
  # as 0.16 "Application" resources normally fetched from a GitHub release
  # URL AT RUNTIME. On a host that cannot reach that CDN at runtime (the
  # reference deployment this module was extracted from is IPv6-only;
  # objects.githubusercontent.com has no IPv6 route), that fetch just hangs
  # or fails forever. Baking both as fixed-output derivations means the
  # FETCH happens on whatever machine BUILDS this configuration (which only
  # needs to be dual-stack once, not the deployed box), and the plan then
  # points Stalwart at the resulting store path via a `file://` URL --
  # `offlineResources.*` lets a consumer on a fully dual-stack host set
  # these to `null` instead and let Stalwart fetch normally at its own
  # runtime.
  #
  # Each pin is one record (URL + hash), not two facts spread across the file -- a version bump
  # would otherwise mean editing both by hand with nothing checking they still describe the same
  # release. `version` below is DERIVED from the URL (every upstream release URL embeds it as
  # `/vX.Y.Z/`) rather than a third hand-typed copy of the same fact -- a URL bumped without also
  # updating a separately-maintained version string is exactly the kind of drift this module's own
  # outbound-bridge sibling documents elsewhere.
  #
  # Exposed below as read-only `offlineResources.webuiSource` /
  # `...spamFilterRulesSource` options (url, hash, version) specifically so
  # a supply-chain audit can read what this deployment is pinned to via
  # `nix eval`, instead of having to open this file -- pinned upstream
  # asset versions are exactly the kind of fact an auditor asks about, not
  # one they merely read once and move on from.
  versionFromReleaseUrl = url:
    let m = builtins.match ".*/v([0-9][0-9.]*)/.*" url;
    in
    if m == null then
      throw "nixmail stalwart: could not extract a /vX.Y.Z/ version segment from release URL: ${url}"
    else
      elemAt m 0;

  mkPinnedSource = { url, hash }: {
    inherit url hash;
    version = versionFromReleaseUrl url;
  };

  webuiSource = mkPinnedSource {
    url = "https://github.com/stalwartlabs/webui/releases/download/v1.0.4/webui.zip";
    hash = "sha256-pT2uAazbpMvl+cthzN/EErZiSYHFy+ATJo3S/RCYUHg=";
  };
  spamRulesSource = mkPinnedSource {
    url = "https://github.com/stalwartlabs/spam-filter/releases/download/v3.0.0/spam-filter-rules.json.gz";
    hash = "sha256-xObN2h5oG2HtWWFuOJSp8rv/jJT8ugFCfDC1sLMP7vo=";
  };

  webuiUpstreamUrl = webuiSource.url;
  spamRulesUpstreamUrl = spamRulesSource.url;

  webuiZipFOD = pkgs.fetchurl {
    url = webuiSource.url;
    hash = webuiSource.hash;
  };
  spamRulesFOD = pkgs.fetchurl {
    url = spamRulesSource.url;
    hash = spamRulesSource.hash;
  };

  # ── on-disk config.json: 0.16 = a single DataStore object, nothing else.
  configJson = pkgs.writeText "stalwart-config.json" (
    builtins.toJSON {
      "@type" = "RocksDb";
      path = cfg.dataDir;
    }
  );

  # ── Registry-object builders (one function per object "shape") ─────────

  domainOp = name: d: {
    "@type" = "create";
    object = "Domain";
    value.${domainLocalId name} =
      {
        inherit name;
        # Always true: entries with `enable = false` never reach this
        # function at all (see `enabledDomains` above) -- there is no
        # "created but disabled" state in the registry model.
        isEnabled = true;
        subAddressing."@type" = if d.subAddressing then "Enabled" else "Disabled";
        # Deliberately no per-domain `directoryId`: every domain uses the
        # single system-default directory wired up via `Authentication.
        # directoryId` below, so this op never needs a forward reference to
        # the (not-yet-created-at-this-point) directory object.
      }
      // optionalAttrs (d.catchAll != null) { catchAllAddress = d.catchAll; };
  };

  directoryOp = {
    "@type" = "create";
    object = "Directory";
    value.dir-ldap = {
      "@type" = "Ldap";
      description = cfg.ldap.description;
      url = cfg.ldap.url;
      # Fixed rather than an option: this object models a directory
      # reached over a trusted local/loopback path, matching every
      # deployment this module has actually been run against. A directory
      # reached over an untrusted network would need `useTls`/
      # `allowInvalidCerts` exposed too -- not yet needed, so not yet
      # built; raise it if your deployment needs LDAP-over-TLS.
      useTls = false;
      allowInvalidCerts = false;
      baseDn = cfg.ldap.baseDn;
      bindDn = resolvedBindDn;
      bindSecret = {
        "@type" = "File";
        filePath = cfg.ldap.bindPasswordFile;
      };
      # "search-then-bind": Stalwart looks the principal up via
      # filterLogin first, then binds AS that principal using the
      # password the client supplied -- never reads/compares a stored
      # hash itself. This is deliberate: it lets Stalwart authenticate
      # against a directory that stores passwords in a form the mail
      # server can't and shouldn't be able to inspect (see `attrSecret`
      # below for the corollary trick this enables).
      bindAuthentication = true;
      inherit (cfg.ldap) filterLogin filterMailbox filterMemberOf;
      attrClass = mkSet [ "objectClass" ];
      attrEmail = mkSet cfg.ldap.attrEmail;
      attrEmailAlias = mkSet cfg.ldap.attrEmailAlias;
      # Deliberately points at an attribute name that does not exist in the
      # directory schema. Because `bindAuthentication = true` above means
      # Stalwart never actually reads a stored secret/hash through this
      # mapping -- the bind IS the auth check -- this field only needs to
      # satisfy the registry schema's "a secret attribute is configured"
      # requirement, not resolve to real data. Proven against a real
      # directory; re-verify with `stalwart-cli describe Directory` if a
      # future version starts validating this field's target exists.
      attrSecret = mkSet cfg.ldap.attrSecret;
      attrMemberOf = mkSet cfg.ldap.attrMemberOf;
      groupClass = cfg.ldap.groupClass;
      poolMaxConnections = cfg.ldap.poolMaxConnections;
    };
  };

  certPaths =
    if cfg.acme.enable then {
      certificateFile = "/var/lib/acme/${cfg.acme.hostname}/fullchain.pem";
      keyFile = "/var/lib/acme/${cfg.acme.hostname}/key.pem";
    } else if cfg.tls.certificateFile != null && cfg.tls.keyFile != null then {
      inherit (cfg.tls) certificateFile keyFile;
    } else null;

  certOp = optional (certPaths != null) {
    "@type" = "create";
    object = "Certificate";
    value.cert-primary = {
      certificate = {
        "@type" = "File";
        filePath = certPaths.certificateFile;
      };
      privateKey = {
        "@type" = "File";
        filePath = certPaths.keyFile;
      };
      # subjectAlternativeNames is SERVER-SET (parsed straight out of the
      # PEM by Stalwart itself) -- there is no field to set it through.
    };
  };

  listenerOp = localId: name: l: {
    "@type" = "create";
    object = "NetworkListener";
    value.${localId} = {
      inherit name;
      inherit (l) protocol useTls tlsImplicit;
      bind = mkSet [ l.bind ];
    };
  };

  # The four well-known native-client ports (IMAPS/SMTPS/Submission/POP3S)
  # are IANA-standard, not deployment-specific, so only the BIND ADDRESS is
  # a real option (`publicListeners.bindAddress`) -- the port/protocol/TLS
  # shape of each is fixed.
  publicListenerSpecs = [
    { name = "imaps-public"; port = 993; protocol = "imap"; useTls = true; tlsImplicit = true; }
    { name = "submissions-public"; port = 465; protocol = "smtp"; useTls = true; tlsImplicit = true; }
    { name = "submission-public"; port = 587; protocol = "smtp"; useTls = true; tlsImplicit = false; }
    { name = "pop3s-public"; port = 995; protocol = "pop3"; useTls = true; tlsImplicit = true; }
  ];

  smarthostOps = optionals (cfg.smarthost != null) (
    [
      {
        "@type" = "create";
        object = "MtaRoute";
        value.${"relay-" + cfg.smarthost.name} = {
          "@type" = "Relay";
          inherit (cfg.smarthost) name port protocol;
          address = cfg.smarthost.host;
          implicitTls = cfg.smarthost.implicitTls;
          allowInvalidCerts = cfg.smarthost.allowInvalidCerts;
          authSecret."@type" = "None";
        };
      }
    ]
    ++ optional cfg.forceOutboundThroughSmarthost {
      "@type" = "update";
      object = "MtaOutboundStrategy";
      value.route = {
        # 0.16's Expression form is {else, match:[{if,then}]} -- NOT a flat
        # if/then/else -- and `match` is an OBJECT keyed "0","1",... rather
        # than a JSON array. Deviating from either shape silently fails to
        # match anything rather than erroring.
        "else" = "'${cfg.smarthost.name}'";
        match."0" = {
          "if" = "is_local_domain(rcpt_domain)";
          "then" = "'local'";
        };
      };
    }
  );

  authenticationOp = {
    "@type" = "update";
    object = "Authentication";
    value = {
      directoryId = "#dir-ldap";
      # Assigning default ROLES is what actually grants LDAP-authenticated
      # principals mail permissions -- without this they authenticate fine
      # and then get a 403 on every mail operation, because a fresh 0.16
      # init sets these automatically but a 0.15->0.16 migration does NOT.
      # These built-in role ids are Stalwart's own STABLE internal
      # identifiers (b=User, c=Group, d=TenantAdmin, e=SystemAdministrator)
      # -- not something this module invents or that varies by deployment.
      defaultUserRoleIds = mkSet [ "b" ];
      defaultGroupRoleIds = mkSet [ "c" ];
      defaultAdminRoleIds = mkSet [ "e" "b" ];
      defaultTenantRoleIds = mkSet [ "d" "b" ];
    };
  };

  systemSettingsOp = {
    "@type" = "update";
    object = "SystemSettings";
    # No `defaultCertificateId` here: it is only the no-SNI fallback, and
    # every real native client connects by hostname (SNI), which selects
    # the right certificate via its subjectAlternativeNames regardless.
    value = {
      defaultHostname = cfg.publicHostname;
      defaultDomainId = "#" + domainLocalId cfg.defaultDomain;
    };
  };

  corsOp = optional cfg.permissiveCors {
    "@type" = "update";
    object = "Http";
    value.usePermissiveCors = true;
  };

  webuiOp = {
    "@type" = "create";
    object = "Application";
    value.app-webui = {
      description = "Stalwart WebUI (admin + account)";
      resourceUrl =
        if cfg.offlineResources.webui != null
        then "file://${cfg.offlineResources.webui}"
        else webuiUpstreamUrl;
      urlPrefix = mkSet cfg.offlineResources.webuiUrlPrefixes;
      enabled = true;
    };
  };

  spamSettingsOp = {
    "@type" = "update";
    object = "SpamSettings";
    value.spamFilterRulesUrl =
      if cfg.offlineResources.spamFilterRules != null
      then "file://${cfg.offlineResources.spamFilterRules}"
      else spamRulesUpstreamUrl;
  };

  # ── The full declarative apply-plan (NDJSON: one registry op per line) ──
  planOps =
    (mapAttrsToList domainOp enabledDomains)
    ++ [ directoryOp ]
    ++ certOp
    ++ (mapAttrsToList (name: l: listenerOp ("l-" + name) name l) cfg.listeners)
    ++ optionals cfg.publicListeners.enable (map
      (s: listenerOp ("l-" + s.name) s.name {
        inherit (s) protocol useTls tlsImplicit;
        bind = "${cfg.publicListeners.bindAddress}:${toString s.port}";
      })
      publicListenerSpecs)
    ++ smarthostOps
    ++ [ authenticationOp systemSettingsOp ]
    ++ corsOp
    ++ [ webuiOp spamSettingsOp ]
    ++ cfg.bootstrap.extraPlanOps;

  # The rendered plan body, bound as a Nix STRING rather than inlined into the
  # `writeText` call below, so that `planHash` can be taken from the string
  # itself. That is the whole reason this binding exists.
  #
  # Hashing the FILE instead (`builtins.readFile applyPlan`) is
  # import-from-derivation: it forces the plan derivation to be BUILT during
  # evaluation. On a host evaluating its own system that is merely slow; on an
  # x86_64 evaluator checking the aarch64-linux instance of this module -- which
  # is exactly what `nix flake check --all-systems` does -- it demands a build
  # for a platform the evaluator cannot run, and the check fails on the
  # evaluation rather than on anything about the configuration. Hashing the
  # string keeps evaluation pure: nothing is built to decide what the plan is.
  #
  # The two are the same bytes by construction -- `writeText` writes its text
  # argument verbatim -- so the recorded hash, and therefore the marker file
  # already sitting on every deployed host, are unchanged by this.
  applyPlanText = concatStringsSep "\n" (map builtins.toJSON planOps) + "\n";

  applyPlan = pkgs.writeText "stalwart-apply.ndjson" applyPlanText;

  # Hash of the rendered plan -- the bootstrap unit applies once per plan
  # version (identified by this hash), never on every boot.
  planHash = builtins.hashString "sha256" applyPlanText;

  # ── Mutable runtime settings (idempotent `update` ops) ────────────────────
  #
  # WHY THIS IS A SECOND PLAN AND NOT MORE LINES IN `planOps`.
  # `planOps` is create-only, and the stalwart-config unit below gates it
  # behind a virgin-database guard: once the database holds any of the plan's
  # own domains, that unit records the hash and returns WITHOUT applying
  # anything -- forever. That is right for `create` ops (re-creating a Domain
  # or Directory duplicates it and leaves dangling `#localId` references), but
  # it also means no value carried in that plan can ever be CHANGED again
  # after the first boot. Anything declared there is, on a live deployment,
  # decoration: the server keeps Stalwart's compiled-in default. That is how a
  # mail server ends up advertising a 100 MiB SMTP `SIZE` while the very next
  # hop refuses anything over 25 MiB -- accepted at submission, bounced later.
  #
  # `update` ops carry none of that hazard. They address singleton registry
  # objects by name, hold no `#localId` cross-reference that only resolves
  # inside the apply that created its target, and are idempotent -- applying
  # the same values twice is a no-op. So they get their own plan, their own
  # marker file and their own unit, with NO domain guard, re-applied whenever
  # the rendered values change.
  #
  # Shapes verified against stalwart-cli 1.0.12 on a live 0.16.16 registry with
  # `apply --dry-run`, which reported "0 destroy, 4 update, 0 create".

  # Drop options the consumer left at null, so an `update` only ever carries
  # fields that were actually declared. Without this a single unset option
  # would emit `null` and clear a value the module was never asked to manage.
  definedFields = filterAttrs (_: v: v != null);

  # One `update` op per registry object, omitted entirely when every field of
  # that object is unset -- an op with an empty value would change nothing and
  # still churn the plan hash, re-running the unit on every rebuild.
  settingsObjectOp = object: fields:
    let kept = definedFields fields;
    in optional (kept != { }) {
      "@type" = "update";
      inherit object;
      value = kept;
    };

  settingsOps =
    # `MtaStageData.maxMessageSize` is `object<Expression>`, NOT a bare number
    # (`stalwart-cli describe MtaStageData`). Its live shape is
    # `{match:{}, else:"<bytes>"}` with the byte count as a STRING; a plain
    # integer is rejected by the schema. `else` is a Nix keyword, hence quoted.
    #
    # `match` is an OBJECT keyed "0", "1", ... -- NOT a JSON array. Getting that
    # wrong does not error; it silently matches nothing and every port quietly
    # falls through to `else`. Stalwart's own shipped config uses the same shape
    # for `addReceivedHeader` (`local_port == 25`), which is where this was read
    # from rather than guessed.
    (settingsObjectOp "MtaStageData" {
      maxMessageSize = mapNullable
        (n: {
          "else" = toString n;
          match = listToAttrs (imap0
            (i: port: nameValuePair (toString i) {
              "if" = "local_port == ${port}";
              "then" = toString cfg.limits.smtpMaxMessageSizeByPort.${port};
            })
            (attrNames cfg.limits.smtpMaxMessageSizeByPort));
        })
        cfg.limits.smtpMaxMessageSize;
    })
    ++ (settingsObjectOp "Email" {
      maxMessageSize = cfg.limits.emailMaxMessageSize;
      maxAttachmentSize = cfg.limits.emailMaxAttachmentSize;
    })
    ++ (settingsObjectOp "Jmap" {
      maxUploadSize = cfg.limits.jmapMaxUploadSize;
      uploadQuota = cfg.limits.jmapUploadQuota;
    })
    ++ (settingsObjectOp "Imap" {
      maxRequestSize = cfg.limits.imapMaxRequestSize;
    })
    ++ cfg.limits.extraSettingsOps;

  # Bound as a string for the same reason `applyPlanText` is -- see its comment
  # for why hashing the rendered file rather than the string is
  # import-from-derivation, and why the bytes are identical either way.
  settingsPlanText = concatStringsSep "\n" (map builtins.toJSON settingsOps) + "\n";

  settingsPlan = pkgs.writeText "stalwart-settings.ndjson" settingsPlanText;

  # Same marker discipline as the bootstrap plan: the unit re-applies only
  # when the rendered VALUES change, not on every boot.
  settingsHash = builtins.hashString "sha256" settingsPlanText;

  stateDirBaseName = removePrefix "/var/lib/" (toString cfg.stateDir);

  stalwartPkg =
    if !(cfg.workarounds.dropSystemJemalloc || cfg.workarounds.skipCargoCheck)
    then cfg.package
    else cfg.package.overrideAttrs (old:
      optionalAttrs cfg.workarounds.skipCargoCheck { doCheck = false; }
      // optionalAttrs cfg.workarounds.dropSystemJemalloc {
        # A specific nixpkgs revision window added the shared, unprefixed
        # system jemalloc (`pkgs.rust-jemalloc-sys`) to Stalwart's
        # buildInputs unconditionally. Before/after that revision the
        # cargoHash and vendored dependency tarball are byte-identical --
        # this buildInput is the only thing that changed. Linking the
        # shared system jemalloc makes it interpose glibc's
        # `malloc_usable_size()` process-wide, which SIGSEGVs rocksdb's
        # boot-time block-cache iteration (it calls that function on a
        # buffer allocated by the OTHER allocator, gets a garbage size back,
        # and walks off the end of it). Dropping the buildInput reverts
        # jemalloc-sys to its previous, self-contained (symbol-prefixed)
        # vendored build, with no other change. Opt-in, not unconditional:
        # this is a workaround for one nixpkgs window, not a permanent
        # property of the package -- leave it off unless you actually hit
        # the crash (a boot-time SIGSEGV in the mail server process, not a
        # build failure) against your own nixpkgs pin.
        buildInputs = lib.remove pkgs.rust-jemalloc-sys old.buildInputs;
      }
    );

  domainSubmodule = types.submodule {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether this domain's `create` op is emitted into the bootstrap
          apply-plan at all. Because the plan is create-only (see the
          module-level comment on why), flipping this to `false` for a
          domain that a database has ALREADY bootstrapped does nothing to
          that live database -- it only stops a *future* fresh bootstrap
          from creating it. Removing a domain from an already-configured
          system is a manual `stalwart-cli destroy` operation.
        '';
      };
      catchAll = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Address any message to an unrecognized recipient at this domain
          is delivered to, instead of bouncing. Leave `null` for domains
          where an unrecognized recipient really is an error worth
          bouncing on (e.g. a domain that only ever has a handful of named
          mailboxes) rather than a domain-wide fallback inbox.
        '';
      };
      subAddressing = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Accept RFC 5233-style `user+tag@domain` sub-addressing for this
          domain. Almost always wanted; turn off only if some downstream
          tool actively misparses a `+` in the local part of an address.
        '';
      };
    };
  };

  listenerSubmodule = types.submodule {
    options = {
      protocol = mkOption {
        type = types.enum [ "smtp" "imap" "pop3" "lmtp" "http" ];
        description = "Which Stalwart service this listener speaks.";
      };
      bind = mkOption {
        type = types.str;
        example = "127.0.0.1:587";
        description = "`host:port` (or `[ipv6]:port`) literal to bind.";
      };
      useTls = mkOption {
        type = types.bool;
        default = false;
        description = "Whether TLS is available on this listener at all (implicit or STARTTLS).";
      };
      tlsImplicit = mkOption {
        type = types.bool;
        default = false;
        description = ''
          `true` = implicit TLS from the first byte (e.g. IMAPS/993,
          SMTPS/465). `false` with `useTls = true` = STARTTLS/opportunistic
          TLS negotiated after a plaintext greeting (e.g. Submission/587).
        '';
      };
    };
  };

  smarthostSubmodule = types.submodule {
    options = {
      host = mkOption {
        type = types.str;
        description = "Address of the outbound relay every non-local message gets handed to.";
      };
      port = mkOption {
        type = types.port;
        default = 587;
      };
      protocol = mkOption {
        type = types.str;
        default = "smtp";
      };
      implicitTls = mkOption {
        type = types.bool;
        default = false;
      };
      allowInvalidCerts = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Skip certificate validation when connecting to the relay. This
          defaults to `true` for a reason, not out of laziness: it is only
          ever safe because the intended target is a bridge process you
          also control, typically reachable over loopback or a private
          network path where certificate identity isn't doing any real
          security work. If your smarthost is a genuine third-party relay
          reachable over an untrusted network, set this to `false`.
        '';
      };
      name = mkOption {
        type = types.str;
        default = "smarthost";
        description = "Registry object name; also referenced by the routing expression when forceOutboundThroughSmarthost is set.";
      };
    };
  };
in
{
  options.nixmail.stalwart = {
    enable = mkEnableOption "Stalwart Mail Server (0.16.x; JMAP + IMAP + SMTP submission, registry-configured)";

    package = mkPackageOption pkgs "stalwart_0_16" {
      extraDescription = ''
        Override to pin/patch a build. See the module-level comment on
        version coupling: this module's rendered plan targets one specific
        registry schema, reverse-engineered against one specific package
        version -- swapping this without re-validating the plan (at
        minimum `stalwart-cli apply --dry-run`) is how a silent schema
        mismatch reaches production.
      '';
    };

    cliPackage = mkPackageOption pkgs "stalwart-cli" {
      extraDescription = ''
        The CLI used both by the bootstrap unit below and for any manual
        reconfiguration. Syntax and verb set are NOT stable across major
        versions -- this module was built against a CLI whose auth flags
        are `--url`/`--user`/`--password` (not e.g. `-u`/`-c`) and whose
        verbs are get/query/create/update/destroy/describe/apply/snapshot,
        with NO `upsert` and NO `server healthcheck` subcommand. Getting an
        auth-flag rename wrong here fails EVERY invocation with a generic
        argument-parsing error that looks identical to "the server isn't up
        yet" -- which can silently defeat the bootstrap unit's readiness
        probe below on every single boot, forever, with nothing in the
        logs to distinguish it from a slow-starting server. Verify by hand
        against a real instance before changing this package.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "stalwart-mail";
      description = "System user the server runs as.";
    };
    group = mkOption {
      type = types.str;
      default = "stalwart-mail";
      description = "System group the server runs as.";
    };
    uid = mkOption {
      type = types.nullOr types.int;
      default = if stalwartIdentity != null then stalwartIdentity.uid else null;
      defaultText = literalExpression "the uid of nixiam.posix.identities.<user>, else null";
      description = ''
        Numeric uid to pin the service user to, or `null` to let NixOS
        allocate one automatically. Leave `null` on a fresh install with no
        nixiam identity declared for `user`.

        Defaults from `config.nixiam.posix.identities.<user>.uid` (`user`
        being this module's own `user` option, default "stalwart-mail")
        whenever nixiam's posix module is imported alongside this one AND
        declares an identity by that exact name -- read defensively (see
        this module's own nixiam.posix read at the top of its `let` block),
        so a host that has never heard of nixiam, or simply hasn't named
        this identity there yet, still defaults to `null` exactly as
        before this lookup existed, and NixOS allocates one. An EXPLICIT
        value set here always wins over that default -- nothing about
        gaining this default takes away the ability to state the number
        directly, the same as `esp.byLabel` defaulting from nixstorage's
        layout in the sibling nixboot repo doesn't stop a host from typing
        its own label.

        PIN THIS EXPLICITLY -- don't lean on the nixiam default -- whenever
        the mail store already exists on disk owned by a specific uid:
        e.g. state that lives on a bind-mounted disk moved from another
        install, or an image rebuilt from scratch that must keep reading
        the same persistent volume. nixmail is a product that ships a
        RUNNING DAEMON WITH PERSISTED STATE, not a stateless job: unlike a
        config value, a uid that changes under an already-bootstrapped
        RocksDB store is a DATA-OWNERSHIP INCIDENT, because every file
        underneath becomes unreadable to the service with no error until
        the first failed open, discovered (if ever) only then. If you hit
        that, pin BOTH `uid` and `gid` to whatever `stat`/`getent` reports
        the existing files are owned by, not a guessed value -- and NOT
        whatever nixiam's table happens to say today, since that table can
        be renumbered by someone who has never heard of this host's
        already-bootstrapped store.
      '';
    };
    gid = mkOption {
      type = types.nullOr types.int;
      default = stalwartGid;
      defaultText = literalExpression "nixiam.posix.groups.<group>, else the resolved gid of nixiam.posix.identities.<group>, else null";
      description = ''
        Numeric gid to pin the service group to, or `null` to let NixOS
        allocate one. Defaults the same way `uid` does -- see its
        description both for the nixiam.posix lookup (`group` being this
        module's own `group` option, default "stalwart-mail") and for why
        an already-bootstrapped mail store needs this pinned by hand from
        `stat`/`getent`, never left to nixiam's table, once one exists.
      '';
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/stalwart-mail";
      description = ''
        Base state directory. Backed by systemd's `StateDirectory=`
        mechanism (hence the `/var/lib/` assertion below), which creates it
        and sets its ownership to `user`/`group` on every start.
      '';
    };
    dataDir = mkOption {
      type = types.path;
      default = "${cfg.stateDir}/data";
      description = "RocksDB store path -- the one thing `config.json` actually names (see the module-level comment on why everything else lives in the registry instead).";
    };

    domains = mkOption {
      type = types.attrsOf domainSubmodule;
      default = { };
      description = ''
        Every mail domain this server should serve, keyed by the domain
        name itself. This is the actual data model the bootstrap plan
        renders from -- there is no separate, parallel domain list inside
        this module to keep in sync with it. Owning your domain/mailbox
        topology as data that lives in the CONSUMING configuration (not
        this repo) mirrors every other nix* module in this family: this
        repo ships the mechanism, your own configuration supplies what's
        actually private (which domains you run, which of them has a
        catch-all, and to what address).
      '';
    };
    defaultDomain = mkOption {
      type = types.str;
      example = "example.org";
      description = ''
        Which entry in `domains` becomes `SystemSettings.defaultDomainId`
        -- the domain Stalwart falls back to whenever it needs one but
        nothing else disambiguates. MUST be a key that also exists in
        `domains` (enforced by an assertion below); typically your primary
        / oldest domain.
      '';
    };

    publicHostname = mkOption {
      type = types.str;
      default = "mail.example.org";
      description = "SystemSettings.defaultHostname -- the hostname Stalwart identifies itself as (SMTP HELO/EHLO context, etc.).";
    };
    httpPublicUrl = mkOption {
      type = types.str;
      example = "https://jmap.example.org";
      description = ''
        The public https origin the JMAP session object advertises
        (apiUrl/uploadUrl/downloadUrl/eventSourceUrl), exported to the
        server process as `STALWART_PUBLIC_URL`. This is the native 0.16
        replacement for the kind of bespoke reverse-proxy URL-rewriting
        hack a JMAP deployment behind a different public hostname than the
        server's own idea of itself would otherwise need.
      '';
    };

    listeners = mkOption {
      type = types.attrsOf listenerSubmodule;
      default = {
        lmtp = {
          protocol = "lmtp";
          bind = "127.0.0.1:2424";
        };
        submission = {
          protocol = "smtp";
          bind = "127.0.0.1:587";
        };
        imap = {
          protocol = "imap";
          bind = "127.0.0.1:143";
        };
        http = {
          protocol = "http";
          bind = "127.0.0.1:8080";
        };
      };
      description = ''
        Loopback-bound listeners: local delivery (LMTP for glue bridges),
        local submission/IMAP for a webmail or another local relay, and the
        HTTP listener the JMAP management API (and the bootstrap unit
        below) talk to. Public, TLS-terminated native-client listeners are
        a SEPARATE, fixed-shape option set (`publicListeners`) below, not
        part of this attrset -- see its own description for why.
      '';
    };

    publicListeners = {
      enable = mkEnableOption ''
        public native-client listeners: IMAPS/993, Submissions/465,
        Submission-with-STARTTLS/587, and POP3S/995, all TLS. Off by
        default -- turning this on requires a certificate to be available
        (via `acme` or `tls.*`; enforced by an assertion below) and does
        NOT by itself open any firewall port (see `openFirewall`)'';

      bindAddress = mkOption {
        type = types.str;
        default = "[::]";
        example = "0.0.0.0";
        description = ''
          Wildcard bind address the four public listeners above use. The
          default is IPv6-any, which is only correct on an IPv6-only host
          -- a dual-stack host that also wants IPv4 native-client traffic
          should set this to `"0.0.0.0"` (a single-stack v4-only bind) or
          run this module twice with two different `NetworkListener` sets
          if it needs both simultaneously. This is a plain string
          concatenated with `:<port>`, not parsed -- match the
          bracket/no-bracket convention your chosen value needs.
        '';
      };
    };

    tls = {
      certificateFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Existing certificate chain (PEM) to use, if you manage TLS certificates outside this module entirely. Mutually exclusive with `acme.enable` (enforced by an assertion below).";
      };
      keyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Private key (PEM) matching `certificateFile`.";
      };
    };

    acme = {
      enable = mkEnableOption "certificate management via NixOS's security.acme for the public listeners, using a DNS-01 challenge";

      email = mkOption {
        type = types.str;
        example = "acme@example.org";
        description = "Let's Encrypt account contact address.";
      };
      hostname = mkOption {
        type = types.str;
        example = "mail.example.org";
        description = "Primary name (and `security.acme.certs.<name>` key) the certificate is issued for -- this is also what the Certificate registry object's paths are derived from.";
      };
      extraDomainNames = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Additional subjectAlternativeNames on the same certificate, e.g. separate hostnames your public SMTP/POP3 listeners advertise.";
      };
      dnsProvider = mkOption {
        type = types.str;
        default = "cloudflare";
        description = "lego DNS provider name for the DNS-01 challenge -- passed straight through to `security.acme.certs.<name>.dnsProvider`.";
      };
      credentialsFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "EnvironmentFile holding the DNS provider's API credentials (e.g. `CLOUDFLARE_DNS_API_TOKEN=...`), passed to `security.acme.certs.<name>.environmentFile`.";
      };
      dnsResolver = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          `host:port` literal DNS resolver lego should query directly for
          the DNS-01 propagation check, bypassing ordinary system
          resolution. Default `null` lets lego use normal system DNS,
          which is correct for almost every host. Only set this on a
          network where the ordinary resolution path can't reach whatever
          resolver actually has the propagated record -- e.g. an IPv6-only
          host whose default resolver only has an IPv4 address and is
          therefore unreachable; pin an explicit resolver your host can
          actually route to in that specific case, not as a routine
          setting.
        '';
      };
    };

    smarthost = mkOption {
      type = types.nullOr smarthostSubmodule;
      default = null;
      description = "Outbound relay (MtaRoute). `null` = attempt direct MX delivery. Deliberately no SMTP auth support here: the assumed shape is a trusted local relay/bridge process, not a third-party provider that itself needs credentials.";
    };
    forceOutboundThroughSmarthost = mkOption {
      type = types.bool;
      default = cfg.smarthost != null;
      description = ''
        Whether to also install an `MtaOutboundStrategy` routing rule that
        sends ALL non-local mail through `smarthost` unconditionally.
        Defaults to on whenever a smarthost is configured at all, matching
        the assumption that if you bothered to define a relay you want it
        used. Set explicitly to `false` if you want the relay object to
        exist (so other MTA routing logic you manage yourself can
        reference it) without this module forcing every outbound message
        through it.
      '';
    };

    ldap = {
      url = mkOption {
        type = types.str;
        default = "ldap://127.0.0.1:3890";
        description = "LDAP URL of the directory Stalwart authenticates against.";
      };
      baseDn = mkOption {
        type = types.str;
        example = "dc=example,dc=org";
        description = "Directory base DN.";
      };
      bindDn = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''Bind DN Stalwart's Directory object uses as the search identity. `null` defaults to `"uid=admin,ou=people,${"$"}{baseDn}"`, matching a conventional single-admin directory layout -- set explicitly if yours differs.'';
      };
      bindPasswordFile = mkOption {
        type = types.path;
        description = "File containing the bind password, read at Directory-object-render time and referenced by path (never inlined into the rendered plan or the Nix store).";
      };
      description = mkOption {
        type = types.str;
        default = "External LDAP directory";
        description = "Free-text description on the Directory registry object -- cosmetic, shown in the admin webui.";
      };

      mailGroupDn = mkOption {
        type = types.str;
        default = "cn=mail,ou=groups,${cfg.ldap.baseDn}";
        description = ''
          DN of the group whose membership gates mail delivery -- used to
          build `filterMailbox`'s default below. Keeping "is allowed to
          receive mail" as plain group membership (rather than a
          mailbox-specific flag/attribute) keeps the directory schema
          uniform and lets you grant or revoke delivery for a principal
          just by editing group membership, with zero Stalwart-side
          config change.
        '';
      };

      filterLogin = mkOption {
        type = types.str;
        default = "(&(objectClass=person)(|(uid={user})(mail={user})${aliasLoginOrs}))";
        description = "LDAP filter used to look a principal up by login name (`{user}` placeholder) before Stalwart binds as them. Default accepts uid, primary mail, or any of `attrEmailAlias`.";
      };
      filterMailbox = mkOption {
        type = types.str;
        default = "(&(objectClass=person)(memberOf=${cfg.ldap.mailGroupDn})(|(mail={email})${aliasEmailOrs}))";
        description = "LDAP filter used to decide whether an address (`{email}` placeholder) may receive mail: membership in `mailGroupDn`, matched against the primary mail attribute or any `attrEmailAlias`.";
      };
      filterMemberOf = mkOption {
        type = types.str;
        default = "(&(objectClass=groupOfUniqueNames)(uniqueMember={user}))";
        description = "LDAP filter Stalwart uses for its own group-membership lookups (`{user}` placeholder). Fully generic -- does not reference any specific group.";
      };

      groupClass = mkOption {
        type = types.str;
        default = "groupOfUniqueNames";
        description = "objectClass of group entries in the directory.";
      };
      attrEmail = mkOption {
        type = types.listOf types.str;
        default = [ "mail" ];
        description = "Attribute name(s) holding a principal's primary email address.";
      };
      attrEmailAlias = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Attribute name(s) holding SECONDARY email addresses for a
          principal. This same list feeds two consumers: the `attrEmail
          Alias` registry mapping AND the OR-clauses added to `filterLogin`
          / `filterMailbox` above -- keep it as one option rather than two
          so they can never drift apart.

          MUST be all-lowercase if your directory server lowercases
          attribute names in its own LDAP responses (several common
          directory servers do this unconditionally, regardless of how the
          schema itself defines the attribute's casing). The two consumers
          above are affected differently by getting this wrong: the SEARCH
          FILTER still matches correctly even with the "wrong" case,
          because most directories match attribute names
          case-insensitively server-side -- so receiving mail keeps working
          and hides the bug. The attrEmailAlias EXTRACTION does not get
          that same leniency: Stalwart looks the value up in the LDAP
          result entry by the exact configured key, and a directory that
          actually returned the attribute under a different case then
          simply has no matching key, so the alias never enters the
          principal's identity at all -- the address keeps receiving mail
          but silently cannot be used to send-as (JMAP Identity/set and
          similar reject it as "not configured for this account"). If
          aliases receive but can't send, this is the first thing to check.
        '';
      };
      attrMemberOf = mkOption {
        type = types.listOf types.str;
        default = [ "memberOf" ];
        description = "Attribute name(s) exposing a principal's group memberships.";
      };
      attrSecret = mkOption {
        type = types.listOf types.str;
        default = [ "dummyStalwartSecret" ];
        description = ''
          Attribute name the registry schema wants configured as "where the
          password/secret lives", even though `bindAuthentication = true`
          means Stalwart never actually reads through this mapping (the
          bind itself IS the authentication check -- see `directoryOp`'s
          own comment). The default deliberately points at a name that does
          not exist in any real schema, so it's obviously a placeholder,
          not an oversight, to anyone reading the rendered plan later.
        '';
      };
      poolMaxConnections = mkOption {
        type = types.ints.positive;
        default = 10;
        description = "LDAP connection pool size.";
      };
    };

    permissiveCors = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Sets `Http.usePermissiveCors`, which puts a wildcard
        Access-Control-Allow-Origin on the JMAP API. This is a real,
        security-relevant toggle -- it lets ANY web origin make
        credentialed-adjacent JMAP requests against this server from a
        browser -- so it defaults OFF here, unlike Stalwart's own recovery
        mode (which forces it on). Only turn this on if you actually run a
        cross-origin JMAP web client (a separately-hosted webmail, the
        admin webui on a different origin than the API, a third-party JMAP
        app) that needs it; same-origin deployments never need this at all.
      '';
    };

    offlineResources = {
      webui = mkOption {
        type = types.nullOr types.path;
        default = webuiZipFOD;
        description = ''
          Store path of the admin/account webui asset, baked in at build
          time as the default so a runtime-network-restricted host never
          needs to reach GitHub itself. Set to `null` to instead let
          Stalwart fetch the upstream release URL directly at its own
          runtime -- correct for a host with unrestricted outbound access,
          and the only way to pick up an upstream webui release newer than
          the one this module happens to pin.
        '';
      };
      webuiSource = mkOption {
        type = types.attrsOf types.str;
        readOnly = true;
        default = webuiSource;
        description = ''
          What `offlineResources.webui`'s default is actually pinned to:
          `{ url, hash, version }` of the upstream webui release this
          module fetches at build time. Read-only and purely informational
          -- exists so a supply-chain audit can read the pinned
          version/URL/hash via `nix eval` without opening this module's
          source, which is otherwise the only place that fact is visible.
          Changing the pin means editing the `webuiSource` binding in this
          file's `let` block (which also changes what `webui` builds), not
          this option.
        '';
      };
      webuiUrlPrefixes = mkOption {
        type = types.listOf types.str;
        default = [ "/admin" "/account" ];
        description = "HTTP path prefixes the webui Application is mounted under.";
      };
      spamFilterRules = mkOption {
        type = types.nullOr types.path;
        default = spamRulesFOD;
        description = "Store path of the spam-filter ruleset asset. Same offline/online trade-off as `webui` above.";
      };
      spamFilterRulesSource = mkOption {
        type = types.attrsOf types.str;
        readOnly = true;
        default = spamRulesSource;
        description = ''
          What `offlineResources.spamFilterRules`'s default is actually
          pinned to: `{ url, hash, version }` of the upstream spam-filter
          ruleset release. Same read-only, audit-facing purpose as
          `webuiSource` above.
        '';
      };
    };

    workarounds = {
      dropSystemJemalloc = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Rebuild `package` with `pkgs.rust-jemalloc-sys` removed from its
          buildInputs. See the comment on `stalwartPkg` in this module's
          `let` block for the exact SIGSEGV this works around and why it's
          opt-in rather than unconditional: it's a fix for one specific
          nixpkgs revision window, not a permanent property of the
          package. Leave off unless you actually observe the server
          crashing at boot with a segfault inside its storage layer against
          your own nixpkgs pin.
        '';
      };
      skipCargoCheck = mkOption {
        type = types.bool;
        default = false;
        description = "Rebuild `package` with `doCheck = false`, skipping upstream's own cargo test phase. That phase can take a very long time on modest build hardware relative to the rest of the build; safe to skip once you've confirmed the binary you get matches an upstream release you already trust.";
      };
    };

    recoveryAdmin = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Compose a break-glass admin credential (`STALWART_RECOVERY_ADMIN`)
          into the server's environment at every start, and use that SAME
          credential to authenticate the bootstrap unit's own readiness
          probe and apply call below. Required (asserted below) whenever
          `bootstrap.enable` is true, since the bootstrap unit has no other
          way to authenticate to the management API on a fresh database
          that has no LDAP-backed admin yet.
        '';
      };
      username = mkOption {
        type = types.str;
        default = "recovery-admin";
        description = "Username portion of `STALWART_RECOVERY_ADMIN`.";
      };
      passwordFile = mkOption {
        type = types.path;
        description = "File containing the recovery-admin password, read fresh at every service start.";
      };
    };

    bootstrap = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to run the bootstrap unit at all. See the module-level comment: this only ever populates an EMPTY database once, never reconfigures a live one.";
      };
      markerFile = mkOption {
        type = types.path;
        default = "${cfg.stateDir}/.applied-plan";
        description = "Where the bootstrap unit records the hash of the plan it last successfully applied, so it only re-runs when the rendered plan actually changes.";
      };
      readinessTimeout = mkOption {
        type = types.ints.positive;
        default = 120;
        description = "Seconds to wait, polling every 2s, for the management API to come up and authenticate before giving up for this boot (a later boot, or unit restart, tries again).";
      };
      continueOnError = mkOption {
        type = types.bool;
        default = true;
        description = "Pass `--continue-on-error` to `stalwart-cli apply`, so one op failing (e.g. a Certificate op whose file doesn't exist yet) doesn't abort the rest of the plan.";
      };
      extraPlanOps = mkOption {
        type = types.listOf types.attrs;
        default = [ ];
        description = "Additional raw registry ops (same shape as this module's own internal ops -- `{ \"@type\" = ...; object = ...; value = ...; }`) appended to the rendered plan, for anything a consumer needs that this module doesn't have a dedicated option for. Avoids forking the module for one extra op.";
      };
    };

    # ── Size limits ──────────────────────────────────────────────────────
    #
    # Every option here is null by default, which means "leave Stalwart's own
    # compiled-in default alone". Set one and it is applied, and KEPT applied,
    # by the stalwart-settings unit (see the `settingsOps` comment above for
    # why that is a separate unit from the bootstrap).
    #
    # WIRE FORMAT vs FILE SIZE -- the distinction that makes these numbers
    # confusing in practice. A limit measured on the WIRE applies to the
    # RFC822 message as transmitted, in which every attachment is
    # base64-encoded: 76 output characters plus CRLF for each 57 input bytes,
    # a factor of ~1.3684. A limit measured in RAW octets applies to the file
    # itself. So a 25 MiB wire ceiling carries an attachment of about 19.2 MB,
    # and two limits that look equal in bytes are not equal in what they let a
    # user send. Each option below states which of the two it is.
    limits = {
      markerFile = mkOption {
        type = types.path;
        default = "${cfg.stateDir}/.applied-settings";
        description = ''
          Where the settings unit records the hash of the settings plan it last
          applied. Deliberately a DIFFERENT file from `bootstrap.markerFile`:
          the two plans change independently, and sharing one marker would make
          a settings change look like a bootstrap re-run (and vice versa).

          KNOWN LIMIT, stated because the difference matters: the hash is
          computed from the DECLARED values, so the unit re-applies whenever
          this configuration changes, but it does not detect the server drifting
          underneath it -- a value edited in the WebUI, or reset by a
          major-version migration, is not noticed until the declaration changes
          or the marker is removed. Deleting this file forces a re-apply.
        '';
      };
      smtpMaxMessageSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 26214400;
        description = ''
          `MtaStageData.maxMessageSize` -- the largest message, in bytes of
          WIRE format, that the SMTP and LMTP stack will accept.

          This is also the number the server advertises in its ESMTP `SIZE`
          capability, which is the only way a submitting client learns the
          limit before it spends bandwidth. Keep it in step with whatever the
          NEXT hop accepts (a smarthost, an outbound bridge, a relay API): a
          server that advertises more than the next hop takes will accept a
          message at submission and bounce it afterwards, which is strictly
          worse than refusing it up front.

          Note this one number governs BOTH directions -- inbound LMTP and
          outbound submission -- so if inbound arrives through a gateway that
          appends `Received:` headers, leave headroom above that gateway's own
          ceiling or an inbound message sized exactly at it will be refused.
        '';
      };
      smtpMaxMessageSizeByPort = mkOption {
        type = types.attrsOf types.ints.positive;
        default = { };
        example = { "2424" = 27262976; };
        description = ''
          Per-listener overrides of `smtpMaxMessageSize`, keyed by local port.
          Any port not named here gets `smtpMaxMessageSize`.

          This exists because ONE size limit has to serve two populations with
          opposite requirements. The submission ports must advertise exactly
          what the next hop out will accept, or a client is told its message was
          sent and gets a bounce afterwards. An INGRESS port has no next hop and
          the opposite failure: a message that arrived at some upstream
          gateway's own ceiling has since grown -- envelope rewriting, a
          `Received:` header, dot-stuffing -- so a limit equal to that gateway's
          refuses mail the gateway already accepted, and it refuses it at the
          last possible moment.

          Giving the ingress port its own, higher value is what lets the
          advertised number stay honest without inheriting that edge. Set only
          the ports that genuinely need to differ; a value here that is LOWER
          than `smtpMaxMessageSize` is legal but almost always a mistake.
        '';
      };
      emailMaxMessageSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 26214400;
        description = ''
          `Email.maxMessageSize` -- largest assembled message, in bytes of
          WIRE format, that the JMAP layer will build and submit. This is the
          gate a webmail client hits when it presses Send.
        '';
      };
      emailMaxAttachmentSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 19000000;
        description = ''
          `Email.maxAttachmentSize` -- the summed size of a message's
          attachments, in RAW octets (not wire format).

          Set this to `smtpMaxMessageSize` divided by ~1.37, not to the same
          number: the attachments are still un-encoded when this is checked and
          will grow by that factor before anything measures them against a
          wire limit. Setting the two equal is what produces the failure where
          a file attaches without complaint and the send bounces afterwards.
        '';
      };
      jmapMaxUploadSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 19000000;
        description = ''
          `Jmap.maxUploadSize` -- largest single upload, in RAW octets, that
          the JMAP upload endpoint accepts. This is the FIRST gate a webmail
          attachment meets, so it is the one that can still produce a useful
          error message in the composer; every later gate fails after the user
          has already waited for the upload. Keep it in step with
          `emailMaxAttachmentSize`.
        '';
      };
      jmapUploadQuota = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 10737418240;
        description = ''
          `Jmap.uploadQuota` -- total bytes of temporary upload blobs one
          account may hold within the upload TTL window.

          This is a per-account rate limit, not a message limit, and Stalwart's
          default is small enough that a bulk import or a migration hits it
          long before it hits any size limit. It is also exactly the kind of
          value that gets raised by hand during such an import and then
          silently reverts on the next major-version migration, because
          nothing re-asserts it -- which is the reason it is an option here.
        '';
      };
      imapMaxRequestSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 27262976;
        description = ''
          `Imap.maxRequestSize` -- largest IMAP request, in bytes of WIRE
          format, the server will accept. In practice this is the `APPEND`
          ceiling: it caps saving a large sent-copy or draft into a mailbox,
          so a value below `smtpMaxMessageSize` means a message can be sent
          but its own copy cannot be filed.
        '';
      };
      restartServerAfterApply = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Restart `stalwart.service` after the settings plan is applied.

          Required for the settings to take effect, and it is on by default
          because leaving it off makes this whole unit a no-op that LOOKS like
          it worked. Stalwart 0.16 reads these registry values into memory at
          startup and has no reload path: the management API exposes no reload
          endpoint (`POST /api/reload` and its obvious spellings all 404) and
          `stalwart-cli` has no reload verb. Measured on a live 0.16.16 server:
          three minutes after `apply` reported `4 updated`, the SMTP listener
          was still advertising the OLD `SIZE`.

          The restart is issued only on the runs that actually change something
          -- the marker file short-circuits every other run -- so this costs one
          restart per real configuration change, not one per boot. The marker is
          written BEFORE the restart, so the unit that comes back up after it
          sees its own plan as applied and stops rather than looping.
        '';
      };
      extraSettingsOps = mkOption {
        type = types.listOf types.attrs;
        default = [ ];
        description = ''
          Additional raw `update` ops appended to the settings plan, for
          mutable registry values this module has no dedicated option for.

          Only ever put IDEMPOTENT ops here -- ops that address a singleton
          object and carry no `#localId` reference. This plan is re-applied
          whenever it changes and has no virgin-database guard in front of it;
          a `create` op placed here would run against a populated database.
          Use `bootstrap.extraPlanOps` for anything that must be created once.
        '';
      };
    };

    dependsOnUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Extra systemd units to order the server after (`after`, not
        `wants`/`requires`) -- typically whatever unit in your own
        configuration actually provisions `ldap.bindPasswordFile` and
        `recoveryAdmin.passwordFile` (a secrets-fetch unit, a directory
        service unit, etc.). This module intentionally has no opinion on
        how secrets are delivered -- it only accepts `*File` paths -- so it
        cannot guess this dependency for you.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open 993/465/587/995 in `networking.firewall` for the public
        listeners. Deliberately a SEPARATE toggle from `publicListeners.
        enable`, not implied by it -- creating a listener and exposing it
        through the host firewall are two different decisions (e.g. a host
        that reaches the public internet through some other proxying
        mechanism entirely may want the listeners running without ever
        opening these ports directly).
      '';
    };

    queueMonitor = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Periodically fail a systemd unit when outbound mail is piling up in
          the queue instead of being delivered.

          WHY THIS EXISTS. Liveness checks do not detect a dead relay. A mail
          server can accept submissions, answer on every port, serve its web
          UI and pass every TCP/HTTPS probe you point at it while delivering
          NOTHING -- because the outbound leg is a separate path that only
          runs when a message is actually queued. That failure mode is
          SILENT: senders get a clean 250, nothing bounces (the queue is
          retrying, not rejecting), and the operator finds out days or weeks
          later from a human saying "did you get my mail?".

          This check watches the one signal that distinguishes the two:
          messages sitting in the queue past `maxAgeMinutes`. A healthy
          server drains its queue continuously, so a message older than a
          few minutes means delivery is failing, whatever the ports say.

          The unit FAILS (non-zero exit) rather than notifying, deliberately:
          this module has no opinion on how you alert. A failed systemd unit
          is the lowest common denominator every monitoring system already
          understands -- scrape `systemctl --failed`, let your own monitoring
          catch it, or add an `OnFailure=` of your own.
        '';
      };
      maxAgeMinutes = mkOption {
        type = types.ints.positive;
        default = 30;
        description = ''
          Fail if any queued message is older than this. Keep it comfortably
          above your longest legitimate retry backoff: a remote server being
          briefly unreachable is normal and self-heals, and alerting on that
          trains people to ignore the alert. 30 minutes catches a genuinely
          broken relay while riding out ordinary transient failures.
        '';
      };
      interval = mkOption {
        type = types.str;
        default = "*:0/15";
        description = "systemd OnCalendar expression for how often to check.";
      };
    };
  };

  config = mkIf cfg.enable {
    # nixiam.posix state (c) surfaces here, unconditionally whenever this module is enabled --
    # see `identitiesProbe`/`groupsProbe` above for what this can and cannot tell apart.
    warnings = (collectProbes [ identitiesProbe groupsProbe ]).warnings;

    assertions = [
      {
        # Without this the mistake is SILENT: smtpMaxMessageSize null makes the
        # whole MtaStageData field drop out, taking every per-port override with
        # it, and the server keeps its compiled-in default while the config
        # plainly says otherwise.
        assertion = cfg.limits.smtpMaxMessageSizeByPort == { } || cfg.limits.smtpMaxMessageSize != null;
        message = ''
          nixmail.stalwart.limits.smtpMaxMessageSizeByPort is set but
          smtpMaxMessageSize is null. The per-port values are rendered as
          `match` conditions on the SAME registry field, whose `else` branch is
          smtpMaxMessageSize -- with no `else` there is nothing to attach them
          to, so they would be dropped silently. Set smtpMaxMessageSize to the
          value every other port should get.
        '';
      }
      {
        assertion = hasAttr cfg.defaultDomain cfg.domains;
        message = ''
          nixmail.stalwart.defaultDomain ("${cfg.defaultDomain}")
          must be a key present in nixmail.stalwart.domains --
          SystemSettings.defaultDomainId is rendered as a #localId
          reference to that exact entry and would otherwise dangle.
        '';
      }
      {
        assertion = !(cfg.acme.enable && (cfg.tls.certificateFile != null || cfg.tls.keyFile != null));
        message = ''
          nixmail.stalwart.acme.enable and .tls.certificateFile/
          keyFile are mutually exclusive certificate sources -- pick one.
        '';
      }
      {
        assertion = !cfg.publicListeners.enable || certPaths != null;
        message = ''
          nixmail.stalwart.publicListeners.enable requires a
          certificate source: set either .acme.enable (with .acme.email and
          .acme.hostname) or both .tls.certificateFile and .tls.keyFile.
          Without one, the public TLS listeners would have no certificate
          for the Certificate registry object to select.
        '';
      }
      {
        assertion = !cfg.bootstrap.enable || cfg.recoveryAdmin.enable;
        message = ''
          nixmail.stalwart.bootstrap.enable requires
          .recoveryAdmin.enable -- the bootstrap unit authenticates to the
          management API using the recovery-admin credential, since a
          freshly-created database has no LDAP-backed admin yet for it to
          use instead.
        '';
      }
      {
        assertion = hasPrefix "/var/lib/" (toString cfg.stateDir);
        message = ''
          nixmail.stalwart.stateDir ("${toString cfg.stateDir}")
          must live under /var/lib/ -- it is realized via systemd's
          StateDirectory=, which only ever creates directories there.
        '';
      }
    ];

    environment.etc."stalwart/config.json".source = configJson;

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.stateDir;
      uid = cfg.uid;
    };
    users.groups.${cfg.group} = {
      gid = cfg.gid;
    };

    systemd.services.stalwart = {
      description = "Stalwart Mail Server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ]
        ++ cfg.dependsOnUnits
        ++ optional cfg.acme.enable "acme-${cfg.acme.hostname}.service";
      wants = optional cfg.acme.enable "acme-${cfg.acme.hostname}.service";

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = stateDirBaseName;
        StateDirectoryMode = "0750";
        # A separate LogsDirectory is required, not cosmetic: an already-
        # configured database can carry a Log tracer object pointing here
        # from a previous manual configuration step, and without the
        # directory existing, that tracer silently produces no logs at all
        # rather than erroring.
        LogsDirectory = "stalwart";
        # The server runs as a non-root, static user -- without this
        # capability, binding any port below 1024 (the public 465/993/995
        # listeners) fails with EACCES and only the unprivileged loopback
        # listeners come up, with no obvious error tying the two together.
        # Notably invisible in any test run as root, since root doesn't
        # need the capability at all -- verify against the real
        # unprivileged service user, not a rehearsal environment running
        # as root.
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        ExecStart = "${stalwartPkg}/bin/stalwart --config=/etc/stalwart/config.json";
        Environment = [ "STALWART_PUBLIC_URL=${cfg.httpPublicUrl}" ];
        Restart = "on-failure";
        RestartSec = "5s";
        LimitNOFILE = 65536;
      } // optionalAttrs cfg.recoveryAdmin.enable {
        EnvironmentFile = "-/run/stalwart/recovery-admin.env";
        ExecStartPre = [
          ("+" + (pkgs.writeShellScript "stalwart-recovery-admin" ''
            install -d -m 0750 -o ${cfg.user} -g ${cfg.group} /run/stalwart
            # NOTE: the composed value below is NOT bash-`source`-safe. An
            # LDAP-sourced password can legitimately contain a space (or
            # other shell metacharacters); reading this file with `source`/
            # `export` instead of `cat`/`cut` silently truncates the
            # password at the first word and risks the remainder being
            # interpreted as a second shell command. Treat this as an
            # opaque `KEY=value` line, never a script.
            pw=$(cat ${lib.escapeShellArg cfg.recoveryAdmin.passwordFile})
            umask 077
            printf 'STALWART_RECOVERY_ADMIN=%s:%s\n' ${lib.escapeShellArg cfg.recoveryAdmin.username} "$pw" > /run/stalwart/recovery-admin.env
            chown ${cfg.user}:${cfg.group} /run/stalwart/recovery-admin.env
          ''))
        ];
      };
    };

    # Outbound-delivery health. See queueMonitor's option docs for why a port
    # probe cannot detect a dead relay and this can.
    systemd.services.stalwart-queue-monitor = mkIf cfg.queueMonitor.enable {
      description = "Fail if outbound mail is stuck in the Stalwart queue";
      after = [ "stalwart.service" ];
      serviceConfig.Type = "oneshot";
      # THE PARSER IS NOT ON THE DEFAULT PATH. A systemd `script` gets coreutils,
      # findutils, gnugrep, gnused and systemd -- and nothing else. This unit
      # shipped for months calling `awk`, which is in none of those, and was in
      # consequence STRUCTURALLY INCAPABLE OF ALERTING: awk resolved to nothing,
      # so the counting pipeline below died on every single tick while the unit
      # reported "queue draining normally" and exited 0. Measured on the live
      # production host before this fix: 41 "awk: command not found" lines and 41
      # "queue draining normally" lines in the same 12-hour window. Anything this
      # script calls that is not in that five-package set belongs on this list.
      path = [ pkgs.jq ];
      script = ''
        # pipefail is load-bearing, not hygiene. Without it the status of
        # `cli | jq | wc -l` is `wc -l`'s alone, which is 0 even when every
        # earlier stage collapsed -- and `wc -l` on an empty stream prints 0, so
        # `stuck` was always 0 and the guard below could never trip. That is the
        # exact shape of the bug this unit shipped with: a monitor unable to tell
        # "zero stuck messages" from "I failed to count", which is strictly worse
        # than no monitor because it manufactures confidence.
        set -euo pipefail

        broken() {
          echo "stalwart-queue-monitor: BROKEN MONITOR -- $1" >&2
          echo "  Outbound health is UNKNOWN, not healthy. Do not read this run as green." >&2
          exit 1
        }

        # Read the password rather than sourcing it: the file is a plain
        # secret, and its value may legitimately contain shell metacharacters.
        pw=$(cat ${lib.escapeShellArg cfg.recoveryAdmin.passwordFile})
        cli="${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password $pw"

        # WHAT THE CLI ACTUALLY PRINTS. Measured against a live server
        # (stalwart-cli 1.0.12), not assumed -- `--json` is NDJSON, one JSON
        # object per line, carrying the requested field plus `id` and nothing
        # else. No header, no footer, no totals, no pager (the CLI only prompts
        # "Show more?" on a TTY, and never in --json mode; it walks the API's
        # pages itself). Literal, from the server this module manages:
        #
        #     $ stalwart-cli query Account --json --fields createdAt
        #     {"createdAt":"2026-06-25T03:34:06Z","id":"s"}
        #     {"createdAt":"2026-06-25T03:34:06Z","id":"r"}
        #
        # A `datetime` field comes back as an ISO-8601 UTC instant with a `Z`
        # suffix -- confirmed on two different live objects of that type
        # (Account.createdAt above, Certificate.notValidAfter
        # "2028-09-09T18:39:18Z"). An EMPTY result set, which is what a healthy
        # queue gives on every tick, prints ZERO BYTES and exits 0.
        #
        # THE HUMAN TABLE IS DELIBERATELY NOT PARSED. Its columns are whatever
        # the SERVER's schema names as that object's default list, its headers
        # are display labels rather than field names ("Expires" for
        # notValidAfter), and its cells are truncated at 60 characters. An
        # earlier version of this script parsed exactly that, keyed on an
        # assumed "Next Retry"/"Received" column pair that no one had ever
        # observed the server emit. `--json --fields` pins both the shape and
        # the field, so neither depends on a display decision.
        #
        # `createdAt` is QueuedMessage's "when the message was received and
        # queued" (`stalwart-cli describe QueuedMessage`), which is the age that
        # matters. `nextRetry` would also fire on an overdue retry, a different
        # and noisier condition. If that field is ever renamed this does not
        # silently read zero either: `--fields <unknown>` exits 1 with
        # "error: unknown field", which the query guard below turns into a
        # BROKEN MONITOR.
        #
        # Lexicographic comparison IS chronological here: both sides are
        # fixed-width UTC. Every row must carry a parseable createdAt -- a row
        # that does not is an ERROR, never a "not stuck". That distinction is
        # the whole difference between a parser and a wish, and self-test 3
        # below is what proves this one has it.
        countStuck() {
          jq --raw-output --arg cutoff "$1" '
            if type != "object" then
              error("queue row is not a JSON object: \(tojson)")
            elif (.createdAt | type) != "string" then
              error("queue row carries no string createdAt: \(tojson)")
            elif (.createdAt | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?Z$") | not) then
              error("queue row createdAt is not an ISO-8601 UTC instant: \(tojson)")
            else
              select(.createdAt < $cutoff) | .createdAt
            end
          ' | wc -l
        }

        cutoff=$(date -u -d "-${toString cfg.queueMonitor.maxAgeMinutes} minutes" +%Y-%m-%dT%H:%M:%SZ)

        # SELF-TEST -- the part that makes a BROKEN monitor loud instead of green.
        # Tool presence alone is not the property that matters; what matters is
        # that the counting pipeline still returns a TRUE COUNT. So it runs the
        # REAL `countStuck` (not a copy of it) over fixtures in the CLI's real
        # recorded output shape, and asserts all three answers that matter.
        #
        # 1. THE EMPTY QUEUE -- zero bytes in, 0 out, exit 0. This is the case
        #    the check actually sees on a healthy system, so it is the one most
        #    worth pinning: "no output" must mean "nothing is stuck", and it
        #    must be reached by parsing rather than by the pipeline collapsing.
        if empty=$(printf "" | countStuck "$cutoff"); then
          [ "$empty" = 0 ] || broken "parser self-test 1 (empty queue) expected 0, got '$empty'."
        else
          broken "parser self-test 1 (empty queue) could not run at all -- jq, date or wc is missing or failing."
        fi

        # 2. A REAL-SHAPED QUEUE -- rows in exactly the NDJSON grammar recorded
        #    above, one older than any cutoff and one that is not old until the
        #    year 2999. The answer is 1 whatever the clock says.
        if some=$(printf '%s\n' \
          '{"createdAt":"1970-01-01T00:00:00Z","id":"selftest-stuck"}' \
          '{"createdAt":"2999-01-01T00:00:00Z","id":"selftest-fresh"}' \
          | countStuck "$cutoff"); then
          [ "$some" = 1 ] || broken "parser self-test 2 (one stuck of two) expected 1, got '$some'."
        else
          broken "parser self-test 2 (one stuck of two) could not run at all."
        fi

        # 3. THE WRONG SHAPE MUST FAIL. The human table that the earlier version
        #    of this script parsed is fed in, and the parser is REQUIRED to
        #    reject it. A self-test that only ever sees good input cannot tell a
        #    working parser from one that answers 0 to everything -- which is
        #    precisely the bug being fixed here, so the negative case is not
        #    optional. Its stderr is dropped: a jq parse error is the expected
        #    result of this case, and printing it would read as a fault.
        if bad=$(printf '%s\n' \
          'Id            Next Retry            Received' \
          'aaaa  1970-01-01T00:00:00Z  1970-01-01T00:00:00Z' \
          | countStuck "$cutoff" 2>/dev/null); then
          broken "parser self-test 3 ACCEPTED the CLI's human table where NDJSON is required, and answered '$bad'. It is parsing a shape this command does not emit, so its count of the real queue would be fiction."
        fi

        # Capture the query as its own step instead of as the head of a pipe, so
        # a management-API failure (Stalwart down, credentials rotated, admin
        # account locked, field renamed) is distinguishable from a genuinely
        # empty queue. The CLI's own stderr is left to flow to the journal
        # rather than captured and re-echoed -- it is the useful diagnostic, and
        # re-printing text that came back from a command invoked with a password
        # on its argv is a good way to leak one.
        if ! queue=$($cli query QueuedMessage --json --fields createdAt); then
          broken "'stalwart-cli query QueuedMessage --json --fields createdAt' failed (its own error is above): the management API is unreachable, the credentials are rejected, or that field no longer exists."
        fi

        # `printf '%s'`, not `'%s\n'`: an empty queue is an empty string here,
        # and appending a newline to it would feed the parser a blank line to
        # rule on. jq tolerates that, but the input it is handed should be the
        # bytes the CLI produced and nothing else.
        stuck=$(printf '%s' "$queue" | countStuck "$cutoff") \
          || broken "counting the live queue failed -- the CLI returned something this parser refused (its error is above). It is NOT a count of zero."
        case "$stuck" in
          ""|*[!0-9]*)
            broken "counting the live queue yielded '$stuck', which is not a number."
            ;;
        esac

        if [ "$stuck" -gt 0 ]; then
          echo "stalwart-queue-monitor: $stuck message(s) queued longer than ${toString cfg.queueMonitor.maxAgeMinutes}m -- OUTBOUND DELIVERY IS FAILING" >&2
          echo "hint: check the delivery log for connect-errors; a stale cached relay route needs a FULL service restart, reload is not enough" >&2
          exit 1
        fi
        echo "stalwart-queue-monitor: queue draining normally (self-test passed: empty=0, fixture=1, human-table rejected; live queue parsed, 0 of it older than ${toString cfg.queueMonitor.maxAgeMinutes}m)"
      '';
    };

    systemd.timers.stalwart-queue-monitor = mkIf cfg.queueMonitor.enable {
      description = "Periodic outbound-queue health check";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.queueMonitor.interval;
        Persistent = true;
      };
    };

    systemd.services.stalwart-config = mkIf cfg.bootstrap.enable {
      description = "Apply Stalwart registry config (declarative NDJSON bootstrap plan)";
      after = [ "stalwart.service" ];
      requires = [ "stalwart.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # Re-run only when the rendered plan's content actually changes.
      restartTriggers = [ applyPlan ];
      script = ''
        set -u
        marker=${lib.escapeShellArg cfg.bootstrap.markerFile}
        if [ "$(cat "$marker" 2>/dev/null)" = "${planHash}" ]; then
          echo "stalwart-config: plan ${planHash} already applied -- skipping"
          exit 0
        fi
        pw=$(cat ${lib.escapeShellArg cfg.recoveryAdmin.passwordFile})

        # READINESS. See cliPackage's own option description for the exact
        # CLI-flag footgun that can make this loop silently never succeed.
        ok=0
        for i in $(seq 1 ${toString (cfg.bootstrap.readinessTimeout / 2)}); do
          if ${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password "$pw" query Domain >/dev/null 2>&1; then
            ok=1
            break
          fi
          sleep 2
        done
        if [ "$ok" != 1 ]; then
          echo "stalwart-config: management API not reachable/authenticated within ${toString cfg.bootstrap.readinessTimeout}s -- leaving for next boot"
          exit 0
        fi

        # SAFETY GUARD (bootstrap-only). This plan is CREATE-ONLY: applying
        # it a second time against an already-configured database PK-
        # violates existing objects and leaves duplicate Directory/
        # Certificate/Application objects and dangling #localId references
        # behind, with the Authentication object left pointing at whichever
        # duplicate was created last. So this only ever proceeds against a
        # database that has NONE of THIS plan's OWN configured domains in
        # it yet -- never a single hardcoded literal domain name, which
        # would (a) not generalize past one deployment and (b) ALWAYS read
        # as "empty" on every other deployment, defeating the guard
        # entirely and reproducing the duplicate-object failure on every
        # single boot.
        pattern=${lib.escapeShellArg domainGuardPattern}
        if [ -n "$pattern" ]; then
          ndom=$(${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password "$pw" query Domain 2>/dev/null | grep -cE "$pattern" || true)
        else
          ndom=0
        fi
        if [ "''${ndom:-0}" -gt 0 ]; then
          echo "stalwart-config: DB already has $ndom of this plan's domains -- NOT re-applying (avoids duplicate-object pollution); marking applied."
          echo "${planHash}" > "$marker"
          exit 0
        fi

        if ${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password "$pw" apply --file ${applyPlan} ${optionalString cfg.bootstrap.continueOnError "--continue-on-error"}; then
          echo "${planHash}" > "$marker"
          echo "stalwart-config: applied plan ${planHash}"
        else
          echo "stalwart-config: apply reported errors (see above) -- marker NOT written"
        fi
      '';
    };

    # Applies the mutable-settings plan. Deliberately a SEPARATE unit from
    # stalwart-config rather than more lines in it: that unit must keep its
    # virgin-database guard (its plan creates objects), and this one must NOT
    # have it (its plan only updates singletons, and the whole point is that it
    # still runs on an already-configured database). Sharing a unit would mean
    # choosing one behaviour for both.
    systemd.services.stalwart-settings = mkIf (cfg.bootstrap.enable && settingsOps != [ ]) {
      description = "Apply Stalwart mutable runtime settings (idempotent update-only plan)";
      # Ordered after stalwart-config so that on a genuinely fresh database the
      # objects exist before these updates address them. `after` only -- not
      # `requires` -- because stalwart-config skipping (which is its normal
      # steady state) must not stop these settings being applied.
      after = [ "stalwart.service" "stalwart-config.service" ];
      # `wants`, NOT `requires`, and that is deliberate. This unit restarts
      # stalwart.service itself when the settings change; with `requires` that
      # restart propagates a STOP back to this unit, systemd SIGTERMs it
      # mid-run, and the unit lands in `failed` with `result 'signal'` even
      # though the apply succeeded a second earlier. On a mail host that is a
      # false alarm that costs someone a night. The work is already done and the
      # marker already written by then, so nothing is lost -- but nothing should
      # look broken either. Ordering (`after`) is what actually matters here;
      # the readiness loop below covers a server that is not up yet.
      wants = [ "stalwart.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Without this the `exit 1` below is a dead end: switch-to-configuration
        # does not re-run a failed unit whose plan has not changed, so a single
        # transient failure (server still starting, a lost connection mid-apply)
        # would leave the declared settings unapplied until someone noticed by
        # hand. `on-failure` is legal on Type=oneshot -- `always` is not, and
        # systemd rejects the unit file outright if you use it.
        #
        # No TimeoutStartSec is needed: Type=oneshot defaults to infinity, not
        # to DefaultTimeoutStartSec, so the readiness loop below runs to its own
        # deadline rather than being SIGTERMed at 90s (verified live:
        # `systemctl show stalwart-settings -p TimeoutStartUSec` -> infinity).
        Restart = "on-failure";
        RestartSec = 30;
      };
      restartTriggers = [ settingsPlan ];
      script = ''
        set -u
        marker=${lib.escapeShellArg cfg.limits.markerFile}
        if [ "$(cat "$marker" 2>/dev/null)" = "${settingsHash}" ]; then
          echo "stalwart-settings: plan ${settingsHash} already applied -- skipping"
          exit 0
        fi
        pw=$(cat ${lib.escapeShellArg cfg.recoveryAdmin.passwordFile})

        # Same readiness poll as stalwart-config: the management API comes up
        # after the server socket does, and a settings apply against a
        # not-yet-authenticating API would otherwise fail once per boot.
        ok=0
        for i in $(seq 1 ${toString (cfg.bootstrap.readinessTimeout / 2)}); do
          if ${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password "$pw" query Domain >/dev/null 2>&1; then
            ok=1
            break
          fi
          sleep 2
        done
        if [ "$ok" != 1 ]; then
          # FAIL, deliberately, rather than the bootstrap unit's exit 0. That
          # unit populates an empty database and can honestly wait for the next
          # boot; this one is the only thing asserting the declared limits, and
          # a green unit that applied nothing is indistinguishable from a green
          # unit that applied everything. Restart=on-failure retries it.
          echo "stalwart-settings: management API not reachable/authenticated within ${toString cfg.bootstrap.readinessTimeout}s -- failing so it is retried" >&2
          exit 1
        fi

        # NO domain guard here, and that is the entire difference from
        # stalwart-config. These ops are updates against singletons: running
        # them against a populated database is the intended case, not the
        # hazard. See the `settingsOps` comment in this module's `let` block.
        #
        # No --continue-on-error either: every op in this plan is a value the
        # consumer explicitly asked for, so a partial apply must leave the
        # marker unwritten and retry, not be recorded as done.
        if ${cfg.cliPackage}/bin/stalwart-cli --url http://127.0.0.1:8080 --user ${lib.escapeShellArg cfg.recoveryAdmin.username} --password "$pw" apply --file ${settingsPlan}; then
          echo "${settingsHash}" > "$marker"
          echo "stalwart-settings: applied plan ${settingsHash}"
${optionalString cfg.limits.restartServerAfterApply ''
          # --no-block is load-bearing, not politeness. This unit is ordered
          # After=stalwart.service, so a SYNCHRONOUS restart job would be
          # ordered against the very unit whose start job is still active --
          # systemd resolves that by deadlocking one of them. Detaching the job
          # lets this unit exit first and the restart run immediately after.
          echo "stalwart-settings: restarting stalwart to load the new settings"
          systemctl --no-block try-restart stalwart.service || true
''}
        else
          echo "stalwart-settings: apply reported errors (see above) -- marker NOT written, will retry" >&2
          exit 1
        fi
      '';
    };

    security.acme = mkIf cfg.acme.enable {
      acceptTerms = true;
      defaults.email = cfg.acme.email;
      certs.${cfg.acme.hostname} = {
        dnsProvider = cfg.acme.dnsProvider;
        environmentFile = cfg.acme.credentialsFile;
        dnsResolver = cfg.acme.dnsResolver;
        extraDomainNames = cfg.acme.extraDomainNames;
        group = cfg.group;
      };
    };

    networking.firewall.allowedTCPPorts =
      mkIf (cfg.publicListeners.enable && cfg.openFirewall) [ 993 465 587 995 ];
  };
}
