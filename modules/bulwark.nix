# modules/bulwark.nix
#
# A NixOS module for running Bulwark (a self-hosted JMAP webmail client,
# shipped upstream only as a Next.js-standalone OCI image) as a rootless
# podman container. Named after the actual upstream project, not
# "webmail.nix" -- there is no real shared abstraction across Bulwark,
# Roundcube, SnappyMail etc. here (different image formats, different auth
# models, different persistence layouts), and a fake "webmail" interface
# with exactly one implementation behind it would document a boundary that
# doesn't exist. If a second webmail client is ever added to nixmail, it
# gets its own module; whether a shared `webmail-core.nix` makes sense at
# that point is a question for two data points, not one.
#
# What justifies publishing this at all is three pieces of genuinely
# transferable mechanism, none of them specific to webmail:
#
#   1. Baking an OCI image into the Nix closure at BUILD time (via
#      `pkgs.dockerTools.pullImage`) instead of pulling it at RUNTIME, as
#      the fix for a real and easy-to-miss problem: any registry that is
#      IPv4-only (no AAAA record -- GHCR included) is completely
#      unreachable from an IPv6-only host, and `podman pull` against it
#      doesn't fail fast, it hangs and retries, which is worse when it
#      happens to be sitting in the critical path of a `nixos-rebuild
#      switch`. `pullImage` runs the pull as a fixed-output derivation on
#      whatever machine actually builds/substitutes for you (a CI runner,
#      a build box -- anything dual-stack), producing a content-addressed
#      store path. That store path is then a completely ordinary Nix
#      artifact: it gets substituted to the target over IPv6 like any
#      other build output, and the target's container unit `podman load`s
#      it locally. The target itself never resolves the registry's
#      hostname or opens a connection to it -- no DNS64/NAT64 needed, and
#      the whole thing stays byte-for-byte reproducible. This pattern
#      generalizes to any OCI image on any IPv6-only (or otherwise
#      network-restricted) NixOS host; see `imageFile` below for how to
#      opt out of it if your host is dual-stack and you'd rather pull
#      normally.
#   2. The rootless-podman `--userns=keep-id:uid=1001,gid=1001` mapping
#      that makes a bind-mounted host directory writable by a container
#      process running as a fixed, image-baked UID -- without ever
#      `chown`-ing that host directory to that UID. See `stateDir` below
#      for the full mechanism and why the naive fix (just chown the host
#      dir to 1001) does not work under rootless podman.
#   3. The `jmapServerUrl` option's documentation: a real, non-obvious JMAP
#      protocol trap where the backend origin you configure is NOT purely
#      an internal wire detail -- the JMAP session object hands the
#      BROWSER absolute URLs anchored on that origin, and the browser then
#      talks to those URLs directly. Point this at a loopback address (the
#      instinctive choice for "backend the frontend proxies to") and
#      uploads, downloads, and the EventSource push channel all silently
#      break, while the login page itself works fine. This one is worth
#      preserving on its own; it is exactly the kind of thing that costs
#      someone a full afternoon of "why do attachments 404" before they
#      find it.
#
# Caveats, published deliberately rather than glossed over:
#
#   - Image pinning is by DIGEST (see `image.digest`), which means this
#     module ships one specific upstream release and does not track new
#     Bulwark releases on its own. Bumping requires a manual
#     `nix-prefetch-docker` run and a new set of `image.*` values (see
#     that option's description for the exact invocation) -- nixmail does
#     not auto-update this pin.
#   - The `oidc.*` option surface implements Bulwark's documented OIDC
#     env-var contract, but it has NOT been exercised end-to-end against a
#     real OIDC provider in the deployment this module was extracted from
#     (confirmed live: zero OAUTH_* environment variables present on that
#     container -- it runs basic JMAP username+password auth only).
#     Treat `oidc.enable = true` as an unverified code path until someone
#     confirms it against a real IdP, not as a proven feature just because
#     the options exist and look complete.

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.nixmail.bulwark;

  # The image `pullImage` bakes when `imageFile` is left at its default.
  # Built lazily -- if you set `imageFile = null` to opt out of the bake
  # (see that option), this derivation is simply never evaluated, and
  # nothing here requires network access at build time on that path.
  bulwarkImage = pkgs.dockerTools.pullImage {
    imageName = cfg.image.name;
    imageDigest = cfg.image.digest;
    sha256 = cfg.image.sha256;
    finalImageName = cfg.image.name;
    finalImageTag = cfg.image.tag;
    os = "linux";
    # Assumes an x86_64-linux consumer, matching the reference deployment.
    # Change if you're deploying to aarch64 -- and re-run the
    # nix-prefetch-docker invocation documented on `image.sha256` with
    # `--arch arm64`, since the FOD hash is architecture-specific.
    arch = "amd64";
  };
in
{
  options.nixmail.bulwark = {
    enable = lib.mkEnableOption ''
      Bulwark, a self-hosted JMAP webmail client (Next.js standalone), run
      as a rootless-podman OCI container. Talks JMAP to any RFC 8620/8621
      JMAP mail server you point it at via `jmapServerUrl` -- this module
      does not assume or require any particular mail server, though it was
      extracted from a deployment pairing it with Stalwart.
    '';

    image = {
      name = lib.mkOption {
        type = lib.types.str;
        default = "ghcr.io/bulwarkmail/webmail";
        description = ''
          Container image repository, without tag or digest. Upstream
          publishes a stable `webmail` and a `webmail-beta` image under
          the `bulwarkmail` org on GHCR.
        '';
      };

      tag = lib.mkOption {
        type = lib.types.str;
        default = "1.7.3";
        description = ''
          Human-readable tag baked alongside `digest` below. Purely
          informational once `imageFile` is set (podman resolves the
          loaded tarball by name:tag, but the actual bytes come from the
          digest-pinned fixed-output derivation) -- it exists so `podman
          images`/`podman inspect` show something meaningful, and so the
          runtime-pull path (`imageFile = null`) has a tag to pull.
        '';
      };

      digest = lib.mkOption {
        type = lib.types.str;
        default = "sha256:a8a66a19bd038b695d18c354ef33fd978b48191d2cdc1caced6e805346fbf030";
        description = ''
          The multi-arch manifest-index digest this module pulls by (not
          the per-arch image digest) -- this is what makes the build
          reproducible: `tag` can be re-pointed upstream at any time,
          `digest` cannot silently change under you. Regenerate together
          with `sha256` below on every upgrade; see `sha256`'s description
          for the exact command.
        '';
      };

      sha256 = lib.mkOption {
        type = lib.types.str;
        default = "sha256-jpeQ35LLsvlqgpjboiQEdZBiaTL316pxS4pfWxpgBm8=";
        description = ''
          Fixed-output hash of the tarball `pkgs.dockerTools.pullImage`
          produces for `image.name`@`image.digest`. This is what makes the
          build-time bake (see `imageFile`) a valid Nix fixed-output
          derivation at all -- Nix needs to know the expected output hash
          up front so it can be built on any machine and substituted
          anywhere without re-fetching.

          Regenerate `digest` and this value TOGETHER when bumping the
          image, with:

            nix run nixpkgs#nix-prefetch-docker -- \
              --image-name <image.name> --image-tag <new tag> \
              --arch amd64 --os linux

          Then update `tag`, `digest`, and `sha256` all three from that
          command's output. Mismatch any one of them and the build fails
          closed (a Nix hash mismatch), not open -- there is no silent
          way to end up running an image whose bytes don't match what you
          pinned.
        '';
      };
    };

    imageFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = bulwarkImage;
      description = ''
        Store path of a `podman load`-able image tarball, baked at BUILD
        time via `pkgs.dockerTools.pullImage` from `image.*` above (see
        this module's file header for the full IPv6-only-registry
        rationale). Defaulted so the common case -- a host that genuinely
        cannot reach `image.name`'s registry directly -- needs zero extra
        configuration: the generated container unit `podman load`s this
        tarball before `podman run` and podman never contacts the
        registry at runtime at all.

        Set this to `null` to opt OUT of the bake entirely and let podman
        pull `image.name:image.tag` normally at container start, the way
        `virtualisation.oci-containers` behaves everywhere else. Do this
        if your host is dual-stack (or otherwise has a working path to
        the registry) and you'd rather track a moving tag/pull cache than
        rebuild-and-substitute a store path on every image bump.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Host address the container's port is published on. Left at
        loopback by default on the assumption that whatever fronts this
        publicly (a reverse proxy, a tunnel client, a load balancer) runs
        on the same host and reaches it over loopback -- set this to a
        routable address only if you know your firewalling covers it.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 3000;
      description = ''
        Host port mapped to the container's internal :3000 (Bulwark's
        fixed default -- its Dockerfile `EXPOSE`s 3000 and the image sets
        `PORT=3000` internally regardless of this value). Point whatever
        fronts this module at `http://<listenAddress>:<port>`.
      '';
    };

    jmapServerUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://mail.example.com";
      description = ''
        Backend JMAP server base URL -- and the one option in this module
        most likely to be set wrong on a first pass, because the obvious
        choice (some internal/loopback address, mirroring how you'd wire
        a typical backend-API reverse-proxy target) silently breaks part
        of the app instead of failing to connect.

        Bulwark fetches the JMAP session object from this origin's
        `.well-known/jmap`. That session object is NOT just used
        server-side: per the JMAP spec (RFC 8620), it contains absolute
        API/upload/download/EventSource URLs anchored on whatever origin
        served it, and the BROWSER then talks to those URLs directly --
        file uploads, attachment downloads, and the EventSource push
        channel all bypass Bulwark's own Next.js proxy and hit the JMAP
        server straight from the client. So this MUST be the public,
        browser-reachable https origin your JMAP server is actually
        served on (e.g. via a reverse proxy or tunnel in front of it), not
        an internal service address, not `http://127.0.0.1:<port>`, even
        if that internal address is exactly where Bulwark's own server-
        side requests would otherwise be routed. Get this wrong and login
        can still work (the initial session fetch may succeed via a
        server-side-only path) while attachments and live updates fail
        with no obvious error pointing back at this option.

        Setting this also skips Bulwark's first-run setup wizard and
        locks the field, which is what you want for immutable infra.
        `STALWART_FEATURES=true` is always set alongside it, enabling
        Stalwart-specific extras (password change, Sieve filter editing)
        when the backend happens to be Stalwart; it is a harmless no-op
        against any other spec-compliant JMAP server.
      '';
    };

    appName = lib.mkOption {
      type = lib.types.str;
      default = "Webmail";
      description = "Branding name shown in the UI title bar and PWA manifest.";
    };

    # --- Auth model -----------------------------------------------------
    # Two paths, mutually compatible (Bulwark supports both at once):
    #
    #   1. Basic JMAP auth (DEFAULT, oidc.enable = false): the user types
    #      their mailbox address + password into Bulwark's own login form;
    #      Bulwark authenticates that straight against the JMAP server. No
    #      IdP round-trip, no OAuth client to register, nothing else to
    #      stand up first -- the simplest path to a working deployment.
    #
    #   2. OIDC SSO (oidc.enable = true): Bulwark redirects to your OIDC
    #      provider, the user authenticates there, and Bulwark exchanges
    #      the resulting code (PKCE S256) for tokens it presents to the
    #      JMAP server as a Bearer credential. Requires an OAuth client
    #      registered with that provider AND the JMAP server itself
    #      configured to trust access tokens issued by it -- this module
    #      only configures Bulwark's own side of that handshake. See this
    #      module's file header: this path is UNTESTED against a real
    #      provider in the deployment it was extracted from.
    oidc = {
      enable = lib.mkEnableOption ''
        OIDC SSO via an external OpenID Connect provider, instead of (in
        addition to, since both can coexist) basic JMAP username/password
        login. Off by default -- basic JMAP auth is the proven path.
        UNTESTED end-to-end: see this module's file header before relying
        on it in production.
      '';

      issuerUrl = lib.mkOption {
        type = lib.types.str;
        example = "https://id.example.com";
        description = ''
          OIDC issuer URL. Bulwark auto-discovers the rest of the
          endpoints it needs from `<issuerUrl>/.well-known/openid-configuration`,
          so this is the only endpoint you need to supply by hand.
        '';
      };

      clientId = lib.mkOption {
        type = lib.types.str;
        default = "webmail";
        description = ''
          OAuth `client_id` registered with your OIDC provider for this
          app. Not secret -- it is sent to the browser as part of the
          authorization redirect, unlike `OAUTH_CLIENT_SECRET` (see
          `environmentFile`).
        '';
      };

      onlySso = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          When true, hides the username/password form entirely and forces
          the SSO button (`OAUTH_ONLY=true`). Keep this false while your
          IdP integration is new: basic JMAP login then remains a
          break-glass path if the IdP is ever unreachable, rather than a
          single point of total login failure.
        '';
      };
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      example = "/var/lib/bulwark";
      description = ''
        Host directory bind-mounted into the container at `/app/data`
        (the image's `WORKDIR` is `/app`, and its own default `./data/*`
        paths resolve under that). Holds the admin config (config.json,
        policy.json, plugins, themes), admin runtime state (audit log,
        setup token), encrypted settings-sync blobs, and a telemetry
        instance id. Point this at whatever path on your host is meant to
        survive a rebuild -- this module has no opinion on your disk
        layout, only that this directory must exist and persist across
        container restarts for Bulwark's own state to be meaningful.

        The trap this option's default deliberately avoids: the container
        process runs as the IMAGE's own `nextjs` user, a fixed UID 1001
        baked into the image, not something this module or you control.
        Under ROOTLESS podman, that in-container UID 1001 is not the same
        thing as host UID 1001 -- it is remapped through the rootless
        runtime user's subuid range, so a host directory naively `chown
        1001`'d is USELESS to the container (it's writable by a
        completely different host UID than the one the remap actually
        produces). This module instead passes
        `--userns=keep-id:uid=1001,gid=1001` (see `extraOptions` in the
        config below), which tells podman: map in-container UID/GID
        1001 onto the HOST UID/GID that is running the rootless podman
        process itself, rather than through the subuid range. That means
        `stateDir` must be owned by the host user/group that actually runs
        this container's rootless podman service -- typically via a
        `systemd.tmpfiles.rules` entry you add alongside this option, not
        a hardcoded `chown 1001` anywhere. If you run this container under
        ROOT-owned podman instead, drop `keep-id` from `extraOptions` and
        chown `stateDir` to 1001:1001 directly -- the two approaches are
        mutually exclusive, not layered.
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.path;
      example = "/run/secrets/bulwark-env";
      description = ''
        Path to an EnvironmentFile (`KEY=VALUE` lines, one per line) read
        by systemd before the container starts and injected via podman's
        `environmentFiles`. This module is deliberately agnostic about how
        this file gets there -- sops-nix, agenix, a custom fetch-at-boot
        unit, anything that lands a file at this path before the unit
        starts is fine. See `dependsOnUnits` for wiring the ordering
        guarantee that makes "before" actually true.

        Required key:
          SESSION_SECRET=<a random secret, e.g. `openssl rand -base64 32`>
            Encrypts "remember me" cookies and the settings-sync blobs at
            rest.

        Required ONLY when `oidc.enable = true` AND your OAuth client is
        registered as confidential (a public PKCE client needs no secret
        at all, in which case this key is simply omitted):
          OAUTH_CLIENT_SECRET=<your OIDC provider's client secret>
      '';
    };

    dependsOnUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "sops-nix.service" ];
      description = ''
        Extra systemd units this container's generated unit orders after
        AND requires, on top of `network-online.target` (always
        included). List whatever unit(s) on your system actually produce
        `environmentFile` -- a sops-nix secret-activation target, an
        agenix unit, a custom fetch-at-boot service, whatever your
        deployment uses.

        This exists because the deployment this module was extracted from
        hardcoded exactly one such unit (its own bespoke secrets-delivery
        mechanism) directly into `after`/`requires`, which only made sense
        for that one fleet. The underlying failure mode this guards
        against is universal, though: without SOME ordering guarantee,
        podman starts up fine and reads `environmentFile` whether or not
        it has actually been written yet by whatever process is supposed
        to produce it -- on a slow boot, or before first
        provisioning, that file may not exist or may still hold stale
        content, and the container starts anyway with an empty
        `SESSION_SECRET` or a missing `OAUTH_CLIENT_SECRET` instead of
        failing loudly and obviously.
      '';
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "256m";
      description = ''
        Hard cap passed to podman's own `--memory`. This is applied
        UNCONDITIONALLY regardless of `slice` below -- it is podman's own
        cgroup limit on this one container, independent of any host-level
        systemd accounting. Next.js standalone idles around ~80-120 MB
        RSS; 256m gives headroom for a couple of concurrent mailbox loads
        without inviting the OOM killer for anything else sharing the
        host. Raise cautiously on a memory-constrained host -- every extra
        MB here is a MB unavailable to whatever else runs alongside it.
      '';
    };

    slice = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "bulwark.slice";
      description = ''
        Optional systemd slice name to place this container's unit into,
        for host-level memory accounting/capping ON TOP OF podman's own
        `--memory` (see `memoryMax`) -- useful if you want `systemd-cgtop`/
        `systemd-run --slice` visibility, or if several units are meant to
        share one memory budget together.

        When set, this module DEFINES `systemd.slices.<slice>` itself
        (with a `MemoryMax` mirroring `memoryMax`), specifically so the
        reference this module writes into the container unit's `Slice=`
        is always guaranteed to resolve to something real. The trap this
        avoids: a slice referenced by `Slice=` but declared NOWHERE in
        NixOS config is not an error -- systemd auto-vivifies an empty,
        UNCONFIGURED slice unit on demand. The container starts, nothing
        logs a warning, and the memory cap you thought you were applying
        at the slice level is simply never enforced there, silently,
        forever -- exactly the shape of bug that survives for a long time
        precisely because nothing about it looks broken. If you want a
        slice shared with OTHER units under your own control (not just
        this one container), declare `systemd.slices.<name>` yourself with
        whatever config you want, point this option at that same name,
        and this module's own default `systemd.slices` entry for it simply
        won't be the only definition -- NixOS merges multiple modules'
        config for the same slice normally.

        Leave this `null` to skip host-level slice placement entirely and
        rely solely on podman's own `--memory` cgroup limit -- a single
        container already gets real enforcement from that alone; the
        slice only adds something if you specifically want systemd-level
        accounting or a shared budget across multiple units.
      '';
    };

    manageBackend = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether this module itself sets the machine-wide OCI backend
        (`virtualisation.podman.enable` and `virtualisation.
        oci-containers.backend`, per `backend` below). Defaulted on so a
        single-purpose host needs zero extra configuration to get a
        working container.

        Set this to `false` if something else on your system already
        configures `virtualisation.oci-containers.backend` -- e.g. you
        also run docker-backed `oci-containers` workloads, or you simply
        prefer to own that machine-wide choice in your own config. That
        option is a single global value, not per-container: a public
        module that force-sets it unconditionally will silently collide
        with (and can flip) whatever a consumer already configured
        elsewhere on the same host. With this set to `false`, this module
        assumes podman is already enabled and configured correctly, and
        touches neither `virtualisation.podman` nor
        `virtualisation.oci-containers.backend` at all.
      '';
    };

    backend = lib.mkOption {
      type = lib.types.enum [ "podman" "docker" ];
      default = "podman";
      description = ''
        OCI backend for this container, applied to `virtualisation.
        oci-containers.backend` only when `manageBackend` is true (the
        default). Podman (rootless, no persistent daemon) is what this
        module's `stateDir`/`extraOptions` are actually written for --
        the `--userns=keep-id` mapping this module relies on for
        `stateDir` ownership is podman-specific syntax that has no direct
        docker equivalent. Setting this to `"docker"` changes which
        backend NixOS renders the container unit for, but does NOT
        translate `extraOptions`; expect to override those yourself if
        you actually run this under docker.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        LOG_LEVEL = "debug";
        TELEMETRY_ENABLED = "false";
      };
      description = ''
        Freeform environment variables merged into the container, for any
        of Bulwark's own env-var surface this module doesn't model as a
        typed option -- health-check tuning, plugin toggles, telemetry
        opt-out, and whatever upstream adds in future releases. Rather
        than chase every new variable with a PR against this module,
        anything set here passes straight through.

        Keys this module manages directly (`APP_NAME`, `HOSTNAME`,
        `PORT`, `JMAP_SERVER_URL`, `STALWART_FEATURES`,
        `SETTINGS_SYNC_ENABLED`, `LOG_FORMAT`, `LOG_LEVEL`, and the
        `OAUTH_*` keys when `oidc.enable` is true) always win over the
        same key set here -- this is deliberate, so a typo or a well-
        meaning override in `settings` can never silently break the
        wiring the typed options above establish. Use the typed option
        instead of `settings` for anything this module already models.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    (lib.mkIf cfg.manageBackend {
      # No compose, no docker socket -- this module only ever needs
      # `oci-containers` to run one container.
      virtualisation.podman = lib.mkIf (cfg.backend == "podman") {
        enable = true;
        dockerCompat = false;
      };
      virtualisation.oci-containers.backend = cfg.backend;
    })

    {
      virtualisation.oci-containers.containers.bulwark = {
        # `image` is the name:tag the loaded tarball carries; podman
        # resolves it against whatever `imageFile` (if non-null) just
        # loaded, or pulls it normally from the registry if `imageFile`
        # is null. Either way the two options stay consistent by
        # construction, since `imageFile`'s own default is built FROM
        # `image.*`.
        image = "${cfg.image.name}:${cfg.image.tag}";
        imageFile = cfg.imageFile;
        autoStart = true;

        # host-ip:host-port:container-port.
        ports = [ "${cfg.listenAddress}:${toString cfg.port}:3000" ];

        volumes = [ "${cfg.stateDir}:/app/data" ];

        environment = cfg.settings // {
          APP_NAME = cfg.appName;

          # Bind inside the container to all interfaces; podman's own
          # port-publish mapping is what actually restricts the HOST side
          # to `listenAddress`. (This HOSTNAME is the in-container Node
          # listen address, not a DNS name.)
          HOSTNAME = "0.0.0.0";
          PORT = "3000";

          # Backend wiring -- see jmapServerUrl's own description for the
          # protocol-level reason this must be a public, browser-
          # reachable origin.
          JMAP_SERVER_URL = cfg.jmapServerUrl;
          STALWART_FEATURES = "true";

          # Persist user settings server-side, encrypted with
          # SESSION_SECRET (see environmentFile).
          SETTINGS_SYNC_ENABLED = "true";

          # Structured logs into whatever this unit's stdout/stderr feeds
          # (journald, under a plain systemd/oci-containers unit).
          LOG_FORMAT = "json";
          LOG_LEVEL = "info";
        }
        // lib.optionalAttrs cfg.oidc.enable {
          OAUTH_ENABLED = "true";
          OAUTH_CLIENT_ID = cfg.oidc.clientId;
          OAUTH_ISSUER_URL = cfg.oidc.issuerUrl;
          OAUTH_ONLY = lib.boolToString cfg.oidc.onlySso;
          # OAUTH_CLIENT_SECRET (confidential clients only) comes from
          # environmentFile, never the world-readable Nix store.
        };

        # Secrets (SESSION_SECRET, optional OAUTH_CLIENT_SECRET) from a
        # file delivered outside the Nix store -- see environmentFile and
        # dependsOnUnits.
        environmentFiles = [ cfg.environmentFile ];

        # `--memory` is podman's own cgroup cap, applied unconditionally
        # (see memoryMax) independent of whether `slice` is set.
        # `--userns=keep-id` is what makes stateDir's ownership model work
        # under rootless podman -- see stateDir's description for the
        # full mechanism and why a plain chown does not achieve the same
        # thing.
        extraOptions = [
          "--memory=${cfg.memoryMax}"
          "--userns=keep-id:uid=1001,gid=1001"
          "--security-opt=no-new-privileges"
        ];
      };

      # oci-containers names the generated unit "podman-bulwark.service"
      # (backend-prefixed) regardless of the container's own name --
      # this is upstream's own naming convention, not something this
      # module chooses.
      systemd.services."podman-bulwark" = {
        after = [ "network-online.target" ] ++ cfg.dependsOnUnits;
        wants = [ "network-online.target" ];
        requires = cfg.dependsOnUnits;
        unitConfig.RequiresMountsFor = cfg.stateDir;
      }
      // lib.optionalAttrs (cfg.slice != null) {
        # This is what actually enrolls the unit's cgroup into the slice;
        # podman's own --memory above is the redundant inner cap. See
        # `slice`'s description for why this module also has to DEFINE
        # the slice below, not just reference it.
        serviceConfig.Slice = cfg.slice;
      };

      systemd.slices = lib.mkIf (cfg.slice != null) {
        ${cfg.slice}.sliceConfig.MemoryMax = cfg.memoryMax;
      };
    }
  ]);
}
