{
  description = "Self-hosted mail stack: Stalwart, a webmail frontend, and the two glue daemons that make outbound/inbound delivery work on an IPv6-only host behind an HTTP-only inbound mail route. Identity (an LDAP directory, OIDC SSO) is out of scope here -- see README.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # For exactly one thing: `lib.probeFact`/`lib.collectProbes` (github:julian-corbet/
    # nixhost-corbet-ch, `lib/facts.nix`) -- the shared, plain-function fix for the
    # cross-namespace defensive-read defect class (a bare `config.nixfoo.bar or fallback`
    # cannot tell "nixfoo not composed here" from "nixfoo composed but `bar`
    # moved/renamed/rejected" -- see nixhost's own `lib/facts.nix` header). `stalwart.nix`'s own
    # `config.nixiam.posix.identities`/`.groups` read is exactly this shape, so it takes
    # `probeFact`/`collectProbes` closed over as plain function arguments (below), never
    # `_module.args` -- the same partially-applied-before-the-module-system-sees-it pattern this
    # family already uses for `nixfsCatalogue` (see infra's own flake.nix comment on `mkNixnas`
    # for that precedent) -- so a consumer importing `nixosModules.stalwart` sees an ordinary
    # module function and never needs to know `probeFact` exists.
    nixhost = {
      url = "github:julian-corbet/nixhost-corbet-ch";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixhost }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
    in
    {
      # ---------------------------------------------------------------
      # Each service is independent -- there is no shared "core" engine
      # to opt into here (unlike nixnet's core+providers shape). Import
      # whichever of these your deployment actually runs; none of them
      # requires another to evaluate, though stalwart + one or both
      # bridges is the common pairing (see README).
      #
      # Named after the actual upstream project/binary behind each
      # module, not an abstract role -- see each module's header comment
      # for why (a fake generic interface with exactly one implementation
      # behind it documents a boundary that doesn't exist).
      # ---------------------------------------------------------------
      # `probeFact`/`collectProbes` closed over here, before the module system ever sees the
      # result -- see the input comment above. The exported value is a plain module function
      # taking the usual `{ config, lib, pkgs, ... }`; nothing about consuming it changes.
      nixosModules.stalwart = import ./modules/stalwart.nix { inherit (nixhost.lib) probeFact collectProbes; };
      nixosModules.bulwark = ./modules/bulwark.nix;
      nixosModules."outbound-bridge" = ./modules/outbound-bridge.nix;
      nixosModules."inbound-bridge" = ./modules/inbound-bridge.nix;

      # The CLIENT half: tools that TALK to a mail server rather than being one (a terminal mail
      # user agent, an IMAP-to-IMAP synchroniser). Pure option surface -- it publishes package
      # intent and installs nothing -- so the identical file serves both planes rather than
      # needing a system-manager-specific twin. See modules/clients.nix for the one line each
      # plane wires, and lib/clients.nix for the catalogue and its verification.
      nixosModules.clients = ./modules/clients.nix;
      systemManagerModules.clients = ./modules/clients.nix;

      # ---------------------------------------------------------------
      # The two bridges are real programs, not configuration, so they get
      # real tests rather than an evaluation check. Both suites are stdlib
      # unittest and run offline: no socket leaves the sandbox, no provider
      # is contacted, and no mail is sent.
      #
      # What they pin is deliberately narrow and deliberately chosen: the
      # behaviours whose failure is SILENT. A status mapped the wrong way
      # does not raise — it makes a caller retry a hard refusal forever, or
      # discard a message that only needed retrying. An allow-list that
      # widens by accident does not raise either; it turns a listener
      # holding a paid account's sending credentials into an open relay,
      # which is the incident the outbound module's own comments record.
      # ---------------------------------------------------------------
      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };

          # The inbound bridge is stdlib-only, by design. Its test suite is too,
          # so a bare interpreter is the whole dependency set.
          inboundPython = pkgs.python3;

          # The outbound bridge speaks HTTP to providers and SMTP to the local
          # mail server, so it has two real dependencies.
          outboundPython = pkgs.python3.withPackages (ps: [ ps.httpx ps.aiosmtpd ]);

          pyTest = { name, python, src }:
            pkgs.runCommand "nixmail-test-${name}"
              { nativeBuildInputs = [ python ]; }
              ''
                cp -r ${src}/. ./work
                chmod -R u+w ./work
                cd ./work
                export HOME=$PWD

                # httpx builds an SSL context the moment a client is constructed,
                # and reads SSL_CERT_FILE to do it — which points at nothing
                # inside the sandbox, so merely CONSTRUCTING a client raises
                # FileNotFoundError before any request is attempted. Pointing it
                # at a real bundle is what lets the delivery tests exercise the
                # relay chain. Nothing is fetched: every relay is a stub, and the
                # sandbox has no network regardless.
                export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt

                # Stated explicitly rather than inherited: piping into tee makes
                # the pipeline's status tee's, so without pipefail a failing suite
                # would pass silently. The nixpkgs builder already sets it — this
                # is here so the guarantee survives someone running the same lines
                # by hand, where it does not hold.
                set -o pipefail
                python3 -m unittest discover -p 'test_*.py' -v 2>&1 | tee ./log
                echo "--- ${name} suite passed ---" >> ./log
                cp ./log $out
              '';
        in
        {
          inbound-bridge-tests = pyTest {
            name = "inbound-bridge";
            python = inboundPython;
            src = ./modules/inbound-bridge;
          };

          outbound-bridge-tests = pyTest {
            name = "outbound-bridge";
            python = outboundPython;
            src = ./modules/outbound-bridge;
          };

          # All four modules composed into one system. They share the `nixmail.*`
          # namespace, so this is what catches a collision between two of them —
          # the failure mode a per-module check cannot see by construction.
          #
          # The string context around the derivation path MUST be discarded: a
          # store path inside a string is tracked as a build dependency, so
          # keeping it would BUILD an entire NixOS system rather than evaluate
          # one — minutes and a multi-gigabyte download versus seconds.
          modules-evaluate =
            let
              host = lib.nixosSystem {
                inherit system;
                modules = lib.attrValues self.nixosModules
                  ++ [ ./examples/host/configuration.nix ];
              };
            in
            pkgs.writeText "nixmail-host-drvpath"
              (builtins.unsafeDiscardStringContext host.config.system.build.toplevel.drvPath);

          # ---------------------------------------------------------------
          # The client catalogue. Three properties, and the third is the one
          # that matters: a selected tool nixpkgs does not package must be
          # REPORTED rather than quietly dropped, because a host that selects
          # a tool, evaluates cleanly and does not have it is the silent
          # partial outcome this option surface exists to prevent.
          # ---------------------------------------------------------------
          clients-catalogue =
            let
              evalClients = tools: (lib.evalModules {
                modules = [ ./modules/clients.nix { nixmail.clients.tools = tools; } ];
              }).config.nixmail.clients;

              none = evalClients [ ];
              both = evalClients [ "s-nail" "imapsync" ];

              ok =
                # Nothing selected contributes nothing, on every plane.
                none.archPackages == [ ] && none.nixosPackages == [ ]
                && none.unavailableOnNixos == [ ]
                # Both are official-repo pacman names, so neither may reach the AUR half -- and
                # nothing may reach it that is not there deliberately.
                && lib.sort (a: b: a < b) both.archPackages == [ "imapsync" "s-nail" ]
                && both.aurPackages == [ ]
                # nixpkgs packages exactly one of the two, and the other is NAMED rather than
                # silently missing.
                && both.nixosPackages == [ "imapsync" ]
                && both.unavailableOnNixos == [ "s-nail" ];
            in
            if ok
            then pkgs.runCommand "nixmail-clients-catalogue" { } "touch $out"
            else throw ''
              nixmail client catalogue FAILED:
                selected both -> arch=${builtins.toJSON both.archPackages} aur=${builtins.toJSON both.aurPackages}
                                 nixos=${builtins.toJSON both.nixosPackages} unavailable=${builtins.toJSON both.unavailableOnNixos}
                selected none -> arch=${builtins.toJSON none.archPackages} nixos=${builtins.toJSON none.nixosPackages}
            '';
        });

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
