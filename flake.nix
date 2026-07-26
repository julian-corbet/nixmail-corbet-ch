{
  description = "Self-hosted mail stack: Stalwart, a webmail frontend, and the two glue daemons that make outbound/inbound delivery work on an IPv6-only host behind an HTTP-only inbound mail route. Identity (an LDAP directory, OIDC SSO) is out of scope here -- see README.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
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
      nixosModules.stalwart = ./modules/stalwart.nix;
      nixosModules.bulwark = ./modules/bulwark.nix;
      nixosModules."outbound-bridge" = ./modules/outbound-bridge.nix;
      nixosModules."inbound-bridge" = ./modules/inbound-bridge.nix;

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
        });

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
