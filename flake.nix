{
  description = "Self-hosted mail + identity stack: Stalwart, an LDAP directory, a webmail frontend, and the two glue daemons that make outbound/inbound delivery work on an IPv6-only host behind an HTTP-only inbound mail route.";

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
      nixosModules.lldap = ./modules/lldap.nix;
      nixosModules.bulwark = ./modules/bulwark.nix;
      nixosModules."outbound-bridge" = ./modules/outbound-bridge.nix;
      nixosModules."inbound-bridge" = ./modules/inbound-bridge.nix;

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
