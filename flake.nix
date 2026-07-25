{
  description = "Self-hosted mail + identity stack: Stalwart, an LDAP directory, OIDC SSO, a password manager, a webmail frontend, and the two glue daemons that make outbound/inbound delivery work on an IPv6-only host behind Cloudflare Email Routing.";

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
      # Scaffold only -- no modules extracted yet. See README.md's
      # "Extraction plan" for the intended shape:
      #   nixosModules.{core,stalwart,ldap-directory,sso,password-manager,
      #     webmail,outbound-bridge,inbound-bridge}
      nixosModules = { };

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
