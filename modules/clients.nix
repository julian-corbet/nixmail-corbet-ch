# modules/clients.nix — selection policy over ../lib/clients.nix, and the resolved package lists a
# backend consumes. Dual-plane: this module writes NOTHING but options, so the same file is
# exported as both `nixosModules.clients` and `systemManagerModules.clients` — the two planes
# differ in which OUTPUT they read, not in what this module does.
#
# PUBLISHES INTENT, INSTALLS NOTHING, which is the same stance every other package-owning repo in
# this family takes and it is deliberate on both planes. On Arch the consuming host owns exactly
# one package reconciler and this module has no business invoking a second; on NixOS a consumer
# may want these in a system profile, a user profile or a devshell, and a module that force-fed
# `environment.systemPackages` would be making that decision for them. So: name what is wanted,
# let the host wire it.
#
#   Arch:   nixarch.packages.pacman = config.nixmail.clients.archPackages;
#           nixarch.packages.aur    = config.nixmail.clients.aurPackages;
#   NixOS:  environment.systemPackages = map (n: pkgs.${n}) config.nixmail.clients.nixosPackages;
#
# THE ARCH/AUR SPLIT IS LOAD-BEARING, NOT COSMETIC. `pacman -S` aborts the ENTIRE transaction on
# one unknown target, so a single AUR-only name mixed into the repo list fails every other package
# in the same converge — including packages that have nothing to do with mail. `archPackages` and
# `aurPackages` are therefore two lists rather than one, exactly as the sibling catalogue repos
# already do it.
#
# A NULL `nixpkgs` IS REPORTED, NEVER SILENTLY DROPPED. A catalogue spanning two platforms will
# eventually carry a tool one of them does not package — this one already does. The wrong shape is
# to filter it out of `nixosPackages` and say nothing, because the result is a NixOS host that
# selected a tool, evaluated cleanly, and does not have it. `unavailableOnNixos` names those
# entries so a consumer can assert on them, print them, or knowingly accept the gap.
{ lib, config, ... }:
let
  cfg = config.nixmail.clients;
  catalogue = import ../lib/clients.nix { };

  selected = map (name: catalogue.${name}) cfg.tools;
in
{
  options.nixmail.clients = {
    tools = lib.mkOption {
      type = lib.types.listOf (lib.types.enum (lib.attrNames catalogue));
      default = [ ];
      example = [ "imapsync" ];
      description = ''
        Which mail CLIENT tools this host wants — tools that talk to a mail server, as opposed to
        the service modules in this repo that are one. Available: ${lib.concatStringsSep ", " (lib.attrNames catalogue)}.

        An `enum` rather than free strings: a typo in a package name is only discoverable at
        reconcile time on Arch, and by then it has already aborted the transaction it was part of.
        Here it fails evaluation instead.

        Selecting a tool does not install it — see this module's header for the one line each
        plane wires, and `unavailableOnNixos` below for the case where a selected tool has no
        nixpkgs package at all.
      '';
    };

    archPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        READ-ONLY, computed: official-repo pacman names for the selected tools. Kept separate
        from `aurPackages` because one unresolvable name aborts the whole `pacman -S` transaction.
      '';
    };

    aurPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        READ-ONLY, computed: AUR names for the selected tools, for the AUR-helper half of a host's
        reconciler. Empty today — both catalogue entries are official-repo — and present anyway,
        so adding an AUR-only tool later is a catalogue edit rather than a new option surface.
      '';
    };

    nixosPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        READ-ONLY, computed: nixpkgs attribute names for the selected tools that nixpkgs actually
        packages. A selected tool with no nixpkgs package is absent here and named in
        `unavailableOnNixos` instead.
      '';
    };

    unavailableOnNixos = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        READ-ONLY, computed: selected tools that nixpkgs does not package, by catalogue name.

        Exists so the gap is VISIBLE. Quietly dropping such a tool from `nixosPackages` would let
        a NixOS host select it, evaluate cleanly, and simply not have it — a silent partial
        outcome, which is the failure mode worth the most to make loud. A consumer that cannot
        tolerate the gap can assert this is empty.
      '';
    };
  };

  config = {
    nixmail.clients.archPackages =
      lib.unique (map (t: t.arch) (lib.filter (t: !(t.aur or false)) selected));
    nixmail.clients.aurPackages =
      lib.unique (map (t: t.arch) (lib.filter (t: t.aur or false) selected));
    nixmail.clients.nixosPackages =
      lib.unique (map (t: t.nixpkgs) (lib.filter (t: t.nixpkgs != null) selected));
    nixmail.clients.unavailableOnNixos =
      lib.unique (map (name: name) (lib.filter (name: catalogue.${name}.nixpkgs == null) cfg.tools));
  };
}
