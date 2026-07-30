# The smallest NixOS configuration that composes all four nixmail modules,
# used by the `modules-evaluate` check.
#
# This is not a machine anyone would run. Every domain is under example.com,
# every secret is a path that does not exist, and the root filesystem is tmpfs.
# It exists so the four modules can be type-checked together — they share the
# `nixmail.*` namespace, and a collision between two of them is exactly
# what a per-module check cannot see.
{ ... }:
{
  # The mail server itself.
  nixmail.stalwart = {
    enable = true;

    # Keyed by the domain name itself — this attrset IS the data model the
    # bootstrap plan renders from, so there is no second parallel list to keep
    # in step with it.
    domains."example.com" = { };

    # Must be a key of `domains`; the module asserts it. This is the domain
    # Stalwart falls back to when it needs one and nothing disambiguates.
    defaultDomain = "example.com";

    # Users live in an external LDAP directory, so its coordinates are site
    # facts the module refuses to guess. Identity is out of scope for this
    # repository — see the sibling nixiam project for the directory itself.
    ldap = {
      baseDn = "dc=example,dc=com";
      bindPasswordFile = "/run/secrets/example-ldap-bind";
    };

    # The break-glass account, for when the directory itself is what is broken.
    # A mail server that can only authenticate against an external directory has
    # no way back in when that directory is down, which is precisely when you
    # need it.
    recoveryAdmin.passwordFile = "/run/secrets/example-recovery-admin";

    # The URL clients are told to reach this server at. Load-bearing: autoconfig
    # and JMAP session discovery hand it to clients, so a wrong value produces
    # clients that connect once and then talk to the wrong place.
    httpPublicUrl = "https://mail.example.com";
  };

  # Webmail. Its three required values are precisely the site facts it cannot
  # guess: where the mail server is, where state lives, and where credentials
  # come from.
  nixmail.bulwark = {
    enable = true;
    jmapServerUrl = "https://mail.example.com";
    stateDir = "/var/lib/example/bulwark";
    environmentFile = "/run/secrets/example-bulwark-env";
  };

  # Outbound: SMTP in, a provider's HTTP API out. `bindHost` and `allowedClients`
  # are left at their defaults deliberately — those defaults ARE the security
  # model for a listener with no authentication of its own, and the bridge's own
  # test suite pins them rather than this file restating them.
  nixmail.outboundBridge = {
    enable = true;
    keysEnvFile = "/run/secrets/example-relay-keys";
  };

  # Inbound: HTTP in, LMTP out.
  nixmail.inboundBridge = {
    enable = true;
    secretFile = "/run/secrets/example-inbound-secret";
  };

  # ── Stubs NixOS demands of any bootable system ───────────────────────────
  # tmpfs on / could never boot a real machine, which is the point: this exists
  # to type-check modules, not to describe hardware.
  fileSystems."/" = {
    device = "nodev";
    fsType = "tmpfs";
  };

  boot.loader.grub = {
    enable = true;
    devices = [ "nodev" ];
  };

  networking.hostName = "example-node";
  system.stateVersion = "25.05";
}
