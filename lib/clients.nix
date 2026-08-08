# lib/clients.nix — the CLIENT-side catalogue: tools that talk to a mail server rather than
# being one. Pure data, no module system, the same shape the sibling catalogue repos in this
# family use (a name-keyed attrset carrying `arch`, `aur`, `nixpkgs` and a `note`), read by
# ../modules/clients.nix on both planes.
#
# WHY A CLIENT HALF BELONGS IN A MAIL REPO AT ALL. Everything else here runs a mail service: a
# server, a webmail frontend, two delivery bridges. A command-line client is the other end of the
# same protocols — IMAP, SMTP — and it is the tool you actually reach for when a delivery question
# needs answering from a shell rather than a browser. Filing it anywhere else would put "speaks
# IMAP" in one repo and "serves IMAP" in another, which is a split by direction rather than by
# subject. The subject is mail.
#
# THE PLACEMENT BOUNDARY, so a future addition is decidable rather than argued: is the tool's
# subject MAIL, or is mail merely one of the things it can carry? A mail user agent and an
# IMAP-to-IMAP synchroniser are here. A general file-transfer tool that happens to support a
# mail-shaped URL is not; nor is a terminal mail client already catalogued by the repo that owns
# terminal tools — one package, one catalogue, for the reason that family already documents: two
# entries resolving to the same package collide in a NixOS package list rather than being
# harmlessly redundant.
#
# FIELD SEMANTICS. `arch` is the pacman package name; `aur` (default false) marks a pacman name
# that lives in the AUR rather than an official repository, which is load-bearing rather than
# cosmetic — `pacman -S` fails the WHOLE transaction on an unknown target, taking every other
# package in the same converge down with it. `nixpkgs` is the attribute, or `null` for a tool
# nixpkgs does not package at all; a null is a real, reportable fact (see
# `nixmail.clients.unavailableOnNixos` in ../modules/clients.nix), not a placeholder to fill in
# later.
#
# Both entries below were verified on both platforms on 2026-08-08, three sources per Arch name
# (`pacman -Si` on a live host, which reports the repository a name resolves in but cannot by
# itself distinguish a derivative's own repository from its rebuild of an upstream Arch one;
# archlinux.org's package-search API, which is upstream Arch and knows nothing about a
# derivative's extra repositories; and the AUR RPC), and a FORCED derivation for each nixpkgs
# attribute rather than an existence check — an attribute can exist and still be a throwing
# rename alias, which an existence check reports as present right up until something builds it.
{ ... }:
{
  s-nail = {
    arch = "s-nail";

    # NOT IN NIXPKGS AT ALL, and this null is the verified answer rather than a gap someone
    # forgot to close. Searched for the project name, the historical name and the command name;
    # nixpkgs has no attribute for any of them (2026-08-08). The consequence is concrete and a
    # consumer should see it rather than discover it: a NixOS host cannot select this tool, and
    # ../modules/clients.nix reports it through `unavailableOnNixos` instead of silently
    # resolving to nothing.
    nixpkgs = null;

    note = ''
      The BSD mailx successor — a terminal mail user agent that speaks SMTP and IMAP directly,
      rather than driving a local MTA.

      THE PACKAGE NAME IS NOT A BINARY NAME, and this trips everyone exactly once: `s-nail`
      installs no command called `s-nail`. It ships `mailx` and `mail`. Anyone grepping a box
      for the package's own name concludes it is missing, and anyone grepping for `mail`
      concludes something else entirely.

      WHY IT IS CATALOGUED HERE: the built-in IMAP client. A mail user agent that speaks IMAP
      itself needs no local MTA, no maildir sync step and no second daemon between it and the
      server — it opens the account and reads it. Confirmed on a live installation
      (`mailx -Xversion`, v14.9.25, 2024-06-27): the build reports `+imap`, `+imap-search`,
      `+gssapi`, `+maildir` and `+net`.

      THE CONSTRAINT WORTH KNOWING BEFORE BUILDING ON IT. Upstream announced the removal of the
      inherited POP3 and IMAP subsystems for the v15 line, then RETAINED them after users
      objected, with a rewrite described as likely rather than a removal as scheduled (upstream's
      own manual and project pages, checked 2026-08-08 — it carries no deprecation notice and
      still documents a full IMAP CLIENT section). So the accurate statement is neither "it is
      going away" nor "it is settled": this is a legacy subsystem its maintainer has twice
      considered replacing, kept alive by demand. Something built on it should expect the
      interface to move, and should not be the only way to reach an account.
    '';
  };

  imapsync = {
    arch = "imapsync";
    nixpkgs = "imapsync";
    note = ''
      One-way IMAP account-to-account synchroniser: connects to two servers as a client of both
      and copies messages, flags and folder structure from one to the other, incrementally and
      idempotently. The tool for a migration, a mirror or a rescue, not for daily reading — which
      is why it sits beside a mail user agent here rather than replacing one.

      IT IS A CLIENT OF BOTH ENDS, which is why it belongs in this catalogue rather than in the
      server half of this repo: it holds no state of its own beyond a cache, and it neither runs
      nor configures a service.

      An official-repo package on both platforms (`extra` upstream, one archlinux.org result,
      zero AUR results), and its nixpkgs attribute forces to a real derivation. So unlike its
      sibling entry above, this one is selectable on every plane this repo supports. Worth
      stating because the packaging is not trivial — it is a Perl program with a long runtime
      dependency list, and "the script exists" and "the script's dependencies are present" are
      different claims. Taking it from a distribution package means the packager answered the
      second one.
    '';
  };
}
