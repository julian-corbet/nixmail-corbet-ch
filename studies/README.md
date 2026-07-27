# studies

Written-up findings: things that were tried, worked (or failed
instructively), and are worth recording properly -- with the reasoning, not
just the result. A study earns its place here once it changed a decision in
this repo. See [`../experiments/`](../experiments/README.md) for the
open-questions ledger everything here started as, and the main
[README](../README.md) for the project itself.

**Honesty check before you read further:** almost nothing in nixmail has
been measured from inside this repo. The main README's "proven end to end
with real messages" claim describes a production deployment that lives
*outside* this repo, and `nix flake check`'s three checks (15 inbound-bridge
tests, 21 outbound-bridge tests, one module-evaluation check) are real,
reproducible, and passing -- but they pin *behaviour* (a status code maps
the right way, an allow-list defaults closed, envelope recipients win over
header recipients), not *performance or capacity* numbers. No timeout,
memory limit, or resolver has had a real number attached to it by actually
running this code under load. One exception exists (below), and it's the
only entry so far.

## Table of contents

001. Stalwart's 0.16 registry-object wire format was reverse-engineered against a real instance, not sourced from documentation

---

## 001 — Stalwart's 0.16 registry-object wire format was reverse-engineered against a real instance, not sourced from documentation

**What this is:** not a measurement performed for this task -- a summary of
a genuinely measured finding that's already load-bearing in `stalwart.nix`,
recorded here because it meets the studies/ bar (measured, reproducible in
principle, and it drives a real design decision) rather than because it was
re-verified for this ledger.

**Finding, quoted from `stalwart.nix`'s file header:** "TESTED VERSION
PAIR: stalwart 0.16.10-0.16.13 against stalwart-cli 1.0.8. The registry
object schema this module encodes is NOT a documented, stable upstream
API -- it was reverse-engineered from `stalwart-cli describe` output and
trial apply runs against a real instance." The module's `mkSet` helper is
the concrete artifact of that work: "Stalwart's 0.16 registry schema
represents several attributes (LDAP attribute-name mappings, listener
`bind` addresses, URL prefix sets) as a `Map<T>` that this module's
original reverse-engineering found deserializes from a boolean-valued JSON
OBJECT (`{"item": true, ...}`), not a JSON array -- exactly one example in
upstream's own docs showed array form instead."

**Why it's load-bearing:** every `mkSet`-shaped value in the rendered
apply-plan (`attrClass`, `attrEmail`, `attrEmailAlias`, and others) depends
on this one finding being right. Get the object-vs-array shape wrong and
`stalwart-cli apply` rejects the whole plan, or silently accepts a
misinterpreted one -- there is exactly one function in the module deciding
this (`mkSet`), by design, specifically so that if the finding ever needs
revisiting there's one place to change it.

**Why it's flagged fragile, not settled:** the same header records that
"field shapes... have already changed meaning between minor releases once"
-- i.e. this isn't a one-time discovery that can be trusted indefinitely,
it's a known-moving target that happened to move once already within the
0.16 line. The module's own prescribed response is explicit: "Treat any
nixpkgs bump that changes either package as a 're-validate the whole plan'
event, not a routine update."

**What would still be worth measuring:** whether the object-form
`Map<T>` behavior holds for every `mkSet`-shaped field, or only the ones
actually exercised by the trial applies that produced this finding (the
module lists LDAP attribute mappings, listener `bind` addresses, and URL
prefix sets as the known instances -- it's not clear from the comment
whether every one of those was individually trial-tested, or whether the
pattern was confirmed for one and assumed for the rest). See entry 009 in
[`../experiments/README.md`](../experiments/README.md) for the related,
still-open gap: nothing automated re-checks this on a version bump.

**Status:** recorded as a real, historical finding; not independently
re-verified for this ledger.
