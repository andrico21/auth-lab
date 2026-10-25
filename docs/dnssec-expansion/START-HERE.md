# Auth Flow Studio - DNSSEC scoped correction closure

## Reviewed delivery - retained unchanged

1. `auth-flow-studio-dnssec-source-and-review.zip`
2. `auth-flow-studio-dnssec.html`
3. `START-HERE.md`

The independently reviewed delivery remains in `corrections-03`; earlier `corrections-01` and `corrections-02` deliveries also remain unchanged. This repository entrypoint now records the subsequent closure. The entrypoint, evidence and checksums inside the frozen delivery are not rewritten. No replacement upload or repackaging is needed for this documentation-only update.

The retained ZIP is 46,942,245 bytes. It includes all required authority inputs, application/test source, verification producers and bounded evidence, without a bulk capture archive. `CONTENTS.json` and `review/SHA256SUMS` retain their original selected/omitted inventory and exact payload binding.

**Independent closure performed:** Astra's [DNS-R10 closure review](inputs/dnssec-r10-closure-review.html), dated 25 October 2026, SHA256 `b60da5cb2ffa32fd766168ebd214eaca92626a2e6da2e700a64c424771b96407`, closes **DNS-R10 for corrections-03** and identifies **no further required DNSSEC correction**. The original nine scoped closures, C01-C03 dispositions, one **DNS-C04 = DNS-R09-focus-identity** closure and two separately verified semantic follow-ups remain preserved. This is not overall release acceptance or publication authorization.

## Exact independently closed candidate

- Branch `expansion/dnssec`; working-tree snapshot, not a new committed checkpoint.
- Base checkpoint: `c99ebd6fec16e01dc9fef6c9590d534b8f1daf85`.
- Canonical application/test identity: 231 files, SHA256 `1b5a3350e5e2b778efb52dccb46473e197df1ec202e3cd202618540c1988f234`.
- Standalone: 5,243,123 bytes, SHA256 `5e13671a57cfb0d4c827b4eb6af52fc6d0d53f48c5816c8e7bcc423e54022f54`.
- Current eighth worksheet: SHA256 `d88705d909df1043d7a5c0295e35272afae6ab01af73aac7faa766c5061f164d`.
- Footer in the reviewed snapshot: **1.0**, **Kirill**, GitHub profile and `andrico21/auth-lab`. The user subsequently authorized the sole source-text correction to **Kirill Andrienko**, without retesting. Version injection and links are unchanged.
- Publication: **the user has now authorized commit and push of the reviewed DNSSEC work plus the footer-name correction**. This authorization does not accept human G01, performance costs or overall release conditions.

The reviewed corrections02 source was `f9876de1...`, HTML `0b1c9bdb...`. Earlier corrections01 was `481ace7a...` / `2855771e...`; the original reviewed expansion was `dd9a3527...` / `9d18f504...`. Their raw reports and packets retain their actual executed bytes. This R10 delta changes one application module and two existing behavioral test files.

R10 fixes the independently secure CNAME cache in `cname-bogus-target`: remaining TTL is **300**, validation time comes from its existing successful alias check, and the authenticated proof deadline comes from its own signature. Original receipt and 300-second expiry stay fixed. The separate target retains its five-second failure cache and the application still receives SERVFAIL/refuses the target. Literal source and rendered-inspector regressions failed before the fix. No authority, signed tuple, wire packet, network exchange or signature-check event was changed.

## Repository read order after closure

1. [Closure report](inputs/dnssec-r10-closure-review.html), [performed closure disposition](corrections/independent-r10-closure-disposition.json) and [response ledger](corrections/response-ledger.json) - actual scoped closure and unchanged candidate identities.
2. [Implementation handoff](implementation.md) - the narrow fix, literal expectations, retained worker checks and open owner conditions.
3. [Scenario manifest](scenario-manifest.json) and [reviewer navigation](reviewer-navigation.md) - all 22 lessons/159 named cases and reproduction commands. The original plan remains [worker-plan.html](inputs/worker-plan.html).
4. [Authority index](contract-errata/README.md) - all eight immutable additive layers and independent-authoring limits; current authority is `effective-cache-namespace-location/worksheet.json`.
5. [Frozen worker summary](../verification/dnssec-r10-correction/final-gates-summary-01.json), [source/emitted equality](../verification/dnssec-r10-correction/source-emitted-equivalence-01.json), [reviewed case delta](../verification/dnssec-r10-correction/reviewed-source-case-delta-01.json) and [semantic delta](../verification/dnssec-r10-correction/semantic-delta-01.json) - original executed proof, not restamped after closure. The summary's then-pending closure is resolved by the separate report above.
6. [Before](../verification/dnssec-r10-correction/focused-before-01.json), [after](../verification/dnssec-r10-correction/focused-after-02.json), [compiled](../verification/dnssec-r10-correction/compiled-teaching-01.json) and [native inspector](../verification/dnssec-r10-correction/native-inspector-01.json) - retained worker executions on these unchanged bytes.
7. [Open gates](open-gates.json), [performance dispositions](../verification/dnssec-review-corrections/performance-dispositions-04.json) and [prior-key continuity](../verification/dnssec-review-corrections/performance-prior-correction-continuity-01.json) - measured corrections02 conditions, human G01 and conformance limits.
8. [Closure-only consistency check](../verification/dnssec-r10-closure/disposition-consistency-01.json) - actual pre-publication source/HTML/authority identity, links and gate state. It predates the user-authorized footer-name correction and is not relabelled as a check of the later build.

## Retained exercised checks, not release acceptance

| Check | Observed result |
| --- | --- |
| Current source and emitted contract | 159/159 cases each; 1,068 independent checkpoints; 27,031 canonical prefixes |
| Complete canonical case equality | Every case field/prefix hash/step/selected field/exact inspection/final outcome equal; raw execution counters remain mode-specific |
| Full regression | 1,996 pass, 0 fail across 121 files; exact current inputs unchanged and original 900000ms per-test timeout |
| Numeric | 502 checks; 212 signatures including seven additional R04 tuples; original 205 unchanged |
| Narrow current native | Two headless native Chromium source HTTP/offline-file inspector surfaces, plus genuine offline exact-history/rewind; two parent-viewed captures |
| Compiled/held preservation | 317 choices; 921 Core configurations; 86 interactions; 64,784 equal-cursor comparisons |
| Retained legacy vector scope | Earlier 31 expansion / nine JWT checks retain their identified bytes; unchanged fixture catalog, not a new R10 vector execution |

These worker executions predate the closure and retain their actual input/runtime attribution. Source01, Emitted01, Numeric01, compiled smoke01, held01 and narrow native records remain under `dnssec-r10-correction/` on the unchanged source/build. The 62 affected source/lifetime tests and ten actual compiled-IIFE UI tests pass. All 159 complete source/emitted case records are equal. Against corrections02, 158 complete records are unchanged; only 11 prefixes of `cname-bogus-target` differ, with unchanged steps, final result and inspected artifact identity. The closure review separately identifies its own fresh probes and audits; this documentation update runs only consistency checks.

The two new literal regressions recorded 0 pass / 2 fail before the product fix. A separately labelled retrospective replay of the final identical test bytes against the exact reviewed product also records 0 pass / 2 fail; `final-regression-attribution-01.json` preserves both chronologies and inputs. Exact cache metadata, T+6 eligibility, original-expiry rejection, bogus-target refusal, neighbors and full/field/exact rewind are checked. Native04's earlier 60-cell matrix and timing collection remain historical; no unrelated native/zoom/performance sweep is claimed for R10. Both new inspector images were actually viewed.

## Integrity and offline build

Copy the delivery files into a fresh directory and extract there, alongside the standalone and this entrypoint:

```sh
unzip -q auth-flow-studio-dnssec-source-and-review.zip
sha256sum -c review/SHA256SUMS
(cd source && bun --no-install build.mjs --source-version)
cmp source/dist/auth-flow-studio.html auth-flow-studio-dnssec.html
```

Use pinned Bun **1.4.2** for exact reproduction. The application needs no install, Git metadata or network fetch. Source/emitted/numeric reproduction and all eight transform checks are in reviewer-navigation; use separate new output leaves, not the frozen candidate. Native/numeric producer environments are explicitly separate from the offline application build.

Sibling `packaging-status.json` and `SHA256SUMS.txt` record final inventory/member-byte checks, unchanged source identity and extracted-source rebuild integrity. Independent relocation checks repeat the actual delivered set. These are available with the delivery; they are not additional required LLM uploads or release acceptance. In-ZIP checksums exclude themselves and `CONTENTS.json` self-reference explicitly.

## Conditions that remain open

1. **Human G01 remains open.** Screenshots, DOM, keyboard/touch and zoom cannot supply screen-reader speech/comprehension acceptance.
2. Measured corrections02 performance conditions remain unaccepted: five material flags, zero variability flags, and all nine original plus five prior additional keys accounted for. R10 was not remeasured. Non-reproduced flags are not owner-closed or waived; owner `andrico21` has not accepted the remaining costs or prior conditions.
3. Six inherited measured conditions, seven historical flags, six frozen-P0 variable cells and six sibling-origin omissions remain unchanged. Preserve 21 scoped P6 closures, four optional deferrals and N01 without reopening or broadening them.
4. No live DNS/service, native DNS cryptographic implementation, cross-engine or general platform conformance is claimed. Independent authoring/numeric QA is not OS-enforced author isolation or installed-service acceptance.
5. The user has now authorized commit and push after scoped review, including the simple footer-name correction without retesting. This does not supply overall release acceptance, human G01 acceptance or any performance-owner waiver.

## Separate next assignment

The closure directs continuation with `auth-flow-studio-windows-protection-worker-plan.html`, document version 3, for Windows protection / PAM / hidden-search-tags. That authoritative file is not present in the supplied artifact tree or checkout documentation; existing reviews only refer to it. Implementation is blocked until the actual plan or its path is supplied. No requirements are inferred from its title.
