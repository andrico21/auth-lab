# DNSSEC independent contract errata

The original D0 freeze, worksheets, authority captures and numerical package remain unchanged. The original freeze is `b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19`; its integrity check still covers 354 inputs, 22 lessons and 159 named cases.

Two independent input-consistency reviews found missing evidence receipts, contradictory initial publication/custody declarations, record-identity mismatches and clock/cache metadata errors. Their raw audit reports and proposals are retained here. Production D1 code already existed during those reviews. The reviewers report that they did not read, import or execute that code; this addendum is not represented as having preceded the evaluator.

- `resolution-patches.json`: 395 fully expanded, attributed patches against the exact frozen resolution worksheet.
- `publication-patches.json`: 406 fully expanded, attributed patches against the exact frozen publication worksheet.
- `effective/`: the derived resolution/publication worksheets, merged 22-lesson/159-case worksheet and additive integrity manifest.

The corrections preserve every lesson ID, named case and default. Missing DS/DNSKEY evidence is supplied by explicit receipts, not by silently declaring it trusted. Positive RFC9615 signaling requirements remain secure and noncircular; they are not downgraded because the original inputs were incomplete.

Additional numerical material is isolated in `../numeric/post-freeze-contract-errata/`. Its catalog SHA256 is `2c8c7a134e56714d09be1371c8b8cd6f90cb8dc1737fe381f78d59f0e53fa7c5`. The independent reports record 382 publication and 46 resolution assertions, including actual verification of 30 additional signatures. The withdrawn `03` owner-wire length for the two-octet `zz` label, failed verification record and corrected `02` metadata are retained; failed material is not active evidence. Opaque unsupported/archival DS payloads have authenticated parent signatures but are not claimed to be DNSKEY-derived digests or complete archival signature paths.

Reproduce and check the canonical derived files without rewriting originals:

```sh
bun tools/verification/apply-dnssec-contract-errata.mjs --check
bun tools/verification/freeze-dnssec-contract.mjs --check
```

`--emit NEW_DIRECTORY` produces a separate copy and refuses to overwrite an existing output directory. Each transform imports no application/evaluator code and checks exact input identities, before-values and supplied canonical hashes. Original and previous derived inputs remain immutable. Input review and transform reproduction are not application acceptance, live interoperability, manual G01 or publication approval.

## Completion overlay

`completion-resolution-erratum.json` and `completion-publication-erratum.json` supply 45 further independent patches. `effective-completion/` preserves the first overlay and adds explicit cryptographic-observation semantics, exact anchor-reference binding, the established DoT scope and the selected 300-second DNS17 negative-cache lifetime. Its merged worksheet is `d1f319e715da522e5a64e564514e1b6791486cb276394ebb380ca6e42c895bbc`.

Additional independently verified numerical material is sealed in `../numeric/post-freeze-completion/POST-FREEZE-COMPLETION-CATALOG.json` (`5cbea7727bdcea3eb75a2e3be542eb38ab6788c1b54f644927ef56613029a0ee`). Its public application projection excludes fixture-generation private scalars and TSIG secret references. Raw verification inputs are not application holdings.

## Receipt overlay

Three retained, input-only independent proposals supply 244 exact patches:

- `receipt-resolution-erratum.json`: 159 patches for actual stub-visible prerequisites, query/header mutations, attempted-but-undelivered transport, old cache deadlines, independent client stores and typed evidence ownership.
- `receipt-wildcard-erratum.json`: 14 disjoint DNS09 wildcard-NODATA patches. The received NSEC/SOA proofs do not include the catalog-only wildcard A RRset.
- `receipt-publication-erratum.json`: 71 patches binding parent-management receipts, retry identities, literal signal records and DSYNC ports to the independently sealed tuples.

The receipt layer is `effective-receipts/worksheet.json`, SHA256 `d189ae3805268d378f4c2acd32f8a562ada4557b9ae67a1493734d47ecfbaedd`, with all 22 lessons and 159 named cases. The transform preserves all IDs, defaults, security classifications, application results, acceptance and cache decisions. Explicit receipt, header, ownership, checking-target and lifetime metadata is corrected only by the retained patches. The original 354 D0 inputs are hashed before and after production of this overlay.

Evidence references identify exact inputs or observations; they do not independently establish authentication, possession, checker invocation or validation ownership. Raw inputs, failed attempts and authenticated evidence remain distinct. A null validation owner stays null; an observer or artifact producer is not silently promoted to an authenticated validator. Authority-local NSEC3PARAM, descendant A and wildcard A catalog inspection is not a resolver receipt. An authenticated DNSKEY-RRset chain can remain established when a leaf RRSIG's ZSK is missing.

Reproduce all derived layers, without application/evaluator imports:

```sh
bun tools/verification/apply-dnssec-contract-errata.mjs --check
bun tools/verification/apply-dnssec-completion-errata.mjs --check
bun tools/verification/apply-dnssec-receipt-errata.mjs --check
bun tools/verification/apply-dnssec-client-context-errata.mjs --check
bun tools/verification/apply-dnssec-cache-kind-errata.mjs --check
bun tools/verification/freeze-dnssec-contract.mjs --check
```

The receipt producer follows JSON Patch array-insertion semantics: an added array element addresses a gap, while the complete input array remains bound by the target's exact hash and ordered prior patches. Earlier failed producer attempts are retained as `docs/verification/dnssec-expansion/receipt-errata-emit-*.json`; they are not passing records.

## Client-context overlay

`input-audits/client-context-audit.raw` records an independent, read-only review of the DNS22 input profile. The selected topology is one literal `dnsValidator` with two per-client checking contexts and three declared answer conversations. A Source implementation with two physical validators or a different conversation graph must conform to that profile; it is not a reason to change the independent topology.

`client-context-erratum.json` supplies only four independently justified patches: the two namespace-checkpoint cache kinds become `answer`, consistent with their unchanged accepted cache occurrences, and the existing ownership declaration gains the already-selected clientA root anchor and clientB private operator-provisioned anchor. No setup, outcome, packet, signature, deadline, owner actor or application disposition changes.

The client-context layer is `effective-client-context/worksheet.json`, SHA256 `c7fc1efdd3b0e011499da4cf3bd19e2ae95b21885a1ac4975d6458646d0c77bc`. Its additive seal is `3a0bad331b33f2fe45f01832a1029c8b5064a6aec638ddda5761b8d9c0e1a4bb`. The producer's emit/check records verify all 354 original inputs and every previous layer without application/evaluator imports.

`input-audits/denial-associations-audit.raw` rejects further DNS09/DNS10 errata. Wildcard receipt owners and RRSIG reconstructed signing owners have different typed roles. Cached-proof display aliases and original-receipt annotations bind by exact signed intervals; fresh-query coverage must be independently checked. A complete conversation trace may include prerequisite exchanges without pretending their payload arrived in the leaf response.

Both raw audit reports preserve their authors' no-production-access statements. These are reported input-review boundaries, not claims of an OS-enforced sandbox, cryptographic implementation conformance, successful new application gates or release approval.

## Cache-kind overlay - fifth historical input

The follow-up input-only audit in `input-audits/cache-kind-and-observation-audit.raw` covers all 159 cases. It identifies one further same-occurrence inconsistency: DNS20 `retry-after-expiry` describes the same generation-2 cache receipt as `positive` at its partial new-work checkpoint and `answer` at accepted use. `cache-kind-erratum.json` changes only the earlier `kind` to `answer`; the generation, namespace, owner, evidence, receipt, expiry and every setup/outcome remain fixed.

The reviewed predecessor used `effective-cache-kind/worksheet.json`, SHA256 `330fbc0db84e21e116d78da6ea316fb4694cd16d40c73f13a8c49f7a0100c055`, with seal `f500a7278bac53f72b9cf5c43927601c2b4d7aefd2f5e81fc2887d4f6ec5a4f3`. Emit/check reproduces the single patch and verifies all 354 original inputs without rewriting any previous layer. The correction checks below use the later eighth layer, not this predecessor as an unchanged current oracle.

The audit rejects broader kind normalization: `outcome.cacheKind` is a response/result class, not a stored-entry-kind oracle; DNS21's compact response context and authenticated negative answer are distinct objects. DNS10 `eligibleForReuse` is a later-clock observation, not a change to its immutable stored cache body or original deadline. The application and verifier retain that distinction.

## Review-correction layers - current check input

The changes-required review is retained byte-for-byte at `../inputs/dnssec-review-and-worker-comments.html`. Three additional layers preserve all 354 original inputs, all seven preceding worksheet/seal layers, every lesson/default/case identity and all original numerical tuples:

- Sixth: `review-corrections-proposal.json` and its audit define 30 ownership, NXDOMAIN, rollover and policy corrections. `effective-review-corrections/worksheet.json` is `c0312c6841e141b50bde40d91baf6d376f6d2b33523c0d98c262c2a0d1a4e8a2`.
- Seventh: `mixed-path-policy-proposal.json` and its audit define three mixed-DS explanatory corrections. Per-path failed constraints remain distinct from the explicit primary display convention; neither the labels nor precedence are claimed to be RFC terminology or observed implementation execution order. `effective-mixed-path-policy/worksheet.json` is `97c42a3ae12a2939bcbd89a546ebbf7350ff8c3caf03e3e94b1317dbdf2a4f9f`.
- Eighth/current: `cache-namespace-location-proposal.json` moves unchanged validating-stub checking-owner/trust-store expectations under the canonical cache `namespace`, removing the misplaced top-level keys. `effective-cache-namespace-location/worksheet.json` is `d88705d909df1043d7a5c0295e35272afae6ab01af73aac7faa766c5061f164d`. The schema mapping was explicitly supplied by the integration owner; its design was not independently discovered. No new semantic outcome values or production aliases are introduced.

The authors report no application/test/evaluator access or execution while authoring these layers. Production already existed; no preimplementation or OS-enforced-isolation claim is made. The eighth audit separately records the parent-provided schema-location contract.

Additional signed NSEC3/delegation/DNAME authority controls are isolated in `../numeric/review-corrections/PUBLIC-CATALOG.json`, SHA256 `7f2eba596704ba73bddc3d20a1616b8ecce9cd6b8b4a57229df0a511b1c43f28`. The pinned independent verification report records 105 byte/hash predicates and seven OpenSSL signature verifications. It is a structured observation summary, not verbatim process stdout or browser cryptography. Original 205 signature tuples are unchanged; the public projection additionally binds these seven tuples.

Run the preceding five transform checks above, then:

```sh
bun tools/verification/apply-dnssec-review-corrections-errata.mjs --check
bun tools/verification/apply-dnssec-mixed-path-policy-errata.mjs --check
bun tools/verification/apply-dnssec-cache-namespace-location-errata.mjs --check
```

Complete source/emitted correction checks take the eighth worksheet explicitly. Passing transform reproduction does not establish application behavior, actual-human G01, performance acceptance, independent Astra closure or publication approval.

