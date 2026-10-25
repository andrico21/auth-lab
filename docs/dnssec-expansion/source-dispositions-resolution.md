# DNSSEC D0 resolution source and oracle dispositions

Research cutoff: 2026-10-23. This is the resolution research/oracle shard only. It does not implement, import or invoke a production DNSSEC evaluator. The frozen worker-plan input, scenario manifest and source-group map supply the case denominator, not a prospective implementation.

## Deliverable identities and coverage

- `source-ledger-resolution.json`: SHA256 `45b0872ab30f46bd4ece5733fee10a193ad72cc66ebd5536b29c3690ca3bc3d0`.
- `worksheet-resolution.json`: SHA256 `b013da69b7a532fc62f074f91f215d1fae9dcf8251f3c01d29894239cb0cdac5`.
- `sources/resolution/`: 120 immutable HTTP captures, each with actual requested/final URL, observed HTTP status, response headers, retrieval timestamp, exact byte count, SHA256, local identity and relevant sections in the ledger. All 120 attempts returned HTTP200; no blocked capture or failed retrieval is hidden or treated as a standard.
- The 120 captures cover all 28 mapped URLs in the 17 owned groups, text renditions and publisher status/update metadata, 41 distinct RFC documents including applicable updates, and all 10 individually captured RFC4034/RFC4035 errata (6 Verified, 2 Held for Document Update, 2 Rejected).
- `sources/resolution/worksheet-authoring-attempts.json` separately preserves attributable authoring faults and their repair. It is not counted as a primary-source capture. Its SHA256 is `ab7c5c9308f6261bdb3c30b0b72da164c750898faac81a832acd01ea7e2f05a7`.
- `sources/resolution/integration-adjustment-resolution.json`: SHA256 `8381ba8845d15efc51c6b424fcb99d408038c93aa8b25348332e229aa401a24c`. It preserves prior worksheet SHA256 `1230e6bcfb03cc116bb9ca2a8ea31df5ec3cf24ddd9d191f3808f2c39f44090c`, the parent's concrete numerical-binding finding, exact inspected dataset hashes and the source-derived adjustment. It is not a primary-source capture.

The worksheet contains 13 lessons and 93 named cases, with no extra default case:

| Lesson | Cases |
| --- | ---: |
| DNS01 | 4 |
| DNS03 | 7 |
| DNS04 | 11 |
| DNS05 | 7 |
| DNS06 | 8 |
| DNS07 | 7 |
| DNS08 | 6 |
| DNS09 | 7 |
| DNS10 | 10 |
| DNS11 | 6 |
| DNS20 | 7 |
| DNS21 | 7 |
| DNS22 | 6 |

The first named case remains the default in each lesson. Every case is expanded as literal JSON with setup, ownership, correlated network/local sequence, semantic checkpoints, structured outcome, exact selected hop flags/RCODE/EDE, time dependencies, custody invariants, inspection requirements, source sections and policy notes. Repetition in this independent data is deliberate: a consumer need not execute an expectation generator or import production to recover the expected states.

## Source-group dispositions

| Group | Primary source findings and update disposition |
| --- | --- |
| S01 | RFC4033 sections2-8: public object authentication, explicit last-hop trust and temporal dependencies. No confidentiality, availability or management authorization claim. |
| S02 | RFC9364 sections2-5 is a document map, not a replacement for specifications. Its older algorithm-policy references must be read through the current update chain. |
| S03 | RFC6840 sections4-6: same-zone denial, CNAME/NS bitmap checks, unsupported-only authenticated DS treatment, one valid path, query AD interest, response DO copying/ignoring and upstream CD1/cache context. RFC8749 removes historical DLV guidance. |
| S04 | RFC9499 sections3-11 supplies current terminology and explicitly does not reconcile the differing older state definitions. The worksheet chooses RFC4033 section5 absent-anchor indeterminate versus authenticated insecure-delegation terminology. |
| S05 | RFC4034 fields, signing boundaries and canonical forms, with individual verified corrections, RFC6840, RFC9077 and RFC9824. RFC1982 supplies serial comparisons; RFC3597/4343 constrain case/compression handling. RFC6944 -> RFC8624 -> RFC9904 is the captured policy lineage. |
| S06 | RFC4035 sections2-5: parent-issued DS, child DNSKEY authentication, actual verification before use/cache, authoritative versus recursive flags, wildcard/denial proof completeness and checking-client failure. Apply RFC8198/9077/9520/9824 updates, not obsolete core-only rules. |
| S07 | RFC5155: actual hash inputs, matching/covering proof roles, closest encloser/next closer/wildcard, Opt-Out limits and authority-side NSEC3PARAM. RFC9157 is registry-allocation policy, not a new proof-success rule. RFC9276/9077 update parameters/lifetimes. |
| S08 | RFC9276 section3: publisher iterations0 and preferably empty salt; zero additional iterations still performs the initial hash. Expensive-proof handling is selectable and is not successful denial merely because evaluation was limited. |
| S09 | RFC2308 negative-answer/cache keys and SOA timing, read through RFC8020, RFC9499 and RFC9520. ENT is not NXDOMAIN. Alias-chain denial attaches to the final denied name. |
| S10 | RFC8198 complete validated proof/wildcard reuse with RFC9077 replacement TTL rules. No mandatory attached SOA for every aggressively reused proof. No synthesis outside coverage, across an incompatible cut, using prohibited Opt-Out evidence or after expiry. |
| S11 | RFC9824 NSEC online-signing profile: signed NXNAME128 bitmap, NODATA-shaped NOERROR, optional hop-specific CO restoration, local FORMERR for explicit NXNAME, and minimal-span limits. The NSEC3 alternative is explained without preferring or claiming to implement it. |
| S12 | RFC8914 diagnostics are optional unsigned metadata; RFC9520 makes bounded resolution/validation failure caching mandatory; RFC7646 NTA is manual, scoped and temporary, not cryptographic repair. |
| S22 | RFC1034/1035 base message/service facts, current EDNS6891 and TCP7766. Applicable updates RFC9471 (glue/TC), RFC9619 (one question), RFC6604 (alias final RCODE) and RFC1982 are captured. No DSO, XFR-over-TLS or serve-stale implementation is claimed. |
| S23 | RFC5625 transparency and RFC3225 DO behavior read with RFC4035/6840. A route does not install an anchor, propagate AD as an independent local check, or authorize insecure fallback from a known secure delegation. |
| S24 | RFC7858 and RFC8310: selected Strict Privacy authenticates a configured endpoint and encrypts that hop. Opportunistic encryption is not the same identity guarantee. Neither produces valid DNSSEC evidence. |
| S26 | RFC4592 existence/wildcard semantics and RFC6672 DNAME synthesis, plus RFC6604 final-chain RCODE/AD. Signed aliases do not authenticate destination data. A correctly synthesized CNAME need not own an independent RRSIG. |
| S28 | Both publisher errata indexes and each individual record were captured. Verified corrections are attributed to the base RFC; held/rejected proposals are not silently promoted. |

## Individual errata lock

| Erratum | Status | Applicable disposition |
| --- | --- | --- |
| RFC4034 193 | Verified, Editorial | Correct algorithm1 tag octets to third-to-last/second-to-last. Retained historical correction; not the selected alg13/15 calculation. |
| RFC4034 1062 | Verified, Technical | HINFO contains no domain-name RDATA; do not lowercase opaque text. RFC6840 section5.1 further corrects NSEC/RRSIG handling. |
| RFC4034 3045 | Verified, Technical | RFC3007 is not actually updated. No DNSSEC-derived UPDATE authorization. |
| RFC4034 4552 | Verified, Technical | Preserve accumulator carries with at least32-bit precision; add carry then low16bits, not an assumed modulo65535 identity. Applies modern key-tag fixtures. |
| RFC4034 2681 | Held for Document Update | Earlier carry proposal recorded, not a replacement normative correction; use verified4552. |
| RFC4034 2824 | Rejected | No normative wildcard-label wording replacement. Only a leftmost asterisk is a wildcard. |
| RFC4035 3044 | Verified, Technical | Remove RFC3007 update claim. |
| RFC4035 5226 | Verified, Technical | Special child-side DS response condition is no authoritative zone anywhere above the child's apex, not just absence of the immediate parent zone. |
| RFC4035 8037 | Held for Document Update | Proposed matching-key MUST-to-SHOULD resource-exhaustion change is not verified consensus replacement. The selected bounded two-candidate collision fixture tries real candidates; no universal unbounded product behavior is claimed. |
| RFC4035 7972 | Rejected | Do not upgrade the original lowercase refetch-race awareness statement into a new RFC2119 MUST. |

## Locked policy and semantic distinctions

1. Baseline represented protocol time is1792713600, inception1792713000 and expiration1792717200. Clock jumps are explicit nonnegative `advance` events. DNS04 wrong-clock leaves represented protocol time unchanged and records the validator's +3601 offset/checkedAt separately. Signature boundaries are inclusive under RFC1982 serial arithmetic; half-range ambiguity is not an ordinary ordering.
2. DNS10 separately exercises received RRset TTL, received RRSIG TTL, signed OriginalTTL and remaining signature validity. The short-OriginalTTL case requires its distinct corresponding signature, not an edited baseline signature. Signature-expires-first inserts the unchanged baseline signature120seconds before its deadline, then refetches it at expiration+1: its final result is bogus/SERVFAIL, not a fabricated fresh signature.
3. A raw public RRset, complete transport response, local signature operation, established anchor path, accepted use/cache, response receipt and application acceptance are different checkpoints. Recursive/authority flags are explicit: authoritative CD clearing is selected0 under RFC4035 section3.1.6; recursive responders echo CD. DO requests records, query AD indicates interest, response AD is a responder assertion and CD does not always force already-authenticated cache AD0.
4. A trusted-upstream/stub profile names resolver/channel trust and records remote assertion separately from local independent verification. Both-validator cases have separate validator entries. The special cached upstream CD0 SERVFAIL context triggers a fresh CD1 query under RFC6840 section5.9; it is not substituted for suppression of a locally established RFC9520 failure. Initial CD0 compatibility cases explicitly declare their deviation from the SHOULD-always-CD1 recommendation.
5. Known supported-path failure, authenticated no-DS or unsupported-only path, absent anchor, transport failure and operator bypass have different reasons and preserved state. The synthetic unsupported-only DS case explicitly has algorithm250/digest250 outside the selected capability set, not private-algorithm253 dispatch or an assumed SHA1 rule. Secure-only application refusal can leave the cryptographic result insecure rather than relabel it bogus.
6. NSEC/NSEC3 proof components and zone/bitmap/Opt-Out constraints are literal. NSEC3 SHA1 hashing is not the deprecated SHA1 signature algorithm. The fixed empty-salt, zero-additional-iteration owner hashes match the numeric worker's independently reported outputs; reference-byte acceptance remains the parent numeric freeze's responsibility.
7. RFC9276 permits different policies for authenticated nonzero-iteration parameters. This profile verifies the advertised parameter's signature and refuses with SERVFAIL/selected EDE27, with no successful proof. It does not claim every conforming resolver must return that same status or diagnostic.
8. Failure caching uses selected initial5seconds, linear +5second backoff and300second ceiling, within RFC9520's mandatory1..300second bounds. Its key includes view/trust/checking context. EDE may be absent for the same failure; selected diagnostics never override RCODE or serve as signed proof.
9. RFC9824 NXNAME128 remains a signed bitmap meta-type only. Explicit NXNAME query receives FORMERR without forwarding, with selected optional EDE30. CO/source-RCODE context is stored per hop/cache, and DO1/CO0 downstream gets NOERROR even from upstream CO/NXDOMAIN context. Minimal proof cannot be stretched into broad aggressive denial or an NXDOMAIN subtree cut.
10. DNS22 uses separate named public/private trust stores, routes, keys and cache namespaces. No-covering-anchor means no applicable anchor anywhere and selected indeterminate delivery. Public-chain conflict instead has an authenticated public DS demanding a different key and fails bogus. Conditional forwarding is neither authenticated delegation nor anchor bootstrap.
11. Numeric record-profile bindings use the sibling `other.example.`, distinct target keys/DS/signatures, private same-owner A198.51.100.80 under child-CSK, and exact-owner compact NSEC signatures. A CNAME/DNAME/private/compact profile must never borrow an unrelated baseline RRset signature.

## Genuine unresolved source issues and limits

- No unresolved or failed primary-source capture remains.
- RFC9905 contains an actual source discrepancy: section2 tells operators to treat alg5/7 as unsupported/insecure, while section5 retains RECOMMENDED Use-for-Validation and MUST implementation cells, and section4 says those columns are not being changed. The parent/publication owner were notified. Preserve the competing statements; the selected operator policy follows section2 without rewriting registry/capability cells or claiming a unified universal table. Baseline alg13/DS2 is unaffected.
- S14's managed-anchor/root-publication sources and S16's full dated IANA policy snapshot are publication-owned. This shard uses explicit trusted local provisioning, not an invented RFC5011 bootstrap, and does not substitute an old RFC table for that independent snapshot.
- The numerical worker reports a reference-library limitation: TYPE128 is used for actual NXNAME wire bitmap128 because the mnemonic is not recognized. This is not missing wire support and is not a reason to invent a different type value.
- Authoring failures were retained and repaired before worksheet promotion. The defective scalar-conversion payload was never written. This is not evidence of any application regression or of a passing app check.
- No build, test suite, linter, formatter, browser acceptance, live/native DNS check, conformance gate or performance comparison was run by this worker. Parent owns one integration verification and the merged D0 freeze. Existing closures, human G01, predecessor performance conditions and historical limits are untouched by this shard.

## Pre-freeze exact numeric binding adjustment

The parent found that the original literal baseline did not match the independent numeric bundle: actual `www-a` has two records, `192.0.2.80` and `192.0.2.81`, with signed OriginalTTL3600. The final worksheet binds those exact records/signature, while received TTL300 and intended cache300 remain separate occurrence inputs. Application results now expose the complete RRset. The fixed changed-A failure uses the independent `[192.0.2.82,192.0.2.81]` mutation without changing its original signature. The short-OriginalTTL lesson uses the actual separately signed OriginalTTL60 fixture and base+61 probe, not an edited OriginalTTL45/300.

All selected primary and prerequisite records now carry exact independent dataset/RRset/signature identities, signed metadata, canonical RDATA, signature-RDATA/signing-input hashes and namespaced occurrence mappings. Catalog availability is explicitly not trusted receipt, DNSKEY-set membership or a validation success. Wildcards use actual A192.0.2.90; sibling aliases use their own A192.0.2.80 signatures; the private view uses its own A198.51.100.80 signature. Stale private anchor and supported DS mismatch bind real new-generation key sets rather than unrelated old signatures.

Conventional no-wildcard, wildcard, ENT, parent-noDS, NSEC3 no-wildcard/Opt-Out/saltAA/iteration1 and invalid-candidate inputs use the independently signed `resolution-profile-fixtures.json` variants. No authored NSEC interval is assigned a baseline signature over different bytes. Exact signed candidate-containing DNSKEY sets isolate Protocol2/clear-Zone prerequisite failure from an earlier broken DNSKEY signature. The explicit parent DS negative answer uses `parent-negative-fixtures.json` SOA minimum300; child SOA also has actual minimum300. Algorithm250 and digest250 remain separately signed singleton snapshots, not a merged RRset authenticated by two unrelated singleton signatures.

Leaf-time cases use actual long-valid upper DS/DNSKEY signatures and explicit current-clock upper-path work. Expired leaf uses the unchanged baseline signature at expiration+1; not-yet-valid uses an actual future-inception successor signature; wrong-clock offsets only the validator. The signature-expiry cache lesson advances monotonically through upper-path validation, near-expiration insertion and an expired refetch, without timeless prerequisite-cache assumptions.

This adjustment inspected and bound independently produced bytes before the D0 freeze. It did not import a production evaluator, derive security outcomes from production, rerun the parent's reported failing integration check, or run application build/test/lint/browser gates. Existing literal classifications remain standard-authored; the parent owns merged integration checking and sealing.
