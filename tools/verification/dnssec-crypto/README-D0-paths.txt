Additive DNSSEC D0 numeric closure inputs
=======================================

This addendum preserves every file in the original seven-dataset numeric seal.
It adds actual bytes requested while reconciling the literal D0 worksheets;
it does not rewrite earlier RRSIG metadata or relax any earlier failure.

complete-path-fixtures.json
--------------------------
SHA256a94a106399372c65a7e1e3f2e6a8b44738e13c8ee7c72c5ce96cdf7ba0e02f7f
One final-g2-only DNSKEY RRset plus seven real long-window signatures over
unchanged www-a OriginalTTL3600 and the final DNSKEY set. Fifteen explicit paths
name EVERY consumed DNSKEY/DS/answer signature, source dataset, signer, OriginalTTL
and Inception/Expiration. Root-based paths include actual root DNSKEY,
root-example DS, example DNSKEY, child DS, child DNSKEY and leaf signatures;
local-child-anchor paths are separately declared and do not invent upstream use.
Profiles cover g1/g2-final, CSK1/CSK2, Ed25519, dual algorithm and provider B,
with TTL3600/7200 alternatives as appropriate. Day35/day90 are numerical validity
observations, not claims that RFC5011 anchor management queries the leaf.

complete-path-verification.json
SHA2566090c4a59cedda55d447b71f30f8b4121bb72c5c99141df946caf832e8f74291
2748 named assertions and69 complete clocked-path observations. Each path starts
with the explicit local anchor, verifies each actually authenticated DS before
promoting matching child KSKs, verifies DNSKEY before admitting contained ZSKs,
then verifies the leaf. All consumed signatures are checked with independent
canonical reconstruction/cryptography and the pinned DNS library at that exact
clock. Seven new signatures also have actual OpenSSL CLI observations.
The short base leaf still fails expired atday35/day90 as a preserved negative.
Long windows base-600..day120 are explicit synthetic lifecycle choices, NEVER
recommended normal operational signature lifetimes. Cache reuse eligibility,
RFC5011 state transitions and application policy remain worksheet-owned.

resolution-profile-fixtures.json
-------------------------------
SHA2564001c10f0f19a52d69d7d07198874ea4d96a448e75ac4f35d0bb7f97f282973d
Two deliberately ineligible candidate DNSKEY metadata variants,37 RRsets and37
real signatures. Conventional denial variants are explicit independent zones:
- No-wildcard apex->a->www->apex; no MX/TXT at that variant apex.
- Wildcard apex->*->a->www->apex, using the existing actual wildcard answer.
- ENT apex->a->x.branch->www->apex; branch exists only as an empty nonterminal.
- Parent noDS lab.example.->next.example. NS/RRSIG/NSEC, signed example-zsk-g1;
  this cannot be reused as a denial proof inside lab.example.
NSEC3 no-wildcard and Opt-Out variants use lab/a/www/z with zero iterations and
empty salt, actual NSEC3PARAM, actual hashes and actual signed links. The unsigned
Opt-Out delegation's hash is omitted, with exactly its covering intervalflag1;
its delegation NS/glue deliberately have no signatures. Additional actual chains
have iteration1/empty salt and iteration0/saltAA, each with matching NSEC3PARAM.
These are parameter-comparison inputs, not an invented mixed-parameter proof pass.
Actual parent-signed DS variants retain opaque algorithm250/digest250 fields;
no unknown digest calculation is claimed.

Protocol2 candidate child-zsk-protocol2 tag55146 and ZoneFlag-clear candidate
child-zsk-zoneflag-clear tag55147 preserve original Z public/private lineage.
Their DNSKEY sets are genuinely signed by the valid child KSK. Their leaf
signatures bind the new tag and really verify cryptographically; DNSSEC rejects
candidate eligibility instead of failing a secretly corrupted DNSKEY-set RRSIG.
The missing-key variant has an authenticated KSK-only DNSKEY set.

resolution-profile-verification.json
SHA2568a261fae59309c7d0ddbecabd5c3a1283208ac87bbcddb5fc2483e9fffc75c7a
220 named assertions,79 observations,37 OpenSSL signature observations. Actual
candidate filtering returns zero eligible keys and library validation rejects;
the authenticated candidate DNSKEY-set signatures pass first. Independent
canonical-name/hash interval arithmetic checks the explicit denial setups.
NSEC3 no.lab is covered by denial-nsec3-no-wildcard-1, while *.lab is covered
by denial-nsec3-no-wildcard-2. NSEC3PARAM remains authority-side coordination,
not a validator substitute for parameters in the actual proof records.

parent-negative-fixtures.json
-----------------------------
SHA2560d0c433ab595dec3991ad83d26ed1ff71fa3656205e7fcc7388f8db6d43646f3
Actual example-soa-negative-cache and its real example-zsk-g1 signature:
OriginalTTL3600, SOA minimum300, separately decremented receivedTTL300. Binds
parent noDS NSEC to the explicitly unsigned-delegation variant, not the public
baseline signed delegation.
parent-negative-verification.json
SHA25699733b96576f067981ccb66b3d864d4e2d12f82ba80fea0977e27cd49a2329f3
Eight assertions, actual parent SOA+NSEC library checks and SOA OpenSSL check.

Execution and packaging
-----------------------
All additional producer/verifier commands are captured in runs/run-029.json
throughrun-034.json. They used the already successful retained offline reference
environment, without repeating setup or moving/deleting it. Corresponding tools:
  generate_complete_paths.py / verify_complete_paths.py
  generate_resolution_profiles.py / verify_resolution_profiles.py
  generate_parent_negative.py / verify_parent_negative.py
The new verifiers check only their added bytes/path observations and required
consumed dependencies; they do not run application suites.

The original FIXTURE-IDENTITIES.json/CONTENTS.json/SHA256SUMS remain byte-for-byte
unchanged. seal_additions.py produces a separately named expanded catalog and
contents/checksum set over all retained files, excluding generated environments
and __pycache__. Dependency/runtime/license provenance and all earlier failures
are unchanged. No production source, live DNS/server, deployment or manual gate
claim is introduced by this addendum.
