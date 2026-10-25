Separately sealed post-freeze numeric completion
===============================================

This package is additive to both the original frozen numeric package and the
independently verified post-freeze-contract-errata package. It never replaces
FINAL-FIXTURE-IDENTITIES.json or POST-FREEZE-CATALOG.json. Only components bound
to actually successful independent reports/command captures are active in the
unified completion catalog. Failed attempts remain attributable and unpromoted.

Component interfaces
---------------------
denial-anchor/: positive NSEC3 other.lab.example. bytes and an independent B
signature on the unchanged complete A-revoked/B/Z0 RRset. The nsec3 map and
nsec3ReferenceTuples name identical independently derived hash bytes. The new B
ordinary-refresh signature remains distinct from A's revocation self-signature.
Local fixed-clock signature checks do not manufacture network receipts, RFC5011
hold-down eligibility, upper-path or leaf application acceptance.

parent-signing/: public exact CDS/CDNSKEY/DS/NSEC/DSYNC input tuples, source-owned
signatures, positive digest-reference tuples and authenticated provider ancestor
paths. SHA1 DS is the already-published historical validation input, not new
publisher permission. Opaque obsolete-algorithm extras are authenticated envelopes,
not numerical legacy DNSKEY paths. Digest4 is an explicit real SHA384 tuple,
not an obsolete digest. Scheme/port/endpoint and mixed/delete inputs remain
application policy inputs, not stored expected application acceptance.
The extra remote TTL3600/SOA-minimum3600 tuple is a separately verified,
UNSELECTED reference profile. The independently audited DNS17 case remains
the existing TTL300 proof/SOA-minimum300, remote receiptbase+500 and expirybase+800.
No verified extra tuple replaces that selected contract.

DNS19/: public TSIG keys are opaque fingerprints/ref/custody records, NOT DNSKEYs
and NOT shared secret bytes. Keep that namespace separate when promoting to the
application bridge. Positive macReferenceTuples bind exact unsigned message wire,
canonical key/algorithm names,48-bit time/fudge/error/other data and the applicable
request/prior MAC. The retained-MAC mutation has its own actual recomputed
positive tuple; a stored expected-false flag is not a numerical oracle.

Transfer streams identify requests/responses, initial baseZoneText and complete
resultZoneText plus explicit RRset/signature manifests. baseZoneText represents
initial holdings, not an implied transfer. IXFR requires actual delete/add
application, not using resultZoneText as an acceptance shortcut. The allowed
UPDATE case changes an explicitly signed initial .82 A to the unchanged existing
.80/.81 A and its real signature, with actual independently signed SOA2302.
TSIG mathematical message authentication is distinct from ACL policy and from
DNSSEC zone/RRset trust. Ordinary NOERROR/REFUSED response wire is authenticated;
a TSIG bad-MAC error is not falsely given an authenticated error response.

ZONEMD positive reference tuples bind the complete independently reconstructed
canonical zone input, excluding apex ZONEMD and RRSIG(ZONEMD), including unsigned
glue. Original and .200->.201 mutated input each have their actual recomputed
SHA384 digest. A digest mismatch must be established by comparing the selected
signed expected digest with the independently bound actual input tuple, not by
storing an expected false application result.

Execution, identities and limits
--------------------------------
All components reuse the already successful recorded Python3.14.4/dnspython2.8.0/
cryptography46.0.3/cffi2.1.1/pycparser3.12 reference environment. No install or setup
is repeated. Each component retains exact producer/verifier command argv,
stdout/stderr/status and every failed attempt in its own folder. Tools generate
or verify only offline numerical inputs. They do not import production source,
a DNSSEC evaluator or app startup, and run no application build/test/lint/formatter.
No live DNS, transfer server or cross-product interoperability is claimed.

The common seal consumes COMPONENTS.json with the actual per-component hashes,
normalizes explicit report bindings (fixtureSha256 or dataset.sha256), verifies
reported numerical observations and captures, rejects secret payload fields in
active public data, and records all object/vector IDs. Parent-signing reports
use explicit per-signature equal/verified/OpenSSL-exit0 facts rather than a top
level pass flag; the catalog does not invent an absent numerical assertion count.
Application namespace allowlists exclude all generation/derivation/seed metadata.
In particular DNS19 promotes dnssecKeys as DNSKEYs, but keys as separate tsigKeys
with only id/keyName/algorithm/fingerprint/custodians/scope. Opaque generator
secretRef and the entire provenance object are excluded from application projection.
The catalog records the canonical public projection hash without rewriting the
independently verified component datasets or emitting private bytes.

POST-FREEZE-COMPLETION-CATALOG.json supplies activeDatasetsAndReports-style refs
for parent promotion. CONTENTS.json and SHA256SUMS identify only this new package.
The seal separately checks every authority-listed frozen input and every retained
prior audit-package file, preserving older manifests/catalogs/checksums byte-for-byte.
Parent owns application bridge promotion and all application/integration gates.
