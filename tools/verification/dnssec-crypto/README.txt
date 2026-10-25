DNSSEC independent numeric fixtures - D0 reference package

Purpose and boundaries
----------------------
Verification-only Python tooling. No production src module is imported or edited.
No Node/npm dependency. No numeric crypto is installed in app startup. No live
DNS, BIND, Unbound, Knot, PowerDNS, transfer server or browser interoperability
claim is made. These are explicit deterministic synthetic teaching inputs.

The initial baseline is immutable; later requested coverage is supplied in
separately hash-pinned supplements, never by changing covered bytes in place.
All JSON uses schemaVersion1. Object maps have stable IDs; signature entries
bind exact rrsetId, keyId, metadata, signingInputHex and signatureHex. DS entries
bind owner wire plus DNSKEY RDATA, not TTL. Private material is public fixture-only
illustration with dnsSigner custody and is not a network DNSKEY field. TSIG has
a separate public fixture shared secret and transaction-authentication scope.

Data files in docs/dnssec-expansion/numeric/
------------------------------------------
dnssec-numeric-fixtures.json:
  16 key records,19 RRsets,26 signatures,15 DS records,20 NSEC3 calculations.
  Baseline '.' -> 'example.' -> 'lab.example.', alg13/DS2; explicit Ed25519
  signature/DS alternate. Exact real P256 key-tag collision scalars31/60,
  flags256, same owner/algorithm/tag46075; candidate-a fails and b verifies.
  Child KSK flags257 tag22775 -> flags385 tag22903 preserves public/private
  lineage; revocation changes signed DNSKEY bytes and tag, not public key.
  Canonical RR order/name case/permitted MX compression/received TTL equivalence;
  A/TXT opaque case/actual owner/NSEC next-name case mutations fail unchanged
  signatures. RFC6840's NSEC next-name exception is explicit. Wildcard input
  reconstructs '*.lab.example.' with Labels2; signature validity alone does not
  prove wildcard applicability. Eleven literal signature-time cases include
  wraparound and undefined half-range ordering; no universal half-range pass.
  Modern NSEC3 is SHA1 name hash, iterations0, empty salt, one initial hash;
  comparison vectors also have iterations1/12 and saltaabbccdd. Hash steps and
  hexadecimal initial/final bytes are in independent-verification.json.

lifecycle-fixtures.json:
  1 new root successor key(tag3531),7 RRsets,15 actual signatures. Authenticated
  root/child anchor-observation DNSKEY OriginalTTL35days with signature through
  day120; repeated observations0/15/30/35+1second/50+1second/60days executed.
  Real old/new rollover signatures have A OriginalTTL7200 and DS86400.
  Short OriginalTTL60 is an actual signed field, unlike a decremented received
  TTL. Revoked-key self-signature is valid day3..40; manual successor DNSKEY
  signature day89..120. Long lifetimes are explicit fixtures, not operations
  recommendations. TSIG HMAC-SHA256 authenticates one deterministic UPDATE at
  clock1792713600; normal, expired and tampered message observations are actual.
  Its ZONEMD variant is a checksum only, not authenticated expected-digest trust.

profile-fixtures.json:
  8 RRsets/8 signatures. Coherent CSK1/CSK2/Ed25519 alternate child DNSKEY
  self-signatures and parent-signed DS; old/new DS overlap. Authenticated
  child-anchor-omission has only original KSK/ZSK and covers day10 interruption.

zonemd-auth-fixtures.json:
  2 RRsets/2 signatures. Distinct signed-zone variant adds the ZONEMD bit to
  apex NSEC and re-signs NSEC before calculating the digest. Apex ZONEMD and
  RRSIG(ZONEMD) are excluded from the digest, then ZONEMD is actually signed.
  Concrete synthetic root DNSKEY anchor -> parent DS/DNSKEY -> child DS/DNSKEY
  validates SOA and expected digest before whole-zone comparison. Mutating an
  unsigned glue address rejects the whole zone while preserving individually
  valid signed RRsets. This is separate from the checksum-only RFC8976 vector.

record-profile-fixtures.json:
  2 sibling keys,26 RRsets/25 signatures/1 DS. Actual AAAA, cross-zone CNAME and
  DNAME plus independently signed other.example. target path, unsigned
  synthesized DNAME CNAME, private same-owner A under independent local CSK
  anchor, signed child CDS/CDNSKEY intent and exact singleton delete bytes,
  parent-signed DSYNC discovery and child CSYNC(NS/A/AAAA), and compact denial.
  Compact NXNAME is bitmap type128, not a standalone RR. Minimally covering
  next name has literal prefix0100 and the exact owner; no/other names have
  separate signatures. Compact ENT branch and DNAME branch are separate zone
  variants, never merged into a contradictory zone. dnspython has TYPE128 wire
  support but no NXNAME mnemonic. DSYNC is a trigger; CSYNC is not DS authority.

refresh-fixtures.json:
  1 RRset/2 signatures. Same child-zsk-g1, signed OriginalTTL7200. Old signature
  expiration base+10000; refreshed inception base+5400, expiration base+14days.
  Offsets7000/10000/10001 actually checked; old expires at10001. A refresh outage
  means fresh bytes not delivered, not cryptographic invalidity of fresh bytes.

long-profile-fixtures.json:
  5 RRsets/16 signatures. Actual upper root/example/child signatures through
  day120, A OriginalTTL7200 signed by CSK1/CSK2/Ed25519/providerB, dual-algorithm
  child DNSKEY signed with both13 and15, dual-algorithm parent DS and provider
  overlap/final parent DS. All16 signatures actually checked at offsets0,
  95100,175200 and45days. Existing CSK/Ed15 DNSKEY+DS dependencies were consumed
  at95100 too; no timeless upstream signature assumption.

Together the7 immutable datasets contain19 key records,68 RRsets,94 signatures,
16 DS records and20 NSEC3 vectors. Individual reports total629 named assertions,
with separate library/CLI observations and preserved negative results. These
counts are reference-data coverage, not all159 lesson-case acceptance.

Primary references and independent expectation origin
----------------------------------------------------
Raw immutable RFC/source bytes, status, redirect identity, UTC capture time,
byte count and SHA256 are in sources/ and capture-ledger.json. Raw source
errors are preserved, not treated as standards. Important published anchors:
- RFC6605 section6.1: alg13 public key, tag55648, SHA256 DS and signature.
- RFC8080 section6.1: raw example parsing fails. Verified technical erratum4935
  supplies algorithm15, Labels2 AND corrected signature bytes; merely fixing
  the header leaves the old signature invalid. Original bytes and both observed
  failures are retained. https://www.rfc-editor.org/eid4935/
- RFC4509 section2.3: historical alg5 key/tag60485 and exact DS SHA256 bytes;
  verification-only old input, not current signing policy.
- RFC5155 AppendixA:11 published name hashes, iterations12/saltaabbccdd.
- RFC8976 AppendixA.1: independently transcribed SIMPLE/SHA384 zone vector.
- RFC4034 sections2/3/5/6/AppendixB; RFC4035 section5.3; RFC1982 serial rules;
  RFC6840 section5.1; RFC5011; RFC9276; RFC8945; RFC7344; RFC7477; RFC6672;
  RFC9824 sections2/3; RFC9859 sections2-4.
- RFC8078 section4 corrected by verified technical erratum5049: CDS0 0 0 00
  and CDNSKEY0 3 0 AA==, both exactly one payload octet00. The original single
  character0 presentations fail parsing; they are not silently accepted.
  https://www.rfc-editor.org/eid5049/

The producer is dnspython2.8.0's signing/canonicalization implementation with
cryptography46.0.3 deterministic signatures. The independent verifier's
reference_bytes.py reconstructs canonical inputs from authored presentation,
without importing dns or any producer. It compares the immutable producer
bytes and verifies signatures both with cryptography and the separate system
OpenSSL CLI. Published expected key/tag/DS/signature/NSEC3/ZONEMD bytes are fixed
transcriptions, not generated by this independent canonicalizer. Thus one buggy
canonicalizer cannot generate both expected input and verification oracle.
The verifier is intentionally a limited fixture-type reader, not general DNS
software. It rejects unsupported types rather than emitting placeholder bytes.

Actual environment and offline scope
------------------------------------
Python3.14.4, uv0.12.10, dnspython2.8.0, cryptography46.0.3, cffi2.1.1,
pycparser3.12; system OpenSSL3.5.5, cryptography backend OpenSSL3.5.4.
Exact build/compiler/libc identities and source license copies are in
runtime-and-licenses.json. dependencies/ contains4 pinned wheels,4 source
archives and4 actual PyPI metadata captures; hashes are checked against those
captures. Full source licenses remain in the archives;6 license files are also
copied byte-for-byte into licenses/. Existing host runtime/tool executables
are not bundled, and source rebuild of cryptography's Rust graph is not claimed.

A fresh CPython3.14 Linux x86_64 environment was provisioned with --offline,
--no-index and --require-hashes from the supplied wheels, then generation and
verification were actually executed. This establishes offline dependency
installation/re-verification on the recorded platform, not cross-platform or
OS-complete distribution.4 wheels total5096815bytes;4sdists1807101bytes;
PyPI metadata199469bytes; dependency directory total7103385bytes.

Commands (run from repository root)
-----------------------------------
Existing successful environments are retained for provenance and excluded from
source/review packaging: tools/verification/dnssec-crypto/.venv/ and
.offline-venv/. Exclude __pycache__/ recursively too. Future environments belong
outside source, for example an explicitly chosen owned external cache path.
Do not rerun successful setup unnecessarily.

For a new offline reference machine with Python3.14/uv/OpenSSL already present:
  uv venv --python /usr/bin/python3 /chosen/external/cache/dnssec-reference
  uv --offline pip install --python /chosen/external/cache/dnssec-reference/bin/python --no-index --find-links docs/dnssec-expansion/numeric/dependencies --require-hashes -r tools/verification/dnssec-crypto/requirements.txt
Then use that interpreter for the following scripts under this directory:
  generate.py; generate_lifecycle.py; generate_profiles.py;
  generate_zonemd_auth.py; generate_records.py; generate_refresh.py;
  generate_long_profiles.py
  verify.py; library_check.py; verify_lifecycle.py; verify_profiles.py;
  verify_zonemd_auth.py; verify_records.py; verify_refresh.py;
  verify_long_profiles.py
Each script refuses differing bytes over an existing frozen output. Use explicit
new dataset IDs for intentional changes. Existing provenance calls and exact
argv/stdout/stderr/exit status are in numeric/runs/run-001.json onward; record.py
is the command recorder. Published source recapture uses capture.py, only for
missing files; it never overwrites fetched bytes.

Failure preservation and limits
-------------------------------
- Host pip absent; uv default CA store failed UnknownIssuer. --system-certs
  resolved provisioning without disabling TLS verification. Exact initial
  attempts are transcribed in prerequisite-attempts.json.
- run006: independent ZONEMD verifier initially decoded only first split Base64
  signature chunk. Joining all chunks fixed verification; fixture bytes unchanged.
- run017: generator immutable-byte check caught dnspython's default MX RRset
  shuffling. Explicit sorted initial occurrence plus want_shuffle=False preserves
  the exact original frozen bytes. This was not hidden by overwriting fixtures.
- run022: RFC8078 errata redirect connection reset; actual failure retained in
  ledger and run. Direct canonical RFC Editor errata route succeededrun023.
- library-observations.json records14 expected failures, including raw RFC8080,
  mutations/time cases, and4 valid-wraparound disagreements. dnspython2.8.0
  uses plain integer time comparisons. Literal RFC serial vectors and separate
  independent serial evaluation pass; library wraparound validation DOES NOT.
- NXNAME mnemonic unavailable; TYPE128 bit encoding and compact signatures
  actually verify. Original RFC8078 malformed shorthand parse failures retained.
- No app builds/regressions/lint/formatters ran as part of this numeric work.
  None of the numeric passes imply full resolver policy, live deployment,
  server interoperability, manual accessibility or historical gate acceptance.

Fixed delivery identities
-------------------------
python3 tools/verification/dnssec-crypto/seal.py writes FIXTURE-IDENTITIES.json,
CONTENTS.json and SHA256SUMS under numeric/. The catalog binds all7 dataset and
verification hashes, exact counts, key tags and signature IDs. CONTENTS covers
retained scripts, raw sources, wheels/source archives/licenses, fixtures, reports
and all28 recorded attempts; it excludes itself/SHA256SUMS from its payload list
and excludes generated environments/caches. SHA256SUMS additionally binds CONTENTS.
Parent owns the combined D0 worksheet/freeze and all app integration verification.
