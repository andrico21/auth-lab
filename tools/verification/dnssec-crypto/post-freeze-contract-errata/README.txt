Independent additive post-freeze DNSSEC audit material
=====================================================

Authority: docs/dnssec-expansion/contract-freeze.json
SHA256b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19

This package adds separately named fixtures/reports/catalogs. It does not modify
or replace any frozen numeric file, worksheet, source capture, signed object or
earlier seal, including FINAL-FIXTURE-IDENTITIES.json. No production source or
DNSSEC evaluator is imported. No app build/test/lint/formatter or live DNS/server
interoperability is performed. The already successful pinned offline Python
reference environment is reused; there is no new dependency setup.

Active publication data
-----------------------
publication-fixtures.json contains the exact requested collision, original/revoked
A/B/Z0 DNSKEY sets, provider3-key Model1/Model2 sets and explicitly opaque DS
algorithm17/5/12 envelopes. Real parent RRSIGs authenticate those envelopes;
opaqueSyntheticPayload/notDnskeyDerivedDigest are true. Alg5/12 are selectedPolicyOnly
extras, not evidence of a real legacy DNSKEY digest or signature path.

Two distinct synthetic chains are actually verified:
  synthetic root anchor -> net. -> example.net. -> provider.example.net.
  synthetic root anchor -> org. -> example.org. -> provider.example.org.
They end in CDS and CDNSKEY copies at the exact _dsboot names under _signal.ns1
and _signal.ns2. Claim payloads match the singleton child-ksk-g1 apex claims by
type, but the child apex signatures are NEVER initial trust. Each claim is signed
by its independent signaling zone, not the child. A separately authenticated
parent no-DS prerequisite is checked. New deterministic operator keys are public
fixture-only illustration, signer-only and explicitly attributed, not production
secrets or network private records. All metadata/IDs/windows are in the fixture
and publication-verification.json, including actual independent/OpenSSL/library
observations. RFC9615 source captures are reused byte-identically from the frozen
publication source package; their hashes are recorded in generation-provenance.

Active resolution data and retained failed attempt
-------------------------------------------------
Use resolution-fixtures-owner-wire-corrected.json, not resolution-fixtures.json.
The initial auditor request incorrectly specified owner wire03 for the two-octet
label zz. Independent verification rejected that literal. The auditor withdrew
03 and accepted RFC1035 section3.1's correct02. Actual generated RRset/signature
bytes already covered zz with02 and were never changed. Exact key55402, owner,
clock, A addresses, signedOriginalTTL3600 and received RRset/RRSIGTTL300 remain.

resolution-fixtures.json is retained as the attributable failed metadata candidate.
runs/run-002.json records the exact assertion failure; attempts/ retains the first
verifier source bytes. correct_owner_wire.py creates the explicitly separate
corrected fixture, preserving every RRset and signature byte. Raw RFC1035 and
actual capture metadata are retained under sources/. resolution-verification.json
reports corrected owner wire, canonical/signing bytes/hashes, exact public key,
RRSIG RDATA/hash and successful independent/OpenSSL/library verification.

The second resolution variant contains unsigned www.other.example. A192.0.2.80,
receivedTTL300, with no RRSIG. Parent other.example. NSECzzz.example. has exactly
NS/RRSIG/NSEC bits, no DS/SOA, and a real example-zsk-g1 signature with signed and
receivedTTL300. Its root/example authentication path is verified. This is a new
unsigned-target variant, not a mutation of the frozen signed other-www-a object.
Authenticated parent DS absence does not authenticate the unsigned target address.

Commands and final identities
-----------------------------
Run from repository root, using the recorded retained reference interpreter:
  python3 tools/verification/dnssec-crypto/post-freeze-contract-errata/record.py tools/verification/dnssec-crypto/.offline-venv/bin/python tools/verification/dnssec-crypto/post-freeze-contract-errata/generate.py
The initial verify.py attempt and its failure are retained in run002. Correction:
  python3 tools/verification/dnssec-crypto/post-freeze-contract-errata/record.py tools/verification/dnssec-crypto/.offline-venv/bin/python tools/verification/dnssec-crypto/post-freeze-contract-errata/correct_owner_wire.py
Then the accepted corrected independent verifier:
  python3 tools/verification/dnssec-crypto/post-freeze-contract-errata/record.py tools/verification/dnssec-crypto/.offline-venv/bin/python tools/verification/dnssec-crypto/post-freeze-contract-errata/verify.py
All exact argv/stdout/stderr/exit statuses are under this additive package's runs/;
none of the frozen run logs are changed. Existing dnspython2.8.0/cryptography46.0.3,
Python3.14.4 and frozen reference_bytes.py are used. The independent canonicalizer
does not import the producer or production code. Every new signature also has an
actual system OpenSSL CLI verification.

seal.py emits POST-FREEZE-CATALOG.json, CONTENTS.json and SHA256SUMS in the new
additive data directory. It checks every input from the frozen authority (none
are production src paths), records preservation, identifies the active corrected
fixture separately from the failed candidate, and preserves all earlier catalogs.
