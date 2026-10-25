Public parent/signing post-freeze completion

Run from repository root, using existing pinned environment (no installation):
tools/verification/dnssec-crypto/.offline-venv/bin/python tools/verification/dnssec-crypto/post-freeze-completion/parent-signing/produce.py
tools/verification/dnssec-crypto/.offline-venv/bin/python tools/verification/dnssec-crypto/post-freeze-completion/parent-signing/verify.py

Active public dataset and report:
docs/dnssec-expansion/numeric/post-freeze-completion/parent-signing/parent-signing-fixtures.json
docs/dnssec-expansion/numeric/post-freeze-completion/parent-signing/parent-signing-verification.json
Captured commands, UTC times, return codes, stdout and stderr: sibling run-001.json through run-004.json in that data directory. Both generations and both verifications succeeded; no failed process attempts occurred. First generation/report were superseded by explicit signal SHA256 digest reference tuples; all actual command captures remain.

Dataset maps: keys, rrsets, signatures, ds. Public key source pointers are literal repository-relative paths and JSON pointers; references contains consumed frozen apex NSEC and post-audit oldK singleton signals. providerAncestorPaths contains independent root-anchored steps through net/org and example.net/org before provider noDS. No provider or child apex initial trust. Remote TTL3600 proof is a distinct object from the TTL300 primary proof; its SOA minimum3600 and receipt/expiry values are mathematical numerical facts, not cache/application policy.

Reference primitives: frozen reference_bytes.py, independently reconstructed canonical RDATA/signing inputs, cryptography signature verification, actual system OpenSSL verification per signature, and pinned dnspython2.8.0 validation at1792713600. Python3.14.4, cryptography46.0.3, cffi2.1.1, pycparser3.12. Producer regenerates only necessary synthetic private scalars in memory, checks public DNSKEY RDATA equality against originals, and never exposes private material.

Primary references: RFC8078 section4 exact singleton delete syntax; RFC7344 sections3-6 CDS/CDNSKEY publication; RFC9859 sections2-4 DSYNC tuple encoding and discovery; RFC9615 sections3.1,3.2,4.1,4.2 independent signaling ancestry; RFC4035 sections3.1.4 and5.2 delegation noDS; RFC6840 sections4.4 and5.1 delegation proof and non-folded NSEC next name; RFC4034 sections3-5 canonical signatures and DS digest. Captured source paths/hashes are in dataset provenance and verification report.

Limits: no production source imports/reads; no application builds/tests; no network DNS or endpoint lookup. Parent signatures over exact opaque algorithm5/digest2 and algorithm12/digest3 DS extras establish no oldalgorithmcrypto path. Historical SHA1 DS bytes are reused unchanged, not newly generated. Actual providerB-owned conflicting CDS/CDNSKEY intent is separate from parent publication. No expected application/ACL acceptance booleans. Freeze inputs and previous addendum untouched. Main numeric owner supplies unified public catalog/seal; these files do not claim independent application behavior.
