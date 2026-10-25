// Plan-derived navigation/input identities only; no independent expected outcomes.
const dnssecLessonFreeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(dnssecLessonFreeze);Object.freeze(value);}return value;};
export const DNSSEC_LESSONS=dnssecLessonFreeze([
  {
    "number": 1,
    "id": "lab-dnssec01",
    "planId": "DNS01",
    "title": "Follow a signed lookup",
    "learningQuestion": "How does a cold resolver obtain and trust an answer?",
    "family": "resolution",
    "defaultCaseId": "cold-secure",
    "caseIds": [
      "cold-secure",
      "warm-answer-cache",
      "partial-chain-cache",
      "tampered-answer"
    ],
    "sourceGroups": [
      "S01",
      "S02",
      "S03",
      "S04",
      "S05",
      "S06"
    ]
  },
  {
    "number": 2,
    "id": "lab-dnssec02",
    "planId": "DNS02",
    "title": "From zone data to signatures",
    "learningQuestion": "What exactly is signed, by which key, and what gets published?",
    "family": "signing-publication",
    "defaultCaseId": "split-ksk-zsk",
    "caseIds": [
      "split-ksk-zsk",
      "combined-key",
      "equivalent-presentation",
      "changed-rdata",
      "opaque-rdata-case-change",
      "changed-owner",
      "keytag-collision"
    ],
    "sourceGroups": [
      "S01",
      "S03",
      "S05",
      "S13",
      "S17"
    ]
  },
  {
    "number": 3,
    "id": "lab-dnssec03",
    "planId": "DNS03",
    "title": "Cross a delegation boundary",
    "learningQuestion": "Why is one child secure, another insecure, and another broken?",
    "family": "resolution",
    "defaultCaseId": "signed-child",
    "caseIds": [
      "signed-child",
      "proved-no-ds",
      "supported-ds-mismatch",
      "missing-ds-proof",
      "no-covering-anchor",
      "signed-island-with-local-anchor",
      "unsupported-only-ds"
    ],
    "sourceGroups": [
      "S01",
      "S03",
      "S04",
      "S06"
    ]
  },
  {
    "number": 4,
    "id": "lab-dnssec04",
    "planId": "DNS04",
    "title": "Explain a validation decision",
    "learningQuestion": "Which check failed, and what does the client receive?",
    "family": "validation",
    "defaultCaseId": "valid",
    "caseIds": [
      "valid",
      "signature-expired",
      "signature-not-yet-valid",
      "wrong-clock",
      "missing-dnskey",
      "missing-rrsig",
      "wrong-signer-or-key",
      "wrong-covered-data",
      "one-valid-plus-one-invalid-signature",
      "dnskey-protocol-not-three",
      "zone-key-flag-clear"
    ],
    "sourceGroups": [
      "S03",
      "S05",
      "S06",
      "S12"
    ]
  },
  {
    "number": 5,
    "id": "lab-dnssec05",
    "planId": "DNS05",
    "title": "Stub validation and the AD flag",
    "learningQuestion": "Does my workstation verify DNSSEC itself or trust a resolver?",
    "family": "forwarding-trust",
    "defaultCaseId": "unaware-stub",
    "caseIds": [
      "unaware-stub",
      "trusted-resolver-ad",
      "ad-interest-without-do",
      "validating-stub",
      "forged-ad-untrusted-hop",
      "do-zero-explicit-dnskey-query",
      "response-flags-and-cached-ad"
    ],
    "sourceGroups": [
      "S01",
      "S03",
      "S06",
      "S23"
    ]
  },
  {
    "number": 6,
    "id": "lab-dnssec06",
    "planId": "DNS06",
    "title": "Who validates when DNS is forwarded?",
    "learningQuestion": "Where does validation happen in client → local resolver → upstream resolver → authorities?",
    "family": "forwarding-trust",
    "defaultCaseId": "local-validates-upstream-fetches",
    "caseIds": [
      "local-validates-upstream-fetches",
      "upstream-validates-local-relies",
      "both-validate",
      "upstream-servfail-cd-zero",
      "local-checks-cd-one-data",
      "dnssec-stripping-forwarder",
      "forwarder-loop-or-unreachable",
      "cached-upstream-servfail-cd-zero-then-cd-one"
    ],
    "sourceGroups": [
      "S03",
      "S12",
      "S23"
    ]
  },
  {
    "number": 7,
    "id": "lab-dnssec07",
    "planId": "DNS07",
    "title": "Prove that a name or type does not exist with NSEC",
    "learningQuestion": "Prove that a name or type does not exist with NSEC",
    "family": "validation",
    "defaultCaseId": "nxdomain",
    "caseIds": [
      "nxdomain",
      "existing-name-nodata",
      "empty-nonterminal",
      "wildcard-excluded",
      "no-ds-at-delegation",
      "incomplete-proof",
      "proof-from-wrong-zone"
    ],
    "sourceGroups": [
      "S05",
      "S06",
      "S09"
    ]
  },
  {
    "number": 8,
    "id": "lab-dnssec08",
    "planId": "DNS08",
    "title": "NSEC3 and Opt-Out",
    "learningQuestion": "NSEC3 and Opt-Out",
    "family": "validation",
    "defaultCaseId": "nsec3-nxdomain",
    "caseIds": [
      "nsec3-nxdomain",
      "nsec3-nodata",
      "unsigned-optout-delegation",
      "missing-closest-encloser",
      "hash-parameter-mismatch",
      "excessive-iterations-policy"
    ],
    "sourceGroups": [
      "S07",
      "S08"
    ]
  },
  {
    "number": 9,
    "id": "lab-dnssec09",
    "planId": "DNS09",
    "title": "Wildcards and aliases across zones",
    "learningQuestion": "Wildcards and aliases across zones",
    "family": "resolution",
    "defaultCaseId": "wildcard-positive",
    "caseIds": [
      "wildcard-positive",
      "wildcard-nodata",
      "wildcard-missing-proof",
      "cname-secure-target",
      "cname-insecure-target",
      "cname-bogus-target",
      "dname-synthesized-cname"
    ],
    "sourceGroups": [
      "S05",
      "S06",
      "S11",
      "S26"
    ]
  },
  {
    "number": 10,
    "id": "lab-dnssec10",
    "planId": "DNS10",
    "title": "Reuse validated cache data",
    "learningQuestion": "Reuse validated cache data",
    "family": "resolution",
    "defaultCaseId": "positive-cache-hit",
    "caseIds": [
      "positive-cache-hit",
      "expired-ttl",
      "signature-expires-first",
      "short-rrsig-ttl",
      "short-original-ttl",
      "negative-cache-hit",
      "aggressive-nsec",
      "aggressive-nsec3",
      "wildcard-synthesis",
      "out-of-proof-range"
    ],
    "sourceGroups": [
      "S06",
      "S09",
      "S10"
    ]
  },
  {
    "number": 11,
    "id": "lab-dnssec11",
    "planId": "DNS11",
    "title": "Large answers, EDNS and encrypted transport",
    "learningQuestion": "Large answers, EDNS and encrypted transport",
    "family": "forwarding-trust",
    "defaultCaseId": "udp-complete",
    "caseIds": [
      "udp-complete",
      "udp-truncated-tcp-retry",
      "tcp-blocked",
      "edns-stripped",
      "dot-authenticated-resolver",
      "encrypted-but-bogus-dns-data"
    ],
    "sourceGroups": [
      "S22",
      "S23",
      "S24"
    ]
  },
  {
    "number": 12,
    "id": "lab-dnssec12",
    "planId": "DNS12",
    "title": "Refresh signatures and roll a ZSK",
    "learningQuestion": "Refresh signatures and roll a ZSK",
    "family": "keys-delegation",
    "defaultCaseId": "resign-before-expiry",
    "caseIds": [
      "resign-before-expiry",
      "zsk-prepublish",
      "zsk-double-sign",
      "old-key-removed-too-early",
      "secondary-lags",
      "signature-refresh-outage"
    ],
    "sourceGroups": [
      "S13"
    ]
  },
  {
    "number": 13,
    "id": "lab-dnssec13",
    "planId": "DNS13",
    "title": "Roll a KSK or combined signing key",
    "learningQuestion": "Roll a KSK or combined signing key",
    "family": "keys-delegation",
    "defaultCaseId": "ksk-double-ds",
    "caseIds": [
      "ksk-double-ds",
      "ksk-double-ksk-method",
      "combined-key-rollover",
      "parent-ds-delayed",
      "old-ds-cache",
      "premature-old-key-removal"
    ],
    "sourceGroups": [
      "S13",
      "S19"
    ]
  },
  {
    "number": 14,
    "id": "lab-dnssec14",
    "planId": "DNS14",
    "title": "Change algorithms and digest policy",
    "learningQuestion": "Change algorithms and digest policy",
    "family": "keys-delegation",
    "defaultCaseId": "modern-baseline",
    "caseIds": [
      "modern-baseline",
      "dual-algorithm-rollover",
      "algorithm-unsupported",
      "unsupported-digest-only",
      "modern-and-obsolete-paths",
      "sha1-signing-disabled",
      "sha1-digest-compatibility",
      "nsec3-sha1-not-signature-policy"
    ],
    "sourceGroups": [
      "S03",
      "S13",
      "S16",
      "S18"
    ]
  },
  {
    "number": 15,
    "id": "lab-dnssec15",
    "planId": "DNS15",
    "title": "Install and maintain a trust anchor",
    "learningQuestion": "Install and maintain a trust anchor",
    "family": "keys-delegation",
    "defaultCaseId": "provisioned-anchor",
    "caseIds": [
      "provisioned-anchor",
      "untrusted-self-signed-key",
      "rfc5011-add",
      "add-hold-down-interrupted",
      "revoke-and-remove",
      "offline-misses-rollover",
      "manual-recovery"
    ],
    "sourceGroups": [
      "S14"
    ]
  },
  {
    "number": 16,
    "id": "lab-dnssec16",
    "planId": "DNS16",
    "title": "Maintain parent DS with CDS/CDNSKEY",
    "learningQuestion": "Maintain parent DS with CDS/CDNSKEY",
    "family": "keys-delegation",
    "defaultCaseId": "consistent-update",
    "caseIds": [
      "consistent-update",
      "consistent-ds-removal",
      "one-authority-stale",
      "cds-cdnskey-keyset-disagreement",
      "nodata-versus-removal",
      "unreachable-authority-retry",
      "digest-policy-comparison",
      "dsync-notify-trigger",
      "invalid-dsync-target",
      "malformed-delete-signal"
    ],
    "sourceGroups": [
      "S19",
      "S21",
      "S29"
    ]
  },
  {
    "number": 17,
    "id": "lab-dnssec17",
    "planId": "DNS17",
    "title": "Bootstrap DS and operate automation safely",
    "learningQuestion": "Bootstrap DS and operate automation safely",
    "family": "keys-delegation",
    "defaultCaseId": "authenticated-rfc9615-bootstrap",
    "caseIds": [
      "authenticated-rfc9615-bootstrap",
      "unauthenticated-child-only-claim",
      "signaling-zone-not-secure",
      "only-in-domain-nameservers",
      "parent-policy-declines",
      "update-would-break-validation",
      "concurrent-manual-update",
      "report-and-retry"
    ],
    "sourceGroups": [
      "S19",
      "S20",
      "S21"
    ]
  },
  {
    "number": 18,
    "id": "lab-dnssec18",
    "planId": "DNS18",
    "title": "Operate multiple signers/providers",
    "learningQuestion": "Operate multiple signers/providers",
    "family": "keys-delegation",
    "defaultCaseId": "shared-ksk-model",
    "caseIds": [
      "shared-ksk-model",
      "separate-ksk-model",
      "cached-keys-provider-switch",
      "missing-cross-provider-key",
      "coordinated-rollover",
      "provider-migration",
      "conflicting-cds-intent"
    ],
    "sourceGroups": [
      "S15",
      "S21"
    ]
  },
  {
    "number": 19,
    "id": "lab-dnssec19",
    "planId": "DNS19",
    "title": "Publish and replicate a signed zone",
    "learningQuestion": "Publish and replicate a signed zone",
    "family": "signing-publication",
    "defaultCaseId": "offline-signer-secondary",
    "caseIds": [
      "offline-signer-secondary",
      "notify-ixfr",
      "axfr-fallback",
      "tsig-authenticated-update",
      "tsig-valid-policy-denied",
      "tsig-failure",
      "zonemd-mismatch"
    ],
    "sourceGroups": [
      "S22",
      "S25"
    ]
  },
  {
    "number": 20,
    "id": "lab-dnssec20",
    "planId": "DNS20",
    "title": "Diagnose failure and recovery",
    "learningQuestion": "Diagnose failure and recovery",
    "family": "validation",
    "defaultCaseId": "bogus-servfail-with-ede",
    "caseIds": [
      "bogus-servfail-with-ede",
      "same-failure-without-ede",
      "cd-one-diagnostic-data",
      "transport-timeout",
      "failure-cache-suppresses-retry",
      "retry-after-expiry",
      "temporary-negative-trust-anchor"
    ],
    "sourceGroups": [
      "S12"
    ]
  },
  {
    "number": 21,
    "id": "lab-dnssec21",
    "planId": "DNS21",
    "title": "Compact denial of existence",
    "learningQuestion": "Compact denial of existence",
    "family": "validation",
    "defaultCaseId": "compact-nonexistent-name",
    "caseIds": [
      "compact-nonexistent-name",
      "genuine-nodata",
      "empty-nonterminal",
      "co-enabled",
      "co-disabled-downstream",
      "explicit-nxname-query",
      "no-wide-aggressive-synthesis"
    ],
    "sourceGroups": [
      "S11"
    ]
  },
  {
    "number": 22,
    "id": "lab-dnssec22",
    "planId": "DNS22",
    "title": "Private DNS, local anchors and conditional forwarding",
    "learningQuestion": "Private DNS, local anchors and conditional forwarding",
    "family": "forwarding-trust",
    "defaultCaseId": "private-signed-zone-local-anchor",
    "caseIds": [
      "private-signed-zone-local-anchor",
      "private-signed-zone-no-covering-anchor",
      "conditional-forward-with-local-validation",
      "different-client-trust-stores",
      "stale-private-anchor",
      "private-view-versus-public-chain"
    ],
    "sourceGroups": [
      "S01",
      "S04",
      "S14",
      "S23"
    ]
  }
]);
export function dnssecLessonMeta(number){if(!Number.isInteger(number)||number<1||number>DNSSEC_LESSONS.length)throw new RangeError('Unknown DNSSEC lesson '+number);return DNSSEC_LESSONS[number-1];}
