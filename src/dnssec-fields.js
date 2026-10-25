import { labAttribute } from './lab-common.js';

// Bindings are declared data. Neither field labels nor explanatory prose select object properties.
function dnssecFieldFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) dnssecFieldFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const DNSSEC_SOURCES = dnssecFieldFreeze([
  {
    "id": "dnssec_source_S01_1",
    "groupId": "S01",
    "name": "S01 RFC 4033 \u00a7\u00a72-8: roles, trust, scope, last hop and temporal considerations.",
    "standard": "S01 RFC 4033 \u00a7\u00a72-8: roles, trust, scope, last hop and temporal considerations.",
    "url": "https://www.rfc-editor.org/rfc/rfc4033.html",
    "note": "S01 RFC 4033 \u00a7\u00a72-8: roles, trust, scope, last hop and temporal considerations.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc4033.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc4033.html",
        "retrievedAt": "2026-10-23T08:17:19.461094+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s01-rfc4033.txt",
        "bytes": 65726,
        "sha256": "2e63aad16e3cf4077995a6b63d8780bc87c5dce2418827ba328340c4a67677b0"
      }
    ]
  },
  {
    "id": "dnssec_source_S02_1",
    "groupId": "S02",
    "name": "S02 RFC 9364: DNSSEC BCP and document map, supplemented by newer updates.",
    "standard": "S02 RFC 9364: DNSSEC BCP and document map, supplemented by newer updates.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9364",
    "note": "S02 RFC 9364: DNSSEC BCP and document map, supplemented by newer updates.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9364",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9364",
        "retrievedAt": "2026-10-23T08:17:19.462066+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s02-rfc9364.html",
        "bytes": 97574,
        "sha256": "61bb9e207345be98371e410d5d2080a0deeb24e135bf0a9ceeaa5d40ad28f26f"
      }
    ]
  },
  {
    "id": "dnssec_source_S03_1",
    "groupId": "S03",
    "name": "S03 RFC 6840 \u00a7\u00a75-6: validation, flags, usable algorithms/signatures and clarifications.",
    "standard": "S03 RFC 6840 \u00a7\u00a75-6: validation, flags, usable algorithms/signatures and clarifications.",
    "url": "https://datatracker.ietf.org/doc/html/rfc6840",
    "note": "S03 RFC 6840 \u00a7\u00a75-6: validation, flags, usable algorithms/signatures and clarifications.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc6840",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc6840",
        "retrievedAt": "2026-10-23T08:17:19.462765+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s03-rfc6840.html",
        "bytes": 120878,
        "sha256": "4387d5a129ddf12ba2d53a3b6b9ed47d8fc2b1874b4332f6bb7d6cbdcbd7e58e"
      }
    ]
  },
  {
    "id": "dnssec_source_S04_1",
    "groupId": "S04",
    "name": "S04 RFC 9499 \u00a7\u00a73-11: current terminology, actors, registration, states.",
    "standard": "S04 RFC 9499 \u00a7\u00a73-11: current terminology, actors, registration, states.",
    "url": "https://www.rfc-editor.org/rfc/rfc9499.html",
    "note": "S04 RFC 9499 \u00a7\u00a73-11: current terminology, actors, registration, states.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc9499.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc9499.html",
        "retrievedAt": "2026-10-23T08:17:19.463669+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s04-rfc9499.html",
        "bytes": 397812,
        "sha256": "75ee897223d10f1d067a1853656c5ea92e52b3f6a00cefc0e6b7297035b6bf52"
      }
    ]
  },
  {
    "id": "dnssec_source_S05_1",
    "groupId": "S05",
    "name": "S05 RFC 4034 \u00a7\u00a72-6 and Appendix B: DNSKEY/RRSIG/NSEC/DS, canonical form and key tags.",
    "standard": "S05 RFC 4034 \u00a7\u00a72-6 and Appendix B: DNSKEY/RRSIG/NSEC/DS, canonical form and key tags.",
    "url": "https://datatracker.ietf.org/doc/html/rfc4034",
    "note": "S05 RFC 4034 \u00a7\u00a72-6 and Appendix B: DNSKEY/RRSIG/NSEC/DS, canonical form and key tags.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc4034",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc4034",
        "retrievedAt": "2026-10-23T08:17:19.464339+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s05-rfc4034.html",
        "bytes": 139387,
        "sha256": "f9525263143afbcb699788dfd3db68536c3f67c6bb0ef46455d58db74f24d731"
      }
    ]
  },
  {
    "id": "dnssec_source_S06_1",
    "groupId": "S06",
    "name": "S06 RFC 4035 \u00a7\u00a72-5: publication, response construction, resolution and validation.",
    "standard": "S06 RFC 4035 \u00a7\u00a72-5: publication, response construction, resolution and validation.",
    "url": "https://datatracker.ietf.org/doc/html/rfc4035",
    "note": "S06 RFC 4035 \u00a7\u00a72-5: publication, response construction, resolution and validation.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc4035",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc4035",
        "retrievedAt": "2026-10-23T08:17:19.464949+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s06-rfc4035.html",
        "bytes": 210907,
        "sha256": "81a49c32874679bab4fd78f3648286ffa0960066462d5f08f4cb856ebf85eadd"
      }
    ]
  },
  {
    "id": "dnssec_source_S07_1",
    "groupId": "S07",
    "name": "S07 RFC 5155 \u00a7\u00a73-9, 12: NSEC3/NSEC3PARAM, proof construction/validation and Opt-Out.",
    "standard": "S07 RFC 5155 \u00a7\u00a73-9, 12: NSEC3/NSEC3PARAM, proof construction/validation and Opt-Out.",
    "url": "https://www.rfc-editor.org/rfc/rfc5155.html",
    "note": "S07 RFC 5155 \u00a7\u00a73-9, 12: NSEC3/NSEC3PARAM, proof construction/validation and Opt-Out.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc5155.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc5155.html",
        "retrievedAt": "2026-10-23T08:17:19.955846+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s07-rfc5155.txt",
        "bytes": 138193,
        "sha256": "cf057f761f239e206f231bd42874675995b3320c9dbc0475cb11a3b43a0d1ecc"
      }
    ]
  },
  {
    "id": "dnssec_source_S08_1",
    "groupId": "S08",
    "name": "S08 RFC 9276 \u00a73: modern NSEC3 operational settings and handling.",
    "standard": "S08 RFC 9276 \u00a73: modern NSEC3 operational settings and handling.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9276",
    "note": "S08 RFC 9276 \u00a73: modern NSEC3 operational settings and handling.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9276",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9276",
        "retrievedAt": "2026-10-23T08:17:19.967939+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s08-rfc9276.html",
        "bytes": 99830,
        "sha256": "d1d903c7388afa740711f1d55ad822462680485025c1d66fba1921ef6686fe38"
      }
    ]
  },
  {
    "id": "dnssec_source_S09_1",
    "groupId": "S09",
    "name": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "standard": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "url": "https://www.rfc-editor.org/rfc/rfc2308.html",
    "note": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc2308.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc2308.html",
        "retrievedAt": "2026-10-23T08:17:20.213638+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s09-rfc2308.txt",
        "bytes": 46858,
        "sha256": "613de9d15f9db4556f4a245dc0a1efa927cca7e02c605dcb080e778965c407ed"
      }
    ]
  },
  {
    "id": "dnssec_source_S09_2",
    "groupId": "S09",
    "name": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "standard": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "url": "https://www.rfc-editor.org/rfc/rfc8020.html",
    "note": "S09 RFC 2308, RFC 8020 \u00a72: negative caching and NXDOMAIN cuts, read with later updates.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8020.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8020.html",
        "retrievedAt": "2026-10-23T08:17:20.321564+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s09-rfc8020.txt",
        "bytes": 30312,
        "sha256": "df426bce2cb31c83a319bd0a57265ecf12fdbac53fc414499c713545ad8778b3"
      }
    ]
  },
  {
    "id": "dnssec_source_S10_1",
    "groupId": "S10",
    "name": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "standard": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "url": "https://www.rfc-editor.org/rfc/rfc8198.html",
    "note": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8198.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8198.html",
        "retrievedAt": "2026-10-23T08:17:20.417763+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s10-rfc8198.txt",
        "bytes": 36042,
        "sha256": "7edc6d1ad7c66f0afc5dd80b3037621d9508ecb8dc7fde71405191c92f47d895"
      }
    ]
  },
  {
    "id": "dnssec_source_S10_2",
    "groupId": "S10",
    "name": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "standard": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9077",
    "note": "S10 RFC 8198 \u00a7\u00a74-5; RFC 9077 \u00a73: aggressive validated proof reuse and TTL updates.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9077",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9077",
        "retrievedAt": "2026-10-23T08:17:20.418488+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s10-rfc9077.html",
        "bytes": 78274,
        "sha256": "0b2926d7c0827b25cc1e0b36baa829b99267d4e2e4b8ef48e03f3c4e29c60ce2"
      }
    ]
  },
  {
    "id": "dnssec_source_S11_1",
    "groupId": "S11",
    "name": "S11 RFC 9824 \u00a7\u00a72-9: compact denial, NXNAME, CO, response restoration and limits.",
    "standard": "S11 RFC 9824 \u00a7\u00a72-9: compact denial, NXNAME, CO, response restoration and limits.",
    "url": "https://www.rfc-editor.org/rfc/rfc9824.html",
    "note": "S11 RFC 9824 \u00a7\u00a72-9: compact denial, NXNAME, CO, response restoration and limits.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc9824.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc9824.html",
        "retrievedAt": "2026-10-23T08:17:20.540732+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s11-rfc9824.html",
        "bytes": 95218,
        "sha256": "6196e8944c6a69684b3d7abe893f532e2a3cdc39fee3c53ee3cdbe6544332753"
      }
    ]
  },
  {
    "id": "dnssec_source_S12_1",
    "groupId": "S12",
    "name": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "standard": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "url": "https://www.rfc-editor.org/rfc/rfc8914.html",
    "note": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8914.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8914.html",
        "retrievedAt": "2026-10-23T08:17:20.623242+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s12-rfc8914.html",
        "bytes": 96272,
        "sha256": "71637315c215390c59b16d4137ea54176135062c1a29a6948e79989f63698eac"
      }
    ]
  },
  {
    "id": "dnssec_source_S12_2",
    "groupId": "S12",
    "name": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "standard": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9520",
    "note": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9520",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9520",
        "retrievedAt": "2026-10-23T08:17:20.974290+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s12-rfc9520.html",
        "bytes": 127778,
        "sha256": "82b510c0e3bc7999097c9c0d92fad6f56d32d0d21016bba2f3f02ada8eda511d"
      }
    ]
  },
  {
    "id": "dnssec_source_S12_3",
    "groupId": "S12",
    "name": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "standard": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "url": "https://www.rfc-editor.org/rfc/rfc7646.html",
    "note": "S12 RFC 8914 \u00a7\u00a72-4; RFC 9520 \u00a73; RFC 7646: EDE, resolution failure caching and negative trust anchors.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc7646.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc7646.html",
        "retrievedAt": "2026-10-23T08:17:21.084454+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s12-rfc7646.txt",
        "bytes": 44559,
        "sha256": "c16f8b5a8236a5f7f774278f79a8248f961dc6f10fd734b06f0b87b71b06ce1d"
      }
    ]
  },
  {
    "id": "dnssec_source_S13_1",
    "groupId": "S13",
    "name": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "standard": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "url": "https://www.rfc-editor.org/rfc/rfc6781.html",
    "note": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc6781.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc6781.html",
        "retrievedAt": "2026-10-23T08:17:13.920975+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc6781.raw",
        "bytes": 193523,
        "sha256": "e56e103b6ff142a4e7599be4e6710dc58fdf72f95c9cfe98bfdb0ebe13a6c95a"
      }
    ]
  },
  {
    "id": "dnssec_source_S13_2",
    "groupId": "S13",
    "name": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "standard": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "url": "https://datatracker.ietf.org/doc/html/rfc7583",
    "note": "S13 RFC 6781 \u00a7\u00a73-4; RFC 7583: signing operations, key/algorithm rollover and timing. The latter is Informational, not a universal fixed timer.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc7583",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc7583",
        "retrievedAt": "2026-10-23T08:17:13.922720+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc7583.raw",
        "bytes": 124749,
        "sha256": "1b8be6b82fbf5635d8f6589fdb2ef9b2a5a84345be947fd14773c4d8f62d9342"
      }
    ]
  },
  {
    "id": "dnssec_source_S14_1",
    "groupId": "S14",
    "name": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "standard": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "url": "https://datatracker.ietf.org/doc/html/rfc5011",
    "note": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc5011",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc5011",
        "retrievedAt": "2026-10-23T08:17:13.923491+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc5011.raw",
        "bytes": 79998,
        "sha256": "6e0475a1119d07794eb72c4b4f479409b177af9096cc507e6e151580c3d658fd"
      }
    ]
  },
  {
    "id": "dnssec_source_S14_2",
    "groupId": "S14",
    "name": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "standard": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "url": "https://www.rfc-editor.org/rfc/rfc9718.html",
    "note": "S14 RFC 5011 \u00a7\u00a72-4; RFC 9718 (obsoletes RFC 7958): managed trust anchors and current root trust-anchor publication context.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc9718.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc9718.html",
        "retrievedAt": "2026-10-23T08:17:13.924212+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9718.raw",
        "bytes": 81924,
        "sha256": "eea6a268fd3d3bc5da53521462bfff6be6db0f2a1fd66bed74956cdcd207515f"
      }
    ]
  },
  {
    "id": "dnssec_source_S15_1",
    "groupId": "S15",
    "name": "S15 RFC 8901 \u00a7\u00a72-7: multi-signer models, rollover and coordination.",
    "standard": "S15 RFC 8901 \u00a7\u00a72-7: multi-signer models, rollover and coordination.",
    "url": "https://www.rfc-editor.org/rfc/rfc8901.html",
    "note": "S15 RFC 8901 \u00a7\u00a72-7: multi-signer models, rollover and coordination.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8901.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8901.html",
        "retrievedAt": "2026-10-23T08:17:13.925192+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8901.raw",
        "bytes": 91525,
        "sha256": "8db86ee26f9efa1f78849c6f887e36eb113c962270e0cefb61c2536cb57ef1f3"
      }
    ]
  },
  {
    "id": "dnssec_source_S16_1",
    "groupId": "S16",
    "name": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "standard": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9904",
    "note": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9904",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9904",
        "retrievedAt": "2026-10-23T08:17:13.927994+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9904.raw",
        "bytes": 128861,
        "sha256": "3cca61ae7e405866a40d0f7ebd2972ebace554d10a2f767852c5470cc2c709c5"
      }
    ]
  },
  {
    "id": "dnssec_source_S16_2",
    "groupId": "S16",
    "name": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "standard": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "url": "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml",
    "note": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml",
        "finalUrl": "https://www.iana.org/assignments/dns-sec-alg-numbers",
        "retrievedAt": "2026-10-23T08:17:13.929005+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/iana-algorithms.raw",
        "bytes": 47256,
        "sha256": "06d6cf7656f86fdcd1153f7698c193524c98dbe63d3f803503ee9f53914c2890"
      }
    ]
  },
  {
    "id": "dnssec_source_S16_3",
    "groupId": "S16",
    "name": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "standard": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "url": "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml",
    "note": "S16 RFC 9904; IANA DNS Security Algorithm Numbers; IANA DS Digest Algorithms: current separated policy columns.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml",
        "finalUrl": "https://www.iana.org/assignments/ds-rr-types",
        "retrievedAt": "2026-10-23T08:17:13.929657+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/iana-digests.raw",
        "bytes": 33168,
        "sha256": "37cbeaeb417e523ee33bf887c1fce5e950e2a4dd28ba0c6ee04e4d14571d7eef"
      }
    ]
  },
  {
    "id": "dnssec_source_S17_1",
    "groupId": "S17",
    "name": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "standard": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "url": "https://www.rfc-editor.org/rfc/rfc6605.html",
    "note": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc6605.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc6605.html",
        "retrievedAt": "2026-10-23T08:17:14.664067+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc6605.raw",
        "bytes": 18979,
        "sha256": "beedc53ce1a41366a13770b61229a1dacfcef5d2d73cfd972609a4d92aec97c6"
      }
    ]
  },
  {
    "id": "dnssec_source_S17_2",
    "groupId": "S17",
    "name": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "standard": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "url": "https://www.rfc-editor.org/rfc/rfc8080.html",
    "note": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8080.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8080.html",
        "retrievedAt": "2026-10-23T08:17:14.690036+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8080.raw",
        "bytes": 18675,
        "sha256": "95c9b503860e8e04fa679125411d5a9d9a6fc81cdbf07efbf92978718a99061d"
      }
    ]
  },
  {
    "id": "dnssec_source_S17_3",
    "groupId": "S17",
    "name": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "standard": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "url": "https://www.rfc-editor.org/rfc/rfc4509.html",
    "note": "S17 RFC 6605; RFC 8080; RFC 4509: ECDSA, Edwards curves and SHA-256 DS encoding/examples.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc4509.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc4509.html",
        "retrievedAt": "2026-10-23T08:17:14.711019+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc4509.raw",
        "bytes": 18629,
        "sha256": "0b4bac8009c7737054cc8a79780a65fbe80742962cf38884c30fabde01e76688"
      }
    ]
  },
  {
    "id": "dnssec_source_S18_1",
    "groupId": "S18",
    "name": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "standard": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9905",
    "note": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9905",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9905",
        "retrievedAt": "2026-10-23T08:17:14.722108+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9905.raw",
        "bytes": 81313,
        "sha256": "95a6a663ec44e383532d61169964517b27d12f5395a498014767c507f1dd3a4d"
      }
    ]
  },
  {
    "id": "dnssec_source_S18_2",
    "groupId": "S18",
    "name": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "standard": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "url": "https://www.rfc-editor.org/rfc/rfc9906.html",
    "note": "S18 RFC 9905 \u00a7\u00a72, 4-5; RFC 9906: contemporary algorithm deprecations and their precise scope.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc9906.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc9906.html",
        "retrievedAt": "2026-10-23T08:17:14.737043+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9906.raw",
        "bytes": 50375,
        "sha256": "91b169cd3b446b850c63cbfba0152b86e5c099ad804c85254bd409911c24e751"
      }
    ]
  },
  {
    "id": "dnssec_source_S19_1",
    "groupId": "S19",
    "name": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "standard": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "url": "https://www.rfc-editor.org/rfc/rfc7344.html",
    "note": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc7344.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc7344.html",
        "retrievedAt": "2026-10-23T08:17:15.351244+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc7344.raw",
        "bytes": 49301,
        "sha256": "46601a878a4694cd5938914143696ef54502837e082895e79ba588dedc1b8b05"
      }
    ]
  },
  {
    "id": "dnssec_source_S19_2",
    "groupId": "S19",
    "name": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "standard": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "url": "https://www.rfc-editor.org/rfc/rfc8078.html",
    "note": "S19 RFC 7344 \u00a7\u00a73-6; RFC 8078 \u00a7\u00a73-6: CDS/CDNSKEY management, initial-enrollment policy and removal signaling.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8078.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8078.html",
        "retrievedAt": "2026-10-23T08:17:15.389636+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8078.raw",
        "bytes": 27131,
        "sha256": "f0d83887445add497a3054fb9707e9f99ce3079b2b7500fc4d065eb8a1eec6b8"
      }
    ]
  },
  {
    "id": "dnssec_source_S20_1",
    "groupId": "S20",
    "name": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "standard": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "url": "https://www.rfc-editor.org/rfc/rfc9615.html",
    "note": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc9615.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc9615.html",
        "retrievedAt": "2026-10-23T08:17:15.403131+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9615.raw",
        "bytes": 85971,
        "sha256": "fe2f082c33485229b25d5010c887f862a71eace341ad38403289debaaa25924d"
      }
    ]
  },
  {
    "id": "dnssec_source_S20_2",
    "groupId": "S20",
    "name": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "standard": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "url": "https://www.rfc-editor.org/rfc/rfc10026.html",
    "note": "S20 RFC 9615 \u00a7\u00a73-4; RFC 10026 \u00a7\u00a73-7: authenticated bootstrap, operational checks, reporting and concurrent changes.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc10026.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc10026.html",
        "retrievedAt": "2026-10-23T08:17:15.414500+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc10026.raw",
        "bytes": 136443,
        "sha256": "7fe8011ec8911c27aa1c667c949fc0300c8c349d37a0da0845c725cd1852c1ed"
      }
    ]
  },
  {
    "id": "dnssec_source_S21_1",
    "groupId": "S21",
    "name": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "standard": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9975",
    "note": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9975",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9975",
        "retrievedAt": "2026-10-23T08:17:15.639258+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9975.raw",
        "bytes": 111483,
        "sha256": "e1fd779cb4c4be55251b9e1bc06f850e95210bf0abcf4f91b1a8e25548b7f4f6"
      }
    ]
  },
  {
    "id": "dnssec_source_S21_2",
    "groupId": "S21",
    "name": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "standard": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "url": "https://www.rfc-editor.org/rfc/rfc7477.html",
    "note": "S21 RFC 9975 \u00a73 and Appendix A; RFC 7477: child-signal consistency and separate CSYNC behavior.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc7477.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc7477.html",
        "retrievedAt": "2026-10-23T08:17:15.686323+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc7477.raw",
        "bytes": 43190,
        "sha256": "39e6ba5710b8bec8ee738c60c6814e864dfa1919303777d925f371c0efea8cf5"
      }
    ]
  },
  {
    "id": "dnssec_source_S22_1",
    "groupId": "S22",
    "name": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "standard": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "url": "https://www.rfc-editor.org/rfc/rfc1034.html",
    "note": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc1034.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc1034.html",
        "retrievedAt": "2026-10-23T08:17:21.095057+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s22-rfc1034.txt",
        "bytes": 142381,
        "sha256": "b836375d9ce5b9d3565c8f4c55066764d8572bcad65d7a1af53d3662c94fd59e"
      }
    ]
  },
  {
    "id": "dnssec_source_S22_2",
    "groupId": "S22",
    "name": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "standard": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "url": "https://www.rfc-editor.org/rfc/rfc1035.html",
    "note": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc1035.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc1035.html",
        "retrievedAt": "2026-10-23T08:17:21.149476+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s22-rfc1035.txt",
        "bytes": 140476,
        "sha256": "2d604f2c272b41983f98cecf5f9ccc101f2eda690e255c2e95121462f3373cf9"
      }
    ]
  },
  {
    "id": "dnssec_source_S22_3",
    "groupId": "S22",
    "name": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "standard": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "url": "https://www.rfc-editor.org/rfc/rfc6891.html",
    "note": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc6891.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc6891.html",
        "retrievedAt": "2026-10-23T08:17:21.166743+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s22-rfc6891.txt",
        "bytes": 42300,
        "sha256": "c790af0cf255e5ab75ac56a7fa3863ca5f4898a791a022a6cb946d15b6be7dee"
      }
    ]
  },
  {
    "id": "dnssec_source_S22_4",
    "groupId": "S22",
    "name": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "standard": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "url": "https://www.rfc-editor.org/rfc/rfc7766.html",
    "note": "S22 RFC 1034; RFC 1035; RFC 6891; RFC 7766: DNS messages, EDNS and TCP.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc7766.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc7766.html",
        "retrievedAt": "2026-10-23T08:17:21.302208+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s22-rfc7766.txt",
        "bytes": 53333,
        "sha256": "e3489f7b0fe65823250d02fb82f6dcaa6ecc2d77c1edd48a166b51ef2e1c958e"
      }
    ]
  },
  {
    "id": "dnssec_source_S23_1",
    "groupId": "S23",
    "name": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "standard": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "url": "https://www.rfc-editor.org/rfc/rfc5625.html",
    "note": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc5625.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc5625.html",
        "retrievedAt": "2026-10-23T08:17:21.663141+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s23-rfc5625.txt",
        "bytes": 32514,
        "sha256": "56c1ec1d405463a0886cae0b0d2387959fa807509ea0f07d4b284df5b8b8f06f"
      }
    ]
  },
  {
    "id": "dnssec_source_S23_2",
    "groupId": "S23",
    "name": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "standard": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "url": "https://www.rfc-editor.org/rfc/rfc3225.html",
    "note": "S23 RFC 5625 \u00a7\u00a73-4; RFC 3225 \u00a73: forwarding/proxy transparency and DO, read with RFC 6840.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc3225.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc3225.html",
        "retrievedAt": "2026-10-23T08:17:21.701809+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s23-rfc3225.txt",
        "bytes": 13577,
        "sha256": "aa4bd11ea190cefc0d6541c2dbf3ef420d5918cd6b837d59831c7a42ac52e8a3"
      }
    ]
  },
  {
    "id": "dnssec_source_S24_1",
    "groupId": "S24",
    "name": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "standard": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "url": "https://www.rfc-editor.org/rfc/rfc7858.html",
    "note": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc7858.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc7858.html",
        "retrievedAt": "2026-10-23T08:17:21.721989+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s24-rfc7858.txt",
        "bytes": 55802,
        "sha256": "896c7f1bc0049e41fda9bb6bd59bf2bf7596f64f1d7551f33d0046d37c8a8138"
      }
    ]
  },
  {
    "id": "dnssec_source_S24_2",
    "groupId": "S24",
    "name": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "standard": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "url": "https://www.rfc-editor.org/rfc/rfc8310.html",
    "note": "S24 RFC 7858; RFC 8310: DNS over TLS and resolver authentication profiles.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8310.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8310.html",
        "retrievedAt": "2026-10-23T08:17:21.824536+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s24-rfc8310.txt",
        "bytes": 80645,
        "sha256": "79ba065e928e1a28ce6627b62f9b0930a3f903eddd9c17fec5d57418b103bb72"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_1",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://datatracker.ietf.org/doc/html/rfc8945",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc8945",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc8945",
        "retrievedAt": "2026-10-23T08:17:16.040541+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8945.raw",
        "bytes": 175810,
        "sha256": "d429c8ecafc408998e8fdba8a57d4c3afcc4e534a11f1b8e6f2deb82efc8c0da"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_2",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://www.rfc-editor.org/rfc/rfc5936.html",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc5936.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc5936.html",
        "retrievedAt": "2026-10-23T08:17:16.059921+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc5936.raw",
        "bytes": 85752,
        "sha256": "4cde18bd504a9c55d1b147e2085ce39f613d1f99f3aba746cf664e1a1282ac6c"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_3",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://www.rfc-editor.org/rfc/rfc1995.html",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc1995.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc1995.html",
        "retrievedAt": "2026-10-23T08:17:16.098110+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc1995.raw",
        "bytes": 19168,
        "sha256": "adff6d81a2943fe1d446e93ec22e0edbd3e56b674310a5995d0f75fa618d723f"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_4",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://www.rfc-editor.org/rfc/rfc1996.html",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc1996.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc1996.html",
        "retrievedAt": "2026-10-23T08:17:16.189476+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc1996.raw",
        "bytes": 17048,
        "sha256": "bbef78b5f96a15adc0890048017970a5e02d80d77aa665a96d13a925e8edf85b"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_5",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://www.rfc-editor.org/rfc/rfc2136.html",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc2136.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc2136.html",
        "retrievedAt": "2026-10-23T08:17:16.264872+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc2136.raw",
        "bytes": 62790,
        "sha256": "6a8169f712cfd5c3117387965e8d2214e750c8be7d4cc67a139e676ff58b1ecc"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_6",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://www.rfc-editor.org/rfc/rfc3007.html",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc3007.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc3007.html",
        "retrievedAt": "2026-10-23T08:17:16.391221+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc3007.raw",
        "bytes": 22754,
        "sha256": "ca9b740e4ecc87f0c998d291d8f0ba47d12c6f98ad1ce327ad150dcf6a006d0d"
      }
    ]
  },
  {
    "id": "dnssec_source_S25_7",
    "groupId": "S25",
    "name": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "standard": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "url": "https://datatracker.ietf.org/doc/html/rfc8976",
    "note": "S25 RFC 8945; RFC 5936; RFC 1995; RFC 1996; RFC 2136; RFC 3007; RFC 8976: TSIG, AXFR/IXFR, NOTIFY, UPDATE authentication/authorization and ZONEMD.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc8976",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc8976",
        "retrievedAt": "2026-10-23T08:17:16.548423+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8976.raw",
        "bytes": 205899,
        "sha256": "f8e1dd600d22c0211c2a1ee4396970ae774bf247dbd92b8840606076ddb7b8e3"
      }
    ]
  },
  {
    "id": "dnssec_source_S26_1",
    "groupId": "S26",
    "name": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "standard": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "url": "https://www.rfc-editor.org/rfc/rfc6672.html",
    "note": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc6672.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc6672.html",
        "retrievedAt": "2026-10-23T08:17:21.961183+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s26-rfc6672.txt",
        "bytes": 60114,
        "sha256": "db0b5fd4ca20fd67041cbf82e547af9c062f3b120ccad43d1f04172698b27b80"
      }
    ]
  },
  {
    "id": "dnssec_source_S26_2",
    "groupId": "S26",
    "name": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "standard": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "url": "https://www.rfc-editor.org/rfc/rfc4592.html",
    "note": "S26 RFC 6672 \u00a7\u00a73-5; RFC 4592: DNAME and wildcard semantics.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc4592.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc4592.html",
        "retrievedAt": "2026-10-23T08:17:22.076288+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s26-rfc4592.txt",
        "bytes": 56305,
        "sha256": "a8568c5d7b0d3392f6d7bbd426c5d68b5fb14745fe16dafd2827ea0275917ea6"
      }
    ]
  },
  {
    "id": "dnssec_source_S27_1",
    "groupId": "S27",
    "name": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "standard": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "url": "https://www.rfc-editor.org/rfc/rfc8749.html",
    "note": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/rfc/rfc8749.html",
        "finalUrl": "https://www.rfc-editor.org/rfc/rfc8749.html",
        "retrievedAt": "2026-10-23T08:17:16.556522+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc8749.raw",
        "bytes": 48065,
        "sha256": "52d8ad9dcb29050b54821e6c1be8b303abaf89bc7cc63415710ff4a9238c69e7"
      }
    ]
  },
  {
    "id": "dnssec_source_S27_2",
    "groupId": "S27",
    "name": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "standard": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "url": "https://www.rfc-editor.org/subjects/dnssec/",
    "note": "S27 RFC 8749: DLV Historic. RFC Editor DNSSEC index: update discovery, not a replacement for the documents.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/subjects/dnssec/",
        "finalUrl": "https://www.rfc-editor.org/subjects/dnssec/",
        "retrievedAt": "2026-10-23T08:17:16.606980+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc-editor-dnssec-index.raw",
        "bytes": 919887,
        "sha256": "4b84b3a84cc3c91cf1764f1cf0cae4a9246a7a970db485b91d85a7f04ee1b932"
      }
    ]
  },
  {
    "id": "dnssec_source_S28_1",
    "groupId": "S28",
    "name": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "standard": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "url": "https://www.rfc-editor.org/errata/rfc4034",
    "note": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/errata/rfc4034",
        "finalUrl": "https://errata.rfc-editor.org/search/?rfc_number=4034&presentation=records",
        "retrievedAt": "2026-10-23T08:17:22.350125+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s28-rfc4034-errata-index.html",
        "bytes": 39895,
        "sha256": "99d266c730d1c702b9162fbff80729b7c995f97aa70e8e44eba1949967c5f74a"
      }
    ]
  },
  {
    "id": "dnssec_source_S28_2",
    "groupId": "S28",
    "name": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "standard": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "url": "https://www.rfc-editor.org/errata/rfc4035",
    "note": "S28 RFC 4034 errata; RFC 4035 errata: verify individual status and applicable corrections.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://www.rfc-editor.org/errata/rfc4035",
        "finalUrl": "https://errata.rfc-editor.org/search/?rfc_number=4035&presentation=records",
        "retrievedAt": "2026-10-23T08:17:22.390185+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/resolution/s28-rfc4035-errata-index.html",
        "bytes": 31439,
        "sha256": "00e3dfaf6b147f1c197a384b7134f76e2422c7e73406ccb6258208b991effa6f"
      }
    ]
  },
  {
    "id": "dnssec_source_S29_1",
    "groupId": "S29",
    "name": "S29 RFC 9859 \u00a7\u00a72-4: DSYNC discovery and generalized NOTIFY; an additional trigger for existing checked workflows.",
    "standard": "S29 RFC 9859 \u00a7\u00a72-4: DSYNC discovery and generalized NOTIFY; an additional trigger for existing checked workflows.",
    "url": "https://datatracker.ietf.org/doc/html/rfc9859",
    "note": "S29 RFC 9859 \u00a7\u00a72-4: DSYNC discovery and generalized NOTIFY; an additional trigger for existing checked workflows.",
    "researchCutoff": "2026-10-23",
    "captures": [
      {
        "requestedUrl": "https://datatracker.ietf.org/doc/html/rfc9859",
        "finalUrl": "https://datatracker.ietf.org/doc/html/rfc9859",
        "retrievedAt": "2026-10-23T08:17:16.842412+00:00",
        "httpStatus": 200,
        "path": "docs/dnssec-expansion/sources/publication/rfc9859.raw",
        "bytes": 131941,
        "sha256": "e55d477ce173f7e3224ebec682c06ffd798ed4bd5093cd6771e5ad3a26447b60"
      }
    ]
  }
]);

const dnssecFieldSpecs = {
  "header": {
    "sourceGroups": [
      "S22",
      "S03",
      "S06"
    ],
    "origin": "Constructed by the DNS message sender; response flags report that sender\u2019s state.",
    "fields": [
      [
        "",
        "Complete DNS message occurrence",
        "The exact public DNS message occurrence, including its header, question, EDNS and referenced record values. Receipt does not authenticate it.",
        {},
        "object"
      ],
      [
        "id",
        "Transaction ID",
        "Correlates a DNS response with its request; not an authentication token.",
        4660,
        "integer"
      ],
      [
        "opcode",
        "Opcode",
        "Selects the DNS operation, independently of DNSSEC trust.",
        "QUERY",
        "string"
      ],
      [
        "rcode",
        "Response code",
        "Protocol response code; NOERROR alone does not imply a secure answer.",
        "NOERROR",
        "string"
      ],
      [
        "flags.QR",
        "QR",
        "Distinguishes request from response.",
        true,
        "boolean"
      ],
      [
        "flags.AA",
        "AA",
        "Authoritative Answer concerns the responding server\u2019s authority, not successful DNSSEC validation.",
        false,
        "boolean"
      ],
      [
        "flags.TC",
        "TC",
        "Truncation requires suitable retry/transport handling; missing data is not a cryptographic failure.",
        false,
        "boolean"
      ],
      [
        "flags.RD",
        "RD",
        "Recursion Desired asks the receiving server for recursion.",
        true,
        "boolean"
      ],
      [
        "flags.RA",
        "RA",
        "Recursion Available advertises resolver capability, not answer authenticity.",
        true,
        "boolean"
      ],
      [
        "flags.Z",
        "Reserved header bit",
        "Reserved bit is distinct from AD and CD.",
        false,
        "boolean"
      ],
      [
        "flags.AD",
        "AD",
        "Authenticated Data is a remote resolver assertion; a checking client must use an appropriately trusted channel or validate locally.",
        false,
        "boolean"
      ],
      [
        "flags.CD",
        "CD",
        "Checking Disabled requests delivery without the recursive server withholding data for its validation failure; it does not make received bytes trusted.",
        false,
        "boolean"
      ],
      [
        "questionCount",
        "QDCOUNT",
        "Number of questions represented in the message.",
        1,
        "integer"
      ],
      [
        "answerCount",
        "ANCOUNT",
        "Number of resource records in the answer section.",
        2,
        "integer"
      ],
      [
        "authorityCount",
        "NSCOUNT",
        "Number of resource records in the authority section.",
        0,
        "integer"
      ],
      [
        "additionalCount",
        "ARCOUNT",
        "Number of additional records, including an OPT pseudorecord when present.",
        1,
        "integer"
      ]
    ]
  },
  "question": {
    "sourceGroups": [
      "S22"
    ],
    "origin": "Selected by the querying application or resolver.",
    "fields": [
      [
        "",
        "Complete question record",
        "The exact complete concrete question object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "qname",
        "QNAME",
        "Exact queried DNS name; changing it changes the question.",
        "www.lab.example.",
        "string"
      ],
      [
        "qtype",
        "QTYPE",
        "Requested resource-record type, independently of the question name.",
        "A",
        "string"
      ],
      [
        "qclass",
        "QCLASS",
        "Requested DNS class.",
        "IN",
        "string"
      ]
    ]
  },
  "opt": {
    "sourceGroups": [
      "S22",
      "S23",
      "S11",
      "S12"
    ],
    "origin": "Advertised in an EDNS OPT pseudorecord; OPT is not a signed zone RRset.",
    "fields": [
      [
        "",
        "Complete opt record",
        "The exact complete concrete opt object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "udpPayloadSize",
        "UDP payload size",
        "Advertises receive size, not path MTU or authenticity.",
        1232,
        "integer"
      ],
      [
        "extendedRcode",
        "Extended RCODE",
        "Upper response-code bits carried by OPT.",
        0,
        "integer"
      ],
      [
        "version",
        "EDNS version",
        "EDNS version understood by the sender.",
        0,
        "integer"
      ],
      [
        "DO",
        "DO",
        "DNSSEC OK requests DNSSEC records; requesting or receiving them is not validation.",
        true,
        "boolean"
      ],
      [
        "CO",
        "CO",
        "Compact Answers OK signals RFC9824 response handling, not proof validity.",
        false,
        "boolean"
      ],
      [
        "options",
        "EDNS options",
        "Explicit EDNS option records; they are not additional trust anchors.",
        [],
        "array"
      ],
      [
        "ede.infoCode",
        "EDE information code",
        "Diagnostic Extended DNS Error code; not authenticated proof of the explanation.",
        6,
        "integer"
      ],
      [
        "ede.extraText",
        "EDE extra text",
        "Optional human-readable EDE diagnostic, not a machine trust verdict.",
        "DNSSEC Bogus",
        "string"
      ]
    ]
  },
  "rrset": {
    "sourceGroups": [
      "S05",
      "S06",
      "S28"
    ],
    "origin": "Published by an authoritative zone and received as public data before any trust decision.",
    "fields": [
      [
        "",
        "Complete rrset record",
        "The exact complete concrete rrset object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "RRset identity",
        "Stable identity of this exact fixed numeric RRset.",
        "www-a",
        "string"
      ],
      [
        "owner",
        "Owner name",
        "All members of one RRset have this owner name. Canonicalization does not authorize changing it.",
        "www.lab.example.",
        "string"
      ],
      [
        "type",
        "RR type",
        "The RRset\u2019s resource-record type.",
        "A",
        "string"
      ],
      [
        "typeCode",
        "RR type code",
        "Wire-format numerical type code.",
        1,
        "integer"
      ],
      [
        "class",
        "RR class",
        "RRset class participates in canonical signing input.",
        "IN",
        "string"
      ],
      [
        "ttl",
        "Received TTL",
        "TTL on this representation; it may decrease without changing signed Original TTL.",
        3600,
        "integer"
      ],
      [
        "receivedTtl",
        "Received TTL observation",
        "Explicit received-lifetime observation when recorded separately from the original RRset.",
        42,
        "integer"
      ],
      [
        "records",
        "RDATA members",
        "Exact public RDATA presentations. A changed owner or RDATA requires a separate signature.",
        [
          "192.0.2.80",
          "192.0.2.81"
        ],
        "array"
      ],
      [
        "canonicalRdataHex",
        "Reference canonical RDATA",
        "Exact independently produced canonical RDATA octets; validation must reconstruct from actual records rather than trusting a stale copy.",
        [],
        "array"
      ]
    ]
  },
  "dnskey": {
    "sourceGroups": [
      "S05",
      "S17",
      "S16",
      "S18"
    ],
    "origin": "Published in a DNSKEY RRset; public readability does not authenticate the key.",
    "fields": [
      [
        "",
        "Complete dnskey record",
        "The exact complete concrete dnskey object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "Public key identity",
        "Stable numeric fixture key identity, distinct from a potentially colliding key tag.",
        "child-ksk-g1",
        "string"
      ],
      [
        "owner",
        "DNSKEY owner",
        "Zone owner to which this public DNSKEY belongs.",
        "lab.example.",
        "string"
      ],
      [
        "flags",
        "DNSKEY Flags",
        "Zone Key, SEP and REVOKE are distinct bits. SEP is operational guidance, not an independent validation privilege.",
        257,
        "integer"
      ],
      [
        "protocol",
        "DNSKEY Protocol",
        "The DNSSEC candidate protocol value must be 3.",
        3,
        "integer"
      ],
      [
        "algorithm",
        "DNSKEY Algorithm",
        "Public-key signature algorithm ID, not a DS digest type or NSEC3 hash algorithm.",
        13,
        "integer"
      ],
      [
        "publicKeyBase64",
        "Public Key",
        "Public verification-key octets encoded in Base64; not a secret, cipher key or proof of trust.",
        "Pu0xeazW0puWQsZkqHFph4asNCh+1iew7bKuiVYAaWdHLCv+EHfcc1uIpLSfRPF8YM4gks+nS7FCOOZcNMVOSA==",
        "string"
      ],
      [
        "publicKeyHex",
        "Public key octets",
        "Exact public verification-key octets in hexadecimal.",
        "3eed3179acd6d29b9642c664a871698786ac34287ed627b0edb2ae8956006967472c2bfe1077dc735b88a4b49f44f17c60ce2092cfa74bb14238e65c34c54e48",
        "string"
      ],
      [
        "dnskeyRdataHex",
        "DNSKEY RDATA octets",
        "Flags, protocol, algorithm and public-key bytes in exact wire order.",
        "0101030d\u2026",
        "string"
      ],
      [
        "keyTag",
        "Key tag",
        "16-bit key selector, not a unique key identifier; all matching candidates may need checking.",
        22775,
        "integer"
      ],
      [
        "lineage",
        "Key lineage",
        "Explicit fixed-generation relationship; it never substitutes for matching actual public-key bytes.",
        "child-ksk-g1",
        "string"
      ],
      [
        "purpose",
        "Explicit candidate variant",
        "Source-owned description of this public-key variant; eligibility is checked from actual flags and protocol, never inferred from this prose.",
        "protocol comparison",
        "string"
      ],
      [
        "text",
        "DNSKEY presentation",
        "Public DNSKEY RDATA presentation.",
        "257 3 13 <public-key-base64>",
        "string"
      ],
      [
        "revokedBit",
        "REVOKE observation",
        "Explicit observation of the revoke flag where supplied by the numeric fixture.",
        true,
        "boolean"
      ]
    ]
  },
  "rrsig": {
    "sourceGroups": [
      "S05",
      "S06",
      "S03",
      "S28"
    ],
    "origin": "Produced by the authoritative signer over fixed canonical RRset bytes and signature metadata.",
    "fields": [
      [
        "",
        "Complete rrsig record",
        "The exact complete concrete rrsig object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "Signature identity",
        "Stable identity of these exact RRSIG bytes.",
        "www-a-signature",
        "string"
      ],
      [
        "rrsetId",
        "Covered RRset reference",
        "Reference to the immutable covered RRset, not permission to overwrite covered data.",
        "www-a",
        "string"
      ],
      [
        "keyId",
        "Reference signer key identity",
        "Independent numeric signing-key reference. Runtime matching must still compare actual public bytes.",
        "child-zsk-g1",
        "string"
      ],
      [
        "typeCovered",
        "Type Covered",
        "Resource-record type protected by this signature.",
        1,
        "integer"
      ],
      [
        "algorithm",
        "RRSIG Algorithm",
        "Public-key signature algorithm; verification checks authenticity/integrity and is not decryption.",
        13,
        "integer"
      ],
      [
        "labels",
        "Labels",
        "Original owner label count, excluding the root and wildcard label; used to reconstruct wildcard signing owner.",
        3,
        "integer"
      ],
      [
        "originalTtl",
        "Original TTL",
        "Fixed signed TTL value; never changed to match a received TTL or lesson timeline.",
        3600,
        "integer"
      ],
      [
        "expiration",
        "Signature Expiration",
        "Fixed unsigned 32-bit serial-time endpoint; validity includes the endpoint under defined RFC1982 ordering.",
        1792717200,
        "integer"
      ],
      [
        "inception",
        "Signature Inception",
        "Fixed unsigned 32-bit serial-time start; validity includes the endpoint under defined RFC1982 ordering.",
        1792713000,
        "integer"
      ],
      [
        "keyTag",
        "RRSIG Key Tag",
        "Selector for candidate signing keys, not collision-free identity or successful verification.",
        46075,
        "integer"
      ],
      [
        "signer",
        "Signer Name",
        "Name of the signing zone; it is part of the signed metadata.",
        "lab.example.",
        "string"
      ],
      [
        "signatureHex",
        "Signature octets",
        "Exact public signature bytes; receipt, parsing and verification are separate actions.",
        "194d3ee6\u2026",
        "string"
      ],
      [
        "rrsigRdataHex",
        "RRSIG RDATA octets",
        "Exact RRSIG metadata followed by signature bytes.",
        "00010d03\u2026",
        "string"
      ],
      [
        "rrsigText",
        "RRSIG presentation",
        "Public RRSIG RDATA including the fixed calendar dates.",
        "A 13 3 3600 20261023010000 20261022235000 <key-tag> lab.example. <signature>",
        "string"
      ],
      [
        "signingInputHex",
        "Canonical signing input",
        "Exact reference RRSIG metadata excluding signature octets plus canonical RRset wire data.",
        "00010d03\u2026",
        "string"
      ],
      [
        "signingInputSha256",
        "Canonical input fingerprint",
        "Reference fingerprint for inspectable canonical input; not itself browser cryptographic verification.",
        "<reference SHA-256 hex>",
        "string"
      ],
      [
        "verificationAt",
        "Reference clock",
        "Independent numeric reference clock, separate from the runtime represented observation time.",
        1792713600,
        "integer"
      ]
    ]
  },
  "ds": {
    "sourceGroups": [
      "S05",
      "S16",
      "S18"
    ],
    "origin": "Parent-published delegation evidence.",
    "fields": [
      [
        "",
        "Complete ds record",
        "The exact complete concrete ds object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "Owner",
        "Delegated child zone name used in the DNSKEY digest input.",
        "lab.example.",
        "string"
      ],
      [
        "keyTag",
        "Key Tag",
        "Candidate DNSKEY selector; equal tags do not establish a digest match.",
        22775,
        "integer"
      ],
      [
        "algorithm",
        "Algorithm",
        "Referenced DNSKEY signing algorithm; distinct from Digest Type.",
        13,
        "integer"
      ],
      [
        "digestType",
        "Digest Type",
        "Hash algorithm over canonical owner plus DNSKEY RDATA; modern generation and legacy validation policy are separate.",
        2,
        "integer"
      ],
      [
        "digestHex",
        "Digest",
        "Exact public digest octets. A DS is not a signature and a CDS is not parent authorization.",
        "<fixed digest hex>",
        "string"
      ],
      [
        "digestInputHex",
        "Digest input",
        "Canonical owner wire name followed by exact DNSKEY RDATA.",
        "036c6162\u2026",
        "string"
      ],
      [
        "dsRdataHex",
        "DS-format RDATA",
        "Key tag, signing algorithm, digest type and digest octets in wire order.",
        "58f70d02\u2026",
        "string"
      ],
      [
        "text",
        "Presentation",
        "Public DS-format RDATA; CDS deletion is the corrected singleton 0 0 0 00.",
        "22775 13 2 <digest>",
        "string"
      ],
      [
        "keyId",
        "Referenced key identity",
        "Exact fixture reference, not a replacement for owner/algorithm/tag/digest comparison.",
        "child-ksk-g1",
        "string"
      ],
      [
        "policy",
        "Source digest profile",
        "Explicit numeric source profile label; runtime acceptance comes from the selected named operator policy, not this label.",
        "baseline",
        "string"
      ],
      [
        "id",
        "Digest record identity",
        "Stable identity of this public digest object.",
        "child-ksk-g1-sha256",
        "string"
      ]
    ]
  },
  "cds": {
    "sourceGroups": [
      "S19",
      "S20",
      "S21"
    ],
    "origin": "Child-published management intent; parent DS publication is a separate checked action.",
    "fields": [
      [
        "",
        "Complete cds record",
        "The exact complete concrete cds object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "Owner",
        "Delegated child zone name used in the DNSKEY digest input.",
        "lab.example.",
        "string"
      ],
      [
        "keyTag",
        "Key Tag",
        "Candidate DNSKEY selector; equal tags do not establish a digest match.",
        22775,
        "integer"
      ],
      [
        "algorithm",
        "Algorithm",
        "Referenced DNSKEY signing algorithm; distinct from Digest Type.",
        13,
        "integer"
      ],
      [
        "digestType",
        "Digest Type",
        "Hash algorithm over canonical owner plus DNSKEY RDATA; modern generation and legacy validation policy are separate.",
        2,
        "integer"
      ],
      [
        "digestHex",
        "Digest",
        "Exact public digest octets. A DS is not a signature and a CDS is not parent authorization.",
        "<fixed digest hex>",
        "string"
      ],
      [
        "digestInputHex",
        "Digest input",
        "Canonical owner wire name followed by exact DNSKEY RDATA.",
        "036c6162\u2026",
        "string"
      ],
      [
        "dsRdataHex",
        "DS-format RDATA",
        "Key tag, signing algorithm, digest type and digest octets in wire order.",
        "58f70d02\u2026",
        "string"
      ],
      [
        "text",
        "Presentation",
        "Public DS-format RDATA; CDS deletion is the corrected singleton 0 0 0 00.",
        "22775 13 2 <digest>",
        "string"
      ],
      [
        "keyId",
        "Referenced key identity",
        "Exact fixture reference, not a replacement for owner/algorithm/tag/digest comparison.",
        "child-ksk-g1",
        "string"
      ],
      [
        "id",
        "Digest record identity",
        "Stable identity of this public digest object.",
        "child-ksk-g1-sha256",
        "string"
      ]
    ]
  },
  "cdnskey": {
    "sourceGroups": [
      "S19",
      "S20",
      "S21"
    ],
    "origin": "Child-published public-key management signal, not an already published parent DS.",
    "fields": [
      [
        "",
        "Complete cdnskey record",
        "The exact complete concrete cdnskey object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "CDNSKEY owner",
        "Child zone publishing this signal.",
        "lab.example.",
        "string"
      ],
      [
        "flags",
        "Flags",
        "DNSKEY-format flags of the requested key.",
        257,
        "integer"
      ],
      [
        "protocol",
        "Protocol",
        "DNSKEY-format protocol value; corrected deletion sentinel still uses 3.",
        3,
        "integer"
      ],
      [
        "algorithm",
        "Algorithm",
        "Requested key\u2019s signing algorithm; zero is only part of the deletion sentinel.",
        13,
        "integer"
      ],
      [
        "publicKeyBase64",
        "Public Key",
        "Public key payload; corrected deletion sentinel has exactly one zero octet encoded AA==.",
        "AA==",
        "string"
      ],
      [
        "dnskeyRdataHex",
        "CDNSKEY RDATA octets",
        "DNSKEY-format bytes. Corrected deletion singleton is 0000030000.",
        "0000030000",
        "string"
      ]
    ]
  },
  "nsec": {
    "sourceGroups": [
      "S05",
      "S06",
      "S11",
      "S28"
    ],
    "origin": "Signed zone data used as part of a specific authenticated denial proof.",
    "fields": [
      [
        "",
        "Complete nsec record",
        "The exact complete concrete nsec object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "NSEC owner",
        "Existing owner at the start of the canonical-name interval.",
        "lab.example.",
        "string"
      ],
      [
        "nextName",
        "Next Domain Name",
        "Next name in canonical ordering; NSEC next-name case is not folded in signed RDATA.",
        "WWW.LAB.EXAMPLE.",
        "string"
      ],
      [
        "types",
        "Type bitmap",
        "Types present at the NSEC owner, not at every name in the interval.",
        [
          "NS",
          "SOA",
          "RRSIG",
          "NSEC",
          "DNSKEY"
        ],
        "array"
      ],
      [
        "bitmapHex",
        "Type bitmap wire octets",
        "Exact encoded type bitmap. TYPE128/NXNAME has RFC9824 query-scoped semantics.",
        "000722000000000380",
        "string"
      ],
      [
        "proofRole",
        "Selected proof role",
        "Explicit selected proof role such as closest-encloser or next-closer; never inferred from narration.",
        "next-closer",
        "string"
      ]
    ]
  },
  "nsec3": {
    "sourceGroups": [
      "S07",
      "S08",
      "S10"
    ],
    "origin": "Public hashed denial data or independently computed name-hash input, not encrypted names.",
    "fields": [
      [
        "",
        "Complete nsec3 record",
        "The exact complete concrete nsec3 object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "NSEC3 material identity",
        "Exact name/parameter hash-vector or proof object identity.",
        "lab.example.:i0:saltempty",
        "string"
      ],
      [
        "owner",
        "Input name / record owner",
        "Exact input owner in a hash vector, or explicit record owner in a decoded record; hash identity never substitutes for a name binding.",
        "lab.example.",
        "string"
      ],
      [
        "hashAlgorithm",
        "Hash Algorithm",
        "NSEC3 hash algorithm 1 is SHA-1, a role separate from DS digest or RRSIG signing algorithms.",
        1,
        "integer"
      ],
      [
        "flags",
        "Flags",
        "Opt-Out bit applies to the covered interval and has limited insecure-delegation semantics.",
        0,
        "integer"
      ],
      [
        "iterations",
        "Iterations",
        "Number of additional hashes after the initial hash; zero still hashes once.",
        0,
        "integer"
      ],
      [
        "saltHex",
        "Salt",
        "Exact salt octets; modern operational profile uses the empty salt.",
        "",
        "string"
      ],
      [
        "hashBase32hex",
        "Computed owner hash",
        "Exact independently computed Base32hex name hash, not evidence of authentication by itself.",
        "04VB0R8R70OH5TL9A2UHNPG063F7BEP5",
        "string"
      ],
      [
        "nextHash",
        "Next Hashed Owner Name",
        "Next hash in the matching parameter ring.",
        "63QA5GUBMD1FR1RBM0IB74SP2B7KN3MP",
        "string"
      ],
      [
        "types",
        "Type bitmap",
        "Types at the original owner corresponding to this exact matching hash.",
        [
          "NS",
          "SOA",
          "DNSKEY",
          "RRSIG"
        ],
        "array"
      ],
      [
        "optOut",
        "Opt-Out observation",
        "Explicit observed flag meaning; does not prove arbitrary names nonexistent.",
        false,
        "boolean"
      ],
      [
        "totalHashApplications",
        "Hash application count",
        "One initial hash plus the configured additional iterations.",
        1,
        "integer"
      ],
      [
        "profile",
        "Hash parameter profile",
        "Explicit source variant label; nondefault comparison vectors do not silently change modern policy.",
        "comparison-only nondefault parameters",
        "string"
      ]
    ]
  },
  "nsec3param": {
    "sourceGroups": [
      "S07",
      "S08"
    ],
    "origin": "Authority-side chain-generation parameters; validators read proof-record parameters.",
    "fields": [
      [
        "",
        "Complete nsec3param record",
        "The exact complete concrete nsec3param object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "hashAlgorithm",
        "Hash Algorithm",
        "Authority\u2019s NSEC3 chain hash algorithm.",
        1,
        "integer"
      ],
      [
        "flags",
        "Flags",
        "NSEC3PARAM flags; not an NSEC3 proof Opt-Out assertion.",
        0,
        "integer"
      ],
      [
        "iterations",
        "Iterations",
        "Additional chain-generation hashes; modern profile is zero.",
        0,
        "integer"
      ],
      [
        "saltHex",
        "Salt",
        "Authority\u2019s exact chain-generation salt; modern profile is empty.",
        "",
        "string"
      ]
    ]
  },
  "soa": {
    "sourceGroups": [
      "S22",
      "S09"
    ],
    "origin": "Zone authority metadata; signed SOA may constrain authenticated negative caching.",
    "fields": [
      [
        "",
        "Complete soa record",
        "The exact complete concrete soa object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "mname",
        "MNAME",
        "Primary name server for this zone.",
        "ns1.lab.example.",
        "string"
      ],
      [
        "rname",
        "RNAME",
        "DNS-encoded responsible mailbox name.",
        "hostmaster.lab.example.",
        "string"
      ],
      [
        "serial",
        "Serial",
        "Zone version number under DNS serial arithmetic.",
        2026102301,
        "integer"
      ],
      [
        "refresh",
        "Refresh",
        "Secondary refresh interval; not a signature lifetime.",
        3600,
        "integer"
      ],
      [
        "retry",
        "Retry",
        "Secondary retry interval.",
        600,
        "integer"
      ],
      [
        "expire",
        "Expire",
        "Secondary zone expiry interval; distinct from RRSIG expiration.",
        86400,
        "integer"
      ],
      [
        "minimum",
        "MINIMUM",
        "Negative-cache lifetime input, constrained by SOA TTL and authenticated proof lifetimes.",
        300,
        "integer"
      ]
    ]
  },
  "ns": {
    "sourceGroups": [
      "S22",
      "S06"
    ],
    "origin": "Published as authoritative zone data or parent delegation data with different trust roles.",
    "fields": [
      [
        "",
        "Complete ns record",
        "The exact complete concrete ns object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "NS owner",
        "Zone or delegation owner name.",
        "lab.example.",
        "string"
      ],
      [
        "target",
        "Name server",
        "Server DNS name, not an address or key.",
        "ns1.lab.example.",
        "string"
      ],
      [
        "role",
        "NS role",
        "Explicit apex-authoritative versus parent-delegation role; unsigned referral NS is not a signed child denial.",
        "parent-delegation",
        "string"
      ]
    ]
  },
  "glue": {
    "sourceGroups": [
      "S22",
      "S06"
    ],
    "origin": "Parent-provided address hints needed to reach an in-bailiwick name server.",
    "fields": [
      [
        "",
        "Complete glue record",
        "The exact complete concrete glue object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "Glue owner",
        "Name-server name to which this reachability hint applies.",
        "ns1.lab.example.",
        "string"
      ],
      [
        "type",
        "Address type",
        "A or AAAA record type of the hint.",
        "A",
        "string"
      ],
      [
        "address",
        "Glue address",
        "Reachability hint, not independently authenticated final application data.",
        "192.0.2.53",
        "string"
      ],
      [
        "bailiwick",
        "Bailiwick",
        "Explicit referral context bounding admissible address hints.",
        "lab.example.",
        "string"
      ]
    ]
  },
  "cname": {
    "sourceGroups": [
      "S22",
      "S26",
      "S06"
    ],
    "origin": "Published alias RRset, or explicitly identified synthesized DNAME result.",
    "fields": [
      [
        "",
        "Complete cname record",
        "The exact complete concrete cname object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "Alias owner",
        "Exact alias queried at this hop.",
        "www.lab.example.",
        "string"
      ],
      [
        "target",
        "Canonical target",
        "Target requires its own relevant chain/proof validation, possibly in another zone.",
        "www.other.example.",
        "string"
      ],
      [
        "synthesized",
        "Synthesized CNAME marker",
        "Explicitly identifies an unsigned CNAME derived from an authenticated DNAME, not a fabricated standalone signature.",
        false,
        "boolean"
      ]
    ]
  },
  "dname": {
    "sourceGroups": [
      "S26"
    ],
    "origin": "Published ancestor-name substitution RRset.",
    "fields": [
      [
        "",
        "Complete dname record",
        "The exact complete concrete dname object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "DNAME owner",
        "The ancestor subtree owner; the owner itself is not redirected by this DNAME.",
        "branch.lab.example.",
        "string"
      ],
      [
        "target",
        "DNAME target",
        "Substitution target for descendants; target data still needs appropriate validation.",
        "other.example.",
        "string"
      ],
      [
        "query",
        "Selected descendant name",
        "Exact descendant query used in name substitution.",
        "host.branch.lab.example.",
        "string"
      ],
      [
        "synthesizedName",
        "Substituted name",
        "Concrete derived target, separate from the signed DNAME record.",
        "host.other.example.",
        "string"
      ]
    ]
  },
  "trust": {
    "sourceGroups": [
      "S01",
      "S03",
      "S06",
      "S14",
      "S16",
      "S18"
    ],
    "origin": "Local validator configuration and computed selected-path state; not raw network assertions.",
    "fields": [
      [
        "",
        "Complete trust record",
        "The exact complete concrete trust object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "zone",
        "Trust-point zone",
        "Configured zone at which the selected trust path starts.",
        ".",
        "string"
      ],
      [
        "keys",
        "Anchor keys",
        "Exact locally provisioned public DNSKEY objects, not keys trusted merely on receipt.",
        [],
        "array"
      ],
      [
        "provenance",
        "Anchor provenance",
        "Explicit provisioning or authenticated management origin of the trust point.",
        "explicit operator provisioning",
        "string"
      ],
      [
        "securityStatus",
        "Security status",
        "Secure, insecure, bogus or indeterminate for the selected evidence and policy; absent data is a separate transport/notchecked state.",
        "indeterminate",
        "string"
      ],
      [
        "reasonCode",
        "Trust reason",
        "Computed machine reason from concrete checks, not a lesson-oracle outcome.",
        "no-anchor",
        "string"
      ],
      [
        "signatureChecked",
        "Signature checked",
        "Records an actual local signature-check action, not successful transfer.",
        false,
        "boolean"
      ],
      [
        "chainEstablished",
        "Chain established",
        "Whether the selected configured-anchor-to-answer path was established.",
        false,
        "boolean"
      ],
      [
        "verificationKind",
        "Verification kind",
        "Separates a local check from a remote resolver assertion.",
        "local-check",
        "string"
      ],
      [
        "evidenceMode",
        "Evidence mode",
        "Browser math is symbolic and exact-reference-bound, not browser public-key cryptographic verification.",
        "symbolic-reference-bound",
        "string"
      ],
      [
        "selectedEvidence",
        "Selected evidence",
        "Exact object identities/bytes used by the successful or failed selected path.",
        [],
        "array"
      ],
      [
        "checks",
        "Path checks",
        "Computed validation evidence with each local responsibility explicit.",
        [],
        "array"
      ],
      [
        "policyId",
        "Policy profile identity",
        "Explicit named operator policy; registry capability and operator acceptance are distinct.",
        "modern",
        "string"
      ],
      [
        "now",
        "Represented validation clock",
        "Concrete represented time used for serial signature validity.",
        1792713600,
        "integer"
      ],
      [
        "anchorState",
        "Managed-anchor state",
        "Explicit RFC5011 observation/hold-down/revocation state, separate from ordinary cached DNSKEY receipt.",
        "pending-add",
        "string"
      ]
    ]
  },
  "cache": {
    "sourceGroups": [
      "S06",
      "S09",
      "S10",
      "S12"
    ],
    "origin": "Resolver-local stored accepted data/proof state; receiving bytes alone does not populate a validated cache.",
    "fields": [
      [
        "",
        "Complete cache record",
        "The exact complete concrete cache object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "Cache identity",
        "Identity of this exact stored representation/generation, separate from published zone objects.",
        "cache:www-a:g1",
        "string"
      ],
      [
        "rrsetId",
        "Cached RRset reference",
        "Exact RRset whose accepted representation is stored.",
        "www-a",
        "string"
      ],
      [
        "signatureIds",
        "Cached signature references",
        "Exact selected accompanying signature identities.",
        [
          "www-a-signature"
        ],
        "array"
      ],
      [
        "securityStatus",
        "Cached security status",
        "Trust status established at acceptance under the selected path/policy.",
        "secure",
        "string"
      ],
      [
        "receivedTtl",
        "Received TTL limit",
        "Received RRset lifetime before elapsed represented time.",
        3600,
        "integer"
      ],
      [
        "rrsigTtl",
        "RRSIG TTL limit",
        "Received RRSIG record lifetime, independently limiting cache use.",
        3600,
        "integer"
      ],
      [
        "originalTtl",
        "Original TTL limit",
        "Signed Original TTL bound, not rewritten on receipt.",
        3600,
        "integer"
      ],
      [
        "signatureExpiration",
        "Signature expiration limit",
        "Absolute signature-validity endpoint also caps useful cache life.",
        1792717200,
        "integer"
      ],
      [
        "receivedAt",
        "Received at",
        "Represented time at receipt/acceptance used to account for elapsed lifetime.",
        1792713600,
        "integer"
      ],
      [
        "expiresAt",
        "Effective cache expiry",
        "Computed minimum of remaining RRset TTL, RRSIG TTL, Original TTL and signature lifetime.",
        1792717200,
        "integer"
      ],
      [
        "remainingSeconds",
        "Remaining cache life",
        "Computed nonnegative useful lifetime at the represented clock.",
        3600,
        "integer"
      ],
      [
        "negative",
        "Negative cache marker",
        "Explicit negative result/proof cache entry, not a fabricated positive RRset.",
        false,
        "boolean"
      ],
      [
        "soaMinimum",
        "SOA MINIMUM cap",
        "Authenticated negative caching input where applicable.",
        300,
        "integer"
      ],
      [
        "provenance",
        "Cache provenance",
        "Exact accepted path and generation origin; unrelated entries persist through another path\u2019s failure.",
        {},
        "object"
      ]
    ]
  },
  "publication": {
    "sourceGroups": [
      "S13",
      "S14",
      "S15",
      "S19",
      "S20",
      "S21"
    ],
    "origin": "Explicit signer/operator/parent management configuration and observations, separate from resolver validation.",
    "fields": [
      [
        "",
        "Complete publication record",
        "The exact complete concrete publication object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "Publication identity",
        "Identity of the exact publication generation or management transaction.",
        "lab.example.:generation-1",
        "string"
      ],
      [
        "zone",
        "Published zone",
        "Zone controlled by the selected authority.",
        "lab.example.",
        "string"
      ],
      [
        "generation",
        "Generation",
        "Exact published generation; old cached generations may coexist.",
        1,
        "integer"
      ],
      [
        "serial",
        "Zone serial",
        "Concrete SOA serial for this generation.",
        2026102301,
        "integer"
      ],
      [
        "rrsetIds",
        "Published RRsets",
        "Exact immutable RRset identities in this generation.",
        [],
        "array"
      ],
      [
        "signatureIds",
        "Published RRSIGs",
        "Exact fixed signatures attached only to their covered data.",
        [],
        "array"
      ],
      [
        "keyIds",
        "Published DNSKEY members",
        "Exact DNSKEY membership, not an approximate rollover keyset.",
        [
          "child-ksk-g1",
          "child-zsk-g1"
        ],
        "array"
      ],
      [
        "keyRole",
        "Signer key role",
        "Explicit KSK/ZSK/CSK operational use; SEP alone does not confer cryptographic trust.",
        "KSK",
        "string"
      ],
      [
        "keyState",
        "Signer key state",
        "Explicit generated/published/active/retired state; private capability stays signer-only.",
        "active",
        "string"
      ],
      [
        "signingAlgorithm",
        "Signing policy algorithm",
        "Selected signature-generation algorithm, separate from validator implementation capability.",
        13,
        "integer"
      ],
      [
        "dsDigestType",
        "New delegation digest policy",
        "Selected DS-generation digest type, not NSEC3 hashing or legacy validation policy.",
        2,
        "integer"
      ],
      [
        "parentDsIds",
        "Parent-published DS identities",
        "Parent publication is its own checked action, not implied by child CDS/CDNSKEY receipt.",
        [
          "child-ksk-g1-sha256"
        ],
        "array"
      ],
      [
        "signalRrsetIds",
        "Child intent signals",
        "Exact CDS/CDNSKEY/CSYNC/DSYNC-related public signal identities; signals do not self-authorize.",
        [],
        "array"
      ],
      [
        "authenticated",
        "Management evidence authenticated",
        "Records the management evidence check independently from authorization or subsequent publication.",
        false,
        "boolean"
      ],
      [
        "authorized",
        "Management action authorized",
        "Explicit operator/parent authorization, not a signature-verification side effect.",
        false,
        "boolean"
      ],
      [
        "consistencyChecks",
        "Parent consistency checks",
        "Explicit digest/key-set, concurrent-signal and enrollment checks before acting.",
        [],
        "array"
      ],
      [
        "action",
        "Management action",
        "Requested or completed concrete management operation; discovery/NOTIFY alone is only a trigger.",
        "publish-parent-ds",
        "string"
      ],
      [
        "provenance",
        "Publication provenance",
        "Explicit management source and custody of the generation.",
        {},
        "object"
      ]
    ]
  },
  "dsync": {
    "sourceGroups": [
      "S29",
      "S19",
      "S20"
    ],
    "origin": "Authenticated discovery metadata used to trigger an existing checked management workflow.",
    "fields": [
      [
        "",
        "Complete dsync record",
        "The exact complete concrete dsync object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "owner",
        "DSYNC owner",
        "Discovery owner associated with the parent coordination service.",
        "_dsync.example.",
        "string"
      ],
      [
        "type",
        "RRtype",
        "Type of child data to which the discovery endpoint applies.",
        "CDS",
        "string"
      ],
      [
        "scheme",
        "Scheme",
        "DSYNC notification scheme, separate from DS Digest Type.",
        1,
        "integer"
      ],
      [
        "port",
        "Port",
        "Notification destination port from this discovery record.",
        5359,
        "integer"
      ],
      [
        "target",
        "Target",
        "Name of the notification destination; discovery is not authorization.",
        "notify.example.",
        "string"
      ]
    ]
  },
  "csync": {
    "sourceGroups": [
      "S21"
    ],
    "origin": "Signed child request to synchronize eligible NS/address data; never a DS-change authorization.",
    "fields": [
      [
        "",
        "Complete csync record",
        "The exact complete concrete csync object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "serial",
        "SOA Serial",
        "Child serial used when the serial-arithmetic processing flag applies.",
        2026102301,
        "integer"
      ],
      [
        "flags",
        "Flags",
        "Immediate and SOA-minimum processing controls do not bypass validation or parent policy.",
        3,
        "integer"
      ],
      [
        "types",
        "Type bitmap",
        "Eligible requested record types, not arbitrary parent data.",
        [
          "A",
          "NS",
          "AAAA"
        ],
        "array"
      ],
      [
        "bitmapHex",
        "Type bitmap octets",
        "Exact encoded requested type set.",
        "000440000008",
        "string"
      ]
    ]
  },
  "tsig": {
    "sourceGroups": [
      "S25"
    ],
    "origin": "Transaction authentication between explicitly configured peers; no DNSSEC answer trust or confidentiality is implied.",
    "fields": [
      [
        "",
        "Complete tsig record",
        "The exact complete concrete tsig object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "TSIG reference identity",
        "Identity of this fixed authenticated transaction.",
        "operator-primary-update-hmac-sha256",
        "string"
      ],
      [
        "keyName",
        "TSIG key name",
        "Public identifier of the separately configured shared MAC key.",
        "operator-primary.lab.example.",
        "string"
      ],
      [
        "algorithm",
        "MAC algorithm",
        "Transaction HMAC algorithm name, not a DNSKEY Algorithm number.",
        "hmac-sha256.",
        "string"
      ],
      [
        "timeSigned",
        "Time Signed",
        "48-bit transaction signing time; distinct from RRSIG serial-time dates.",
        1792713600,
        "integer"
      ],
      [
        "fudge",
        "Fudge",
        "Allowed transaction time difference.",
        300,
        "integer"
      ],
      [
        "macHex",
        "MAC",
        "Public message authentication code; shared key bytes are not application material.",
        "045120f3\u2026",
        "string"
      ],
      [
        "messageId",
        "Original ID",
        "Original DNS message ID bound by TSIG.",
        4660,
        "integer"
      ],
      [
        "error",
        "TSIG error",
        "Transaction authentication error, separate from DNS RCODE and DNSSEC security status.",
        0,
        "integer"
      ],
      [
        "otherDataHex",
        "Other Data",
        "Exact optional TSIG error-related data.",
        "",
        "string"
      ],
      [
        "macInputHex",
        "MAC input",
        "Exact transaction MAC input octets; not a DNSSEC canonical RRset input.",
        "12342800\u2026",
        "string"
      ],
      [
        "tsigRdataHex",
        "TSIG RDATA",
        "Exact public TSIG wire fields.",
        "0b686d6163\u2026",
        "string"
      ],
      [
        "authenticatedUpdateWireHex",
        "Authenticated UPDATE wire",
        "Exact DNS UPDATE message including its public TSIG record.",
        "12342800\u2026",
        "string"
      ],
      [
        "unsignedUpdateWireHex",
        "Unsigned UPDATE wire",
        "Exact DNS UPDATE representation before TSIG insertion.",
        "12342800\u2026",
        "string"
      ],
      [
        "custodians",
        "Configured peer custodians",
        "Identifies the two configured MAC peers without exposing their shared key.",
        [
          "dnsOperator",
          "dnsPrimary"
        ],
        "array"
      ]
    ]
  },
  "zonemd": {
    "sourceGroups": [
      "S25"
    ],
    "origin": "Whole-zone digest descriptor; authenticated origin requires separately validated expected ZONEMD data.",
    "fields": [
      [
        "",
        "Complete zonemd record",
        "The exact complete concrete zonemd object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "ZONEMD reference identity",
        "Identity of this exact whole-zone digest input/descriptor.",
        "child-zone-authenticated-simple-sha384",
        "string"
      ],
      [
        "owner",
        "ZONEMD owner",
        "Zone apex publishing the digest.",
        "lab.example.",
        "string"
      ],
      [
        "serial",
        "Serial",
        "SOA serial to which this zone digest applies.",
        2026102301,
        "integer"
      ],
      [
        "scheme",
        "Scheme",
        "Zone digest scheme; SIMPLE has precisely defined exclusions.",
        1,
        "integer"
      ],
      [
        "hashAlgorithm",
        "Hash Algorithm",
        "ZONEMD hash algorithm ID; 1 means SHA-384 here, not NSEC3 SHA-1.",
        1,
        "integer"
      ],
      [
        "digestHex",
        "Digest",
        "Whole-zone digest octets; a checksum without authenticated expected value does not establish origin.",
        "eefaa904\u2026",
        "string"
      ],
      [
        "zoneText",
        "Zone input",
        "Exact public zone presentation used for the independent whole-zone digest fixture.",
        "lab.example. 3600 IN SOA \u2026",
        "string"
      ],
      [
        "expectedDigestRrsetId",
        "Expected digest RRset reference",
        "Exact public ZONEMD RRset whose independently authenticated value is compared.",
        "child-zonemd-auth",
        "string"
      ],
      [
        "expectedDigestSignatureId",
        "Expected digest signature reference",
        "Signature protecting the expected ZONEMD RRset, not the whole zone transfer.",
        "child-zonemd-auth-signature",
        "string"
      ],
      [
        "soaRrsetId",
        "SOA RRset reference",
        "Exact SOA defining the selected serial.",
        "child-soa",
        "string"
      ],
      [
        "soaSignatureId",
        "SOA signature reference",
        "Signature of the selected SOA RRset.",
        "child-soa-signature",
        "string"
      ]
    ]
  },
  "event": {
    "sourceGroups": [
      "S01",
      "S06",
      "S13"
    ],
    "origin": "Source-owned local observation/action record; never an extra stored body artifact.",
    "fields": [
      [
        "",
        "Complete event record",
        "The exact complete concrete event object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "id",
        "Observation identity",
        "Unique local observation occurrence, not a network message or held-body identity.",
        "dnssec-observation-1",
        "string"
      ],
      [
        "action",
        "Observed action",
        "Explicit source-owned action; prose is not parsed to create operations.",
        "check-signature",
        "string"
      ],
      [
        "actorId",
        "Responsible actor",
        "The actor performing this observation/check; validator may be an in-process resolver responsibility.",
        "dnsResolver",
        "string"
      ],
      [
        "objectIds",
        "Observed object identities",
        "Exact existing representations inspected or used, without re-creating them.",
        [
          "www-a",
          "www-a-signature"
        ],
        "array"
      ],
      [
        "now",
        "Observation clock",
        "Concrete represented clock of the local action.",
        1792713600,
        "integer"
      ],
      [
        "result",
        "Observation result",
        "Computed local observation data, not an independent worksheet outcome copied into runtime.",
        {},
        "object"
      ],
      [
        "reasonCode",
        "Observation reason",
        "Explicit result code generated by the selected domain operation.",
        "signature-valid",
        "string"
      ],
      [
        "evidenceRefs",
        "Evidence references",
        "Exact fixed-material/report references used by this observation.",
        [],
        "array"
      ],
      [
        "verificationKind",
        "Check responsibility",
        "Local check versus remote assertion; neither receipt nor parsing is validation.",
        "local-check",
        "string"
      ],
      [
        "evidenceMode",
        "Evidence mode",
        "Exact-reference-bound symbolic browser evidence, not browser cryptography.",
        "symbolic-reference-bound",
        "string"
      ]
    ]
  },
  "secret": {
    "sourceGroups": [
      "S13",
      "S05"
    ],
    "origin": "Signer-only opaque capability tied to one fixed public-key identity; no scalar, PEM or secret bytes are exposed.",
    "fields": [
      [
        "",
        "Complete secret record",
        "The exact complete concrete secret object. All bytes and properties remain inspectable; an event is an observation only and a secret record contains only an opaque signer handle.",
        {},
        "object"
      ],
      [
        "handle",
        "Opaque signer handle",
        "Symbolic HSM/key-service handle usable only by its configured signer custodian.",
        "hsm:dnsSigner:child-ksk-g1",
        "string"
      ],
      [
        "keyId",
        "Bound public-key identity",
        "The exact public DNSKEY identity corresponding to this opaque signing capability.",
        "child-ksk-g1",
        "string"
      ],
      [
        "custodian",
        "Signer custodian",
        "Explicit signer-only capability holder; resolvers and public DNS recipients never receive it.",
        "dnsSigner",
        "string"
      ],
      [
        "capability",
        "Allowed capability",
        "Signing capability, not public-key verification or decryption.",
        "sign",
        "string"
      ]
    ]
  }
};

const dnssecFieldAttributes = Object.create(null);
const dnssecFieldIds = Object.create(null);
const dnssecFieldSourceGroups = Object.create(null);
for (const source of DNSSEC_SOURCES) {
  if (!Object.hasOwn(dnssecFieldSourceGroups, source.groupId)) dnssecFieldSourceGroups[source.groupId] = [];
  dnssecFieldSourceGroups[source.groupId].push(source);
}
for (const [kind, spec] of Object.entries(dnssecFieldSpecs)) {
  const ids = [];
  const sources = spec.sourceGroups.flatMap(groupId => {
    if (!Object.hasOwn(dnssecFieldSourceGroups, groupId)) throw new RangeError('Unknown DNSSEC source group ' + groupId);
    return dnssecFieldSourceGroups[groupId];
  });
  for (const [path, name, meaning, example, dataType] of spec.fields) {
    const id = 'dnssec_' + kind + '_' + (path ? path.replaceAll('.', '_') : 'record');
    if (Object.hasOwn(dnssecFieldAttributes, id)) throw new RangeError('Duplicate DNSSEC field ' + id);
    const purpose = kind === 'secret'
      ? 'Inspect the signer-only opaque capability and its fixed public-key binding, never private input bytes.'
      : kind === 'event'
        ? 'Inspect the exact source-owned observation without creating or transferring a stored body artifact.'
        : 'Inspect this exact declared property of the concrete ' + kind + ' object. Public readability is not trust; signature verification is not decryption.';
    dnssecFieldAttributes[id] = {
      ...labAttribute(name, meaning, spec.origin, purpose, example, sources.map(source => source.standard).join('; '), sources[0].url),
      dnssecKind: kind,
      dnssecPath: path,
      dataType,
      sourceGroups: spec.sourceGroups,
      sources: sources.map(source => source.url),
      researchCutoff: '2026-10-23'
    };
    ids.push(id);
  }
  dnssecFieldIds[kind] = ids;
}

export const DNSSEC_ATTRIBUTES = dnssecFieldFreeze(dnssecFieldAttributes);
dnssecFieldFreeze(dnssecFieldIds);

export function dnssecFields(kind) {
  if (typeof kind !== 'string' || !Object.hasOwn(dnssecFieldIds, kind)) {
    throw new RangeError('Unknown DNSSEC field kind ' + String(kind));
  }
  return dnssecFieldIds[kind];
}
