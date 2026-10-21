import {labAttribute,labP,labStep,labScenario} from './lab-common.js';

export const SPAKELAB_SOURCES = [
 {name:'Kerberos SPAKE',standard:'RFC 9588',section:'3-8,10.4-10.5,Appendix C',url:'https://www.rfc-editor.org/rfc/rfc9588.html',revision:'August 2024',retrieved:'2026-10-21',errata:'RFC Editor search checked 2026-10-21: no matching errata'},
 {name:'MIT SPAKE administration',standard:'MIT Kerberos',section:'SPAKE Preauthentication',url:'https://web.mit.edu/kerberos/krb5-latest/doc/admin/spake.html',revision:'1.22.2',retrieved:'2026-10-21',errata:'Implementation documentation'},
 {name:'Kerberos exchanges',standard:'RFC 4120',section:'3.1-3.3',url:'https://www.rfc-editor.org/rfc/rfc4120.html',revision:'July 2005',retrieved:'2026-10-21',errata:'Published exchange baseline'}
];
const kspObjects = [
  {
    "key": "password",
    "label": "Client password",
    "creator": "spake-client",
    "created": null,
    "fields": [
      {
        "id": "kspPasswordPassword",
        "name": "password",
        "value": "synthetic password: correct horse (illustrative only)"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "kdc-record",
    "label": "Provisioned principal key",
    "creator": "spake-kdc",
    "created": null,
    "fields": [
      {
        "id": "kspKdcRecordPrincipal",
        "name": "principal",
        "value": "alice@SPAKE.EXAMPLE"
      },
      {
        "id": "kspKdcRecordEnctype",
        "name": "enctype",
        "value": 17
      },
      {
        "id": "kspKdcRecordKey",
        "name": "key",
        "value": "symbolic provisioned AES128 principal key"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "realm-key",
    "label": "Realm TGT encryption key",
    "creator": "spake-tgs",
    "created": null,
    "initialHolders": ["spake-kdc","spake-tgs"],
    "fields": [
      {
        "id": "kspRealmKeyPrincipal",
        "name": "principal",
        "value": "krbtgt/SPAKE.EXAMPLE@SPAKE.EXAMPLE"
      },
      {
        "id": "kspRealmKeyKey",
        "name": "key",
        "value": "symbolic realm TGT key"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc",
          "spake-tgs"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "service-key",
    "label": "Service long-term key",
    "creator": "spake-service",
    "created": null,
    "initialHolders": ["spake-tgs","spake-service"],
    "fields": [
      {
        "id": "kspServiceKeyPrincipal",
        "name": "principal",
        "value": "HTTP/app.spake.example@SPAKE.EXAMPLE"
      },
      {
        "id": "kspServiceKeyKey",
        "name": "key",
        "value": "symbolic service long-term key"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-tgs",
          "spake-service"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "unrelated",
    "label": "Unrelated cached credential",
    "creator": "spake-client",
    "created": null,
    "fields": [
      {
        "id": "kspUnrelatedService",
        "name": "service",
        "value": "unrelated/service@OTHER.EXAMPLE"
      },
      {
        "id": "kspUnrelatedCredential",
        "name": "credential",
        "value": "preexisting unrelated credential"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "request",
    "label": "AS request body",
    "creator": "spake-client",
    "created": "request",
    "fields": [
      {
        "id": "kspRequestClient",
        "name": "client",
        "value": "alice@SPAKE.EXAMPLE"
      },
      {
        "id": "kspRequestServer",
        "name": "server",
        "value": "krbtgt/SPAKE.EXAMPLE"
      },
      {
        "id": "kspRequestNonce",
        "name": "nonce",
        "value": 741001
      },
      {
        "id": "kspRequestEnctypes",
        "name": "enctypes",
        "value": [
          17
        ]
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-client",
          "spake-kdc"
        ]
      }
    ],
    "protection": "plaintext Kerberos request",
    "keyRef": null
  },
  {
    "key": "advertisement",
    "label": "Preauthentication advertisement",
    "creator": "spake-kdc",
    "created": "advertisement",
    "fields": [
      {
        "id": "kspAdvertisementError",
        "name": "error",
        "value": "KDC_ERR_PREAUTH_REQUIRED"
      },
      {
        "id": "kspAdvertisementPadataType",
        "name": "padata-type",
        "value": 151
      },
      {
        "id": "kspAdvertisementPadataValue",
        "name": "padata-value",
        "value": "empty"
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-kdc",
          "spake-client"
        ]
      }
    ],
    "protection": "unauthenticated METHOD-DATA",
    "keyRef": null
  },
  {
    "key": "etype",
    "label": "ETYPE-INFO2",
    "creator": "spake-kdc",
    "created": "advertisement",
    "fields": [
      {
        "id": "kspEtypeEnctype",
        "name": "enctype",
        "value": 17
      },
      {
        "id": "kspEtypeSalt",
        "name": "salt",
        "value": "SPAKE.EXAMPLEalice"
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-kdc",
          "spake-client"
        ]
      }
    ],
    "protection": "unauthenticated METHOD-DATA",
    "keyRef": null
  },
  {
    "key": "support",
    "label": "SPAKESupport",
    "creator": "spake-client",
    "created": "support",
    "fields": [
      {
        "id": "kspSupportGroups",
        "name": "groups",
        "value": [
          1
        ]
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-client",
          "spake-kdc"
        ]
      }
    ],
    "protection": "DER PA-SPAKE support",
    "keyRef": null
  },
  {
    "key": "x",
    "label": "KDC ephemeral scalar",
    "creator": "spake-kdc",
    "created": "kdc-challenge-create",
    "fields": [
      {
        "id": "kspXScalar",
        "name": "scalar",
        "value": "symbolic fresh x generation 0"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "challenge",
    "label": "SPAKEChallenge",
    "creator": "spake-kdc",
    "created": "kdc-challenge-create",
    "fields": [
      {
        "id": "kspChallengeGroup",
        "name": "group",
        "value": 1
      },
      {
        "id": "kspChallengePublicT",
        "name": "public-T",
        "value": "symbolic T=xP+wM generation 0"
      },
      {
        "id": "kspChallengeFactors",
        "name": "factors",
        "value": [
          "SF-NONE (1)"
        ]
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-kdc",
          "spake-client"
        ]
      }
    ],
    "protection": "DER PA-SPAKE challenge; initially unauthenticated",
    "keyRef": null
  },
  {
    "key": "cookie",
    "label": "KDC state cookie",
    "creator": "spake-kdc",
    "created": "kdc-challenge-create",
    "fields": [
      {
        "id": "kspCookieCookieBytes",
        "name": "cookie-bytes",
        "value": "symbolic authenticated encrypted cookie generation 0"
      },
      {
        "id": "kspCookieState",
        "name": "state",
        "value": "KDC-only x reference and transcript state generation 0"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-kdc","spake-client"],
        "fields": [
          "cookie-bytes"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-kdc"
        ],
        "fields": [
          "state"
        ]
      }
    ],
    "protection": "KDC-only authenticated state encryption",
    "keyRef": "cookie-key"
  },
  {
    "key": "cookie-key",
    "label": "KDC cookie encryption key",
    "creator": "spake-kdc",
    "created": null,
    "fields": [
      {
        "id": "kspCookieKeyKey",
        "name": "key",
        "value": "symbolic KDC cookie protection key"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "initial-key",
    "label": "Initial reply key",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspInitialKeyEnctype",
        "name": "enctype",
        "value": 17
      },
      {
        "id": "kspInitialKeyKey",
        "name": "key",
        "value": "symbolic initial AES128 key from password and salt"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "y",
    "label": "Client ephemeral scalar",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspYScalar",
        "name": "scalar",
        "value": "symbolic fresh y generation 0"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "client-shared",
    "label": "Client shared group element",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspClientSharedK",
        "name": "K",
        "value": "symbolic K=y(T-wM) generation 0"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "client-transcript",
    "label": "Client transcript hash",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspClientTranscriptHash",
        "name": "hash",
        "value": "symbolic H(H(zeros || DER support || DER challenge) || S), H=SHA-256"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "client-factor-key",
    "label": "Client factor protection key",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspClientFactorKeyKey",
        "name": "key",
        "value": "symbolic K-prime[1] bound to initial key, group1, transcript and KDC-REQ-BODY"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "client-reply-key",
    "label": "Client candidate strengthened key",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspClientReplyKeyKey",
        "name": "key",
        "value": "symbolic K-prime[0] bound to initial key, group1, transcript and KDC-REQ-BODY"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-client"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "response",
    "label": "SPAKEResponse",
    "creator": "spake-client",
    "created": "client-derive",
    "fields": [
      {
        "id": "kspResponsePublicS",
        "name": "public-S",
        "value": "symbolic S=yP+wN generation 0"
      },
      {
        "id": "kspResponseFactorCiphertext",
        "name": "factor-ciphertext",
        "value": "symbolic encryption of DER SF-NONE with K-prime[1], usage65"
      },
      {
        "id": "kspResponseFactorType",
        "name": "factor-type",
        "value": 1
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-client",
          "spake-kdc"
        ],
        "fields": [
          "public-S",
          "factor-ciphertext"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-client",
          "spake-kdc"
        ],
        "fields": [
          "factor-type"
        ]
      }
    ],
    "protection": "factor encrypted under K-prime[1], key usage 65",
    "keyRef": "client-factor-key"
  },
  {
    "key": "kdc-shared",
    "label": "KDC shared group element",
    "creator": "spake-kdc",
    "created": "kdc-validate",
    "fields": [
      {
        "id": "kspKdcSharedK",
        "name": "K",
        "value": "symbolic K=x(S-wN) generation 0"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "kdc-transcript",
    "label": "KDC transcript hash",
    "creator": "spake-kdc",
    "created": "kdc-validate",
    "fields": [
      {
        "id": "kspKdcTranscriptHash",
        "name": "hash",
        "value": "symbolic H(H(zeros || DER support || DER challenge) || S), H=SHA-256"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "kdc-factor-key",
    "label": "KDC factor protection key",
    "creator": "spake-kdc",
    "created": "kdc-validate",
    "fields": [
      {
        "id": "kspKdcFactorKeyKey",
        "name": "key",
        "value": "symbolic K-prime[1] bound to initial key, group1, transcript and KDC-REQ-BODY"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "kdc-reply-key",
    "label": "KDC strengthened reply key",
    "creator": "spake-kdc",
    "created": "as-create",
    "fields": [
      {
        "id": "kspKdcReplyKeyKey",
        "name": "key",
        "value": "symbolic K-prime[0] bound to initial key, group1, transcript and KDC-REQ-BODY"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "tgt-session",
    "label": "KDC-issued TGT session key",
    "creator": "spake-kdc",
    "created": "as-create",
    "fields": [
      {
        "id": "kspTgtSessionKey",
        "name": "key",
        "value": "symbolic K-client-tgs issued by KDC"
      },
      {
        "id": "kspTgtSessionEnctype",
        "name": "enctype",
        "value": 17
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-kdc",
          "spake-client",
          "spake-tgs"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "tgt",
    "label": "TGT",
    "creator": "spake-kdc",
    "created": "as-create",
    "fields": [
      {
        "id": "kspTgtTicketBytes",
        "name": "ticket-bytes",
        "value": "symbolic opaque TGT ciphertext"
      },
      {
        "id": "kspTgtClient",
        "name": "client",
        "value": "alice@SPAKE.EXAMPLE"
      },
      {
        "id": "kspTgtServer",
        "name": "server",
        "value": "krbtgt/SPAKE.EXAMPLE"
      },
      {
        "id": "kspTgtSessionKey",
        "name": "session-key",
        "value": "symbolic K-client-tgs issued by KDC"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-kdc","spake-client","spake-tgs"],
        "fields": [
          "ticket-bytes"
        ]
      },
      {
        "id": "decoded",
        "readers": ["spake-kdc","spake-tgs"],
        "fields": [
          "client",
          "server",
          "session-key"
        ]
      }
    ],
    "protection": "Ticket body encrypted with realm TGT key",
    "keyRef": "realm-key"
  },
  {
    "key": "as-material",
    "label": "AS reply client material",
    "creator": "spake-kdc",
    "created": "as-create",
    "fields": [
      {
        "id": "kspAsMaterialCiphertext",
        "name": "ciphertext",
        "value": "symbolic AS-REP encrypted client part"
      },
      {
        "id": "kspAsMaterialNonce",
        "name": "nonce",
        "value": 741001
      },
      {
        "id": "kspAsMaterialSessionKey",
        "name": "session-key",
        "value": "symbolic K-client-tgs issued by KDC"
      },
      {
        "id": "kspAsMaterialServer",
        "name": "server",
        "value": "krbtgt/SPAKE.EXAMPLE"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-kdc","spake-client"],
        "fields": [
          "ciphertext"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-kdc",
          "spake-client"
        ],
        "fields": [
          "nonce",
          "session-key",
          "server"
        ]
      }
    ],
    "protection": "AS client part encrypted with strengthened K-prime[0]",
    "keyRef": "kdc-reply-key"
  },
  {
    "key": "tgs-request",
    "label": "TGS authenticator and request",
    "creator": "spake-client",
    "created": "tgs-request",
    "fields": [
      {"id":"kspTgsRequestNonce","name":"nonce","value":741002},
      {
        "id": "kspTgsRequestService",
        "name": "service",
        "value": "HTTP/app.spake.example"
      },
      {
        "id": "kspTgsRequestAuthenticator",
        "name": "authenticator",
        "value": "symbolic timestamp and checksum encrypted under K-client-tgs"
      }
    ],
    "representations": [
      {
        "id": "wire",
        "readers": [
          "spake-client",
          "spake-tgs"
        ]
      }
    ],
    "protection": "Authenticator encrypted under TGT session key",
    "keyRef": "tgt-session"
  },
  {
    "key": "service-session",
    "label": "TGS-issued service session key",
    "creator": "spake-tgs",
    "created": "tgs-validate",
    "fields": [
      {
        "id": "kspServiceSessionKey",
        "name": "key",
        "value": "symbolic K-client-service issued by TGS"
      }
    ],
    "representations": [
      {
        "id": "local",
        "readers": [
          "spake-tgs",
          "spake-client",
          "spake-service"
        ]
      }
    ],
    "protection": "local only",
    "keyRef": null
  },
  {
    "key": "service-ticket",
    "label": "Service ticket",
    "creator": "spake-tgs",
    "created": "tgs-validate",
    "fields": [
      {
        "id": "kspServiceTicketTicketBytes",
        "name": "ticket-bytes",
        "value": "symbolic opaque service ticket ciphertext"
      },
      {
        "id": "kspServiceTicketClient",
        "name": "client",
        "value": "alice@SPAKE.EXAMPLE"
      },
      {
        "id": "kspServiceTicketSessionKey",
        "name": "session-key",
        "value": "symbolic K-client-service issued by TGS"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-tgs","spake-client","spake-service"],
        "fields": [
          "ticket-bytes"
        ]
      },
      {
        "id": "decoded",
        "readers": ["spake-tgs","spake-service"],
        "fields": [
          "client",
          "session-key"
        ]
      }
    ],
    "protection": "Ticket body encrypted under service long-term key",
    "keyRef": "service-key"
  },
  {
    "key": "tgs-material",
    "label": "TGS reply client material",
    "creator": "spake-tgs",
    "created": "tgs-validate",
    "fields": [
      {"id":"kspTgsMaterialNonce","name":"nonce","value":741002},
      {
        "id": "kspTgsMaterialCiphertext",
        "name": "ciphertext",
        "value": "symbolic TGS-REP encrypted part"
      },
      {
        "id": "kspTgsMaterialSessionKey",
        "name": "session-key",
        "value": "symbolic K-client-service issued by TGS"
      },
      {
        "id": "kspTgsMaterialService",
        "name": "service",
        "value": "HTTP/app.spake.example"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-tgs","spake-client"],
        "fields": [
          "ciphertext"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-tgs",
          "spake-client"
        ],
        "fields": [
          "nonce",
          "session-key",
          "service"
        ]
      }
    ],
    "protection": "Client part encrypted under TGT session key",
    "keyRef": "tgt-session"
  },
  {
    "key": "ap-request",
    "label": "AP authenticator",
    "creator": "spake-client",
    "created": "ap-request",
    "fields": [
      {
        "id": "kspApRequestCiphertext",
        "name": "ciphertext",
        "value": "symbolic AP authenticator timestamp 20261021T120000Z"
      },
      {
        "id": "kspApRequestTimestamp",
        "name": "timestamp",
        "value": "20261021T120000Z"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-client","spake-service"],
        "fields": [
          "ciphertext"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-client",
          "spake-service"
        ],
        "fields": [
          "timestamp"
        ]
      }
    ],
    "protection": "Authenticator encrypted under service session key",
    "keyRef": "service-session"
  },
  {
    "key": "ap-reply",
    "label": "Mutual authentication reply",
    "creator": "spake-service",
    "created": "ap-reply",
    "fields": [
      {
        "id": "kspApReplyCiphertext",
        "name": "ciphertext",
        "value": "symbolic AP-REP ciphertext"
      },
      {
        "id": "kspApReplyEchoTime",
        "name": "echo-time",
        "value": "20261021T120000Z"
      }
    ],
    "representations": [
      {
        "id": "opaque",
        "readers": ["spake-service","spake-client"],
        "fields": [
          "ciphertext"
        ]
      },
      {
        "id": "decoded",
        "readers": [
          "spake-service",
          "spake-client"
        ],
        "fields": [
          "echo-time"
        ]
      }
    ],
    "protection": "AP-REP encrypted under service session key",
    "keyRef": "service-session"
  }
];
const kspEvents = [
  {
    "suffix": "request",
    "title": "AS-REQ",
    "fromActor": "spake-client",
    "toActor": "spake-kdc",
    "detail": "Initial request has no preauthentication and no cached user TGT.",
    "uses": [
      {
        "key": "request",
        "representation": "wire"
      }
    ],
    "effects": []
  },
  {
    "suffix": "advertisement",
    "title": "PREAUTH_REQUIRED: empty PA-SPAKE",
    "fromActor": "spake-kdc",
    "toActor": "spake-client",
    "detail": "Advertisement is not a challenge. Singular ETYPE-INFO2 supplies enctype17 and salt.",
    "uses": [
      {
        "key": "advertisement",
        "representation": "wire"
      },
      {
        "key": "etype",
        "representation": "wire"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "negotiation.advertised",
        "value": true
      }
    ]
  },
  {
    "suffix": "support",
    "title": "AS-REQ: SPAKESupport",
    "fromActor": "spake-client",
    "toActor": "spake-kdc",
    "detail": "Client sends ordered group list [1].",
    "uses": [
      {
        "key": "support",
        "representation": "wire"
      }
    ],
    "effects": []
  },
  {
    "suffix": "kdc-challenge-create",
    "title": "KDC creates challenge",
    "fromActor": "spake-kdc",
    "toActor": "spake-kdc",
    "detail": "Fresh x and T=xP+wM. The opaque cookie protects KDC state; decoded state is KDC-only.",
    "uses": [
      {
        "key": "x",
        "representation": "local"
      },
      {
        "key": "challenge",
        "representation": "wire"
      },
      {
        "key": "cookie",
        "representation": "decoded"
      },
      {
        "key": "cookie",
        "representation": "opaque"
      }
    ],
    "effects": []
  },
  {
    "suffix": "challenge",
    "title": "MORE_PREAUTH_DATA_REQUIRED: SPAKEChallenge",
    "fromActor": "spake-kdc",
    "toActor": "spake-client",
    "detail": "Challenge receives group1, T and SF-NONE; neither endpoint is yet authenticated.",
    "uses": [
      {
        "key": "challenge",
        "representation": "wire"
      },
      {
        "key": "cookie",
        "representation": "opaque"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "challenge.received",
        "value": true
      }
    ]
  },
  {
    "suffix": "client-derive",
    "title": "Client derives response keys",
    "fromActor": "spake-client",
    "toActor": "spake-client",
    "detail": "Validate T is a group element, then derive initial key from password and ETYPE-INFO2, fresh y, S=yP+wN and K=y(T-wM). Transcript begins support and challenge, then S; derive K-prime[1] and candidate K-prime[0] binding KDC-REQ-BODY. SF-NONE has type1 and no data field.",
    "uses": [
      {
        "key": "initial-key",
        "representation": "local"
      },
      {
        "key": "y",
        "representation": "local"
      },
      {
        "key": "client-shared",
        "representation": "local"
      },
      {
        "key": "client-transcript",
        "representation": "local"
      },
      {
        "key": "client-factor-key",
        "representation": "local"
      },
      {
        "key": "client-reply-key",
        "representation": "local"
      },
      {
        "key": "response",
        "representation": "wire"
      },
      {
        "key": "response",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "client.keysDerived",
        "value": true
      }
    ]
  },
  {
    "suffix": "response",
    "title": "AS-REQ: SPAKEResponse",
    "fromActor": "spake-client",
    "toActor": "spake-kdc",
    "detail": "Public S and encrypted SF-NONE use K-prime[1] and KEY_USAGE_SPAKE 65. Echo opaque cookie; no private scalar is exposed.",
    "uses": [
      {
        "key": "response",
        "representation": "wire"
      },
      {
        "key": "cookie",
        "representation": "opaque"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "response.received",
        "value": true
      }
    ]
  },
  {
    "suffix": "kdc-validate",
    "title": "KDC validates response",
    "fromActor": "spake-kdc",
    "toActor": "spake-kdc",
    "detail": "Validate S is a group element. Compute K=x(S-wN), transcript and K-prime[1]; decrypt factor, validate SF-NONE type1 with omitted data and request binding. Receipt alone was not authentication.",
    "uses": [
      {
        "key": "kdc-shared",
        "representation": "local"
      },
      {
        "key": "kdc-transcript",
        "representation": "local"
      },
      {
        "key": "kdc-factor-key",
        "representation": "local"
      },
      {
        "key": "response",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "kdc.factorValidated",
        "value": true
      }
    ]
  },
  {
    "suffix": "as-create",
    "title": "KDC strengthens key and creates AS-REP",
    "fromActor": "spake-kdc",
    "toActor": "spake-kdc",
    "detail": "Only after successful validation replace reply key with K-prime[0]. KDC issues TGT session key. Ticket uses realm key, client material uses reply key. There is no final PA-SPAKE.",
    "uses": [
      {"key":"realm-key","representation":"local"},
      {"key":"tgt","representation":"decoded"},
      {
        "key": "kdc-reply-key",
        "representation": "local"
      },
      {
        "key": "tgt-session",
        "representation": "local"
      },
      {
        "key": "tgt",
        "representation": "opaque"
      },
      {
        "key": "as-material",
        "representation": "opaque"
      },
      {
        "key": "as-material",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "as.created",
        "value": true
      }
    ]
  },
  {
    "suffix": "as-receive",
    "title": "AS-REP receipt (no PA-SPAKE)",
    "fromActor": "spake-kdc",
    "toActor": "spake-client",
    "detail": "Receive opaque ticket and separately protected client material; no usable credential is cached.",
    "uses": [
      {
        "key": "tgt",
        "representation": "opaque"
      },
      {
        "key": "as-material",
        "representation": "opaque"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "as.received",
        "value": true
      }
    ]
  },
  {"suffix":"kdc-cleanup","title":"KDC releases exchange scratch state","fromActor":"spake-kdc","toActor":"spake-kdc","detail":"KDC-local exchange completion releases temporary SPAKE scalars, transcript and reply construction copies. Provisioned keys remain configured; issued tickets and client caches are unaffected.","uses":[],"effects":[]},
  {
    "suffix": "client-validate",
    "title": "Client validates AS-REP",
    "fromActor": "spake-client",
    "toActor": "spake-client",
    "detail": "Decrypt client part with candidate K-prime[0], check nonce, principal, lifetime and integrity. Acquire the KDC-issued session key; TGT body stays unreadable.",
    "uses": [
      {
        "key": "as-material",
        "representation": "decoded"
      },
      {
        "key": "tgt-session",
        "representation": "local"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "as.validated",
        "value": true
      }
    ]
  },
  {
    "suffix": "cache",
    "title": "Acquire usable TGT in cache",
    "fromActor": "spake-client",
    "toActor": "spake-client",
    "detail": "Separate credential-cache acceptance after successful validation.",
    "uses": [],
    "effects": [
      {
        "op": "put",
        "path": "credentials.tgt",
        "value": true
      },
      {
        "op": "put",
        "path": "credentials.mechanism",
        "value": "SPAKE"
      }
    ]
  },
  {
    "suffix": "tgs-request",
    "title": "TGS-REQ",
    "fromActor": "spake-client",
    "toActor": "spake-tgs",
    "detail": "Present opaque TGT and authenticator with service request binding.",
    "uses": [
      {
        "key": "tgt",
        "representation": "opaque"
      },
      {
        "key": "tgs-request",
        "representation": "wire"
      }
    ],
    "effects": []
  },
  {
    "suffix": "tgs-validate",
    "title": "TGS validates request and issues service credential",
    "fromActor": "spake-tgs",
    "toActor": "spake-tgs",
    "detail": "Realm key decrypts TGT; check authenticator, request checksum, time and replay. Issue service key and separately encrypted ticket/client parts.",
    "uses": [
      {"key":"realm-key","representation":"local"},
      {"key":"service-key","representation":"local"},
      {"key":"service-ticket","representation":"decoded"},
      {
        "key": "tgt",
        "representation": "decoded"
      },
      {
        "key": "tgt-session",
        "representation": "local"
      },
      {
        "key": "service-session",
        "representation": "local"
      },
      {
        "key": "service-ticket",
        "representation": "opaque"
      },
      {
        "key": "tgs-material",
        "representation": "opaque"
      },
      {
        "key": "tgs-material",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "tgs.validated",
        "value": true
      }
    ]
  },
  {
    "suffix": "tgs-reply",
    "title": "TGS-REP receipt",
    "fromActor": "spake-tgs",
    "toActor": "spake-client",
    "detail": "Service ticket and protected client part arrive, but are not yet validated or cached.",
    "uses": [
      {
        "key": "service-ticket",
        "representation": "opaque"
      },
      {
        "key": "tgs-material",
        "representation": "opaque"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "serviceTicket.received",
        "value": true
      }
    ]
  },
  {"suffix":"tgs-cleanup","title":"TGS releases request scratch state","fromActor":"spake-tgs","toActor":"spake-tgs","detail":"TGS-local response completion releases transient request and reply copies. Configured realm/service keys remain; remote credentials are unaffected.","uses":[],"effects":[]},
  {
    "suffix": "service-cache",
    "title": "Client validates TGS reply and caches service credential",
    "fromActor": "spake-client",
    "toActor": "spake-client",
    "detail": "Decrypt TGS client material under TGT session key; validate service/nonce/lifetime before caching.",
    "uses": [
      {
        "key": "tgs-material",
        "representation": "decoded"
      },
      {
        "key": "service-session",
        "representation": "local"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "credentials.serviceTicket",
        "value": true
      }
    ]
  },
  {
    "suffix": "ap-request",
    "title": "AP-REQ",
    "fromActor": "spake-client",
    "toActor": "spake-service",
    "detail": "Present service ticket and fresh encrypted authenticator for mutual authentication.",
    "uses": [
      {
        "key": "service-ticket",
        "representation": "opaque"
      },
      {
        "key": "ap-request",
        "representation": "opaque"
      }
    ],
    "effects": []
  },
  {
    "suffix": "service-validate",
    "title": "Service validates AP-REQ",
    "fromActor": "spake-service",
    "toActor": "spake-service",
    "detail": "Service key decrypts ticket; recover issued session key, validate authenticator, timestamp and replay cache.",
    "uses": [
      {
        "key": "service-ticket",
        "representation": "decoded"
      },
      {
        "key": "service-session",
        "representation": "local"
      },
      {
        "key": "ap-request",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "service.authenticatedClient",
        "value": true
      }
    ]
  },
  {
    "suffix": "ap-reply",
    "title": "AP-REP",
    "fromActor": "spake-service",
    "toActor": "spake-client",
    "detail": "Return encrypted echoed authenticator timestamp; receipt does not itself authenticate service.",
    "uses": [
      {
        "key": "ap-reply",
        "representation": "opaque"
      }
    ],
    "effects": []
  },
  {"suffix":"service-cleanup","title":"Service releases AP exchange scratch state","fromActor":"spake-service","toActor":"spake-service","detail":"Service-local response completion releases temporary ticket/authenticator/reply copies. The accepted service session key stays in the service authenticated context.","uses":[],"effects":[]},
  {
    "suffix": "session",
    "title": "Client validates AP-REP",
    "fromActor": "spake-client",
    "toActor": "spake-client",
    "detail": "Verify echoed timestamp under issued service session key; establish modeled authenticated application context.",
    "uses": [
      {
        "key": "ap-reply",
        "representation": "decoded"
      }
    ],
    "effects": [
      {
        "op": "put",
        "path": "session.established",
        "value": true
      },
      {
        "op": "put",
        "path": "terminal",
        "value": "success"
      }
    ]
  }
];
function kspExtra(key,label,creator,created,fields,representations,protection,keyRef){
 return {key,label,creator,created,fields:fields.map(([name,value])=>({id:'ksp'+key.split('-').map(word=>word[0].toUpperCase()+word.slice(1)).join('')+name.split('-').map(word=>word[0].toUpperCase()+word.slice(1)).join(''),name,value})),representations,protection,keyRef};
}
const kspExtraObjects=[
 kspExtra('initial-cookie','Initial negotiation cookie','spake-kdc','advertisement',[['cookie-bytes','symbolic authenticated initial negotiation cookie'],['state','KDC-only negotiation handle; no scalar or challenge transcript yet']],[{id:'opaque',readers:['spake-kdc','spake-client'],fields:['cookie-bytes']},{id:'decoded',readers:['spake-kdc'],fields:['state']}],'KDC authenticated initial conversation state','cookie-key'),
 kspExtra('failure','Preauthentication rejection','spake-kdc','kdc-reject',[['error','KDC_ERR_PREAUTH_FAILED'],['reason','factor ciphertext integrity failed']],[{id:'wire',readers:['spake-kdc','spake-client']}],'KRB-ERROR; no credential issued'),
 kspExtra('stripped-offer','Modified preauthentication offer','spake-observer','advertisement-stripped',[['mechanisms',['encrypted-timestamp']],['spake','advertisement removed by active attacker']],[{id:'wire',readers:['spake-observer','spake-client']}],'Unauthenticated response altered by observer'),
 kspExtra('policy','Client fallback policy','spake-client',null,[['disable-encrypted-timestamp',true]],[{id:'local',readers:['spake-client']}],'Client-local realm configuration'),
 kspExtra('timestamp','Encrypted timestamp fallback','spake-client','timestamp-derive',[['ciphertext','symbolic PA-ENC-TIMESTAMP under initial principal key'],['timestamp','20261021T120000Z']],[{id:'opaque',readers:['spake-client','spake-kdc'],fields:['ciphertext']},{id:'decoded',readers:['spake-client','spake-kdc'],fields:['timestamp']}],'Encrypted under initial principal key; no SPAKE','initial-key'),
 kspExtra('fallback-reply-key','Unstrengthened timestamp reply key','spake-kdc','timestamp-validate',[['key','symbolic initial principal AES128 key, not SPAKE strengthened']],[{id:'local',readers:['spake-kdc']}],'KDC provisioned principal key, not K-prime[0]'),
 kspExtra('optimistic-x','Abandoned optimistic KDC scalar','spake-kdc','optimistic-create',[['scalar','symbolic fresh x0 for unsupported group2']],[{id:'local',readers:['spake-kdc']}],'KDC-local generation0'),
 kspExtra('optimistic-challenge','Unsupported optimistic challenge','spake-kdc','optimistic-create',[['group',2],['public-T','symbolic P-256 T0'],['factors',['SF-NONE (1)']]],[{id:'wire',readers:['spake-kdc','spake-client']}],'Unauthenticated optimistic challenge generation0'),
 kspExtra('optimistic-cookie','Abandoned optimistic cookie','spake-kdc','optimistic-create',[['cookie-bytes','symbolic encrypted KDC cookie generation0'],['state','KDC-only x0 reference and group2 transcript']],[{id:'opaque',readers:['spake-kdc','spake-client'],fields:['cookie-bytes']},{id:'decoded',readers:['spake-kdc'],fields:['state']}],'KDC authenticated cookie generation0','cookie-key')
];
const kspAttributeObjects=[...kspObjects,...kspExtraObjects];
function kspEvent(suffix,title,fromActor,toActor,detail,uses=[],effects=[]){
 return {suffix,title,fromActor,toActor,detail,uses:uses.map(([key,representation])=>({key,representation})),effects:effects.map(([path,value])=>({op:'put',path,value}))};
}
function kspVariant(branch){
 let objects=JSON.parse(JSON.stringify([...kspObjects,...kspExtraObjects])),events=JSON.parse(JSON.stringify(kspEvents));
 const client='spake-client',kdc='spake-kdc',observer='spake-observer';
 const object=key=>objects.find(item=>item.key===key),event=suffix=>events.find(item=>item.suffix===suffix);
 const set=(key,name,value)=>{object(key).fields.find(field=>field.name===name).value=value;};
 const take=suffixes=>{events=suffixes.map(suffix=>event(suffix));};
 const replaceAt=(suffix,...newEvents)=>events.splice(events.findIndex(item=>item.suffix===suffix),1,...newEvents);
 const cleanup=kspEvent('kdc-cleanup','KDC releases failed-exchange scratch',kdc,kdc,'Release only this KDC exchange scratch; provisioned keys and remote state remain unchanged.');
 const clientCleanup=kspEvent('client-cleanup','Client releases rejected-exchange scratch',client,client,'Discard client-local temporary exchange data; unrelated credential cache remains unchanged.');
 event('advertisement').uses.push({key:'initial-cookie',representation:'opaque'});
 event('support').uses.push({key:'initial-cookie',representation:'opaque'});
 event('advertisement').detail+=' PA-FX-COOKIE starts this continuable conversation; contents remain KDC-only.';
 event('support').detail+=' Echo the exact opaque initial PA-FX-COOKIE bytes.';
 let title='ordinary success',completion='Validated TGT, service credential and mutual AP exchange',support='MIT Kerberos 1.22.2 - configuration required; not AD DS',policy=true;
 if(branch==='wrong-password'){
  title='wrong password rejected';completion='KDC factor integrity failure, client receives PREAUTH_FAILED, no usable TGT';
  set('password','password','synthetic incorrect client password: password!');
  set('initial-key','key','symbolic incorrect-password AES128 initial reply key');
  set('client-shared','K','symbolic mismatching client K from incorrect password');
  set('client-factor-key','key','symbolic mismatching client K-prime[1]');
  set('client-reply-key','key','symbolic mismatching client candidate K-prime[0]');
  take(['request','advertisement','support','kdc-challenge-create','challenge','client-derive','response']);
  events.push(kspEvent('kdc-reject','KDC rejects factor decryption',kdc,kdc,'Validate S, derive local K/K-prime[1], then factor integrity fails because the client used another password. No strengthened reply key or AS-REP is issued.',[['kdc-shared','local'],['kdc-factor-key','local'],['kdc-transcript','local'],['failure','wire']],[['kdc.factorValidated',false],['kdc.error','KDC_ERR_PREAUTH_FAILED']]),
   kspEvent('error-receive','KDC_ERR_PREAUTH_FAILED receipt',kdc,client,'Only now the client learns KDC rejection. Timestamp fallback is disabled.',[['failure','wire']],[['knowledge.client.error','KDC_ERR_PREAUTH_FAILED'],['terminal','wrong-password']]),cleanup,clientCleanup);
  object('kdc-shared').created='kdc-reject';object('kdc-factor-key').created='kdc-reject';object('kdc-transcript').created='kdc-reject';
 }
 if(branch==='no-common-group'){
  title='no common configured group';completion='Explicit KDC rejection policy, no shared key and no usable TGT';
  set('support','groups',[2]);set('failure','reason','configured client group2 and KDC group1 are disjoint; this preset fixes rejection policy');
  object('failure').created='group-reject';
  take(['request','advertisement','support']);
  events.push(kspEvent('group-reject','KDC rejects disjoint configured groups',kdc,kdc,'Client offers P-256 group2; configured KDC accepts edwards25519 group1 only. RFC9588 permits proposing another group; this preset explicitly chooses rejection instead. No scalar or shared key is created.',[['support','wire'],['failure','wire']],[['negotiation.commonGroup',false],['kdc.error','KDC_ERR_PREAUTH_FAILED']]),
   kspEvent('error-receive','KDC_ERR_PREAUTH_FAILED receipt',kdc,client,'Client learns selected group-rejection policy. Timestamp fallback is disabled.',[['failure','wire']],[['knowledge.client.error','KDC_ERR_PREAUTH_FAILED'],['terminal','no-common-group']]),cleanup,clientCleanup);
 }
 if(branch==='optimistic-accepted'){
  title='KDC optimistic challenge accepted';take(events.map(item=>item.suffix).filter(suffix=>!['advertisement','support'].includes(suffix)));
  object('etype').created='kdc-challenge-create';event('challenge').uses.push({key:'etype',representation:'wire'});
  event('challenge').title='PREAUTH_REQUIRED: SPAKEChallenge';
  event('challenge').detail='KDC first response optimistically selects supported group1 and supplies ETYPE-INFO2. Client skips the support round trip as RFC9588 requires.';
  for(const key of ['client-transcript','kdc-transcript'])set(key,'hash','symbolic H(H(zeros || DER challenge) || S), H=SHA-256; no support message');
  event('client-derive').detail='Validate T; ETYPE-INFO2 is available. Derive initial key, fresh y, S and K; transcript contains optimistic challenge then S, not a support message. Derive request-bound K-prime[1]/K-prime[0].';
 }
 if(branch==='client-optimistic'){
  title='client optimistic support';support='RFC 9588 standards optimization; MIT 1.22.2 client configuration knob not claimed';
  take(events.map(item=>item.suffix).filter(suffix=>!['request','advertisement'].includes(suffix)));
  object('etype').created='kdc-challenge-create';event('challenge').uses.push({key:'etype',representation:'wire'});
  object('request').created='support';event('support').uses.push({key:'request',representation:'wire'});
  event('support').uses=event('support').uses.filter(use=>use.key!=='initial-cookie');
  event('support').detail='Initial AS-REQ already contains SPAKESupport. Client skips initial empty request/advertisement pass.';
  event('challenge').detail='KDC accepts initial support and sends challenge with required singular ETYPE-INFO2 before the client first derives its reply key.';
 }
 if(branch==='optimistic-renegotiate'){
  title='optimistic group renegotiation';
  take(events.map(item=>item.suffix).filter(suffix=>suffix!=='advertisement'));
  event('support').uses=event('support').uses.filter(use=>use.key!=='initial-cookie');
  events.splice(1,0,kspEvent('optimistic-create','KDC creates group2 optimistic challenge',kdc,kdc,'Fresh generation0 P-256 scalar and challenge; the client is configured for group1 only.',[['optimistic-x','local'],['optimistic-challenge','wire'],['optimistic-cookie','decoded'],['optimistic-cookie','opaque']]),
   kspEvent('optimistic-challenge','PREAUTH_REQUIRED: unsupported SPAKEChallenge',kdc,client,'Client receives first-pass KRB-ERROR group2 challenge and ETYPE-INFO2, but does not derive a shared key for this unsupported group.',[['optimistic-challenge','wire'],['optimistic-cookie','opaque'],['etype','wire']],[['negotiation.optimisticGroup',2]]),
   kspEvent('transcript-reset','Client resets rejected transcript branch',client,client,'Abandon generation0 challenge and opaque cookie. Restart transcript generation1 with support; do not hash rejected challenge.',[['optimistic-challenge','wire']],[['negotiation.generation',1],['negotiation.clientTranscriptReset',true]]));
  const index=events.findIndex(item=>item.suffix==='support');
  events.splice(index+1,0,kspEvent('kdc-transcript-reset','KDC resets transcript for support',kdc,kdc,'Support restarts negotiation: release generation0 x/cookie and initialize generation1 transcript. Generate a fresh scalar for the selected group1.',[['support','wire']],[['negotiation.kdcTranscriptReset',true]]));
  object('etype').created='optimistic-create';
  for(const key of ['x','y','challenge','cookie','client-shared','kdc-shared','client-transcript','kdc-transcript','client-factor-key','kdc-factor-key','client-reply-key','kdc-reply-key','response']){
   object(key).generation=1;
   for(const field of object(key).fields)if(typeof field.value==='string')field.value=field.value.replaceAll('generation 0','generation 1')+' [generation1 after reset]';
  }
  for(const key of ['client-transcript','kdc-transcript'])set(key,'hash','symbolic H(H(zeros || DER support1 || DER challenge1) || S1), H=SHA-256; excludes rejected challenge0');
  event('kdc-challenge-create').detail='Generation1: fresh x1, group1 T1 and new opaque cookie. Rejected group2 challenge0 is not in this transcript.';
 }
 if(branch.startsWith('downgrade-')){
  const allowed=branch==='downgrade-allowed';policy=!allowed;title=allowed?'downgrade allowed: encrypted timestamp':'downgrade blocked by client policy';
  completion=allowed?'Application context via encrypted timestamp fallback, not SPAKE':'Client policy stop; no usable TGT';
  const tail=events.slice(events.findIndex(item=>item.suffix==='as-create'));
  events=[event('request'),
   kspEvent('advertisement-intercept','Observer intercepts initial KDC advertisement',kdc,observer,'An active attacker receives the unauthenticated initial response. It still advertises PA-SPAKE before modification.',[['advertisement','wire'],['etype','wire']]),
   kspEvent('advertisement-stripped','Observer suppresses PA-SPAKE advertisement',observer,client,'Client receives ETYPE-INFO2 and an encrypted timestamp offer, but not the removed SPAKE advertisement. No SPAKE challenge or key exchange occurred.',[['stripped-offer','wire'],['etype','wire']],[['negotiation.advertisementSuppressed',true]])];
  events.push(kspEvent('observer-cleanup','Observer releases intercepted packet copies',observer,observer,'Observer-local disposal of transient intercepted/modified response copies. It does not erase KDC or client holdings.'));
  object('advertisement').created='advertisement-intercept';object('etype').created='advertisement-intercept';
  object('initial-cookie').created='advertisement-intercept';
  object('initial-cookie').representations[0].readers=[kdc,observer,client];
  event('advertisement-intercept').uses.push({key:'initial-cookie',representation:'opaque'});
  event('advertisement-stripped').uses.push({key:'initial-cookie',representation:'opaque'});
  object('advertisement').representations[0].readers=[kdc,observer];object('etype').representations[0].readers=[kdc,observer,client];
  if(!allowed)events.push(kspEvent('policy-stop','Client blocks encrypted timestamp fallback',client,client,'disable_encrypted_timestamp=true. The KDC may still offer timestamp; the client refuses it. Authentication stops without an AS reply.',[['policy','local']],[['policy.fallback','blocked'],['terminal','downgrade-blocked']]),cleanup,clientCleanup);
  else{
   events.push(kspEvent('fallback-policy','Client allows encrypted timestamp fallback',client,client,'disable_encrypted_timestamp=false permits fallback. Protection against passive offline password guessing is reduced. Completion must not be labeled SPAKE.',[['policy','local']],[['policy.fallback','encrypted-timestamp']]),
    kspEvent('timestamp-derive','Client constructs encrypted timestamp',client,client,'Use ETYPE-INFO2 and password to derive initial key, then encrypt a fresh timestamp. No SPAKE scalar/shared key/transcript exists.',[['initial-key','local'],['timestamp','decoded'],['timestamp','opaque']]),
    kspEvent('timestamp-request','AS-REQ: PA-ENC-TIMESTAMP fallback',client,kdc,'Explicit encrypted-timestamp request echoes the unchanged opaque initial cookie; not PA-SPAKE.',[['timestamp','opaque'],['initial-cookie','opaque']]),
    kspEvent('timestamp-validate','KDC validates encrypted timestamp',kdc,kdc,'Decrypt using provisioned principal key, check freshness and replay; retain original reply key without SPAKE strengthening.',[['timestamp','decoded'],['fallback-reply-key','local']],[['kdc.timestampValidated',true]]),...tail);
   object('initial-key').created='timestamp-derive';
   const creation=event('as-create');creation.title='KDC creates timestamp-fallback AS-REP';creation.detail='Validated encrypted timestamp permits AS-REP. Client material uses original principal reply key, not K-prime[0]; TGT uses realm key. This TGT is not SPAKE protected.';
   creation.uses=creation.uses.filter(use=>use.key!=='kdc-reply-key');creation.uses.push({key:'fallback-reply-key',representation:'local'});
   object('as-material').keyRef='fallback-reply-key';object('as-material').protection='AS client material encrypted with initial principal reply key; no SPAKE strengthening';
   event('client-validate').detail='Validate AS client part under initial principal key and check nonce/principal/lifetime; opaque TGT body remains unreadable. This is timestamp fallback, not SPAKE.';
   event('cache').effects.find(effect=>effect.path==='credentials.mechanism').value='encrypted-timestamp';
  }
 }
 const initialCookie=object('initial-cookie');
 initialCookie.releaseAt={
  [client]:event('challenge')?'challenge':event('timestamp-request')?'timestamp-request':'client-cleanup',
  [kdc]:event('kdc-challenge-create')?'kdc-challenge-create':event('timestamp-validate')?'timestamp-validate':'kdc-cleanup',
  [observer]:'observer-cleanup'
 };
 const cacheUses={cache:[['tgt','opaque'],['tgt-session','local']],'service-cache':[['service-ticket','opaque'],['service-session','local']]};
 for(const item of events){
  if(cacheUses[item.suffix])for(const [key,representation] of cacheUses[item.suffix]){
   const use=item.uses.find(existing=>existing.key===key&&existing.representation===representation);
   if(use)use.kind='store';
   else item.uses.push({key,representation,kind:'store'});
  }
  if(item.suffix==='client-derive')item.uses.unshift(...[['password','local'],['etype','wire'],['challenge','wire'],['request','wire']].map(([key,representation])=>({key,representation,kind:key==='challenge'?'verify':'use'})));
  if(item.suffix==='kdc-challenge-create')item.uses.unshift({key:'kdc-record',representation:'local',kind:'use'},{key:'cookie-key',representation:'local',kind:'use'});
  if(item.suffix==='client-validate')item.uses.unshift({key:branch==='downgrade-allowed'?'initial-key':'client-reply-key',representation:'local',kind:'use'});
  if(item.suffix==='session')item.uses.unshift({key:'service-session',representation:'local',kind:'use'});
  if(item.suffix==='kdc-validate')item.uses.unshift({key:'cookie',representation:'decoded',kind:'decrypt'});
  if(['advertisement','advertisement-intercept','advertisement-stripped','optimistic-challenge','challenge'].includes(item.suffix)){
   const first=item.suffix!=='challenge'||branch==='optimistic-accepted';
   item.errorEnvelope={messageType:'KRB-ERROR',code:first?25:91,name:first?'KDC_ERR_PREAUTH_REQUIRED':'KDC_ERR_MORE_PREAUTH_DATA_REQUIRED'};
  }
 }
 set('policy','disable-encrypted-timestamp',policy);
 if(!branch.startsWith('downgrade-'))object('policy').fields[0].value=true;
 const sourceIds=new Set(events.map(item=>item.suffix));
 const usedKeys=new Set(events.flatMap(item=>item.uses.map(use=>use.key)));
 objects=objects.filter(item=>item.created===null?['password','kdc-record','realm-key','service-key','unrelated','cookie-key','policy'].includes(item.key):(sourceIds.has(item.created)&&usedKeys.has(item.key)));
 return {objects,events,title,completion,support,policy,observer:branch.startsWith('downgrade-')};
}
const kspFieldSubjects={
 password:['3.1','Client input feeds Kerberos string-to-key using the selected enctype and salt; it is never sent to the KDC.','Keep the human secret local and distinguish it from the provisioned KDC key.'],
 'kdc-record':['3.1','KDC principal database record supplies the existing initial reply key, not the client plaintext password.','Authenticate knowledge of the provisioned principal key without transmitting that key.'],
 'realm-key':['4.5','Realm krbtgt long-term key encrypts ticket bodies; KDC/TGS hold it, but the client never does.','Protect the TGT independently of the strengthened AS client reply key.'],
 'service-key':['4.5','TGS and service share a service-principal key for service-ticket body encryption.','Let the service open its ticket without revealing the service key to the client.'],
 unrelated:['3','A preexisting credential for another service is outside this transaction.','Demonstrate that rejection or local cleanup cannot erase unrelated cached state.'],
 request:['7','The exact DER KDC-REQ-BODY, including requested principal/service, nonce and enctype list, is an input to every SPAKE protection-key derivation.','Bind the PAKE result to the request actually answered, not a spliced request.'],
 advertisement:['4.1','An empty PA-SPAKE value in PREAUTH_REQUIRED advertises mechanism support; it is neither a public group value nor successful authentication.','Permit mechanism selection while exposing the initial unauthenticated downgrade surface.'],
 etype:['3.1','Exactly one ETYPE-INFO2 entry identifies the original reply-key enctype and string-to-key salt.','Make the initial reply key available before w and K-prime derivation; optimistic clients need this in the challenge reply.'],
 'initial-cookie':['3.2','The initial opaque PA-FX-COOKIE identifies a continuable negotiation before any scalar exists. The client echoes exact bytes in its next same-conversation request; only the KDC decodes its handle.','Distinguish initial negotiation state from the replacement challenge-state cookie.'],
 support:['4.2','SPAKESupport contains an ordered sequence of client-preferred group numbers; the KDC selects according to available groups and deployment policy.','Negotiate a group and bind that offered list into the transcript.'],
 x:['4.2','The KDC samples fresh cofactor-compatible scalar x and computes masked public T=xP+wM. Only the KDC may inspect x.','Contribute independent KDC entropy; discard exchange scratch locally, never transmit x or expose it through a cookie.'],
 y:['4.3','The client samples fresh cofactor-compatible scalar y and computes masked public S=yP+wN. Only the client may inspect y.','Contribute client entropy without transferring its private scalar.'],
 challenge:['4.2','SPAKEChallenge carries selected group, serialized public T and the offered factor list; SF-NONE is type1 with no data. T must be a valid group element.','Give the client public inputs for its local PAKE computation; challenge receipt alone does not authenticate the KDC.'],
 cookie:['3.2','PA-FX-COOKIE retains authenticated KDC exchange state. Client possession and echo cover opaque bytes only; decoded x/transcript state remains KDC-local.','Continue a stateless KDC exchange without transferring scalar ownership or client read authority.'],
 'cookie-key':['10.4','A KDC-only cookie-protection key authenticates and encrypts server-side ephemeral state; it is unrelated to the password and ticket session keys.','Keep echoed state opaque and prevent an attacker from editing KDC scalar/transcript state.'],
 'initial-key':['5','Kerberos string-to-key produces the original reply key; PRF+(key, SPAKEsecret || group-be32) supplies the registry-specific w input.','Keep the same original key as the base for every K-prime[n] derivation, even after candidate K-prime[0] exists.'],
 'client-shared':['4.3','Client locally computes K=y(T-wM) after validating T. K is a group element, never an encryption key or a wire field.','Supply local entropy to section7 key derivation without sending the shared element.'],
 'kdc-shared':['4.3','KDC locally computes K=x(S-wN) after validating S. A wrong client secret produces nonmatching derived keys.','Validate the protected factor using independently derived KDC keys.'],
 'client-transcript':['6','Client hashes support/challenge and then S; accepted KDC optimism omits support, rejected optimism is excluded after reset. Encrypted factor bytes are not hashed.','Protect group/factor negotiation and public-value binding without carrying abandoned transcript generations forward.'],
 'kdc-transcript':['6','KDC independently hashes the same accepted support/challenge/S framing; support after rejected optimism resets the hash.','Detect inconsistent negotiation or request framing through protection-key mismatch.'],
 'client-factor-key':['7','Client K-prime[1] derives from original key, PRF+ input, K, transcript and exact request body. It encrypts the response factor under KEY_USAGE_SPAKE65.','Protect SF-NONE and implicitly demonstrate password-key knowledge to the KDC.'],
 'kdc-factor-key':['7','KDC independently derives K-prime[1] to decrypt and integrity-check the response factor; successful packet receipt is insufficient.','Perform the actual first-factor verification boundary before issuing any credential.'],
 'client-reply-key':['4.5','Client candidate K-prime[0] has the initial enctype and is derived using the original key. It is not a ticket-encryption key or a usable TGT.','Validate the strengthened AS client material before accepting the separate issued session key and opaque ticket.'],
 'kdc-reply-key':['4.5','KDC replaces its original reply key with K-prime[0] only after factor validation, then encrypts the AS client part; no final PA-SPAKE is sent.','Strengthen the reply key once without changing the realm ticket-encryption key or service-ticket protocol.'],
 response:['4.3','SPAKEResponse contains serialized public S and encrypted SPAKESecondFactor; SF-NONE type1 has omitted data. Only factor ciphertext is sent, and KDC decodes at validation.','Convey the client public contribution and protected first-factor proof without inventing an OTP exchange.'],
 'tgt-session':['4.5','KDC generates a distinct client/TGS session key; it appears inside the TGT body and separately inside AS client material.','Give client and TGS a shared service for future ticket requests only after client validation/cache acceptance.'],
 tgt:['4.5','The TGT envelope is opaque to its client carrier; issuer and TGS alone can inspect protected principal/session-key body fields under the realm key.','Carry a credential to TGS without exposing its ticket body or treating receipt as cache acceptance.'],
 'as-material':['4.5','AS reply client part is protected under strengthened K-prime[0], separately from the TGT body. The client checks request nonce, principal, lifetime and integrity before taking the issued session key.','Separate reply receipt, client verification and usable credential-cache acquisition.'],
 'tgs-request':['4.5','Ordinary RFC4120 TGS request presents TGT plus authenticator and requested-service checksum bound by the client/TGS session key.','Use the accepted TGT to request a service-specific credential; SPAKE does not replace TGS authentication.'],
 'service-session':['4.5','TGS generates a new client/service session key, distinct from both long-term service key and client/TGS session key.','Support mutual AP authentication; retain the accepted key in client cache and service authenticated context.'],
 'service-ticket':['4.5','Service ticket ciphertext is carried by client; TGS issuer/service decoder can read its protected client identity and session key using the service long-term key.','Authenticate to one service without exposing its long-term key or protected ticket body to the client.'],
 'tgs-material':['4.5','TGS reply client material conveys the issued service session key and requested-service identity under the client/TGS session key.','Require TGS-reply validation before service-credential cache acceptance.'],
 'ap-request':['4.5','AP authenticator proves possession of the issued service session key and supplies a fresh client timestamp, independently of the opaque service ticket.','Let the service validate freshness, replay protection and claimed client identity.'],
 'ap-reply':['4.5','AP-REP encrypts an echo of the client authenticator time under the service session key. Receipt alone does not prove that the client checked it.','Advance client mutual-authentication knowledge only at explicit local AP-REP verification.'],
 failure:['4.3','KDC_ERR_PREAUTH_FAILED communicates a KDC-local validation or selected group-policy rejection; it carries no accepted reply or usable TGT.','Keep KDC rejection distinct from when the client actually receives knowledge of failure.'],
 'stripped-offer':['10.5','An active attacker removes the unauthenticated SPAKE advertisement, leaving a timestamp mechanism offer and ETYPE-INFO2.','Contrast explicitly permitted weak fallback with a client policy that refuses timestamp.'],
 policy:['10.5','disable_encrypted_timestamp is client realm policy, not a KDC capability or an instruction that removes the KDC offer.','Decide locally whether advertisement stripping may force timestamp fallback.'],
 timestamp:['10.5','PA-ENC-TIMESTAMP encrypts a fresh timestamp using the original principal key. Its passive capture permits offline password guessing unlike successful SPAKE.','Attribute any resulting credential to encrypted-timestamp fallback, never SPAKE success.'],
 'fallback-reply-key':['10.5','Permitted timestamp fallback retains the original provisioned reply key; no SPAKE K-prime[0] exists.','Encrypt AS client material under the actual fallback mechanism without claiming PAKE strengthening.'],
 'optimistic-x':['4.6','KDC generation0 scalar belongs to the unsupported optimistic group2 challenge and must not be reused after support renegotiation.','Keep abandoned ephemeral state separate from fresh accepted generation1 state.'],
 'optimistic-challenge':['4.6','First-response group2 challenge is unsupported by this configured client; it triggers support negotiation rather than client shared-key derivation.','Explain why both endpoints discard the rejected challenge from the replacement transcript.'],
 'optimistic-cookie':['4.6','Opaque generation0 state cookie belongs to the abandoned group2 challenge; client may hold its bytes but not read x0.','Prevent exact replay or reset from merging abandoned scalar/cookie state with accepted generation1.']
};
const kspFieldRoles={
 nonce:'The client-generated request nonce must match the encrypted reply; packet arrival alone does not validate it.',
 salt:'This string-to-key salt combines the realm and principal identity; it is public derivation input, not the password.',
 enctype:'Enctype17 selects aes128-cts-hmac-sha1-96 for the original and derived reply-key profile.',
 enctypes:'This request list constrains acceptable reply encryption and is covered by the exact request-body derivation binding.',
 groups:'Ordered group numbers express client preference, not proof that the KDC supports each group.',
 group:'This selected registry group fixes curve, cofactor, serialization and hash for the accepted transcript generation.',
 'public-T':'This masked KDC public group element is received and validated before client shared-secret computation; it is not private x.',
 'public-S':'This masked client public element is sent in response and validated before KDC shared-secret computation; it is not private y.',
 'factor-ciphertext':'This is protected DER SPAKESecondFactor ciphertext under K-prime[1] with key usage65, not plaintext factor data.',
 'factor-type':'Type1 is SF-NONE. Its data field is omitted; no OTP is present or validated.',
 factors:'The challenge advertises exactly SF-NONE type1 for this delivery; clients cannot substitute an unoffered factor.',
 'cookie-bytes':'These encrypted authenticated bytes can be carried and echoed without revealing the server state they encode.',
 state:'This decoded server state references private KDC scalar/transcript data; possession of cookie ciphertext never grants client inspection.',
 'ticket-bytes':'These opaque bytes may be read as ciphertext by the carrier, but reveal no decoded ticket body fields.',
 ciphertext:'These wire ciphertext bytes and their later decoded fields are separate representations with separate reader permissions.',
 'session-key':'This issuer-generated session-key reference is conveyed in independently protected client and ticket parts, not generated anew by the recipient.',
 server:'This expected service principal binds the issued credential to the requested Kerberos service.',
 service:'This requested application service must match the validated reply; an accepted TGT alone does not authorize this service.',
 client:'This principal identifies the authenticated ticket subject; the client may not decode it from an opaque ticket body.',
 principal:'This key record is scoped to the named Kerberos principal, not interchangeable with another realm or service.',
 'padata-type':'PA-SPAKE is padata type151.',
 'padata-value':'Empty PA-SPAKE advertises support without supplying SPAKESupport or SPAKEChallenge.',
 'echo-time':'The returned authenticator timestamp must be decrypted and compared by the client before mutual authentication completes.',
 timestamp:'Fresh authenticator time participates in endpoint freshness/replay checks; remote receipt does not itself pass those checks.'
};
function kspDefinition(object,field){
 let [section,meaning,purpose]=kspFieldSubjects[object.key];
 const kerberosSections={'realm-key':'5.3','service-key':'5.3','tgt-session':'3.1.3',tgt:'5.3','as-material':'3.1.3','tgs-request':'3.3.1','service-session':'3.3.3','service-ticket':'5.3','tgs-material':'3.3.3','ap-request':'3.2.3','ap-reply':'3.2.4',timestamp:'5.2.7.2','fallback-reply-key':'3.1.3'};
 const base=Object.hasOwn(kerberosSections,object.key)?SPAKELAB_SOURCES[2]:SPAKELAB_SOURCES[0];
 if(base===SPAKELAB_SOURCES[2])section=kerberosSections[object.key];
 const role=kspFieldRoles[field.name]||'This '+field.name+' has the local origin and narrowly scoped key role described above; it is not interchangeable with another object of a similar name.';
 const definition=labAttribute(object.label+': '+field.name,meaning+' '+role,object.creator+' creates '+field.name+(object.created?' at '+object.created: ' in preexisting configuration'),purpose,field.value,base.standard+' section '+section,base.url+'#section-'+section);
 return {...definition,section,protection:object.protection,keyRef:object.keyRef||null,synthetic:true};
}
export const SPAKELAB_ATTRIBUTES=Object.fromEntries(kspAttributeObjects.flatMap(object=>object.fields.map(field=>[field.id,kspDefinition(object,field)])));
const kspActors=Object.fromEntries([
 ['spake-client','Kerberos client','client',145,365],['spake-kdc','Authentication service','idp',560,120],['spake-tgs','Ticket-granting service','idp',560,610],['spake-service','Application service','service',975,365]
].map(([id,name,kind,x,y])=>[id,{name,role:name,plainRole:name,kind,color:'#4f8ba8',position:{x,y},notes:['MIT / standards profile, not AD DS. Separate logical authority.']}]));
const kspProfile={id:'rfc9588-mit1222-ed25519-aes128',name:'Kerberos SPAKE with configured MIT KDC',version:'RFC 9588 / MIT 1.22.2',implementation:'MIT Kerberos 1.22.2 administration checked',publicationStatus:'Proposed Standard',supportStatus:'MIT Kerberos - configuration required',algorithms:['edwards25519 group1','SHA-256','aes128-cts-hmac-sha1-96 enctype17','SF-NONE'],transports:['Kerberos over TCP'],assumptions:['No FAST armor','Required preauthentication','Configured SPAKE-capable KDC','Provisioned principal and known service','No initial user TGT'],completion:'Validated TGT, service credential and mutual AP exchange',sources:SPAKELAB_SOURCES,cryptoDetail:'Symbolic values, not actual cryptographic bytes. Offline official fixture identity: rfc9588-C-aes128-edwards25519. All K-prime derivations use initial reply key; strengthening occurs only once at completion.'};
function kspBuild(branch){
 const variant=kspVariant(branch),id='lab-krb-spake-'+branch;
 const profile={...kspProfile,id:kspProfile.id+'-'+branch,name:branch.startsWith('downgrade-')?'Kerberos SPAKE advertisement suppression / timestamp policy':kspProfile.name,supportStatus:variant.support,completion:variant.completion,assumptions:[...kspProfile.assumptions,'disable_encrypted_timestamp='+variant.policy],cryptoDetail:branch.startsWith('downgrade-')?'Symbolic active downgrade illustration. No SPAKE shared key, transcript or strengthened reply key exists. Permitted encrypted-timestamp fallback uses the original principal key.':kspProfile.cryptoDetail};
 if(branch==='no-common-group')profile.assumptions.push('Client configured groups=[P-256]; KDC configured groups=[edwards25519]; explicit rejection policy');
 if(branch==='optimistic-renegotiate')profile.assumptions.push('KDC optimistic group=P-256; client supports edwards25519 only; fallback negotiation selects group1 with fresh generation1 state');
 if(branch==='optimistic-accepted')profile.assumptions.push('MIT spake_preauth_kdc_challenge=edwards25519; client supports group1; support round trip omitted');
 if(branch==='client-optimistic')profile.assumptions.push('RFC9588 client initial support optimization; challenge must carry ETYPE-INFO2');
 if(branch==='wrong-password')profile.assumptions.push('Client input differs from provisioned principal secret; timestamp fallback disabled');
 if(branch==='no-common-group'||branch==='optimistic-renegotiate')profile.algorithms=[...profile.algorithms,'P-256 group2 for rejected negotiation only'];
 if(branch.startsWith('downgrade-'))profile.algorithms=['aes128-cts-hmac-sha1-96 enctype17','PA-ENC-TIMESTAMP '+(variant.policy?'refused':'permitted')+'; no SPAKE execution'];
 const objects=variant.objects.map(object=>({...object,instanceId:id+':'+object.key,sourceEventId:object.created?id+'-'+object.created:null}));
 const actors=variant.observer?{...kspActors,'spake-observer':{name:'Active network observer',role:'Advertisement-suppressing attacker',plainRole:'Changes an unauthenticated KDC response',kind:'service',color:'#bc6d52',position:{x:350,y:120},notes:['Only the two downgrade demonstrations include this observer.']}}:kspActors;
 const definitions={...SPAKELAB_ATTRIBUTES,...Object.fromEntries(objects.flatMap(object=>object.fields.map(field=>[field.id,kspDefinition(object,field)])))};
 const derivedObjects=new Set(['initial-key','client-shared','kdc-shared','client-transcript','kdc-transcript','client-factor-key','kdc-factor-key','client-reply-key','kdc-reply-key','tgt-session','service-session','fallback-reply-key']);
 const verificationEvents=new Set(['kdc-validate','kdc-reject','group-reject','client-validate','tgs-validate','service-validate','timestamp-validate','session']);
 const steps=variant.events.map(event=>{
  const local=event.fromActor===event.toActor, sourceEventId=id+'-'+event.suffix;
  const occurrences=event.uses.flatMap(use=>{
   const object=objects.find(item=>item.key===use.key),rep=object.representations.find(item=>item.id===use.representation);
   return object.fields.filter(field=>!rep.fields||rep.fields.includes(field.name)).map(field=>({object,rep,field}));
  });
  const step=labStep(sourceEventId,event.title,event.fromActor,event.toActor,event.suffix,local?'internal':'backchannel',event.title,event.detail,occurrences.map(item=>item.field.id),occurrences.map(({field})=>labP(field.name,field.value,event.detail,field.id)),[],[]);
  step.eventType=local?'local':'message'; step.protocolLabel=local?'Local Kerberos processing':event.title;
  step.beginnerSummary=event.title; step.protocolDetail=event.detail; step.cryptoDetail=profile.cryptoDetail;
  if(event.errorEnvelope){
   step.errorEnvelope={...event.errorEnvelope};
   step.payload.unshift(labP('KRB-ERROR',step.errorEnvelope,event.detail));
   step.protocolLabel=event.errorEnvelope.name+': '+event.title.split(': ').at(-1);
  }
  step.layers=local?[]:[{protocol:'Kerberos',transport:'TCP',from:event.fromActor,to:event.toActor,protection:occurrences.map(item=>item.object.protection).filter((value,index,all)=>all.indexOf(value)===index).join('; '),keyRef:occurrences.map(item=>item.object.keyRef).filter(Boolean).join(',')}];
  step.protocolEffects=event.effects;
  for(const {object,rep,field} of occurrences){
   const use=event.uses.find(item=>item.key===object.key&&item.representation===rep.id);
   const created=object.created===event.suffix;
   const kind=use.kind||(local?(created?(derivedObjects.has(object.key)?'derive':'create'):rep.id==='decoded'?'decrypt':verificationEvents.has(event.suffix)?'verify':object.key==='policy'?'inspect':'use'):'send');
   const occurrence={attributeId:field.id,kind,actorId:event.fromActor,instanceId:object.instanceId,creator:object.creator,holders:[event.fromActor],inspectors:rep.readers,fieldPath:object.key+'.'+field.name,representation:rep.id,value:field.value,sourceEventId,exactValueRef:object.instanceId+':'+rep.id+':'+field.id,detail:event.detail};
   step.attributeOperations.push(occurrence);
   if(local&&kind==='decrypt')step.attributeOperations.push({...occurrence,kind:'verify'});
   if(!local)step.attributeOperations.push({...occurrence,kind:'receive',actorId:event.toActor,holders:[event.toActor]});
  }
  return step;
 });
 // Lifecycle projections retain canonical cursors; disposal never performs protocol work.
 const cleanup={'spake-client':variant.events.some(event=>event.suffix==='session')?'session':'client-cleanup','spake-kdc':'kdc-cleanup','spake-tgs':'tgs-cleanup','spake-service':'service-cleanup','spake-observer':'observer-cleanup'};
 for(const object of objects){
  if(object.created===null)continue;
  const copies=new Map();
  const creation=steps.find(item=>item.id===object.sourceEventId);
  if(creation.from!==creation.to)for(const rep of object.representations)for(const field of object.fields.filter(field=>!rep.fields||rep.fields.includes(field.name)))creation.attributeOperations.unshift({attributeId:field.id,kind:'create',actorId:object.creator,instanceId:object.instanceId,creator:object.creator,holders:[object.creator],inspectors:rep.readers,fieldPath:object.key+'.'+field.name,representation:rep.id,value:field.value,sourceEventId:creation.id,exactValueRef:object.instanceId+':'+rep.id+':'+field.id,detail:object.creator+' creates its '+rep.id+' representation of '+object.label+'; decoded state stays limited to the listed readers.'});
  for(const rep of object.representations)if(rep.id===object.representations[0].id||rep.readers.includes(object.creator))copies.set(object.creator+'|'+rep.id,{actor:object.creator,rep});
  for(const event of variant.events)for(const use of event.uses)if(use.key===object.key){
   const rep=object.representations.find(item=>item.id===use.representation);
   copies.set(event.fromActor+'|'+rep.id,{actor:event.fromActor,rep});
   if(event.fromActor!==event.toActor)copies.set(event.toActor+'|'+rep.id,{actor:event.toActor,rep});
  }
  for(const {actor,rep} of copies.values()){
   const suffix=object.releaseAt?.[actor]||(object.key.startsWith('optimistic-')?(actor==='spake-client'?'transcript-reset':'kdc-transcript-reset'):cleanup[actor]);
   const step=steps.find(item=>item.id===id+'-'+suffix);
   if(!step)throw new Error('Missing SPAKE attribute disposal event for '+object.key+' at '+suffix);
   for(const field of object.fields.filter(field=>!rep.fields||rep.fields.includes(field.name)))step.attributeOperations.push({attributeId:field.id,kind:'evict',actorId:actor,instanceId:object.instanceId,creator:object.creator,holders:[actor],inspectors:rep.readers,fieldPath:object.key+'.'+field.name,representation:rep.id,value:field.value,sourceEventId:step.id,exactValueRef:object.instanceId+':'+rep.id+':'+field.id,detail:'Release only '+actor+' temporary '+rep.id+' copies of '+object.label+'. Retained credential caches and authenticated contexts are unchanged.'});
  }
 }
 return labScenario({id,title:'Kerberos SPAKE: '+variant.title,summary:variant.completion,status:'reference',workspace:'kerberos',family:'mit-standards',protocol:branch==='downgrade-allowed'?'Kerberos encrypted-timestamp fallback':'Kerberos SPAKE',category:'Initial authentication',standard:'RFC 9588 - Proposed Standard',source:SPAKELAB_SOURCES[0].url,supportNote:variant.support,learningObjective:'Distinguish negotiation, local key derivation, message receipt, validation and cache acquisition.',prerequisites:profile.assumptions,profile,keywords:['PA-SPAKE','SF-NONE','reply-key strengthening','group negotiation','key confirmation','encrypted timestamp','transcript reset'],
 relatedLessons:[
  {id:'lab-pake-spake2-success',title:'Balanced PAKE foundation',summary:'Standalone SPAKE2 uses a shared password-equivalent and explicit A-first confirmation; it is not the Kerberos binding.'},
  {id:'lab-pake-spake2plus-success',title:'Augmented PAKE foundation',summary:'Standalone SPAKE2+ gives the verifier w0,L and verifier-first confirmation, not a Kerberos principal key or TGT.'},
  {id:'lab-krb-spake-downgrade-allowed',title:'SPAKE versus timestamp',summary:'Permitted fallback loses PAKE offline-dictionary protection; any issued TGT is from encrypted timestamp.'},
  {id:'lab-ad-pkinit-success',title:'SPAKE versus PKINIT',summary:'Compare password-derived trust with a separate AD DS certificate-based initial-authentication profile. This is not AD DS SPAKE support.'},
  {id:'lab-ad-fast-as-success',title:'SPAKE with FAST: separate protection',summary:'Inspect FAST armor in a separate AD DS profile. RFC 9588 allows SPAKE within FAST, but this SPAKE teaching profile has no armor and this link does not claim AD SPAKE.'}
 ],
 help:{threat:'PAKE limits passive offline guessing, not online guessing or endpoint compromise.',comparisons:['SPAKE versus timestamp: encrypted timestamp permits passive offline guessing; disabling fallback blocks advertisement stripping.','SPAKE versus PKINIT: password-derived trust versus certificate-based authentication.','SPAKE with FAST: separate armor can enclose SPAKE; this preset has none.','Balanced versus augmented PAKE: Kerberos uses a provisioned password-derived key, not a SPAKE2+ registration record.']},initialState:{unrelated:{cache:'preserved unrelated credential'},credentials:{tgt:false,serviceTicket:false},session:{established:false},policy:{disableEncryptedTimestamp:variant.policy},negotiation:{generation:0},terminal:null},heldObjectLedger:{objects,events:variant.events}},definitions,steps,actors);
}
export const SPAKELAB_SCENARIOS=['success','wrong-password','no-common-group','downgrade-allowed','downgrade-blocked','optimistic-accepted','optimistic-renegotiate','client-optimistic'].map(kspBuild);
