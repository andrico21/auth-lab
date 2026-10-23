// Fixed input fixtures authored from the independent worksheet before models.
// Expected predicates remain solely in the worksheet/test contract.
export const K8S_CASE_ROWS = [
  {
    "planId": "K8S01",
    "runtimeId": "lab-k8s01",
    "family": "human-access",
    "title": "Human OIDC login to kubectl API read",
    "goal": "Show the complete client login, token authentication and authorized Kubernetes read.",
    "preconditions": [
      "Pinned cluster fixture; exec credential API client.authentication.k8s.io/v1; public native OIDC client kubernetes-demo; authorization code + S256 PKCE; Alice sub alice and group readers."
    ]
  },
  {
    "planId": "K8S02",
    "runtimeId": "lab-k8s02",
    "family": "human-access",
    "title": "JWT claims to Kubernetes userInfo",
    "goal": "Make username and group mapping inspectable before access decisions.",
    "preconditions": [
      "Structured AuthenticationConfiguration v1; username claim sub with prefix oidc:; groups claim groups with prefix team:; required tenant demo; reject mapped system: names."
    ]
  },
  {
    "planId": "K8S03",
    "runtimeId": "lab-k8s03",
    "family": "token-validation",
    "title": "Kubernetes JWT rejection and key rotation",
    "goal": "Keep failed credential validation outside RBAC and admission.",
    "preconditions": [
      "OIDC ID-token profile audience kubernetes-demo; RS256 fixtures; unknown-key refresh semantics labeled as implementation-specific; link JWT04-JWT07."
    ]
  },
  {
    "planId": "K8S04",
    "runtimeId": "lab-k8s04",
    "family": "authorization-rbac",
    "title": "RoleBinding explains Alice allowed and Bob forbidden",
    "goal": "Make one concrete namespaced permission decision fully traceable.",
    "preconditions": [
      "demo-dev Role reader: core pods get/list/watch; RoleBinding read-pods subjects Group team:readers; Alice member, Bob not."
    ]
  },
  {
    "planId": "K8S05",
    "runtimeId": "lab-k8s05",
    "family": "authorization-rbac",
    "title": "Role and ClusterRole binding scope",
    "goal": "Explain reusable rules versus the scope at which a binding grants them.",
    "preconditions": [
      "Independent resettable variants; custom demo-pod-reader ClusterRole; no built-in cluster-admin."
    ]
  },
  {
    "planId": "K8S06",
    "runtimeId": "lab-k8s06",
    "family": "authorization-rbac",
    "title": "Request attributes, subresources and can-i",
    "goal": "Explain how an HTTP request becomes a policy question.",
    "preconditions": [
      "reader role; optional isolated get pods/log grant; named configmap demo-config rule; no wildcard resources."
    ]
  },
  {
    "planId": "K8S07",
    "runtimeId": "lab-k8s07",
    "family": "authorization-rbac",
    "title": "Additive RBAC and group binding union",
    "goal": "Prevent deny-rule and automatic-role misconceptions.",
    "preconditions": [
      "Two custom bindings: readers gives pod reads; log-readers gives pod log get; separate group claims fixture."
    ]
  },
  {
    "planId": "K8S08",
    "runtimeId": "lab-k8s08",
    "family": "authorization-rbac",
    "title": "Authorized writes, admission and persistence",
    "goal": "Show authorization success that still fails admission, and the path to storage when admitted.",
    "preconditions": [
      "Separate demo-writer role allows create configmaps in demo-dev; custom validation requires label training=approved; no actual production resources."
    ]
  },
  {
    "planId": "K8S09",
    "runtimeId": "lab-k8s09",
    "family": "workload-identity",
    "title": "Projected ServiceAccount token issuance and rotation",
    "goal": "Show workload credentials as Kubernetes-issued bound tokens.",
    "preconditions": [
      "Namespace demo-dev; Pod UID pod-1; ServiceAccount UID sa-1; projected token volume; audience https://kubernetes.demo.example; requested lifetime 3600s but returned expiry authoritative."
    ]
  },
  {
    "planId": "K8S10",
    "runtimeId": "lab-k8s10",
    "family": "workload-identity",
    "title": "ServiceAccount identities and RBAC subjects",
    "goal": "Explain workload group membership and why token possession does not grant namespace access.",
    "preconditions": [
      "reader ServiceAccount in demo-dev; bound token from K8S09; no default resource permissions beyond declared cluster defaults."
    ]
  },
  {
    "planId": "K8S11",
    "runtimeId": "lab-k8s11",
    "family": "workload-identity",
    "title": "TokenReview versus offline service-account JWT validation",
    "goal": "Compare current bound-object checks with offline cryptographic validation.",
    "preconditions": [
      "External service has its own credential permitting create tokenreviews; presented token audience vault.demo.example; object-bound token not yet expired."
    ]
  },
  {
    "planId": "K8S12",
    "runtimeId": "lab-k8s12",
    "family": "workload-identity",
    "title": "Audience-isolated ServiceAccount TokenRequest",
    "goal": "Show Kubernetes issuer versus human issuer, and target-specific workload credentials.",
    "preconditions": [
      "Two separate projected tokens for same ServiceAccount: Kubernetes API audience and vault.demo.example; cluster issuer distinct from external human issuer."
    ]
  },
  {
    "planId": "K8S13",
    "runtimeId": "lab-k8s13",
    "family": "token-validation",
    "title": "Missing credentials, anonymous identity and 401/403",
    "goal": "Avoid a misleading universal status-code shortcut.",
    "preconditions": [
      "Isolated variants: anonymous disabled; anonymous allowed only /livez; separately full anonymous with no pod permission."
    ]
  },
  {
    "planId": "K8S14",
    "runtimeId": "lab-k8s14",
    "family": "delegation-extensions",
    "title": "Impersonation permission and constrained variant",
    "goal": "Explain original caller, impersonated identity and the extra authorization checks.",
    "preconditions": [
      "Classic variant permits only target oidc:bob via explicit impersonate resourceNames; target gets reader through fixture. Separate constrained variant beta since 1.36 with gate state shown."
    ]
  },
  {
    "planId": "K8S15",
    "runtimeId": "lab-k8s15",
    "family": "delegation-extensions",
    "title": "Role creation, bind and escalate safeguards",
    "goal": "Explain why CRUD rights on RBAC objects alone cannot delegate arbitrary power.",
    "preconditions": [
      "Separate nonproduction editor can create roles/rolebindings in demo-dev; owns pod-read rights; no bind or escalate permission initially."
    ]
  }
];
export const K8S_VARIANT_INPUTS = {
  "K8S01": {
    "default": {},
    "wrong-state": {
      "returnedState": "SYM(other-state)"
    },
    "wrong-pkce": {
      "redeemedVerifier": "SYM(other-verifier)"
    },
    "wrong-nonce": {
      "idTokenNonce": "SYM(other-nonce)"
    },
    "no-binding": {
      "removeBinding": "read-pods"
    },
    "cache-hit": {
      "clientCache": "valid"
    }
  },
  "K8S02": {
    "default": {},
    "bob": {
      "subject": "bob",
      "groups": [
        "observers"
      ],
      "operation": "pods"
    },
    "missing-sub": {
      "deleteClaim": "sub"
    },
    "wrong-sub-type": {
      "sub": 17
    },
    "wrong-groups-type": {
      "groups": [
        17
      ]
    },
    "missing-tenant": {
      "deleteClaim": "tenant"
    },
    "wrong-tenant": {
      "tenant": "other"
    },
    "failed-user-validation": {
      "usernamePrefix": "",
      "sub": "system:demo"
    },
    "unprefixed-group": {
      "groupPrefix": ""
    },
    "group-string-mismatch": {
      "groups": [
        "reader"
      ]
    },
    "email-verified": {
      "usernameClaim": "email",
      "email": "alice@demo.example",
      "email_verified": true
    },
    "email-unverified": {
      "usernameClaim": "email",
      "email": "alice@demo.example",
      "email_verified": false
    }
  },
  "K8S03": {
    "default": {},
    "bad-signature": {
      "signatureValid": false
    },
    "expired": {
      "exp": 1792627100
    },
    "wrong-audience": {
      "aud": "different-api"
    },
    "issuer-mismatch": {
      "iss": "https://other.demo.example"
    },
    "unknown-key": {
      "kid": "missing",
      "refreshKeys": []
    },
    "rotated-key": {
      "kid": "human-new",
      "refreshKeys": [
        "human-new"
      ]
    },
    "discovery-outage": {
      "discoveryAvailable": false
    },
    "jwks-outage": {
      "kid": "human-new",
      "jwksAvailable": false
    }
  },
  "K8S04": {
    "default": {},
    "bob": {
      "subject": "bob",
      "groups": [
        "observers"
      ]
    },
    "wrong-namespace": {
      "namespace": "demo-prod"
    },
    "delete": {
      "method": "DELETE",
      "name": "demo-pod"
    },
    "group-name-only": {
      "groups": [
        "reader"
      ]
    }
  },
  "K8S05": {
    "default": {
      "bundle": "namespaced-clusterrole-use",
      "subject": "bob",
      "groups": [
        "observers"
      ]
    },
    "namespaced-other-namespace": {
      "bundle": "namespaced-clusterrole-use",
      "subject": "bob",
      "namespace": "demo-prod"
    },
    "namespaced-nodes": {
      "bundle": "namespaced-clusterrole-use",
      "subject": "bob",
      "resource": "nodes",
      "name": "demo-node",
      "namespace": ""
    },
    "clusterwide-dev": {
      "bundle": "clusterwide-pod-read",
      "subject": "bob"
    },
    "clusterwide-prod": {
      "bundle": "clusterwide-pod-read",
      "subject": "bob",
      "namespace": "demo-prod"
    },
    "clusterwide-not-nodes": {
      "bundle": "clusterwide-pod-read",
      "subject": "bob",
      "resource": "nodes",
      "name": "demo-node",
      "namespace": ""
    },
    "named-node": {
      "bundle": "named-node-read",
      "subject": "bob",
      "resource": "nodes",
      "name": "demo-node",
      "namespace": ""
    },
    "unbound-clusterrole": {
      "bundle": "namespaced-clusterrole-use",
      "removeVariantBindings": true,
      "subject": "bob"
    },
    "cross-namespace-role": {
      "roleRefKind": "Role",
      "roleRefName": "reader",
      "bindingNamespace": "demo-prod",
      "namespace": "demo-prod",
      "subject": "bob"
    },
    "immutable-roleref": {
      "mutateRoleRef": true
    }
  },
  "K8S06": {
    "default": {},
    "named-pod": {
      "name": "demo-pod"
    },
    "pod-log-denied": {
      "name": "demo-pod",
      "subresource": "log"
    },
    "pod-log-granted": {
      "name": "demo-pod",
      "subresource": "log",
      "bundle": "subresource-and-name"
    },
    "named-config": {
      "resource": "configmaps",
      "name": "demo-config",
      "bundle": "subresource-and-name"
    },
    "other-config": {
      "resource": "configmaps",
      "name": "other",
      "bundle": "subresource-and-name"
    },
    "unrestricted-config-list": {
      "resource": "configmaps",
      "bundle": "subresource-and-name"
    },
    "cluster-scope": {
      "resource": "nodes",
      "name": "demo-node",
      "namespaceFlag": "demo-dev",
      "namespace": ""
    },
    "non-resource": {
      "path": "/version"
    },
    "review-then-policy-change": {
      "review": true,
      "removeBindingAfterReview": true
    }
  },
  "K8S07": {
    "default": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "bundle": "additive-groups"
    },
    "log-union": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "bundle": "additive-groups",
      "name": "demo-pod",
      "subresource": "log"
    },
    "secrets-denied": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "bundle": "additive-groups",
      "resource": "secrets",
      "name": "demo-secret"
    },
    "remove-log-still-pods": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "bundle": "additive-groups",
      "removeBinding": "group-log-read"
    },
    "restrictive-role-no-subtraction": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "bundle": "additive-groups",
      "restrictiveRole": true
    },
    "group-without-bindings": {
      "subject": "bob",
      "groups": [
        "readers",
        "log-readers"
      ],
      "removeAllBindings": true
    }
  },
  "K8S08": {
    "default": {
      "bundle": "admission-write",
      "resource": "configmaps",
      "write": true,
      "training": "approved"
    },
    "missing-label": {
      "bundle": "admission-write",
      "resource": "configmaps",
      "write": true,
      "training": null
    },
    "invalid-schema": {
      "bundle": "admission-write",
      "resource": "configmaps",
      "write": true,
      "training": "approved",
      "dataType": "number"
    },
    "storage-conflict": {
      "bundle": "admission-write",
      "resource": "configmaps",
      "write": true,
      "training": "approved",
      "alreadyExists": true
    },
    "read-bypass": {
      "bundle": "admission-write",
      "resource": "configmaps",
      "name": "demo-config"
    }
  },
  "K8S09": {
    "default": {
      "serviceAccount": true,
      "rotation": true
    },
    "cached-old-expired": {
      "serviceAccount": true,
      "rotation": true,
      "reload": false,
      "now": 1792631001
    },
    "automount-disabled": {
      "serviceAccount": true,
      "rotation": true,
      "automount": false,
      "explicitProjection": true
    },
    "no-projection": {
      "serviceAccount": true,
      "automount": false,
      "explicitProjection": false
    }
  },
  "K8S10": {
    "default": {
      "serviceAccount": true
    },
    "explicit-binding": {
      "serviceAccount": true,
      "bundle": "serviceaccount-reader"
    },
    "same-name-other-namespace": {
      "serviceAccount": true,
      "saNamespace": "demo-prod",
      "bundle": "serviceaccount-reader"
    },
    "namespace-group": {
      "serviceAccount": true,
      "bundle": "namespace-serviceaccount-group"
    },
    "global-group-other-sa": {
      "serviceAccount": true,
      "saNamespace": "demo-prod",
      "bundle": "all-serviceaccount-group"
    },
    "human-copied-sa-group": {
      "groups": [
        "system:serviceaccounts:demo-dev"
      ],
      "bundle": "namespace-serviceaccount-group"
    }
  },
  "K8S11": {
    "default": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true
    },
    "missing-returned-audience": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "reviewAudiences": []
    },
    "pod-deleted": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "podExists": false
    },
    "pod-uid-changed": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "observedPodUID": "pod-2"
    },
    "pending-delete-within-grace": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "deletionAge": 59
    },
    "pending-delete-after-grace": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "deletionAge": 61
    },
    "offline-deleted-pod": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "offline": true,
      "podExists": false
    },
    "reviewer-denied": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "reviewerAllowed": false
    },
    "external-policy-denied": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "tokenReview": true,
      "externalAllowed": false
    }
  },
  "K8S12": {
    "default": {
      "serviceAccount": true,
      "dualAudience": true,
      "bundle": "serviceaccount-reader"
    },
    "vault-token-at-api": {
      "serviceAccount": true,
      "audience": "vault.demo.example",
      "expectedAudience": "https://kubernetes.demo.example"
    },
    "api-token-at-vault": {
      "serviceAccount": true,
      "audience": "https://kubernetes.demo.example",
      "expectedAudience": "vault.demo.example",
      "offline": true
    },
    "unauthorized-tokenrequest": {
      "serviceAccount": true,
      "tokenRequestAllowed": false
    },
    "returned-shorter-lifetime": {
      "serviceAccount": true,
      "returnedLifetime": 1800,
      "bundle": "serviceaccount-reader"
    }
  },
  "K8S13": {
    "default": {
      "credential": false,
      "anonymous": "disabled"
    },
    "invalid-no-fallback": {
      "credential": true,
      "signatureValid": false,
      "anonymous": "full"
    },
    "livez-eligible-no-grant": {
      "credential": false,
      "anonymous": "livez",
      "path": "/livez"
    },
    "livez-explicit-route-grant": {
      "credential": false,
      "anonymous": "livez",
      "path": "/livez",
      "routeGrant": true
    },
    "endpoint-only-pods": {
      "credential": false,
      "anonymous": "livez"
    },
    "full-anonymous-pods": {
      "credential": false,
      "anonymous": "full"
    }
  },
  "K8S14": {
    "default": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "classic-impersonation"
    },
    "unauthorized-user": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "classic-impersonation",
      "impersonateUser": "oidc:alice"
    },
    "unauthorized-group": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "classic-impersonation",
      "impersonateGroups": [
        "team:readers"
      ]
    },
    "unauthorized-extra": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "classic-impersonation",
      "impersonateExtra": {
        "scope": [
          "demo"
        ]
      }
    },
    "constrained": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "constrained-impersonation"
    },
    "constrained-no-action": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "constrained-impersonation",
      "removeBinding": "operator-constrained-list"
    },
    "constrained-no-identity": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "constrained-impersonation",
      "removeBinding": "operator-constrained-bob"
    },
    "legacy-fallback": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "constrained-impersonation",
      "legacyFallback": true,
      "removeBinding": "operator-constrained-list"
    },
    "target-denied": {
      "subject": "operator",
      "impersonation": true,
      "bundle": "classic-impersonation",
      "namespace": "demo-prod"
    }
  },
  "K8S15": {
    "default": {
      "subject": "editor",
      "bundle": "rbac-editor-baseline",
      "rbacWrite": "role-excess"
    },
    "bind-excess": {
      "subject": "editor",
      "bundle": "rbac-editor-baseline",
      "rbacWrite": "bind-excess"
    },
    "create-held-rights": {
      "subject": "editor",
      "bundle": "rbac-editor-baseline",
      "rbacWrite": "role-owned"
    },
    "bind-held-rights": {
      "subject": "editor",
      "bundle": "rbac-editor-baseline",
      "rbacWrite": "bind-owned"
    },
    "explicit-narrow-bind": {
      "subject": "binding-editor",
      "bundle": "explicit-narrow-bind",
      "rbacWrite": "bind-owned"
    },
    "narrow-other-role": {
      "subject": "binding-editor",
      "bundle": "explicit-narrow-bind",
      "rbacWrite": "bind-excess"
    },
    "namespace-not-cluster": {
      "subject": "editor",
      "bundle": "rbac-editor-baseline",
      "rbacWrite": "cluster-binding"
    }
  }
};
