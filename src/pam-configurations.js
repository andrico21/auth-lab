import {PAM_EXISTING_CONFIGURATIONS} from './pam-existing-configurations.js';
import {PAM_CONTROL_CONFIGURATIONS} from './pam-control-configurations.js';
// Exact authored Linux-PAM fixtures; mirrored physical files in docs/pam-foundations/configs.
export const PAM_CONFIGURATIONS = Object.freeze({
  ...PAM_EXISTING_CONFIGURATIONS,
  ...PAM_CONTROL_CONFIGURATIONS,
  "afs-login": {
    "id": "afs-login",
    "file": "/etc/pam.d/afs-login",
    "sha256": "d2c86e58deb3051da5b585386f960769b420138aae48e67047421055515e0ba9",
    "text": "# /etc/pam.d/afs-login - teaching profile\nauth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\nsession required pam_unix.so\nsession required pam_limits.so\n"
  },
  "afs-child": {
    "id": "afs-child",
    "file": "/etc/pam.d/afs-child",
    "sha256": "c2ec7d52f9732ed332b176a7ae1f6b3f954b3f0816e734b73281d9f68eaf9684",
    "text": "# deterministic control child\nauth sufficient pam_debug.so auth=success\n"
  },
  "afs-deny": {
    "id": "afs-deny",
    "file": "/etc/pam.d/afs-deny",
    "sha256": "27fdb5030a7b30d94af41e977e413b6dc22ea8f5cc558efbaf007db30e295879",
    "text": "# selected different service\nauth required pam_deny.so\naccount required pam_permit.so\nsession required pam_permit.so\n"
  },
  "afs-required-deferred-failure": {
    "id": "afs-required-deferred-failure",
    "file": "/etc/pam.d/afs-required-deferred-failure",
    "sha256": "808965358e0b2e547b60f9e62bac8f2be7b7d30b66e3c51d578f32f3bdcf18d2",
    "text": "# deterministic simulated module results for learning control flow\nauth required pam_debug.so auth=auth_err\nauth required pam_debug.so auth=success\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-requisite-immediate-failure": {
    "id": "afs-requisite-immediate-failure",
    "file": "/etc/pam.d/afs-requisite-immediate-failure",
    "sha256": "5194583991aaa6f6c683eecf2496279b0a29e2a25a35d142e2e1980496c99c8d",
    "text": "# deterministic simulated module results for learning control flow\nauth requisite pam_debug.so auth=auth_err\nauth sufficient pam_debug.so auth=success\nauth required pam_debug.so auth=success\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-sufficient-early-success": {
    "id": "afs-sufficient-early-success",
    "file": "/etc/pam.d/afs-sufficient-early-success",
    "sha256": "1c32d7a3edb960b3f88478535d9d1780db186c2a32cc92bed41dbd01c43e2461",
    "text": "# deterministic simulated module results for learning control flow\nauth sufficient pam_debug.so auth=success\nauth required pam_deny.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-sufficient-after-failure": {
    "id": "afs-sufficient-after-failure",
    "file": "/etc/pam.d/afs-sufficient-after-failure",
    "sha256": "e3a29186a899d255a51fdc4e2ef8a90e7edbf82a77f2e208b6caf9cfce4aad22",
    "text": "# deterministic simulated module results for learning control flow\nauth required pam_debug.so auth=auth_err\nauth sufficient pam_debug.so auth=success\nauth required pam_debug.so auth=success\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-sufficient-failure-fallback": {
    "id": "afs-sufficient-failure-fallback",
    "file": "/etc/pam.d/afs-sufficient-failure-fallback",
    "sha256": "d211ff2689583aacaf3627feedd798a3cce9372077bd6fd469e503c85a14d44e",
    "text": "# deterministic simulated module results for learning control flow\nauth sufficient pam_debug.so auth=auth_err\nauth required pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-optional-nondecisive": {
    "id": "afs-optional-nondecisive",
    "file": "/etc/pam.d/afs-optional-nondecisive",
    "sha256": "e8e23b88fd4566ddff28e3f587013ca019b527ddee4f09ee2d919c05336251e7",
    "text": "# deterministic simulated module results for learning control flow\nauth required pam_permit.so\nauth optional pam_debug.so auth=auth_err\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-optional-only-success": {
    "id": "afs-optional-only-success",
    "file": "/etc/pam.d/afs-optional-only-success",
    "sha256": "401eac51ddeeea6251ef6c3ae7f8a639e45864f3c805d14cc3ae3ddd8669c2a6",
    "text": "# deterministic simulated module results for learning control flow\nauth optional pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-optional-only-failure": {
    "id": "afs-optional-only-failure",
    "file": "/etc/pam.d/afs-optional-only-failure",
    "sha256": "49f8efb436b0d99f1f32f6e09a8c2e67690ef0b0fdeca2fba0cc266949a52beb",
    "text": "# deterministic simulated module results for learning control flow\nauth optional pam_debug.so auth=auth_err\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-bracket-success-jump": {
    "id": "afs-bracket-success-jump",
    "file": "/etc/pam.d/afs-bracket-success-jump",
    "sha256": "dc2796995d9731e4ad00cd30b9486d28397f506ca53e26c2872bec5229b6fe57",
    "text": "# deterministic simulated module results for learning control flow\nauth [success=1 default=ignore] pam_debug.so auth=success\nauth requisite pam_deny.so\nauth required pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-bracket-default-denial": {
    "id": "afs-bracket-default-denial",
    "file": "/etc/pam.d/afs-bracket-default-denial",
    "sha256": "689218ff8c4e7ef1456600a3f0da4bdab042cb319a820a2e37f3d20a9044337d",
    "text": "# deterministic simulated module results for learning control flow\nauth [success=1 default=ignore] pam_debug.so auth=auth_err\nauth requisite pam_deny.so\nauth required pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-include-termination": {
    "id": "afs-include-termination",
    "file": "/etc/pam.d/afs-include-termination",
    "sha256": "9f8c053076daca98117e88029d783ece0e8dd8bac85c12441c12ffd88c1008b9",
    "text": "# deterministic simulated module results for learning control flow\nauth include afs-child\nauth required pam_deny.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-substack-termination": {
    "id": "afs-substack-termination",
    "file": "/etc/pam.d/afs-substack-termination",
    "sha256": "b80069ae15165e08904c03626f378a75d7a14454d219ad5a62965f5626229cd6",
    "text": "# deterministic simulated module results for learning control flow\nauth substack afs-child\nauth required pam_deny.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-substack-failure": {
    "id": "afs-substack-failure",
    "file": "/etc/pam.d/afs-substack-failure",
    "sha256": "2e14475f57c631152b8726808b991e26711689ee88bc8e6eb279eb7b0f51e3c1",
    "text": "# deterministic simulated module results for learning control flow\nauth substack afs-child-fail\nauth required pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-substack-jump-boundary": {
    "id": "afs-substack-jump-boundary",
    "file": "/etc/pam.d/afs-substack-jump-boundary",
    "sha256": "383ede09e2c36f85a41f56618d286062111ce729cb85d4c0d95610d965ee64af",
    "text": "# deterministic simulated module results for learning control flow\nauth [success=1 default=ignore] pam_debug.so auth=success\nauth substack afs-child\nauth required pam_permit.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-module-unavailable": {
    "id": "afs-module-unavailable",
    "file": "/etc/pam.d/afs-module-unavailable",
    "sha256": "566abce4e35856dc245dfabf3b620fb6fde4fd79f20916498e1b180c56041125",
    "text": "# deterministic simulated module results for learning control flow\nauth required pam_unavailable.so\naccount required pam_permit.so\npassword required pam_debug.so prechauthtok=success chauthtok=success\nsession required pam_permit.so\n"
  },
  "afs-child-fail": {
    "id": "afs-child-fail",
    "file": "/etc/pam.d/afs-child-fail",
    "sha256": "9d0b1ae4a5163f9d3d7fcfbcfde5acd35919b2ae6521a72a28344bc1de7c8338",
    "text": "# child failure\nauth requisite pam_debug.so auth=auth_err\nauth required pam_permit.so\n"
  },
  "afs-child-range": {
    "id": "afs-child-range",
    "file": "/etc/pam.d/afs-child-range",
    "sha256": "1f95965ce3378d0c847273a04c537fa8938722e909c437f0cdc5b6ce1d4bacbb",
    "text": "# child scoped in-range jump\nauth [success=1 default=ignore] pam_debug.so auth=success\nauth required pam_deny.so\nauth required pam_permit.so\n"
  },
  "afs-child-overrun": {
    "id": "afs-child-overrun",
    "file": "/etc/pam.d/afs-child-overrun",
    "sha256": "f7f575fa4ab677ac2a8d8c17a80dd0eb337fb2915882b320c562f4d25549d6fd",
    "text": "# child scoped overrun\nauth [success=2 default=ignore] pam_debug.so auth=success\nauth required pam_permit.so\n"
  },
  "afs-parent-child-overrun": {
    "id": "afs-parent-child-overrun",
    "file": "/etc/pam.d/afs-parent-child-overrun",
    "sha256": "5625a76f2a2525010ffddf5dcc3bd561285e6287e98a3392ae8b30309b764d9a",
    "text": "# scoped child jump\nauth substack afs-child-overrun\nauth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n"
  },
  "afs-child-in-range": {
    "id": "afs-child-in-range",
    "file": "/etc/pam.d/afs-child-in-range",
    "sha256": "6972f11def590d6dcfd1b86ec91c85440028be31585e0280518e52f72d9dd9ba",
    "text": "# scoped child jump\nauth substack afs-child-range\nauth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n"
  },
  "limits.conf": {
    "id": "limits.conf",
    "file": "/etc/security/limits.conf",
    "sha256": "b946749db2c8497120bb8760b09ce6264b5ce445ef81944f1893e45c0741c9bc",
    "text": "labuser soft nofile 1024\nlabuser hard nofile 4096\n"
  }
});
