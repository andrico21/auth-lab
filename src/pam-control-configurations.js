export const PAM_CONTROL_CONFIGURATIONS = Object.freeze({
  "afs-bracket-action-ok": {
    "id": "afs-bracket-action-ok",
    "file": "/etc/pam.d/afs-bracket-action-ok",
    "sha256": "bcd34ca6dcc885805f766ffa1898866cb9b28c82a291e1d30e1d96b94faafd1a",
    "text": "# isolated extended-action fixture\nauth [success=ok default=bad] pam_debug.so auth=success\n"
  },
  "afs-bracket-action-bad": {
    "id": "afs-bracket-action-bad",
    "file": "/etc/pam.d/afs-bracket-action-bad",
    "sha256": "8beb46f849ca4c0fee81db15c79bc31251f86cf5d9186edb70cd5acb5e657243",
    "text": "# isolated extended-action fixture\nauth [success=ok default=bad] pam_debug.so auth=auth_err\n"
  },
  "afs-bracket-action-done": {
    "id": "afs-bracket-action-done",
    "file": "/etc/pam.d/afs-bracket-action-done",
    "sha256": "fbfe9020773a7fcc3a071892b97e55fdc3b8ad52b5c1d5a9c53cb93b28a5940e",
    "text": "# isolated extended-action fixture\nauth [success=done default=die] pam_debug.so auth=success\nauth required pam_deny.so\n"
  },
  "afs-bracket-action-die": {
    "id": "afs-bracket-action-die",
    "file": "/etc/pam.d/afs-bracket-action-die",
    "sha256": "fc2740b29a862c5fea538310176760a03a4eae7ea2a0b9204721a18603ed289b",
    "text": "# isolated extended-action fixture\nauth [success=done default=die] pam_debug.so auth=auth_err\nauth required pam_permit.so\n"
  },
  "afs-close-session-jump": {
    "id": "afs-close-session-jump",
    "file": "/etc/pam.d/afs-close-session-jump",
    "sha256": "3e6ab220578483a19bb839b8790d5df99a4da691246dfe613981adb1c049c166",
    "text": "# isolated cached close-session jump\nsession [success=1 default=ignore] pam_debug.so open_session=success close_session=session_err\nsession requisite pam_deny.so\nsession required pam_permit.so\n"
  },
  "afs-bracket-action-ignore": {
    "id": "afs-bracket-action-ignore",
    "file": "/etc/pam.d/afs-bracket-action-ignore",
    "sha256": "2741e52963f088c90b46ccbeaa14b14c93d424a009b5fec3bc6a40e5edd5fa02",
    "text": "# isolated extended-action fixture\nauth [success=ok default=ignore] pam_debug.so auth=auth_err\nauth required pam_permit.so\n"
  }
});
