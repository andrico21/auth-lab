export const PAM_EXISTING_CONFIGURATIONS = Object.freeze({
  "afs-existing-local": {
    "id": "afs-existing-local",
    "service": "afs-login",
    "file": "/etc/pam.d/afs-login",
    "sha256": "0283d64d50a0f1c7ca1fbc6d9332433ad9e3715c74588d2b5914d3f06bdc1a02",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\nsession required pam_unix.so\nsession optional pam_systemd.so\n"
  },
  "afs-existing-local-no-logind": {
    "id": "afs-existing-local-no-logind",
    "service": "afs-login",
    "file": "/etc/pam.d/afs-login",
    "sha256": "c071fb4b1e0d202b3dbdf5e64b925454c69b8e011b57c79c5b9ad6c25fc7c8ab",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\nsession required pam_unix.so\n"
  },
  "afs-existing-local-nullok": {
    "id": "afs-existing-local-nullok",
    "service": "afs-login",
    "file": "/etc/pam.d/afs-login",
    "sha256": "dbb7082688c9e7545e2b82db9549ca79698bebc493948c384d804656dffadc3d",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so nullok\naccount required pam_unix.so\nsession required pam_unix.so\nsession optional pam_systemd.so\n"
  },
  "afs-existing-sssd": {
    "id": "afs-existing-sssd",
    "service": "afs-login",
    "file": "/etc/pam.d/afs-login",
    "sha256": "f9e78103c490ddbe2895c96578a48aaa4b70de89388e365efb1dd16513ecae39",
    "text": "# Authored selected service; not a distro default\nauth required pam_sss.so\naccount required pam_sss.so\npassword required pam_sss.so\nsession required pam_sss.so\n"
  },
  "sudo": {
    "id": "sudo",
    "file": "/etc/pam.d/sudo",
    "sha256": "5a66f82eaed47d90bbeb70afd8a1deab6dbc376d2ab1afcb4f8884a4f6084d35",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  },
  "su": {
    "id": "su",
    "file": "/etc/pam.d/su",
    "sha256": "149324464b639c652de857a6d72610c38863c894cdd5f35b44955e8a5bfae123",
    "text": "# Authored selected service; not a distro default\nauth sufficient pam_rootok.so\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  },
  "su-no-rootok": {
    "id": "su-no-rootok",
    "service": "su",
    "file": "/etc/pam.d/su",
    "sha256": "5a66f82eaed47d90bbeb70afd8a1deab6dbc376d2ab1afcb4f8884a4f6084d35",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  },
  "su-login": {
    "id": "su-login",
    "service": "su-l",
    "file": "/etc/pam.d/su-l",
    "sha256": "149324464b639c652de857a6d72610c38863c894cdd5f35b44955e8a5bfae123",
    "text": "# Authored selected service; not a distro default\nauth sufficient pam_rootok.so\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  },
  "su-login-no-rootok": {
    "id": "su-login-no-rootok",
    "service": "su-l",
    "file": "/etc/pam.d/su-l",
    "sha256": "5a66f82eaed47d90bbeb70afd8a1deab6dbc376d2ab1afcb4f8884a4f6084d35",
    "text": "# Authored selected service; not a distro default\nauth required pam_unix.so\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  },
  "sshd": {
    "id": "sshd",
    "file": "/etc/pam.d/sshd",
    "sha256": "57421fba3e34c40cc1f115c3820d6b8509c0b1ef1bd86fca8ff4934fa764c1ad",
    "text": "# Authored selected service; not a distro default\nauth required pam_sss.so\naccount required pam_sss.so\nsession required pam_sss.so\n"
  },
  "sshd-publickey": {
    "id": "sshd-publickey",
    "service": "sshd",
    "file": "/etc/pam.d/sshd",
    "sha256": "e8b65859542f2af10f6cfda82434b9c75ddb6221268aee180cb8c97b0cec9311",
    "text": "# Authored selected service; not a distro default\naccount required pam_unix.so\naccount required pam_access.so\nsession required pam_unix.so\n"
  }
});
