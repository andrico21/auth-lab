# SMB 3.1.1 multichannel reference notes

Reviewed sources: 2026-10-21. This is a symbolic teaching model; no native Windows/Linux interoperability or computed packet bytes are claimed.

## Scope and scenario IDs

- `lab-smb-multichannel-binding-success`: complete first-channel Kerberos authentication and encrypted file access, authenticated interface discovery, independent second TCP negotiation, signed session binding, fresh same-user GSS context, final client verification, encrypted READ on the existing open file through channel2.
- `lab-smb-multichannel-binding-rejected`: the same prerequisites, followed by an altered binding signature rejected before GSS. This chosen server behavior retains both transports and the original session; the next encrypted READ succeeds on channel1. It creates no channel2 key or accepted channel.

Both scenarios use SMB 3.1.1 (0x0311), SHA512 preauthentication integrity, negotiated AES-CMAC signing and AES128-GCM encryption. The complete initial session is shown, not pre-seeded as an accepted session. The original standalone Kerberos lesson is copied and rebased without mutation. Both initial NEGOTIATE messages advertise multichannel and carry stable client/server GUIDs in these variants.

The second TCP connection negotiates independently with the same ClientGUID, logical server GUID, dialect, protection selections and notifications setting. Its transcript begins at 64 zero bytes. Successful binding derives its signing key from the binding GSS key and the new transcript through the final client request. The final successful response is excluded from that KDF context.

## Key and identity boundaries

| Operation | Key or identity used |
| --- | --- |
| Binding SESSION_SETUP request | Existing `Session.SigningKey`; existing SessionId; Binding flag; PreviousSessionId=0 |
| Binding GSS authentication | Fresh Kerberos authenticator and mutual context using the valid cached CIFS ticket; same user as Session.UserName |
| Successful binding response | New `Channel.SigningKey` |
| Failed SESSION_SETUP response | Existing `Session.SigningKey` |
| Encrypted I/O on either channel | Retained session C2S/S2C cipher keys |
| Existing resource access | Same SessionId, TreeId, FileId and existing read grant |

The client holds the cached CIFS ticket only in its opaque representation. It uses the separately held ticket session key to construct a fresh authenticator. The binding acceptor subkey first belongs to the server and reaches the client only by verified AP-REP processing. The client derives its new channel signing key locally and verifies the final SMB response before channel2 becomes usable.

Binding does not replace the original session key, application key, cipher keys, resource handles or local desktop identity. `WORKGROUPPC\bob` remains the local desktop user and `CORP\alice` remains the network user. SMB session binding is unrelated to TLS channel binding tokens; this profile uses direct TCP445 with no TLS.

AES-GCM nonce uniqueness is session-wide for each directional key. The symbolic allocator continues from the first-channel CREATE/READ (#1/#2) through interface IOCTL (#3) and follow-up READ (#4). It never restarts on the second connection. New-channel traffic retains the existing encryption requirement and does not add a separate signature to the encrypted inner SMB2 message.

## Source discrepancy and interpretation

The [MS-SMB2 published-version page](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) lists revision 88.0 dated 2026-09-28. Current PDF/DOCX links redirected to an endpoint that could not be retrieved during this review. The following interpretation is explicit rather than claiming that those files were inspected.

The online [client binding section 3.2.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9a697646-6085-4597-808c-765bb2280c6e) contains preauthentication handling for 3.1.1 but still lists the older SMB2AESCMAC/SmbSign signing KDF inputs without a dialect branch. The [server GSS section 3.3.5.5.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654) explicitly selects SMBSigningKey and the binding PreauthSession transcript for 3.1.1. This model applies that explicit 3.1.1 rule consistently at both endpoints.

[Upstream Linux client source](https://github.com/torvalds/linux/blob/master/fs/smb/client/smb2transport.c), retrieved on the review date, corroborates this interpretation: `generate_smb311signingkey` supplies SMBSigningKey and the preauthentication hash, and the binding branch generates only the channel signing key. It does not regenerate the session cipher keys. An [immutable historical Linux source snapshot](https://code.googlesource.com/linux/torvalds/linux/+/5eff55d725a4e0dc6fc7709c4b1ca4fe40588d07/fs/smb/client/smb2transport.c) contains the same dialect-specific label/transcript and binding-only key derivation. This is source corroboration, not a live interoperability test, a claim about a particular OS build, or a resolution of the Microsoft editorial discrepancy.

## Failure boundary

[Server signature verification, 3.3.5.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75) requires rejection of a bad signature and permits disconnecting the current connection. This bounded failure selects no disconnect. It happens before GSS and before any new Channel or key allocation.

Do not generalize that result to arbitrary binding failures. Authentication errors in [3.3.5.5.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654) include session and open/tree cleanup. The product explicitly limits its preserved-original-session outcome to the selected early signature failure.

Other primary rules used:

- [Binding preconditions and same-user check, 3.3.5.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e).
- [Interface discovery request, 3.2.4.20.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/147adde4-d936-4597-924a-8caa3429c6b0).
- [Server response key selection, 3.3.4.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7).
- [Client response signature validation, 3.2.5.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157).

The SMB3.0 alternate-channel example was consulted only for sequence context. Its dialect and older cryptographic details were not copied into the 3.1.1 profile.

## Validation

`tests/smb-multichannel-lab.test.mjs` checks registration and base immutability; all canonical held-object boundaries; per-connection request/response matching; session-key proof versus new channel signing key; GSS receipt/verification and client usability ordering; cipher-key retention; nonce uniqueness across both connections; encrypted receipt versus authenticated decoding; early failure isolation; local field replay and exact-object replay; opaque cached-ticket use.

Independent reviewers additionally examine mounted product flows. Pure model tests and mounted mocks do not establish native SMB implementation conformance.
