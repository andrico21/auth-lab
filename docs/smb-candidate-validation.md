# SMB candidate validation and provenance

## Current four-finding recheck candidate

Version: 1.2.1-smb.1. Standalone: **2,898,880 bytes**, SHA-256 `9a3fc759c77502b52dd7b4d5da0851d706b36e7a0bf0afbe73aca0555798e924`.

The immutable requesting review, SHA-256 `c67d9fa079e9af33d3d8f392028702a898d2f0e401fb92643aa72d81d56a6abe`, closed the original nineteen findings. The subsequent accepting review, SHA-256 `d83a8930e52a4f6e7630e7cee7a71dfac116bb15305ef9795f025fa71bf3128c`, independently closes NET-05, WIN-09, WIN-10 and SMB-R01 and retains those earlier closures. That review deferred the nonblocking P3 WIN-11 follow-up; its [separate independent review](reviewer-handoff/auth-flow-studio-win11-independent-review.html) now accepts its bounded repair against HTML `91cd57f410eede179cc8f464b717a76cee3d93a115e6e544d23406e86f26e257`. The original accepted standalone, archives and execution reports remain unchanged, with the later acceptance recorded in its own sidecar.

Fresh checks use Bun, not Node:

- Actual emitted-bundle smoke: **214/214 choices**, including CSP hash verification.
- Real Chromium in source HTTP, standalone HTTP and direct-file mode: all twelve SMB IDs, all 53 RadSec decoded field occurrences with three actual field replays, six H-side result paths, eleven Windows AES contexts and five displayed SMB key explanations, plus preserved earlier targeted surfaces. No application runtime errors or CSP violations were observed.
- Independent numeric verifier: **31/31 cases** on both Bun 1.4.2 and 1.4.3; numerical verifier inputs are unchanged.
- Full bounded regression: **1,505/1,505 tests across all 87 files**, Bun 1.4.2, zero failures and unchanged source/test identities. The report and all per-file commands/logs are under `verification/review-corrections-recheck/regressions/`; neither earlier 1,490-test result substitutes for this current run.
- The strict package generator binds the independent recheck and reviewed predecessor source ZIP, records all four regression/native pointers and all twelve SMB boundaries, compares extracted source files, and performs an actual offline Bun rebuild that must match the delivered HTML.

Current reports are under `verification/review-corrections-recheck/`; all generators and regeneration commands are shipped. Current WinRM capture names accurately describe their protected command-result inspector. Manual G01, current broad native/performance and live interoperability remain unestablished.

`independent-closure-status.json` records acceptance separately from the immutable pre-review disposition and run reports. Hash-only acceptance recording matched 154 product/build/test/asset inputs and the exact accepted HTML/source/verification delivery; it did not rebuild or rerun tests/native/crypto. The source checkout's subsequent changes are only review and documentation metadata, not a newly reviewed executable or replacement archive.

## Reviewed nineteen-fix predecessor - historical input

The independent recheck reviewed HTML `8cbb6ae44090eb7e4d1a46eebf22bf2b00756c47f4ccaaa9b7d907e3010b9651` (2,894,460 bytes), source ZIP `87a326e18cb4c4b060306687eaf3079a993771100df24e10aaefc2954788e520` and verification ZIP `30e3532d1cd4a14b45dfd77d373cbb9645dca8e3abeeba6fd8806dcededae236`. Its supplied Bun run passed 1,490 tests across 86 files; the independent review separately records 1,490 passing Node tests. The reviewer audited supplied Bun/native/numeric reports, not fresh reviewer executions of those environments. This evidence is distinct from the current four-finding recheck.

## Original incoming candidate - historical input

The supplied `auth-flow-studio-smb311-candidate-source.zip` has SHA-256 `db39bafb05bfce96b4af42042ad9184efcfa0428c12cfb97e371005153fe639c`. Its original package manifest and reviewer evidence are preserved under `reviewer-handoff/`. These are records of a different artifact:

- Incoming version: 1.2.1-smb.1; coordinating review date: 2026-10-21.
- External Node build: 2,836,201 bytes; SHA-256 `7c049674d8d0b128075029dd8c43da5b07fab47a746cf6d0be1d862c09371ba7`.
- External full regression: 1,462/1,462, 84 files, Node v24.19.0; 214 emitted choices.
- External focused checks: 16 base/mounted SMB cases and 10 multichannel cases.
- That review did not exercise a native browser and left the original expansion's nineteen findings open.

The local correction work does not rewrite those historical results or claim their independent acceptance for the new artifact. Targeted Chromium and deterministic models do not establish screen-reader comprehension, cross-engine or live Windows/Linux SMB interoperability, or computed SMB cryptographic packets.
