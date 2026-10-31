# Corrected-02 changed-input performance repeat

Frozen before collection: `fixtures-review02.json`, SHA256 `f27e5c334c1ce31e7225f8264604b073061cb4cfe2dc805bc443c767b0505144`.

Candidate: 271 canonical files, `01f4f40fc980868085d7bcdc941e6cafd3a83de845f94f5c348c549eae6da430`; standalone 5,668,235 bytes, SHA256 `52479dd292643231ca5945c99fd2df41288d502de530013a07f08a28a93398a5`.

Accepted07 control remains canonical `b743e4fc4cc8f9a804c55c1d8b2f8a0f845fab9caf94bb66d0d75c4a3396b825`, standalone SHA256 `9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694`. No install, baseline mutation or production instrumentation is permitted.

## Unchanged method and matrix

Every review01-02 arm, fixture, viewport, loading mode, index state, paired comparison, candidate action, field endpoint and rule is structurally identical. Only the candidate identity and repeat/provenance metadata change. The old fixture and all old measurements remain immutable.

- Three real loaders: source HTTP, emitted HTTP and standalone file.
- Alternating paired accepted07 Full/new Full and same-candidate Full/Compact arms.
- Seven retained measured samples and one separately retained warmup per arm; no outlier removal.
- Candidate-only ordinary/large actions and actual Basic/Core/MCP09 field-list and meaningful definition endpoints.
- Original host-monotonic action-to-usable-result boundary, unchanged producer and browser/helper/runtime bindings.
- Ordinary median target 250 ms, maximum target 500 ms. No thresholds or variability/material rules are loosened.
- Serial timing only after functional/browser jobs finish, before the complete CI job. Resource instrumentation is a separate serial command and is not latency evidence.
- Resource repeat: 20 deliberately paused Compact/Full roundtrips per loader, stable-warmup owned listener/observer/timer and collected detached-node growth bounds remain zero. Heap bytes and unsupported evidence retain their explicit qualifications.

Declared matrix size is not a result. Current counts, flags, exit codes, collection errors and unchanged-input checks come from the completed current reports and `current-results-review02.json`. No historical field timing baseline, physical-phone speed, human/AT acceptance or blanket no-leak claim is inferred.

## Open historical scopes

The 37 earlier b91 flagged rows and 60 corrected-01/7bac flagged rows remain open in their original scopes. They are neither added together as unique regressions nor waived by a later candidate measurement. Astra closure, owner/human/device/AT/Windows/DC/PAM and publication gates remain independent. Version stays 1.1.1; no commit, push or deployment is authorized.
