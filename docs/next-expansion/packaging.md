# Next-expansion phase reviewer packaging

## Default LLM reviewer handoff

Supply three files by default: one single-digit-megabyte source-and-review ZIP, the exact standalone HTML, and `START-HERE.md`. Keep `SHA256SUMS` alongside for local verification. Do not send the multi-hundred-megabyte full verification ZIP to an LLM unless the reviewer explicitly requests raw evidence.

The compact ZIP retains every canonical application/test input, authored worksheets/profile policies/source ledgers, immutable review inputs, a finding-response matrix, bounded case/test outcomes, all timing comparison cells and a few explicitly scoped fresh captures. `CONTENTS.json` identifies every included and omitted source payload by bytes/hash and reason. Generated duplicate output, bulk external captures, giant state dumps, CPU traces, vendor libraries and superseded reports stay in the verified local forensic record.

Freeze the source snapshot first. Extract the compact ZIP into a new owned file-backed directory, verify every member and the complete canonical application/test hash, then actually build with pinned Bun and automatic installation disabled. Compare every standalone byte and check the final delivery checksums. Packaging proof does not imply a repeated test, browser or performance run, independent acceptance or publication.

The compact packet is a bounded code-review input, not full offline forensic reproduction. Collectors that require omitted source captures or verification-only libraries need the explicitly identified local full evidence. Astra review and explicit publication authorization remain required.

## Full forensic phase packaging (on demand)

`tools/verification/package-next-expansion-review.mjs` packages one explicit P0-P6 contract. It does not decide phase scope, infer test counts, rerun accepted WIN-11 checks, execute acceptance suites, install packages, run browsers, commit, push or deploy. The only product execution during packaging is one actual Bun build from freshly extracted source, with automatic dependency installation disabled. It compares rebuilt and delivered standalone bytes, not just filenames.

A successful package means **package integrity**, not release acceptance. The supplied contract determines which evidence/statuses are acceptable for the phase. Missing/stale required evidence fails closed. A phase contract may explicitly admit `partial`, `blocked`, `failed`, `unverified` or `not-performed` evidence, but those statuses remain visible in the handoff and package status; they never become passes. Such a package is a review candidate, not a claim that its phase exit conditions or the full plan are complete.

## Exact CLI

Run from any directory, using the actual path to the script. File-reference paths inside JSON are relative to the repository root unless absolute; CLI contract/status paths are also repository-root-relative unless absolute. The output path is relative to the invoking working directory unless absolute. Its parent must already exist. The output directory must be new, outside the repository, and have no symlink parent. The tool refuses an existing directory, including a previous successful package.

```sh
bun tools/verification/package-next-expansion-review.mjs --identity --manifest=docs/next-expansion/scenario-manifest.json
bun tools/verification/package-next-expansion-review.mjs --phase=P0 --out=/external/new-p0-review --contract=docs/verification/next-expansion/p0/package-contract.json --status=docs/verification/next-expansion/p0/package-input.json
```

`--identity --manifest=REPO_FILE` only reads current files and prints `{source, standalone, manifest, packager}` identity objects. It does not build or certify anything. Use it after source changes have stopped, before authoring/running current evidence. It provides the exact canonical source inventory expected below. Hash each actual evidence runner separately. An identity printed before a source edit is stale.

The normal invocation accepts exactly `--phase=P0` through `--phase=P6`, `--out=...`, `--contract=...`, `--status=...`. Options use `=`; duplicates, unknown options and missing arguments fail. `--help` prints usage. Runtime prerequisites are Bun and system `zip`/`unzip`; there is no install step. Input files must be regular files with no symlink ancestors. All input bytes are read-only; the tool checks them again before completing the package.

The earlier `package-review-corrections.mjs` intentionally packages the fixed 214-choice correction checkpoint, not this expansion. Its historical census guard is not a current 295-choice gate. Use the phase packager above for the next-expansion candidate; historical archives and their recorded runner identities remain unchanged.

## Version 1 input schema

The following is the exact structural contract. Angle-bracket strings below describe required values, not executable fixture values. These are not sample successful evidence. Required arrays are nonempty unless explicitly allowed empty. SHA256 values are lowercase, 64 hex characters; byte counts are exact nonnegative integers. Extra descriptive keys are allowed but do not replace required keys.

### Common file reference

```json
{"path":"<repository-relative or absolute real file>","sha256":"<64 lowercase hex>","bytes":123}
```

All referenced files must exist and match both fields. Manifest, current report, current runner and current raw files must be inside the repository. Immutable references and retained original/failing/historical files may be outside it. Names cannot introduce archive traversal, control characters, symlinks or special files. Only the output directory is written; original accepted archives/reviews/logs are never rewritten.

### Phase contract (`--contract`)

```json
{
  "schemaVersion": 1,
  "kind": "next-expansion-phase-package-contract",
  "phase": "P0",
  "scope": {
    "description": "<actual bounded phase scope>",
    "requiredRuntimeIds": [],
    "implementedRuntimeIds": [],
    "remainingRuntimeIds": [],
    "counts": {"<contract-defined count name>": 0}
  },
  "manifest": {"path":"<current repository manifest>","sha256":"<hash>","bytes":123},
  "references": [
    {"id":"worker-plan","role":"plan","path":"<immutable supplied plan HTML>","sha256":"5a8478ea904e0862da5b0a6e978b7e7389399ffb62890d4e1c7bbee92774a4a0","bytes":123},
    {"id":"win11-review","role":"accepted-review","path":"<immutable WIN-11 independent review HTML>","sha256":"e1c7af3b593161ab4cb49792a3f044e52760a27e3383f7a4cc8eb1fd21064177","bytes":123}
  ],
  "requiredEvidence": [
    {
      "id":"<phase gate ID>",
      "kind":"<automated, native, mounted, performance, numeric, manual or other precise category>",
      "runner":"tools/verification/<actual retained current runner>.mjs",
      "allowedStatuses":["passed"],
      "bindings":[
        {"pointer":"/identity/sourceSha256","target":"sourceSha256"},
        {"pointer":"/identity/standaloneSha256","target":"standaloneSha256"},
        {"pointer":"/identity/manifestSha256","target":"manifestSha256"},
        {"pointer":"/identity/runnerSha256","target":"runnerSha256"},
        {"pointer":"/status","target":"status"}
      ],
      "execution": {"argv":"/execution/argv","runtime":"/execution/runtime","exitStatus":"/execution/exitStatus"},
      "checks":[
        {"pointer":"/execution/exitStatus","op":"equals","value":0},
        {"pointer":"/scope/actualIds","op":"equals","value":["<independently required IDs from phase contract>"]}
      ],
      "fileReferences":[{"pointer":"/logs/*/file","base":"report"}]
    }
  ]
}
```

`scope` is any nonempty JSON object, copied unchanged and required to match the status's scope exactly. Its names/counts are not imposed by this tool. The example shape is a convention, not mandatory field names. Encode actual acceptance scope in `checks`, not just a descriptive scope string. Use checks against actual ID arrays, branch coverage, mode arrays or discovered suite inventory rather than a cosmetic fixed final test count. This tool validates the supplied contract; it is not an oracle for whether the contract faithfully represents the plan. Review the contract itself.

`references` requires unique safe IDs and at least one `plan` and one `accepted-review` role. Their exact bytes are delivered under `verification/inputs/`. The hashes above are the authoritative supplied plan/review identities, not current gate results or instructions to rerun WIN-11. Other original references may also be listed.

Every required evidence row requires a unique safe ID, runner, kind, allowed statuses, bindings, execution pointers and nonempty checks. A safe ID starts with an ASCII letter/digit and then uses ASCII letters/digits, `.`, `_` or `-`. All bindings must match current identities: `standaloneSha256`, `manifestSha256`, `runnerSha256`, `status`, and either `sourceSha256` or `sourceFiles`. Bindings can point anywhere in the report; report field names are not hard-coded. `sourceFiles` means the entire canonical path-to-hash map, not a convenient subset. The manifest and runner are separate identities, not substitutes for source identity. `status` is one of the explicitly allowed strings, not a guessed interpretation of `passed:true`.

Pointers are JSON Pointer: `~1` escapes `/`, `~0` escapes `~`; empty pointer selects the entire document. As an extension, a segment `*` selects every element of an array. Every selected value must satisfy the binding/check; empty selections fail. A wildcard is reserved for arrays, not object keys. Checks support exactly:

- `equals`: structural JSON equality against required `value` (object key order irrelevant, array order significant).
- `length`: array/string length equals numeric `value`.
- `minLength`: array/string length is at least numeric `value`.
- `includes`: an array contains a structurally equal `value`.
- `notEmpty`: nonempty string, array or object; no `value` is needed.

`execution` pointers must each select one value: nonempty string array `argv`, nonempty `runtime` object and integer `exitStatus`. Passed evidence requires exit status zero. Runtime should record actual Bun/browser/dependency versions, OS and loading mode as applicable, not fictitious platform support. A manual/not-performed record describes the actual record-writing invocation and the unperformed manual scope; its zero writer exit status is not a passed manual check.

`fileReferences` is optional; when used, every selected string path must resolve to a listed current raw file or a canonical source file. `base: "report"` resolves from the report directory; `base: "repository"` resolves from the repository root. An optional `sha256Pointer` selects the corresponding recorded hashes in the same array order; the tool requires equal selection counts and compares each recorded hash with the actual file. For example, `{"pointer":"/screenshots/*/file","sha256Pointer":"/screenshots/*/sha256","base":"report"}` checks every screenshot's identity, not just its presence. Use these declarations for raw logs, screenshots, profiles and fixture paths referenced by the report. Include all such referenced non-source files in `files` below. Report schemas differ; declare their actual pointer locations rather than requiring a legacy report layout.

If an existing raw report lacks the required identity/execution fields, retain it unchanged and have a real current runner write a normalization/execution wrapper that records its invocation, exact identities, raw report identity and actual outcome. Declare that real runner in the contract and include the original report/logs in `files`. Do not retrospectively manufacture a successful run, invent a past-session runner, stamp current identities onto stale output, or supply a wrapper that asserts success without actual underlying evidence. Required checks should bind the wrapper's underlying report identities and independently required coverage too.

For the P6 test-harness repairs, `reconcile-next-expansion-runtime-evidence.mjs` is an actual applicability check, not a new browser run or timing collection. It requires the identical canonical path set, byte-identical values for every non-`tests/` input, the same standalone, manifest and original producer runner, and an exact declared test-only delta with retained original bytes. It reconstructs the original full source hash. Native auxiliary-input differences are allowed only for explicitly retained documentation or `package-next-expansion-review.mjs`, which neither fixed browser/timing producer imports; model, consumer-helper and original runner changes reject reuse. The wrapper embeds the unchanged producer record and keeps its original status, argv, runtime, source/test maps and raw-report identity. The phase contract checks both the applicability result and the original complete coverage/distributions. The full-source compiled/held/numeric/regression reports retain their captured verification-tree context; a later packaging-only tool repair is accompanied by exact old/new helper identities and original code snapshots, never a claim that those suites executed the new packager. A runtime-byte change rejects reuse.

### Current evidence input (`--status`)

```json
{
  "schemaVersion":1,
  "kind":"next-expansion-phase-package-input",
  "phase":"P0",
  "contractSha256":"<SHA256 of exact contract JSON bytes>",
  "scope":{"<same keys and values as contract scope>":"<actual values>"},
  "source":{
    "algorithm":"sha256-path-nul-bytes-nul-v1",
    "sha256":"<canonical snapshot hash>",
    "files":{"<every canonical source path>":"<file hash>"}
  },
  "standalone":{"path":"dist/auth-flow-studio.html","sha256":"<current hash>","bytes":123},
  "manifest":{"path":"<same exact reference as contract>","sha256":"<hash>","bytes":123},
  "evidence":[
    {
      "id":"<required gate ID>","current":true,"status":"passed",
      "summary":"<bounded observed claim, not universal certification>",
      "report":{"path":"<actual current report/wrapper JSON>","sha256":"<hash>","bytes":123},
      "runner":{"path":"tools/verification/<actual runner>.mjs","sha256":"<hash>","bytes":123},
      "files":[{"path":"<actual raw log/capture/profile/fixture>","sha256":"<hash>","bytes":123}]
    }
  ],
  "retained":[
    {
      "id":"<unique retained identity>","role":"historical","status":"<original status>",
      "summary":"<original scope and why it is not current acceptance>",
      "files":[{"path":"<original archive/report/log>","sha256":"<original hash>","bytes":123}]
    }
  ],
  "limitations":{
    "manualG01":{"status":"open","details":"<actual owner, named AT/browser/OS, steps/observations or explicitly unavailable; no automated closure>"},
    "siblingKeyOrigins":{"status":"disclosed","total":6,"details":"<six disclosed sibling-key-origin omissions remain outside accepted scope>"},
    "historicalPerformance":{"status":"open","total":7,"details":"<seven predecessor flags and their exact historical comparison identities; no automatic closure from a new comparison>"},
    "currentPerformance":{"status":"<actual status>","details":"<fresh comparison identity/outcome, open material flags and release disposition>"},
    "livePlatform":{"status":"limited","details":"<actual native versus mounted versus manual versus live/OS interoperability limits>"},
    "source":{"status":"<actual status>","details":"<source/profile/platform uncertainties and explicit limitations>"}
  },
  "remainingScope":"<implemented/partial/unsupported/optional/deferred phase scope and reasons>"
}
```

There must be exactly one current evidence row for each contract requirement and no undeclared rows. `files` and `retained` may be empty arrays, but they must be present. Retained roles are `original`, `failing`, `historical`, `superseded`; their files may include original accepted ZIP/TAR archives. They never satisfy current gate requirements. Labels and bytes are preserved. Retained IDs are unique within that array. Required statuses are `passed`, `partial`, `failed`, `blocked`, `unverified`, `not-performed`; `allowedStatuses` must explicitly admit the actual status. The six limitation keys above are mandatory; each needs nonempty `status` and `details`. The six-omission and seven-historical-flag totals remain explicit even if an accurately evidenced disposition changes. Claiming manual G01 `passed` additionally requires a current `kind: "manual"` evidence row with passed status; automation alone cannot close it.

Canonical `source.files` is the sorted complete inventory of `index.html`, `build.mjs`, `security-policy.mjs`, `package.json`, and every regular file recursively under `assets/`, `src/`, `tests/` (excluding dependency/cache names listed below). The snapshot feeds UTF-8 repository-relative POSIX path, NUL, exact file bytes, NUL for each path, in JavaScript default sorted order, into SHA256. `--identity` computes the authoritative form. Every entry must match, with no missing or extra entries. Full delivered source additionally receives a per-file inventory in package status; current runner and manifest have independent exact references.

## Delivered layout and checksum bases

For phase P0 (the phase suffix changes for P1-P6), the directory contains:

```text
HANDOFF.txt
auth-flow-studio-next-expansion-p0.html
auth-flow-studio-next-expansion-p0-source.zip
auth-flow-studio-next-expansion-p0-verification.zip
SHA256SUMS
```

The source ZIP is rooted at the repository root, not at an extra enclosing directory. It contains buildable source, assets, tests, runners, matrices, worksheets and fixtures. It omits `.git`, `node_modules`, `.cache`, `.bun`, `__pycache__`, coverage caches, OS metadata, `.pyc`, all `docs/verification`, and ZIP/TAR/TGZ/7z archive files. It does not indiscriminately remove images needed by the build. Current verification files are selected explicitly into the overlay; bulk predecessor captures are not silently copied. Necessary archive inputs belong in explicit current raw/retained references, not hidden in the source tree. Original accepted archives stay untouched at their input locations and are copied only when explicitly supplied as retained evidence.

Extracting the verification ZIP into the delivery directory creates an identical root `HANDOFF.txt` and:

```text
verification/
  package-status.json
  path-manifest.json
  internal-manifest.json
  INTERNAL-SHA256SUMS
  inputs/
    phase-contract.json
    evidence-input.json
    <ID>-<immutable plan/review filename>
  overlay/
    <original repository-relative current report/raw paths>
  retained/
    <retained ID>/<index>-<original filename>
```

**All checksum filenames are based at the delivery root, never at `verification/`.**

- Outer `SHA256SUMS` covers the final source ZIP, standalone, final verification ZIP and root handoff. It excludes itself.
- Internal `verification/INTERNAL-SHA256SUMS`, inside the verification ZIP, covers the sibling source ZIP and standalone, the root handoff and every verification member including package status and both manifests. It excludes itself, outer `SHA256SUMS`, and the final verification ZIP. Therefore it is usable after extracting the complete delivered set without duplicating the large source ZIP/HTML inside the verification ZIP.
- `verification/internal-manifest.json` records hashes/bytes for the same delivered payload before the internal records are finalized, plus the complete extracted-source inventory. It explicitly excludes itself, the internal checksum file, outer checksum file and verification ZIP. The checksum file then covers this manifest. There are no self-referential ZIP or manifest hashes.
- `verification/package-status.json` records package integrity separately from gate statuses, exact source/manifest/runner/standalone identities, rebuild stdout/stderr, retained results and limitations. It does not contain a fabricated final verification-ZIP hash; the outer checksum does.
- `verification/path-manifest.json` maps original provenance paths to exact delivered paths and hashes. Original absolute paths in immutable raw logs are archival metadata, not instructions to use a producer's home directory.

## Portable reviewer extraction

Run in the directory holding **all five delivered siblings**, not inside the verification subtree. Extraction into an already populated source directory is intentionally not the documented workflow.

```sh
sha256sum -c SHA256SUMS
unzip -n auth-flow-studio-next-expansion-p0-verification.zip
sha256sum -c verification/INTERNAL-SHA256SUMS
mkdir source
unzip -n auth-flow-studio-next-expansion-p0-source.zip -d source
cp -R verification/overlay/. source/
(cd source && BUN_INSTALL_AUTO=disable bun build.mjs)
cmp source/dist/auth-flow-studio.html auth-flow-studio-next-expansion-p0.html
```

The pre-existing root handoff is byte-identical to its ZIP member; `unzip -n` leaves it in place. Copying the overlay restores original repository-relative evidence paths under `source/`; read raw reports there when they reference sibling logs/captures. Retained files remain separately identified under `verification/retained/`. Path-manifest targets resolve from delivered files; immutable producer-local paths need not exist. Automated source/ZIP inventory checks performed by packaging are byte comparisons over every member, not just a successful unzip or a fresh output timestamp.

The package requires no downloads for its product build. Packaging neither bundles nor installs browser binaries. A phase contract may explicitly deliver pinned verification-only libraries in the evidence overlay; packaging does not install them, and the production build does not use them. Their actual versions and prerequisites remain in the evidence and runner manifests. An offline rebuild is the repository's dependency-free `bun build.mjs` with auto-install disabled, not a claim that the operating system denies network syscalls to arbitrary future build code.

Source exclusions apply only to the source snapshot. Every explicitly promoted verification file, including pinned `node_modules` files, must enter the internal inventory, checksum list and verification ZIP. A relocated check must resolve every path-manifest entry and actually run offline numeric QA; successful ZIP creation alone cannot prove that libraries were included.

For multi-gigabyte evidence, check the temporary filesystem itself, not only the repository disk. Set `TMPDIR` to an owned file-backed staging directory when `/tmp` is a smaller RAM disk. The tool still removes its own temporary stage and does not clear unrelated files.

## Failure behavior and retained limitations

Validation and the real extracted rebuild happen in temporary directories before creating the external output directory. Source/evidence/contract/reference hashes are checked again after packaging; in-flight edits fail instead of creating a misleading current package. If copying final artifacts into a newly created output directory fails, the directory is retained with `package-failure.json` where possible, not reused or silently overwritten. A failed invocation does not rewrite reports or delete accepted input archives. Temporary staging files are removed.

Executed packaging-mechanics evidence is in `docs/verification/next-expansion/packaging/portable-integrity-summary.json` and `refusal-summary.json`: both checksum layers, relocated reference resolution, the documented extracted-source rebuild, byte comparison, and nine stale/missing/false-status/output/symlink refusal probes. The mechanics fixture deliberately retains the superseded native-02 snapshot's nine failures; package integrity does not convert those failures into current P0 UI or release acceptance. Current phase contracts must bind their own real evidence. Manual G01, the six disclosed sibling-key-origin omissions, seven historical performance flags, fresh comparison limits and source/platform/live interoperability limits remain separately visible.
