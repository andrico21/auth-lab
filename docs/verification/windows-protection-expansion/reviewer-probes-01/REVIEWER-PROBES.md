# Supplied ui05 / pam05 probes: exact adaptation and actual results

Candidate-07 is a reviewer-probe-complete handoff of the **unchanged candidate-06 product**: canonical source `b743e4fc4cc8f9a804c55c1d8b2f8a0f845fab9caf94bb66d0d75c4a3396b825` (256 files), standalone `9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694` (5,583,631 bytes). No further app, test, model, renderer, native producer or compiler change was needed.

The candidate-05 review SHA256 is `029ec2870e00fa331560826b484c3c0d6acd8bdf7b243d000105b050d20bd8e9`. Its inert scripts were extracted by HTML entity decoding, without reformatting or changing trailing-newline state. Originals, adapted scripts and unified diffs are supplied under this `review/` directory.

## Only three edits across the two scripts

- `ui05-probe.mjs`: change its one emitted SHA256 pin from the reviewed candidate-05 HTML to the exact current HTML above. Its real `[data-pam-disclosure="aggregates"]` / `Completed API aggregate results` mislabel check is unchanged.
- `pam05-probe.mjs`: change the same one emitted pin, and change only the classification contract's actual-value expression to parse the rendered aggregates disclosure's `<pre>` JSON instead of testing `classification.values`, which is the canonical map.
- Every other assertion, expectation, original diagnostic label, fixture and history/custody/flag/public-boundary check remains byte-for-byte unchanged. The literal assertion label `Exact supplied candidate05` is retained; the updated digest, not that historical label, binds the actual current HTML.

The review explicitly permits compatible canonical maps plus a correct renderer partition (lines 417-420), and requires adapted classification inspection without weakened positive assertions (lines 827-830).

## Why the unadapted PAM predicate still flags six variants

The old classification predicate asks the canonical map to contain no `prelim`/`update` keys. This product intentionally retains those compatible keys and separates them in rendering, as the review permits. A hash-pin-only copy of `pam05` therefore still records six classification mismatches per mode even though the public disclosure is correct. The literal original emitted script would first reject the superseded HTML hash as well.

We did not rerun the reported old-script mismatch merely to confirm it. The six state-only mismatches are explicitly **derived from canonical values preserved in the actual new outputs**, not presented as a new unadapted-script execution or a product failure. The adapted contract inspects the real completed-public JSON; it neither deletes the internal state nor hides those observations. `contractFailures` and `disclosureMislabels`, not process exit alone, determine the results below.

## Actual worker executions with pinned Bun 1.4.2

| Script | Mode | Supporting checks | Render/history positions | Substantive failure array |
|---|---|---:|---:|---|
| ui05 | source | 902 | 396 | `disclosureMislabels: []` |
| ui05 | emitted | 904 | 396 | `disclosureMislabels: []` |
| pam05 | source | 5,163 | 1,723 | `contractFailures: []` (all 62 contracts passed) |
| pam05 | emitted | 5,165 | 1,723 | `contractFailures: []` (all 62 contracts passed) |

Each PAM mode checks 55 existing executions and 1,331 source/runtime prefixes; dangling-secret-use and invalid-public-call arrays are empty. Source/emitted observation arrays match exactly. The two extra emitted supporting checks bind the exact HTML digest and its one actual IIFE. Counts overlap and must not be added into a larger unique-case count.

These are **worker executions of minimally adapted reviewer scripts**, not a new independent Astra decision or a Node execution. Original output scope/labels are preserved verbatim; this wrapper supplies the actual execution class. No new Chromium, OS/PAM, assistive-technology, performance or exact-CI acceptance is implied. Prior actual 2,395/135 local regression, 305/12 affected, 141-cell browser and 328-choice compiled results remain their original runs on identical product/producer bytes, not new executions here.

## Files and historical prerequisite

At ZIP root:

- `review/supplied/{ui05-probe.mjs,pam05-probe.mjs}`: exact supplied decoded bytes.
- `review/adapted/{ui05-probe.mjs,pam05-probe.mjs}`: the only permitted adaptations above.
- `review/diffs/{ui05-probe.patch,pam05-probe.patch}`: exact unified diffs against those originals.
- `review/outputs/{ui05-source.json,ui05-emitted.json,pam05-source.json,pam05-emitted.json}`: all four full original outputs, unedited.
- `review/process/`: actual argv, timing, exit, stdout and stderr wrappers for all four runs.
- `review/windows-protection-02/source/`: all 250 exact original canonical app/asset/test inputs required to supply the semantic probe's historical sibling, source identity `14ce8c3ec6ab5754150a3e38a839e2859f202001eb37f02968cb4856b6009ed5`.
- `source/docs/verification/windows-protection-expansion/reviewer-probes-01/{inputs-01.json,summary-01.json}`: complete input/diff/prerequisite binding and the explicit substantive-array result summary. Their archive-member mappings identify review-only files.

The historical source was actually extracted and every canonical byte checked against the retained original candidate-02 compact archive, SHA256 `aa9ed4feffa682246a3f62b9ac74aa7854ca7a5decf19f32d30a1c0f78048cf3`. This is the real old source, not a current model labelled old. Historical documentation/bulk forensics and the old HTML are not required by these imports and are not claimed supplied here.

## Reproduce without changing the supplied relative imports

Use pinned Bun 1.4.2 first in PATH, an extracted packet beside the external standalone, and a **fresh** `reviewer-run` directory. The scripts expect `current/source`, `current/independent-validation` and a sibling `windows-protection-02/source`; archive paths stay safely under `review/`, so stage that documented layout first:

~~~sh
mkdir -p reviewer-run/current/independent-validation reviewer-run/windows-protection-02
cp -a source reviewer-run/current/source
cp -a review/windows-protection-02/source reviewer-run/windows-protection-02/source
cp review/adapted/ui05-probe.mjs review/adapted/pam05-probe.mjs reviewer-run/current/independent-validation/
cp auth-flow-studio-windows-protection.html reviewer-run/current/
export BUN_CONFIG_NO_AUTO_INSTALL=1 BUN_INSTALL_AUTO=disable
bun --no-install reviewer-run/current/independent-validation/ui05-probe.mjs source
bun --no-install reviewer-run/current/independent-validation/ui05-probe.mjs emitted
bun --no-install reviewer-run/current/independent-validation/pam05-probe.mjs source
bun --no-install reviewer-run/current/independent-validation/pam05-probe.mjs emitted
~~~

Fresh JSON results are written beside the staged scripts. Inspect both substantive arrays in those results. Automatic installation is disabled; no OS-enforced network-denial claim is made. The original older provenance05 Python audit is not represented as a current-candidate execution.

Only B's classification correction awaits independent closure. A and the six earlier whole-finding closures remain preserved, while CI, native Windows, G01, performance and inherited release gates remain open/unwaived. No commit, push, deployment or release authorization.
