# Pages publication gate

## Scope and evidence status

This change addresses W11-F4 from the supplied WIN-11 independent review. The review identified two independently triggered workflows: CI checked build freshness, numeric vectors and tests, while Pages could publish after only its own build. That description is historical evidence, not a live workflow observation.

Publication now has one dependency graph in `.github/workflows/ci.yml`:

```text
immutable event SHA checkout
  -> Bun 1.4.2 build
  -> committed dist freshness
  -> frozen isolated verification dependency install
  -> pinned full cryptographic vectors
  -> full isolated test suite
  -> trusted-main-only staging and Pages artifact upload
  -> successful test job dependency
  -> trusted-main-only Pages deployment of that artifact
```

The obsolete `.github/workflows/pages.yml` is removed. There is no second Pages trigger, checkout or build. This document describes the authored configuration; no live CI run, external dispatch, push or deployment was performed as part of this change. Local structural checks and integrated build/test results must be recorded separately by the integration owner.

## Trusted event, ref and SHA

Every publication requires all of these conditions:

- `github.repository == 'andrico21/auth-lab'`.
- `github.ref == 'refs/heads/main'`.
- Either `github.event_name == 'push'`, or `github.event_name == 'workflow_dispatch'` with the boolean `inputs.publish_pages` set to `true`.
- The `test` job completed successfully in this same workflow run.

The same repository/ref/event predicate guards artifact staging, artifact upload and the deploy job. The deploy job additionally declares `needs: test` and `needs.test.result == 'success'`. Neither the job nor the upload steps use `always()`, failure-tolerant steps or a success override.

Checkout explicitly uses `${{ github.sha }}`. For a main push this is the pushed commit; for an allowed manual main run it is the commit selected by GitHub for that main execution. The value remains the run's immutable event SHA, not a later checkout of a moving branch. A later main update does not silently change the candidate being tested or deployed. PR runs check out their event SHA, ordinarily GitHub's PR merge commit, but are never publication candidates.

| Execution | CI checks | Upload / deploy eligibility |
| --- | --- | --- |
| Trusted repository, main push, all checks succeed | Full gate | Allowed |
| Trusted repository, main push, any gate fails or is cancelled | Stops or fails | Blocked |
| Pull request, including one targeting main | Full gate | Blocked regardless of result |
| Feature-branch push | Full gate | Blocked regardless of result |
| Manual main run, `publish_pages: true`, all checks succeed | Full gate | Allowed |
| Manual main run, `publish_pages: false` (default) | Full gate | Blocked |
| Manual feature-branch or tag run, even with `publish_pages: true` | Full gate | Blocked |
| Any run in a different repository, including a fork's own main push | Full gate | Blocked |
| Missing or failed artifact upload | Test job fails | Blocked |
| Missing artifact during deploy | No alternate candidate or build | Deploy fails |

A manual invocation must select the `main` branch and explicitly enable `publish_pages`. It is not a bypass and cannot select an external run's artifact, supply an arbitrary candidate SHA, or skip vectors/tests. The workflow's manual input defaults to testing only. This configuration does not authorize an operator to publish: the project's independent review and explicit publication authorization remain separate process requirements.

## Artifact lineage and failed-CI prevention

The `test` job retains the existing commands in order:

1. `bun run build` with Bun `1.4.2`.
2. `git diff --exit-code -- dist/` to reject a stale committed standalone bundle.
3. `bun install --cwd tools/verification/expansion-crypto --frozen-lockfile --ignore-scripts` for the isolated, pinned verification dependency tree.
4. `bun run verify:crypto` for the full pinned cryptographic vectors.
5. `bun run test`, retaining the package script `bun test --isolate --timeout=900000 tests/*.test.mjs` without reducing scope or raising its deadline.

Only after every command succeeds does an eligible run copy `dist/auth-flow-studio.html` to `_site/index.html` and upload `_site` using `actions/upload-pages-artifact@v5`, explicitly named `github-pages`. Staging changes only the served filename, not the standalone bytes. A build, freshness, install, vector or test failure leaves the subsequent steps skipped under GitHub's normal success condition and prevents the dependent deploy job. A staging or upload failure also fails `test` and blocks deploy.

The deploy job has no checkout, Bun setup, source download or build. `actions/deploy-pages@v5` requests `artifact_name: github-pages` from the current workflow run, not a branch, arbitrary run ID or another workflow's successful build. That artifact is uploaded only by the successful CI job for the same event SHA. `actions/configure-pages@v6` runs in the deploy job before deployment; it does not create a replacement build. An expired or absent artifact cannot fall back to a different checkout. A rerun must still satisfy the job dependency and have the expected artifact available in the same run.

The existing action majors and runner convention are retained: `actions/checkout@v7`, `oven-sh/setup-bun@v2`, Pages configure `@v6`, Pages upload/deploy `@v5`, and `ubuntu-26.04`. No new action or runtime dependency is introduced.

## Permissions and concurrency

Workflow-wide permissions are empty. The test job receives only `contents: read`; it never receives Pages write or OIDC minting permission, including on PRs. Only the gated deploy job receives `pages: write` and `id-token: write`. Other deploy token permissions remain disabled. The deploy job retains the `github-pages` environment and its deployment URL output. Repository environment protection settings remain an external control, not something this source change claims to have inspected or configured.

Pages concurrency is scoped to the deploy job with group `pages` and `cancel-in-progress: false`. Concurrent tests do not cancel an active deployment, and arriving deployment candidates do not interrupt an active Pages job. GitHub may replace a pending job in a concurrency group; this setting is not a guarantee that every successful main commit will be published or that queue order matches commit order.

## Suggested integration checks (not run here)

After all source edits have landed, the integration owner should:

- Parse the workflow with an already available YAML/workflow-aware checker, checking that `on` remains an event mapping, not a YAML 1.1 boolean key. Do not add an installation or runtime dependency just for this check.
- Assert the workflow contains `push`, `pull_request` and `workflow_dispatch`; one `test` job and one `deploy` job; and `deploy.needs == test`. Confirm `.github/workflows/pages.yml` is absent and no remaining independently triggered workflow deploys Pages.
- Evaluate the three identical trust predicates and the deploy success predicate against every row of the table above. Include failed, cancelled and skipped test results, manual main with false/missing input, feature refs, PR refs and fork repository names. Only the two successful trusted-main publication rows may admit deployment.
- Assert that upload occurs after the full build/freshness/install/vector/test steps, that no step uses `continue-on-error`, and that the deploy job has no checkout/build or cross-run artifact input. Confirm the uploader's `name` and deployer's `artifact_name` are both `github-pages`.
- Assert Bun `1.4.2`, the frozen `--ignore-scripts` install, full vector command, full `bun run test` command and its unchanged package-script `--isolate --timeout=900000` remain intact. Confirm job-level permission separation and non-cancelling deploy concurrency.
- Run the integrated local build, committed-dist freshness, isolated install, vectors and full suite using the preserved commands above, sequentially and only when the integration owner schedules them. A local temporary staging copy can additionally be compared byte-for-byte with the built standalone, without invoking upload or deploy actions.

These local checks can establish structure and local behavior, not GitHub service execution, token issuance, environment approval, upload retention or actual Pages publication. Any later authorized GitHub run should retain its event, repository, ref, SHA, run ID/attempt, test result, artifact identity and deployment result as separate fresh evidence.

This pipeline change does not clear manual G01, the six disclosed sibling-key-origin omissions, the seven historical performance flags, current-build performance disposition, or live/platform interoperability limitations. It does not reinterpret the 23 previous closures or WIN-11's scoped independent acceptance as general release acceptance.
