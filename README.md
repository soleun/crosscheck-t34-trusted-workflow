# crosscheck shopify-merchant-app template (RND-4084, spec/559-rnd-4043 T400)

A trusted reusable workflow that turns an enrolled merchant-app source tree
into a governed Shopify app version, with evidence CrossCheck verifies
afterwards. CrossCheck never dispatches this workflow and never writes to
the merchant repository.

## Caller example (pinned by full SHA)

```yaml
# .github/workflows/merchant-app-release.yml in the merchant repo
name: merchant-app-release
on:
  workflow_dispatch:
    inputs:
      claim_mode:
        description: "'live' deploys; 'recording' never touches Shopify"
        required: true
        default: recording
      preparation_nonce:
        description: Correlation nonce echoed in the claim body
        required: true

permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  prepare:
    uses: <trusted-owner>/<trusted-template-repo>/.github/workflows/prepare.yml@<full-40-hex-sha>
    with:
      commit_sha: ${{ github.sha }}
      app_root: app
      config_name: production
      client_id: '12345678'
      baseline_json: ${{ vars.MERCHANT_APP_BASELINE_JSON }}
      claim_mode: ${{ inputs.claim_mode }}
      claim_url: https://api.crosscheck.example/api/v1/connectors/merchant-apps/<app-binding-id>/runs/<deploy-run-id>/upload-claim
      deploy_run_id: 'run-2026-09-29-01'
      workspace_id: 'ws-01'
      app_binding_id: 'binding-01'
      generation: 1
      requested_version: release-2026-09-29-01
      preparation_nonce: ${{ inputs.preparation_nonce }}
      source_control_url: https://github.com/<merchant>/<app>/commit/<sha>
      node_version: '22.17.0'
      trusted_template_repo: <trusted-owner>/<trusted-template-repo>
      trusted_template_ref: <full-40-hex-sha>
      trusted_workflow_ref: <trusted-owner>/<trusted-template-repo>/.github/workflows/prepare.yml@<full-40-hex-sha>
    secrets:
      SHOPIFY_APP_AUTOMATION_TOKEN: ${{ secrets.SHOPIFY_APP_AUTOMATION_TOKEN }}
      CROSSCHECK_UPLOAD_KEY: ${{ secrets.CROSSCHECK_UPLOAD_KEY }}
```

The caller pins the full 40-hex SHA of the reviewed template revision, never
a branch or tag. The `trusted_template_ref` input must name the same SHA:
`prepare.py` and the workflow file are reviewed and versioned together.

A called workflow cannot exceed the caller's permissions, so the caller
job must grant `contents: read`, `id-token: write` and `attestations:
write` as above; narrower caller permissions break `source`, `attest`
and `upload`.

`claim_url` is the full upload-claim route for the run, including the
app-binding id and deploy-run id path segments. The legacy
`/merchant-apps/claim` endpoint is gone; nothing in this template calls it.

The caller pins the full 40-hex SHA of the reviewed template revision, never
a branch or tag. The `trusted_template_ref` input must name the same SHA:
`prepare.py` and the workflow file are reviewed and versioned together.

## Trust boundary

- `source` / `attest` / `upload` run only template code (`prepare.py`,
  Python 3.11 stdlib) and pinned actions. They never execute
  merchant-controlled bytes.
- Only `build` executes merchant bytes (`npm ci --ignore-scripts`, then the
  enrolled `npm run build` recipe). `build` holds no secret (`secrets.*`
  never appears), mints no identity (no `id-token`), and cannot reach the
  App Automation Token. `build` stages only enrolled `dist/**` files into
  `build-output/` (`prepare.py stage-dist`); `attest` re-derives the output
  digest from those staged bytes in strict dist-only mode, and `upload`
  overlays them onto the verified source tree (`prepare.py assemble`,
  collision-refusing) before deploying from `deploy-root/<app_root>`.
  Nothing from `node_modules` — or from the build job at all other than
  `dist/**` — reaches a trusted job.
- The enrolled build recipe receives the config name as
  `SHOPIFY_APP_CONFIG_NAME` in its environment (`shopify app build`
  requires `--config <name>` when the app config is
  `shopify.app.<name>.toml`). The merchant's build script must honor that
  variable (e.g. `shopify app build --config "$SHOPIFY_APP_CONFIG_NAME"`)
  rather than a hardcoded config.
- `prepare.py` refuses loudly instead of compensating: submodules,
  symlinks, LFS pointers, escaping paths, dirty checkouts, TOML drift,
  extension add/remove/retarget, input-query changes, client-id or config
  mismatches, non-regular build outputs, unexpected payload paths, deploy
  collisions, size overruns, and secret-bearing receipts are all refusals,
  never warnings.
- OIDC: `upload` mints one token for the audience
  `crosscheck-merchant-upload` and POSTs the typed claim body exactly once
  (`curl --max-time 60`, no retry) with `Authorization: Bearer
  <CROSSCHECK_UPLOAD_KEY>` and `X-CrossCheck-Upload-Identity: <OIDC JWT>`.
  The OIDC token is never sent as the Bearer: the API treats any `eyJ…`
  bearer as a Cognito token and returns 401. Neither value is echoed.
  `shopify app deploy` runs only when `claim-gate` proves the `{success,
  data}` envelope carries the JSON boolean `dispatchGranted: true`, the
  echoes match the request, and `startDeadlineAt` has not passed.

## Secrets per environment

The `upload` job runs in the `shopify-upload` GitHub environment, which
holds exactly two secrets:

- `SHOPIFY_APP_AUTOMATION_TOKEN` — the Shopify App Automation Token the
  pinned CLI (`@shopify/cli 4.8.2`, installed with `--ignore-scripts`)
  uses for `app deploy`. The exact env var name is confirmed at the
  recording run.
- `CROSSCHECK_UPLOAD_KEY` — the CrossCheck `deploy:write` key sent as the
  claim `Authorization` Bearer. Optional: recording runs never read it.

No other job sees any secret. The OIDC token is written to a file inside
the `upload` job and never printed, persisted, or uploaded.

## Claim body

`prepare.py claim-request` builds the strict typed body: `schemaVersion:
1`, `workspaceId`, `generation` (int), `preparationNonce` (the caller's
`workflow_dispatch`/`workflow_call` input; correlation only, visible on a
public repo), `requestedVersionName`, `githubRepositoryId`/`githubRunId`
(strings), `githubRunAttempt` (int), `trustedWorkflowRef`,
`trustedWorkflowSha`, `sourceArchiveDigest`, `buildOutputDigest`,
`buildArtifactId` (the numeric id of the uploaded `build-output`
artifact, from the `actions/upload-artifact` `artifact-id` output — never
the name), and `outputManifest` (the exact text of the attest job's
re-derived output manifest). A string attempt or a named artifact id
refuses at usage time.

## Receipt artifact

Every run uploads `receipt.json` plus the attested output manifest as the
`crosscheck-receipt` artifact, and the receipt carries the numeric
`build-output` artifact id. A named id refuses.

## The app TOML contract

The enrolled app TOML (`shopify.app.<config>.toml`) must carry
`application_url` and an `[auth]` table: `shopify app deploy` needs both,
and enrollment is rejected without them.

## The App Automation Token is app-scoped, not upload-only

The token authorizes the pinned CLI against the one enrolled Shopify app
(`client_id` in `shopify.app.<config>.toml`, enforced byte-for-byte by
`policy-check`). It is not scoped to "uploads": anyone holding it can
manage that app's versions through the CLI. Protect it accordingly —
environment-scoped storage, owner-only write on the merchant repo, and
rotation with a recorded expiry.

## Digests

- `sourceArchiveDigest` / `buildOutputDigest`: sha256 over canonical JSON
  (sorted keys, no whitespace) of the sorted file records — the same
  canonicalization as T34a's `canonicalizeForHash`, re-verified by Core in
  TypeScript (`@vb-crosscheck/connector-shopify/merchant-app`).
- `toolchain_digest` (receipt `toolchainDigest`): sha256 of the
  `node --version` / `npm --version` / pinned-CLI-dependency bytes captured
  in `build`.
- `image_digest` (receipt `imageDigest`): sha256 of the runner's
  `/etc/os-release` bytes.
- `artifact_digest` (receipt `githubArtifactDigest`): sha256 of the
  emitted output-manifest bytes.

## Recording vs live

- `claim_mode: recording` — no claim POST, no `shopify app deploy`, and the
  receipt records `uploadStatus: not_attempted`. The recording run still
  executes `assemble`, so it proves the overlay, but still never contacts
  Shopify or the claim URL. The executable canaries
  (package lifecycle scripts, `shopify.web.toml` commands, `.npmrc` hooks)
  in the merchant repo prove `build` never executes them.
- `claim_mode: live` — one claim POST; the deploy runs only on a gated
  `true`; `app versions list --json` observes the candidate version for
  the receipt. A refused gate records `uploadStatus: failed`.
