# crosscheck shopify-merchant-app template (RND-4084, spec/559-rnd-4043 T322)

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
      claim_url: https://api.crosscheck.example/api/v1/connectors/merchant-apps/claim
      deploy_run_id: 'run-2026-09-29-01'
      workspace_id: 'ws-01'
      app_binding_id: 'binding-01'
      generation: 1
      requested_version: release-2026-09-29-01
      source_control_url: https://github.com/<merchant>/<app>/commit/<sha>
      node_version: '22.17.0'
      trusted_template_repo: <trusted-owner>/<trusted-template-repo>
      trusted_template_ref: <full-40-hex-sha>
      trusted_workflow_ref: <trusted-owner>/<trusted-template-repo>/.github/workflows/prepare.yml@<full-40-hex-sha>
    secrets:
      SHOPIFY_APP_AUTOMATION_TOKEN: ${{ secrets.SHOPIFY_APP_AUTOMATION_TOKEN }}
```

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
  App Automation Token. `attest` re-derives the output digest from the
  downloaded bytes rather than trusting `build`'s claim.
- `prepare.py` refuses loudly instead of compensating: submodules,
  symlinks, LFS pointers, escaping paths, dirty checkouts, TOML drift,
  extension add/remove/retarget, input-query changes, client-id or config
  mismatches, non-regular build outputs, unexpected payload paths, size
  overruns, and secret-bearing receipts are all refusals, never warnings.
- OIDC: `upload` mints one token for the audience
  `crosscheck-merchant-upload` and POSTs it to the claim URL exactly once
  (`curl --max-time 60`, no retry). `shopify app deploy` runs only when
  `claim-gate` proves the response echoes the request with the JSON boolean
  `dispatchGranted: true`.

## Secrets per environment

The `upload` job runs in the `shopify-upload` GitHub environment, which
holds exactly one secret:

- `SHOPIFY_APP_AUTOMATION_TOKEN` — the Shopify App Automation Token the
  pinned CLI (`@shopify/cli 4.8.2`, installed with `--ignore-scripts`)
  uses for `app deploy`. The exact env var name is confirmed at the
  recording run.

No other job sees any secret. The OIDC token is written to a file inside
the `upload` job and never printed, persisted, or uploaded.

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
  receipt records `uploadStatus: not_attempted`. The executable canaries
  (package lifecycle scripts, `shopify.web.toml` commands, `.npmrc` hooks)
  in the merchant repo prove `build` never executes them.
- `claim_mode: live` — one claim POST; the deploy runs only on a gated
  `true`; `app versions list --json` observes the candidate version for
  the receipt.
