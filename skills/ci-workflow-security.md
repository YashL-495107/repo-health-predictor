# Skill: CI Workflow Security

## When this applies
- A GitHub Actions workflow uses `pull_request_target` or `workflow_run` and checks out or runs PR code.
- `${{ github.event.* }}` values (issue/PR title, body, branch name, comment) are interpolated into `run:` steps.
- A step pipes a download into a shell (`curl ... | sh`, `wget -O- ... | bash`).
- Third-party actions are referenced by tag or branch instead of a full commit SHA, or permissions are `write-all`.

## Indicators to check
1. Trigger: `pull_request_target`, `workflow_run`, `issue_comment` run with the base repo's secrets and write token.
2. Checkout ref: `ref: ${{ github.event.pull_request.head.sha }}` or `head.ref` brings untrusted code into a privileged job.
3. Injection sink: event fields placed directly inside `run:` or `script:` rather than passed through `env:`.
4. Secrets exposure: which secrets and token permissions are available to the step that runs untrusted input.
5. Remote execution: URL being piped to a shell, whether it is pinned or checksum-verified.
6. Action pinning: `uses: owner/action@v1` vs `@<40-char sha>`; first-party `actions/*` is lower risk than unknown owners.

## Step-by-step analysis
1. Identify the workflow trigger and the job-level `permissions`.
2. Find where untrusted data (PR code, event text, downloaded scripts) enters the job.
3. Check whether that data reaches a shell, an interpreter, or a build step.
4. List the secrets and token scopes available at that point.
5. Describe the concrete attack: who can trigger it (any fork contributor, any commenter) and what they gain.
6. Compare with the benign look-alikes below.
7. Conclude: Likely Malicious only if the workflow itself contains attacker code; for misconfigurations use
   Review Required (exploitable weakness) or Likely Benign (mitigated). These are vulnerabilities, not malware.

## Benign look-alikes to rule out
- `pull_request_target` used only for labelling or commenting without checking out PR code.
- Event data passed via `env:` and quoted in the shell (`"$TITLE"`), which prevents injection.
- `curl | sh` of an official installer with a pinned version in a job with no secrets.
- Unpinned first-party `actions/checkout@v4` in a read-only job (low risk, still best practice to pin).
- Jobs gated by `if: github.event.pull_request.head.repo.full_name == github.repository`.

## Output notes
- Explain who can trigger the issue and what access they would get; recommend the specific fix.
