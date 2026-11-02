# VibeDoctor GitHub Action

Sends your test coverage report from GitHub Actions to [VibeDoctor](https://vibedoctor.io). No secret to add: the step signs in with the job's GitHub OIDC token.

## Usage

In the job that runs your tests, add `id-token: write` to its permissions and this step after the tests:

```yaml
jobs:
  test:
    permissions:
      contents: read
      id-token: write
    steps:
      # your checkout, install and test-with-coverage steps
      - uses: VibeDoctor-io/action@v1
        if: ${{ !cancelled() }}
        with:
          coverage-file: coverage/lcov.info
```

Listing permissions on a job sets every permission you leave out to `none`, so keep the ones the job already lists.

`if: ${{ !cancelled() }}` runs the step even when a test fails.

## Inputs

| Input | Description |
|-------|-------------|
| `coverage-file` | Path or glob of your LCOV or Cobertura XML report. One per line, or comma separated. |
| `scan` | `true` runs Gitleaks and Trivy on the checked-out repository and lists what they find in the job summary. With `id-token: write`, it also sends the results to VibeDoctor, which keeps them for VibeDoctor projects. Linux runners only. Default `false`. |

## Reports

- **LCOV:** Jest (`--coverage`), Vitest (add the `lcov` reporter), coverage.py (`coverage lcov`)
- **Cobertura XML:** coverage.py (`coverage xml`), Vitest (the `cobertura` reporter)

## Scan

With `scan: true` the step also runs two open source scanners on the checked-out repository, at the versions VibeDoctor runs:

- **Gitleaks 8.30.1** looks for leaked secrets. It runs with `--redact`, so no secret value reaches the log or the summary. A `.gitleaksignore` at the repository root is used.
- **Trivy 0.74.0** looks for dependencies with known vulnerabilities (critical, high, medium and low) in your lockfiles. `node_modules` and test fixture folders are skipped. Trivy reads npm versions from a lockfile, so commit `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` or `bun.lock`.

Both read the files git tracks, as a fresh clone would, so dependencies, builds and coverage pages your job made are left out.

```yaml
      - uses: VibeDoctor-io/action@v1
        with:
          scan: true
```

Each tool is downloaded from its GitHub release and runs only if the download matches the SHA-256 pinned in this action. Trivy downloads its vulnerability database into a temporary folder, removed when the step ends. The findings are listed in the job summary, the log shows only their counts, and they do not fail the job. The scan runs on Linux x64 and arm64 runners.

With `id-token: write` in the job's permissions, as in [Usage](#usage), the step also sends the results to VibeDoctor. VibeDoctor keeps them when the repository is a VibeDoctor project on a Watch, Guard or Shield plan, or in its Free Week, and does not keep them otherwise. Without `id-token: write`, nothing is sent. Either way the results stay in the job summary, and the log says what happened.

## What it sends

The coverage reports as they are (file paths, line and branch counts, function names), the repository path of each file they list, and the commit, branch and pull request number. Your source files are not sent.

With `scan: true` and `id-token: write`: for each secret, its Gitleaks rule, file and line, never its value; for each vulnerable dependency, the package, its installed and fixed versions, the vulnerability id and title, and the lockfile; the lockfiles Trivy read; the tool versions; the same commit details. At most 1,000 findings per tool, with the count of all of them.

If VibeDoctor can't be reached or does not accept the upload, the step prints a warning (for scan results, a log line) and your job still passes.

## License

MIT
