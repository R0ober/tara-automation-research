# Contributing

This guide describes how we work in this repository. Keep changes small and
reviewable.

## Git workflow

`main` is the only long-lived branch. Do not create `develop` or release branches.

1. Create an issue for the work.
2. Create a short-lived branch from `main`.
3. Implement and test the change.
4. Open a pull request. Link the issue (for example, `Closes #12`).
5. Request one review.
6. Squash-merge after approval and passing required checks. Delete the branch.

Merge or close branches within a few days when possible. Update your branch
from `main` if it becomes outdated.

### Branch naming

Use `<type>/<subproject>-<short-description>`:

```text
feat/generation-attack-path-parser
fix/verification-schema-validation
docs/maintenance-architecture
```

Common types: `feat`, `fix`, `docs`, `test`, `chore`. Use `shared` or
`infra` as the subproject when the change affects those directories.

## Pull request review

- A pull request that affects one subproject: another contributor from that
  subproject reviews it.
- A pull request that affects `shared/` (schemas, reference architecture,
  reference TARA) or `infrastructure/`: a contributor from a different
  subproject than the author reviews it.
- A pull request that affects several subprojects: request a review from each
  affected subproject.

The reviewer checks that the change does what the PR describes, that the
author tested it, and that the PR states known limitations.

## Code ownership

[`.github/CODEOWNERS`](.github/CODEOWNERS) maps directories to owners:

| Path | Owners |
| --- | --- |
| `generation/` | Robin, Lucas |
| `verification/` | Zhuoyu, Yixiang |
| `maintenance/` | Hongbin, Zeren |
| `shared/` | All contributors (cross-team review) |
| `infrastructure/` | All contributors (cross-team review) |

Status: CODEOWNERS is a template. Add the verified GitHub usernames and
uncomment the entries to activate it.

CODEOWNERS only requests reviewers. It does not guarantee that a specific
owner approves the change. The review conventions above are team agreements;
we do not enforce them with automation.

## Branch protection

The `main` branch is protected by the active ruleset `Pull-squash`
(Settings > Rules > Rulesets). It applies to the default branch (`main`):

- Changes go through a pull request. Direct pushes to `main` are blocked.
- A pull request needs 1 approving review.
- Squash merge is the only allowed merge method.
- Force pushes and branch deletion are blocked.
- Nobody can bypass the ruleset, including admins.

Not enabled:

- Required status checks. No CI check runs on every pull request.
- Required review from code owners. CODEOWNERS is still a template.

Repository merge settings:

- Squash merging is the only enabled merge method.
- GitHub deletes the head branch automatically after a merge.



## Continuous integration

We use GitHub Actions. Each subproject defines its own workflows.

Rules:

- GitHub-hosted checks must not depend on Minerva, GPUs, secrets, or external
  services (including LLM APIs). Run those experiments outside of CI.
- Add a workflow only when the subproject has selected its language and tools.
- Use path filters so that a workflow runs only for its own subproject.

### Existing workflows

- [`shared-validation.yml`](.github/workflows/shared-validation.yml): runs on
  pull requests that change `shared/`. It currently checks only the directory
  structure. Add schema and data validation when the shared schemas exist.

### Add a subproject workflow

Create `.github/workflows/<subproject>.yml`. Example skeleton (replace the
setup and test steps with the subproject's real commands):

```yaml
name: Generation

on:
  pull_request:
    paths:
      - "generation/**"
      - ".github/workflows/generation.yml"

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: generation
    steps:
      - uses: actions/checkout@v4
      # Add language setup and dependency installation here.
      # Add the test command here.
```

Expected tests per subproject:

- Generation: unit tests and formal-analysis integration tests.
- Verification: defect-injection tests and schema tests.
- Maintenance: vulnerability-data parsing tests.

If a subproject uses files from `shared/`, add `shared/**` to its path filter.

## Architecture Decision Records

Use ADRs to record meaningful technical decisions. Examples:

- The format of the shared reference architecture.
- Attack-path normalization rules.
- Interfaces to formal reasoning tools.
- Experimental evaluation methods.

Do not write ADRs for minor implementation choices.

Location:

- Subproject decisions: `<subproject>/docs/decisions/`.
- Shared decisions: `shared/docs/decisions/`.

Process:

1. Copy [`docs/adr-template.md`](docs/adr-template.md) into the correct
   directory.
2. Use the next sequential number in that directory: `0001-decision-title.md`,
   `0002-another-decision.md`.
3. Start with `Status: Proposed`. Change it to `Accepted` when the pull
   request merges. If a later ADR replaces it, set
   `Status: Superseded by NNNN`.

Writing style (based on ASD-STE100 principles):

- Use short, direct sentences.
- Use consistent technical terms.
- Avoid unnecessary jargon.
- State assumptions and limitations explicitly.
- Do not use vague claims such as "fully secure" or "guaranteed correct".

## Issue management

We use GitHub Issues and one shared GitHub Projects board.

- Use short, descriptive titles. Good: `Implement attack-path normalization`.
  Do not add tags in brackets to the title; use labels.
- Add one area label: `generation`, `verification`, `maintenance`, `shared`,
  or `infrastructure`.
- Assign the issue to the person who does the work.
- Use sub-issues only when a task has several meaningful parts. We do not
  use epics, sprints, or story points.

Board columns: Backlog, Todo, In Progress, Done.


## Experiment reproducibility

Reproducible experiments are more important than release versions. For each
experiment, record:

- Git commit hash of the code.
- Reference architecture version (Git tag or commit hash).
- TARA dataset version (Git tag or commit hash).
- Model identifier and version, where applicable.
- Model parameters and random seed, where applicable.
- Experiment configuration.
- Execution environment (for example, local or Minerva, hardware, key
  software versions).
- Location of the generated results.

Store this metadata with the results. The group can add an experiment
manifest format later, when the evaluation code exists.

## Versioning

We do not use Semantic Versioning or release versions. Use Git commit hashes
to identify code for experiments. Use Git tags for important milestones:

```text
reference-case-v1
baseline-v1
final-evaluation
```
