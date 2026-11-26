# Verification

Contributors: Zhuoyu, Yixiang

## Scope

This subproject checks TARA content for defects:

- Rule-based TARA verification.
- LLM-based TARA verification.
- Defect injection.
- Evaluation of the verification methods.

## Current status

Milestone 1 of the defect injector is implemented. It covers system `bbw`,
scenario `TS-BRK-01`, operators `C1a`, `C1b`, `C3` and `C4`, and the `local`
policy only. The reviewers and the evaluation are not started.

The injector calls no model. The same seed gives byte-identical output.

## Implementation

Pipeline (`src/tara_verification/injection/`):

| Step | Module | Task |
|---|---|---|
| 1 | `load.py` | Read the inputs from a git revision, verify SHA-256, write canonical JSON |
| 2 | `index.py` | Build ID indexes by kind |
| 3 | `sites.py` | Enumerate injectable sites |
| 4 | `operators/` | Make one edit per site and the label, with hand-written expected violations |
| 5 | `validate.py` | Recompute independently and accept only the expected new violations |
| 6 | `write.py` | Write cases, labels, `rejected.jsonl` and `manifest.json` |

- `known_issues.py` lists the known baseline issues (B1–B9).
- The label and finding contract is in `src/tara_verification/contract/`.
  See [ADR 0001](docs/decisions/0001-label-and-finding-contract.md).
- [`CLAUDE.md`](CLAUDE.md) records the design decisions (in Chinese).

## Setup

Python 3.10 or later. The runtime uses only the standard library.

```bash
cd verification
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Usage

Run from the repository root:

```bash
python -m tara_verification.injection \
  --repo . --system bbw --scenarios TS-BRK-01 \
  --operators C1a,C1b,C3,C4 --seed 295 --out verification/datasets/v0
```

- `--rev` selects the git revision of the inputs. The default is the
  development baseline `5ed3ae1`, with its recorded input hashes.
  `--rev worktree` reads the working tree.
- `--expect-sha256 ROLE=HASH` (`ROLE` is `tara`, `item` or `spec`) sets the
  expected input hashes for other revisions.
- `--overwrite` replaces an existing dataset directory. The tool deletes a
  directory only if it contains a `manifest.json`.

Output:

```
datasets/v0/
  manifest.json             code commit, input hashes, seed, counts per operator
  rejected.jsonl            skipped, rejected and duplicate candidates, with reasons
  labels/<case_id>.json     ground truth; never give it to a reviewer
  dev/context/              item definition and functional specification
  dev/cases/<case_id>/tara.json
```

Give only `dev/` to a reviewer.

## Tests

```bash
cd verification
.venv/bin/python -m pytest -q
```

The tests read the inputs with `git show 5ed3ae1:<path>`. A CI checkout must
therefore include the full history (`fetch-depth: 0`). The tests do not use the
network.

## Known limitations

- Only one scenario (`TS-BRK-01`) and the `local` policy. `TS-BRK-01` has one
  attack step, so aggregation errors are not injected.
- C1b has combination rules only for interface and component fields. Sites
  that hold asset, connection or damage IDs are skipped and logged in
  `rejected.jsonl`.
- C1 covers only fields that hold item-definition IDs. TARA-internal
  references, such as `critical_attack_path`, come later with C2 and C5.
- IDs inside free text are not edited or checked.
- Validation checks M-tier rules only. It cannot detect a case that also
  contains an unintended L-tier defect.
