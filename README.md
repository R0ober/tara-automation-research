# Automating Function-Level TARA for Automotive Systems

This repository contains project work on automating function-level
Threat Analysis and Risk Assessment (TARA) for automotive systems.

The project has three subprojects. Each subproject owns its implementation,
dependencies, and tests. All subprojects use the same shared reference
artifacts.

## Subprojects

| Subproject | Scope | Contributors |
| --- | --- | --- |
| [Generation](generation/README.md) | Threat scenario identification, attack-tree generation, formal analysis, agentic experiments | Robin, Lucas |
| [Verification](verification/README.md) | Rule-based and LLM-based TARA verification, defect injection, evaluation | Zhuoyu, Yixiang |
| [Maintenance](maintenance/README.md) | Vulnerability and threat-intelligence processing, TARA change detection, review recommendations | Hongbin, Zeren |

## Repository structure

```text
.github/           CODEOWNERS, PR template, CI workflows
generation/        Generation subproject (docs, src, tests)
verification/      Verification subproject (docs, src, tests)
maintenance/       Maintenance subproject (docs, src, tests)
shared/            Reference architecture, reference TARA, schemas, shared decisions
infrastructure/    Shared infrastructure instructions (for example, Chalmers Minerva)
docs/              Repository-wide documentation and the ADR template
```

Each subproject has `docs/decisions/` for its own Architecture Decision Records
(ADRs). Shared decisions go in `shared/docs/decisions/`.

## Shared reference artifacts

The `shared/` directory contains the inputs that all three subprojects use:

- `shared/architecture/`: the reference vehicle architecture.
- `shared/reference-tara/`: the initial reference TARA.
- `shared/schemas/`: the data formats that the subprojects exchange.

Status: these artifacts are not yet defined.

Rules for shared artifacts:

- Change shared artifacts only through a pull request. A contributor from a
  different subproject must review the change.
- Record important format decisions as ADRs in `shared/docs/decisions/`.
- Mark important versions with Git tags (for example, `reference-case-v1`).
  Experiments refer to these tags or to commit hashes.

## Documentation

- [Contribution guide](CONTRIBUTING.md): Git workflow, reviews, CI, ADRs, issues,
  experiment reproducibility.
- [ADR template](docs/adr-template.md)
- [Minerva infrastructure](infrastructure/minerva/README.md)
