# Shared research material

The three research tracks use the same reference systems and assessments.
BBW and OTA/ADAS are independent systems. Each has its own folders.

## Directory structure

```text
shared/
├── architecture/
│   ├── bbw/
│   │   ├── item-definition.json
│   │   └── functional-specification.txt
│   └── ota-adas/
├── reference-tara/
│   ├── bbw/
│   │   └── reference-tara.json
│   └── ota-adas/
├── benchmarks/
│   ├── bbw/
│   │   └── planted-vulnerabilities.pdf
│   └── ota-adas/
├── schemas/
└── docs/
    └── decisions/
```

- `architecture/`: system descriptions, including components, functions,
  connections, software, security controls, and operational assumptions.
- `reference-tara/`: manually prepared assessments, including damage scenarios,
  impacts, threat scenarios, attack paths, and risk decisions.
- `benchmarks/`: evaluation material, including planted weaknesses, expected
  findings, defect labels, and expected effects of controlled changes.
- `schemas/`: shared data formats, when defined.
- `docs/decisions/`: decisions about shared artifacts and formats.

BBW documents are under refinement. The OTA/ADAS folders are placeholders.
File locations describe their intended roles. The current architecture
documents still contain assessment content that requires a separate review.

## Experiment inputs

Select inputs for each experiment explicitly. Do not load all shared files
as model inputs.

- Threat discovery uses the item definition, relevant security configuration,
  and specified attacker assumptions. Keep expected threats separate.
- Attack-path generation can also use a selected threat scenario or objective.
  Keep expected reference paths separate.
- Verification uses the system description and a TARA to assess. Keep expected
  defect labels separate.
- Maintenance uses baseline and changed system information with an existing
  TARA. Keep expected reassessment results separate.

Directory separation alone does not prevent disclosure of expected answers.
Check file contents and record the permitted inputs in each experiment.
Reference TARAs are comparison material and are not assumed to be exhaustive.
Record the Git commit or baseline tag used for each experiment.
