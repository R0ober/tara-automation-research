# Generation

Contributors: Robin, Lucas

## Scope

This subproject generates TARA content from the shared reference architecture:

- Threat scenario identification.
- Attack-tree generation.
- Formal analysis tools.
- Agentic (LLM-based) experiments.

## Current status

Stage 1 reads an item definition and calls tools through a model server.

## Planned implementation

Not yet defined. Record important technical decisions as ADRs in
[`docs/decisions/`](docs/decisions/). Use the [ADR template](../docs/adr-template.md).

## Run Stage 1 locally

Start a model server and prepare the Stage 1 databases before running the agent.
For a local Ollama server with, run this command from the repository root.

```bash
(
  cd generation
  OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_MODEL=qwen3.5-65k \
    python3 agents/stage_1_agent.py --item ../shared/architecture/bbw/item-definition.json
)
```

Use `--item` to select another item. If the server requires an API key, set
`OPENAI_API_KEY` in the environment.

## Tests

Not yet defined. Planned test types: unit tests and formal-analysis integration tests.

## Known limitations

Not yet defined.
