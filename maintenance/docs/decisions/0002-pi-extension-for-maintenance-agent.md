# 0002: Pi extension for the maintenance agent

Status: Accepted

## The problem

The maintenance baseline needs an agent interface that can accept different
change files, return structured evidence, and support analyst follow-up. The
interface must not create a second implementation of the decision rules.

## Options considered

- **Selected option: a Pi extension with a custom tool and a prompt template.**
- A fixed workflow that always executes the same sequence of model and tool
  steps.
- Free-form LLM reasoning over the TARA without a deterministic custom tool.

## Rationale

A Pi custom tool gives the model a typed interface to the existing Python CLI.
The model can invoke it for different artifacts and explain the results during
analyst follow-up. A prompt template supplies a reusable `/tara-maintenance`
entry point driven by local configuration. The Python package remains the only
source of decisions and evidence.

A fixed workflow would add orchestration without improving the deterministic
single-tool operation. It would also make ad-hoc inspection and unresolved-case
discussion less direct.

## Consequences

The agent interface requires Node.js 22.18 or newer, Pi, Python, and a configured
model provider for model-generated summaries. Project-local Pi resources require
project trust. The deterministic CLI and runner tests do not require model
access.

Pi spawns Python with an argument array and does not invoke a shell. Large tool
results are truncated in model context; the complete report is retained at a
returned file path. Model-requested report paths must stay within
`maintenance/`, and writes participate in Pi's file-mutation queue.

Only identical in-flight calls are deduplicated within a Pi session. Completed
calls, different inputs, and retries after failure are not blocked. Actual and
synthetic prompt commands are separate so model argument interpretation cannot
substitute local data for examples.

The runner auto-detects the editable-install virtual environment. Tracked
example configuration and synthetic changes are separate from ignored local
configuration, working data, credentials, and generated reports.

## Validation

Node tests execute the real Python baseline through the Pi runner and exercise
the extension's invocation and temporary-file lifecycle, including canonical
attachment paths, output files, and input errors. Pi resource discovery is
checked through RPC. A model-backed `/tara-maintenance` invocation is the final
optional smoke test when valid provider credentials are available.
