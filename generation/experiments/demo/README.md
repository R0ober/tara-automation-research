# Run the Generation demos

These examples show how to run a container, serve a model, and call a tool on
Minerva. Start with the [CPU item-reader demo](../../../infrastructure/minerva/README.md#submit-the-bbw-example).
Run the commands below **on your laptop, from the repository root**. Each
submission prints a Slurm job ID and a remote run directory.

## Prepare the GPU image and weights

```bash
python3 infrastructure/minerva/submit.py --job-yaml generation/experiments/demo/prepare-assets/job.yaml
```

Wait for this job to finish successfully before starting either experiment.
Use `ssh minerva 'sacct -j JOB_ID --format=JobID,State,ExitCode'` with the
printed job ID. The preparation job stores the pinned llama.cpp CUDA image and
both model files in `~/tara-demo/model-inference/assets` on Minerva. Later
runs reuse them. Both experiments request one L4 GPU.

## Model inference

```bash
python3 infrastructure/minerva/submit.py --job-yaml generation/experiments/demo/model-inference/job.yaml
```

After the job completes, open `output/run.txt` for the prompt, model revision,
and GPU. Open `output/response.txt` for the model's answer to the fixed question.

## Tool call

Build the Python tool image once. Rebuild it after changing the reader or the
tool client.

```bash
(cd generation/experiments/demo && apptainer build tool-call/tool-call.sif tool-call/tool-call.def)
python3 infrastructure/minerva/submit.py \
  --job-yaml generation/experiments/demo/tool-call/job.yaml \
  --input-dir shared/architecture/bbw
```

The CUDA image serves Qwen. The Python image sends the prompt, executes the
requested tool, and sends its result back. The first turn requires a tool call.
Open `output/trace.json` to check the call ID, tool result, and final answer.
For BBW, the answer should contain `AUTO-BBW-01`. Run the same command with
`shared/architecture/ota-adas` to check for `AUTO-OTA-ADAS-01`.

To read a trace from your laptop, replace the example path with the remote
directory printed by the launcher.

```bash
ssh minerva 'cat /path/to/your/run/output/trace.json'
```
