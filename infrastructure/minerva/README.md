# Run a container job on Minerva

The shared launcher uploads an Apptainer image, an input directory, and a job
script from your laptop. It submits the script to Slurm and prints the remote
run directory and job ID. The example runs the Brake-by-Wire (BBW) item reader on one CPU.

## Set up SSH on your laptop

Request Minerva access with your Chalmers CID. Connect to the Chalmers network
or use the Chalmers VPN from off campus. [Minerva access guide](https://git.chalmers.se/karppa/minerva/-/blob/main/README.md#getting-access)

On your laptop, create an SSH key without a passphrase. If
`~/.ssh/id_ed25519` already exists, keep it and skip this command.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

Add these lines to `~/.ssh/config` on your laptop. Create the file if needed.
Replace `YOUR_CID` with your Chalmers username.

```sshconfig
Host minerva
    HostName minerva.cse.chalmers.se
    User YOUR_CID
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

Copy the public key to Minerva. Enter your Chalmers password when prompted.

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub minerva
```

If you kept an existing key with a passphrase, run `ssh-add ~/.ssh/id_ed25519`
first. Check the connection. This command should print `minerva` without asking
for a password.

```bash
ssh -o BatchMode=yes minerva hostname
```

## Submit the BBW example

From the repository root on your laptop, install the launcher dependencies.

```bash
pip install -r infrastructure/minerva/requirements.txt
```

If Ubuntu 24.04 reports `externally-managed-environment`, install PyYAML
with `sudo apt install python3-yaml`.

Install Apptainer on your laptop, then build the image from the repository root.
[Apptainer installation guide](https://apptainer.org/docs/admin/latest/installation.html)

```bash
(cd generation/experiments/demo && apptainer build generation-demo.sif generation-demo.def)
```

Submit the job from the repository root.

```bash
python3 infrastructure/minerva/submit.py \
  --job-yaml generation/experiments/demo/job.yaml \
  --input-dir shared/architecture/bbw
```

The job file specifies the image path and the command to run. A relative image
path starts in the directory that contains the job file. The job script mounts
the input directory at `/input` for read-only access. It mounts the output
directory at `/output`. The launcher creates a run directory under `~/tara-demo/`
on Minerva for each submission.

For a custom Slurm job, set `script` in the YAML to a batch script beside the
job file. The launcher uploads it as `job.sh`. You can also supply a local
`image` to upload as `image.sif` and an `--input-dir` to upload as `input/`.
See the [Generation demos](../../generation/experiments/demo/README.md).

## Check the result

Keep the job ID and run directory printed by the launcher. From your laptop,
run `ssh minerva 'squeue --me'` to see your queued and running jobs.

After the job finishes, choose one of the two methods below.

### Read the result on Minerva

Log in from your laptop.

```bash
ssh minerva
```

At the Minerva prompt, replace `/path/to/your/run` with the path printed
after `minerva:` in the launcher output.

```bash
cd /path/to/your/run
cat output/result.json
exit
```

### Copy the result to your laptop

On your laptop, set `run` to the full remote run directory printed by the
launcher. Include the `minerva:` prefix.

```bash
run='minerva:/path/to/your/run'
scp "$run/output/result.json" ./bbw-result.json
cat ./bbw-result.json
```

Both methods should show `{"item_id": "AUTO-BBW-01"}`. If the job starts but
produces no result, read `slurm.log` in the remote run directory.

Record the run details for research experiments. [Experiment reproducibility](../../CONTRIBUTING.md#experiment-reproducibility)
Keep pull request checks independent of Minerva access.
