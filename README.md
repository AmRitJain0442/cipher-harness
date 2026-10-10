# Cipher Harness

A persistent owner console and sequential LLM coordinator for **PentAGI**, **CAI**,
and **T3MP3ST**. It connects to an operator-provided OpenAI-compatible hosted model.
The controller chooses a framework for each subtask, records actual tool evidence,
and keeps job history and command results in SQLite.

This repository contains the integration code and console. The three upstream
frameworks and the model are separate installations; their code and licenses are
not bundled here. No keys, conversations, scan outputs, databases, or cloud account
configuration are included.

## Console

Use Python 3.10+ on a Linux VM with the framework services already installed:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your model base URL, model name, private key-file paths, framework
directory, and service URLs. Generate an owner key with
`python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`, save it in a private
file, and set `HARNESS_OWNER_KEY_FILE`. Run:

```bash
.venv/bin/python control/app.py
```

The default interface listens at `http://127.0.0.1:8092`. Visit
`http://127.0.0.1:8092/join/<your-owner-key>` once to establish the private owner
session. For a remote VM, forward port 8092 over SSH. Keep keys and the join URL
private. The existing console can also be opened with your deployment's original
`open-control.ps1` script.

Framework contracts:

| Framework | Required integration |
| --- | --- |
| [PentAGI](https://github.com/vxcontrol/pentagi) | Native HTTPS API, admin account, Docker worker containers |
| [CAI](https://github.com/aliasrobotics/cai) | `<HARNESS_SECURITY_DIR>/cai-venv/bin/python`, installed CAI runtime and `cai.env` |
| [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) | Native local planning, approval and command APIs, typically port 3333 |

CAI is archived upstream and has its own research-use licensing terms. Install
and configure each framework according to its upstream documentation. Host tools
such as Nikto and sqlmap must also be installed inside PentAGI's worker image when
that framework needs them. The host and each worker have separate tool inventories.

The optional `security/model_gateway.py` implements the local compatibility
gateway, tool-result caching, and CPU embeddings. Install
`requirements-gateway.txt` to use it. `HARNESS_UPSTREAM_BASE` selects the underlying
model endpoint. It binds localhost by default; `HARNESS_GATEWAY_DOCKER_HOST` can
enable a private bridge listener for your Docker workers. The stable exposed model
name comes from `HARNESS_MODEL`.

## Recursive improvement loop

`improvement/runner.py` uses the hosted LLM as a code-maintenance brain:

1. Read the current accepted source and recent test feedback.
2. Request a focused JSON change and a regression test.
3. Apply the change to a separate candidate copy.
4. Run the new test against the old code and the full protected suite against the candidate.
5. Accept only when the new test fails before the change and all tests pass afterward.
6. Commit the change, retain its regression test, push the branch, fetch that exact
   revision from GitHub, rerun the console and regression tests, and repeat.

The focus rotates through tool execution, orchestration/evidence reuse, and the
interface. Model code runs inside a disposable Docker container with no network,
no credentials, no host runtime data, and CPU/memory/time limits. The supervisor,
test gates, publication workflow, and credentials stay outside its editable paths.
Test success is evidence of the checked behavior; it does not establish general
correctness or authorize changes to running services.

On Linux with Docker, build the evaluation image and start a bounded run:

```bash
docker build -t cipher-harness-eval:local -f improvement/Dockerfile .
python3 improvement/runner.py \
  --key-file /path/to/private/model-key \
  --endpoint http://127.0.0.1:8082/v1 \
  --model cyberstrike --cycles 3 --publish
```

For publication, configure Git authentication on the supervisor account and an
`origin` remote first. Passing changes accumulate on an `improve/<timestamp>`
branch, ready for a pull request. Each subsequent cycle reads previously accepted
changes, tests, and feedback. The loop exits after the requested 1–20 cycles;
failed candidates leave the accepted source intact. It does not restart or deploy
the production console.

Inspect private reports in `.improve/cycle-*.json` and `.improve/summary.json`.
Create `.improve/STOP` to stop before the next cycle, or stop the supervisor process.
Remove the marker before starting another run. A lock prevents concurrent runs.
The supervisor can run as a systemd service to continue after an SSH disconnect.
`improvement/supervisor.py` repeats three-cycle batches every 15 minutes on the
`improve/autonomous` branch. Set `IMPROVE_REPO`, `IMPROVE_MODEL_KEY_FILE`, and
Git authentication in its private service configuration. `IMPROVE_ENDPOINT`,
`IMPROVE_MODEL`, `IMPROVE_CYCLES`, and `IMPROVE_BATCH_INTERVAL` are configurable.
Install the trusted supervisor files outside the editable checkout. Enable the
service on boot to resume after a VM restart. Stopping the VM stops the loop.

The LLM may include `vm_packages` in its proposal. The supervisor validates plain
package names, checks availability, and installs missing dependencies through
the VM's configured Ubuntu repositories. Provisioning results are recorded with
the cycle. The model cannot submit arbitrary host shell commands through this
interface. These host installations do not add tools to PentAGI worker containers.

Run local tests with `python -m unittest discover -s tests -v`. GitHub Actions runs
the same suite on pushes and pull requests. Generated tests become part of the
branch and are retained as protected gates for later cycles in that run.

## Layout

- `control/`: coordinator, adapters, CAI runner, evidence store and web console.
- `security/model_gateway.py`: private model compatibility gateway.
- `improvement/`: trusted maintenance supervisor and isolated test image.
- `tests/`: regression checks; accepted improvements add more tests.

Runtime SQLite files live under `control/data/` or `HARNESS_DATA_DIR` and are
excluded from Git. Improvements apply to this standalone copy; deployment into
an existing VM runtime is a separate operation.
