Cypher's runtime agents can execute commands through CAI on the VM, T3MP3ST's
native command API, and PentAGI's isolated worker containers. `available_tools`
lists VM executables; `install_tools` installs explicitly requested packages
using apt. Use `environment=vm` for CAI/T3MP3ST, or `environment=pentagi` to update
the worker image and existing workers using that image.

Build the PentAGI worker image with a copy of the installed Nikto source tree:

```bash
mkdir -p /tmp/cipher-tool-image
cp security/Dockerfile.tools /tmp/cipher-tool-image/Dockerfile
cp -a /opt/nikto /tmp/cipher-tool-image/nikto
docker build -t cipher-tools:local /tmp/cipher-tool-image
```

Set PentAGI's `DOCKER_DEFAULT_IMAGE_FOR_PENTEST=cipher-tools:local`.
Existing containers retain their existing tool installations;
new worker containers use the configured image.

The shared model gateway recognizes failed command tool results from PentAGI,
CAI, and the coordinator's T3MP3ST command delegations. It asks Gemini to correct
the command using the original task, scope, arguments, and redacted error output.
The local model receives the suggestion and executes an appropriate correction
through the same native tool. Suggestions are not execution evidence. Completed
or uncertain commands are not silently replayed. Advisor errors preserve the
normal local-agent flow and are logged.

Configure Vertex AI with `HARNESS_GEMINI_PROJECT`, `HARNESS_GEMINI_LOCATION`,
`HARNESS_GEMINI_MODEL`, and optionally `HARNESS_GEMINI_CREDENTIALS_FILE`. The
gateway also reads the private `~/.config/cipher/gemini.env`. Credentials are
loaded by the gateway, never sent in model messages or committed to Git.

This runtime assistance is independent of the cloud prompt-revision loop.
