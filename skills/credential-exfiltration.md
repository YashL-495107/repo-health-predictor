# Skill: Credential Exfiltration

## When this applies
- Code references credential stores: `~/.ssh/id_*`, `~/.aws/credentials`, `.git-credentials`, `.docker/config.json`,
  `.kube/config`, `.npmrc`, `.netrc`, browser `Login Data`, wallet files, `/etc/shadow`.
- Code collects all environment variables (`dict(os.environ)`, `os.environ.copy()`, `JSON.stringify(process.env)`).
- Code sends data to exfil-style endpoints: Discord/Slack webhooks, Telegram bot API, paste sites, tunnels, raw IPs.
- A secret scanner found a key-like string committed to the repository.

## Indicators to check
1. Source: which credential file or variable set is read, and whether all of it or one named key.
2. Sink: is the data sent over the network, written to a file, logged, or only checked for existence?
3. Endpoint: is the destination the project's own documented service or an anonymous webhook/paste/IP?
4. Same-file combination: credential read + network send in one file is the classic stealer shape.
5. Trigger: does it run at import/install time or only when the user invokes a command?
6. For committed secrets: key type, whether it is in a test/example file, and whether it looks like a placeholder.

## Step-by-step analysis
1. Name the exact credential source in the evidence.
2. Follow the data to its sink; note any encoding (base64, JSON) before sending.
3. Identify the destination host and classify it (project service, cloud API, anonymous endpoint).
4. Determine when the code runs (import, install, CLI command, test).
5. For a committed secret, decide if it is real-looking (correct prefix/length, not `EXAMPLE`/`xxxx`).
6. Compare with the benign look-alikes below.
7. Conclude: Likely Malicious if credentials or full environments are sent to an anonymous endpoint;
   Review Required for reads without a visible sink, or for real-looking committed secrets;
   Likely Benign if a look-alike explains it.

## Benign look-alikes to rule out
- CLI tools and SDKs that read their own config file (`~/.aws/credentials` in an AWS client) to authenticate.
- Deployment or SSH helper tools that use `~/.ssh` keys to connect where the user asked.
- Debug code that prints selected environment variables locally.
- Notification integrations that post build status to a documented webhook configured by the user.
- Test fixtures and documentation with fake keys (`AKIAIOSFODNN7EXAMPLE`, `sk_test_...`).

## Output notes
- Secrets in evidence are masked; never try to reconstruct them.
- A committed real secret is an exposure risk even when there is no malicious intent.
