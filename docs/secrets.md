# Secrets

`dev` can fetch secret values itself and inject them into the container. A
`secrets.json` beside your devcontainer config holds *references* — a provider
name and a locator — and never values. Nothing has to be exported in your shell,
and `dev` never writes a resolved value to disk: not the lockfile, not the
`devcontainer.metadata` image label, no cache anywhere.

This is the one thing `remoteEnv` cannot do. `remoteEnv` copies a value `dev` can
already see. A secret reference sends `dev` to go and fetch it.

## Quick start

The `env` provider needs no vault, so it is the shortest working loop.

`.devcontainer/secrets.json`:

```json
{
  "version": 1,
  "secrets": {
    "API_TOKEN": "env://MY_TOKEN"
  }
}
```

Then:

```sh
export MY_TOKEN=hunter2
dev up
dev exec -- printenv API_TOKEN
```

```
hunter2
```

That is the whole feature. Everything below is which providers exist, where the
file goes, and what each choice costs.

## Where `secrets.json` goes

| Scope | Path |
|---|---|
| Recipe (User) | `~/.dev/devcontainers/<workspace folder name>/.devcontainer/secrets.json` |
| Recipe (Workspace) | `<workspace>/.devcontainer/secrets.json` |
| Plain `devcontainer.json` | `<workspace>/.devcontainer/secrets.json` |

One rule covers all three: the file sits beside the config that governs the
container, so the path is always `<config dir>/secrets.json`. For a recipe that
is the recipe directory. If your config is a root-level `.devcontainer.json`,
the file is `<workspace>/secrets.json`.

A missing `secrets.json` is not an error. It means the project declares no
secrets.

**A workspace-scope `secrets.json` is committed.** That is mostly the point — a
teammate with their own vault access inherits the wiring for free. But it also
publishes your vault names and item names to anyone who clones the repo. Fine
for a private repo. Not fine for a public one. For that case keep the file
outside the tree (or gitignored) and point at it with
[`dev up --secrets <path>`](#dev-up---secrets-path).

## File format

```json
{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential",
    "OPENAI_API_KEY": "keychain://openai-api-key",
    "DB_PASSWORD": {
      "provider": "op",
      "ref": "Private/fsm-db/password",
      "account": "example.1password.com",
      "optional": true
    }
  }
}
```

- `version` must be `1`. Any other number is rejected by name.
- `secrets` is a map of environment variable name to reference.

Comments and trailing commas are accepted, matching the `devcontainer.json`
beside it.

Key rules, which match what `runArgs` `--env` tokens already accept:

- a key cannot be empty;
- a key cannot contain whitespace;
- a key cannot contain `=`;
- a key cannot repeat.

**Validation happens before any side effect.** On every `dev up`, `dev` parses
every reference, rejects unknown providers, and expands variables *before* it
runs `initializeCommand`, before it looks for an existing container, before the
lockfile write, and before any image build. A typo costs a second, not a
five-minute build:

```sh
dev up --rebuild
```

```
Error: Invalid secret reference for `CI_TOKEN`: uses unknown provider `vualt`; known providers are env, exec, file, keychain, op; or put an executable `dev-secret-vualt` on PATH
```

The `initializeCommand` did not run and the existing container was not removed.

Validation resolves nothing. No provider is asked for a value, so it costs no
biometric prompt and no network round trip.

## Reference forms

### String shorthand

A URI whose scheme names the provider. Everything after the first `://` is the
reference body.

```json
{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential"
  }
}
```

Only the **first** `://` splits. A body may contain more, which is the case
people hit with `exec` and `file`:

```json
{ "version": 1, "secrets": { "URLISH": "exec:///bin/echo https://vault.example.com/v1" } }
```

```sh
dev exec -- printenv URLISH
```

```
https://vault.example.com/v1
```

A provider name may contain only letters, digits, `_` and `-`.

### Object form

```json
{
  "version": 1,
  "secrets": {
    "DB_PASSWORD": {
      "provider": "op",
      "ref": "Private/fsm-db/password",
      "account": "example.1password.com",
      "optional": false,
      "createTime": true
    }
  }
}
```

`provider` and `ref` are required. `optional` and `createTime` are described
[below](#optional-and-create-time-flags). Every other key is a **provider
option** and is handed to the provider as-is. `ref` is taken literally and is
never re-parsed as a shorthand, even when it looks like one.

Use the shorthand for anything that needs no options. Switch to the object form
the moment you need one.

### Variable substitution

References go through the same variable expansion `runArgs` gets, at the
validation point on `dev up`, so no provider ever sees an unexpanded string.

```json
{
  "version": 1,
  "secrets": {
    "CI_TOKEN": "file://${localWorkspaceFolder}/.secrets/token"
  }
}
```

```sh
dev exec -- printenv CI_TOKEN
```

```
hunter2
```

Supported variables:

| Variable | Expands to |
|---|---|
| `${localEnv:VAR}` | value of the host env var, empty string if unset |
| `${localEnv:VAR:default}` | value of the host env var, `default` if unset |
| `${containerEnv:VAR}` / `${remoteEnv:VAR}` | expanded using the remote user |
| `${localWorkspaceFolder}` | workspace path on the host |
| `${localWorkspaceFolderBasename}` | basename of the workspace path |
| `${containerWorkspaceFolder}` | workspace path inside the container |

Substitution reaches the reference body in **both** spellings — the shorthand
string and the object form's `ref` — plus every **top-level string** provider
option. It does not reach `provider`, and it does not reach option keys, so no
substitution can change which provider answers a reference.

**Nested placeholders stay literal.** A string inside an option array or object
is not substituted, because a plugin receives the whole options map as its wire
payload and `dev` must not rewrite the inside of a payload it does not
understand. Given this reference:

```json
{
  "version": 1,
  "secrets": {
    "T": {
      "provider": "echo",
      "ref": "${localWorkspaceFolderBasename}",
      "topLevel": "${localWorkspaceFolderBasename}",
      "nested": { "inner": "${localWorkspaceFolderBasename}" }
    }
  }
}
```

the provider is handed:

```json
{
  "key": "T",
  "ref": "demo",
  "options": {
    "nested": { "inner": "${localWorkspaceFolderBasename}" },
    "topLevel": "demo"
  }
}
```

**An unrecognized `${...}` expression is left in the string as literal text.** It
is not an error. A misspelled variable therefore reaches the provider verbatim
and shows up as a confusing not-found error with a `${` in it:

```json
{ "version": 1, "secrets": { "CI_TOKEN": "file://${localWorkspaceFolderr}/.secrets/token" } }
```

```
Error: Failed to resolve secret `CI_TOKEN` from provider `file`: file `/Users/you/code/demo/${localWorkspaceFolderr}/.secrets/token` does not exist
```

If an error names a path or a locator containing `${`, that is the bug.

Note that `${localEnv:VAR}` in a reference is a path *to* the value, not the
value. It does not reintroduce the shell-export problem this feature exists to
remove.

## Providers

Three tiers: five providers built in, the `exec` escape hatch for anything with
a CLI, and external `dev-secret-*` plugins for anything else.

### env

Reads a host environment variable named by the reference, out of `dev`'s own
process.

```json
{ "version": 1, "secrets": { "API_TOKEN": "env://MY_TOKEN" } }
```

- **Options:** none. Any option is a failure.
- **Failure:** the variable is unset, or its value is not valid UTF-8. A variable
  set to the empty string resolves to an empty value rather than counting as
  unset.

```
Error: Failed to resolve secret `CI_TOKEN` from provider `env`: host environment variable `NOT_SET_ANYWHERE` is not set
```

This is `${localEnv:...}` with the same weakness. It is genuinely useful in CI,
where the runner already has the value in its environment. It is not a reason to
put an export in your shell rc.

### file

Reads a path on the host and uses the file's contents as the value. One trailing
newline is removed. Interior whitespace and interior newlines are kept.

Watch the slash count. Absolute paths take three:

```json
{
  "version": 1,
  "secrets": {
    "ABS_TOKEN": "file:///Users/you/.secrets/token",
    "REL_TOKEN": "file://.devcontainer/token"
  }
}
```

A relative path resolves against the **workspace folder**, not the
`.devcontainer/` directory that holds `secrets.json`. That is the same rule
`runArgs` `--env-file` uses and the same context `${localWorkspaceFolder}`
expands to.

- **Options:** none.
- **Failure:** the file does not exist, the path is a directory, the file cannot
  be read, or its contents are not valid UTF-8.

`~` is not expanded. Use `${localEnv:HOME}` or an absolute path.

### op

1Password, through the `op` CLI.

```json
{ "version": 1, "secrets": { "LINEAR_API_KEY": "op://Private/Linear CLI/credential" } }
```

With more than one 1Password account configured, name the one to use:

```json
{
  "version": 1,
  "secrets": {
    "DB_PASSWORD": {
      "provider": "op",
      "ref": "Private/fsm-db/password",
      "account": "example.1password.com"
    }
  }
}
```

- **Options:** `account`.
- **Failure:** `op` is not installed, `op` is not authorized, or the reference
  names nothing.

**Every `op` reference in one file is resolved in a single `op inject`.** Eight
secrets cost one biometric prompt, not eight. References that name different
`account` values are grouped, so it is one `op inject` per account.

The three failures read differently on purpose:

`op` not installed —

```
Error: Failed to resolve secret `LINEAR_API_KEY` from provider `op`: the 1Password CLI (`op`) is not installed or is not on PATH; install it with `brew install 1password-cli`, see https://developer.1password.com/docs/cli/get-started/
```

`op` installed but not authorized —

```
Error: Failed to resolve secret `LINEAR_API_KEY` from provider `op`: `op` is not authorized; run `op signin`: [ERROR] error initializing client: multiple accounts found. Use the --account flag or set the OP_ACCOUNT environment variable to select an account.; with more than one account configured, set `"account"` in the secret's object form
```

reference not found (shape only — this one needs a signed-in `op` to reproduce) —

```
Error: Failed to resolve secret `LINEAR_API_KEY` from provider `op`: 1Password could not resolve `op://Private/Linear CLI/credential`: <op's own message>
```

The first says install it. The second says `op signin`, and adds the `account`
hint when the account filter is what `op` complained about. The third names the
reference so you know which entry to fix, and it is a per-key failure, so
`optional` applies to it.

`op` inherits `dev`'s environment, so `OP_SERVICE_ACCOUNT_TOKEN`,
`OP_SESSION_*`, and `OP_ACCOUNT` all keep working.

### keychain

macOS only. `"keychain://fsm-db"` runs
`security find-generic-password -g -s fsm-db` against `/usr/bin/security`.

```json
{ "version": 1, "secrets": { "DB_PASSWORD": "keychain://fsm-db" } }
```

Put a value there first — this is the first question everyone asks:

```sh
security add-generic-password -a "$USER" -s fsm-db -w
```

`-w` with no argument prompts for the value rather than putting it in your shell
history.

- **Options:** `account`, which becomes `-a`.
- **Failure:** no item for that service name, the keychain prompt was declined,
  or the item is not valid UTF-8.

```
Error: Failed to resolve secret `DB_PASSWORD` from provider `keychain`: no generic password item for service `dev-docs-no-such-service`. Add one with `security add-generic-password -s dev-docs-no-such-service -a <account> -w`.
```

Two things worth knowing before you lean on this.

**`security` has no batch mode.** A batch of eight keychain references is eight
invocations, and on a machine that has not yet granted `dev` access to those
items, eight keychain dialogs. Nothing can avoid that. Declining one stops the
rest of the batch rather than prompting seven more times.

**Two items sharing a service name is silent.** `security` returns one of them,
exits 0, and warns about nothing — so you get a wrong secret rather than a
failure. That is what the `account` option is for, and it is reachable only from
the object form; the `keychain://name` shorthand has nowhere to put it.

```json
{
  "version": 1,
  "secrets": {
    "DB_PASSWORD": { "provider": "keychain", "ref": "fsm-db", "account": "reporting" }
  }
}
```

On a `dev` built for anything but macOS, `keychain` is still a known provider
name, but resolving one fails the batch:

```
Error: Failed to resolve secret `DB_PASSWORD` from provider `keychain`: the `keychain` provider requires macOS and this dev binary was built for another platform. Use the `exec` provider or a `dev-secret-*` plugin for a portable secret store.
```

### exec

Runs a command on the host and takes its stdout as the secret, with one trailing
newline removed. This is the escape hatch that makes Vault, `pass`, `sops`, AWS
Secrets Manager and anything else with a CLI work without `dev` knowing about
them.

```json
{
  "version": 1,
  "secrets": {
    "VAULT_TOKEN": "exec://vault kv get -field=token secret/ci",
    "DB_PASSWORD": "exec://pass show work/fsm-db"
  }
}
```

Three slashes for an absolute program: `exec:///bin/cat .secrets/token`. The
`exec://` is the scheme separator and the command brings its own leading `/`.

- **Options:** none.
- **Failure:** the program is not on `PATH`, the command exits non-zero, the
  command prints nothing, the output is not valid UTF-8, the command string does
  not parse, or the command takes longer than 120 seconds.

**There is no shell.** `dev` splits the command string into argv itself, so `|`,
`>`, `$(...)`, `&&`, `;`, backticks, `~`, `$VAR` and globs are ordinary
characters inside an argument and nothing expands them:

```json
{ "version": 1, "secrets": { "CI_TOKEN": "exec:///bin/echo one | tr a-z A-Z" } }
```

```sh
dev exec -- printenv CI_TOKEN
```

```
one | tr a-z A-Z
```

If you need a pipeline, point `exec` at a script.

Quoting is shell-shaped: `'...'` is literal, `"..."` keeps its contents except
that `\"` and `\\` escape, `\` outside quotes makes the next character literal,
and quotes join to their neighbours so `a"b"c` is the single word `abc`. An
unterminated quote and a trailing `\` each fail that key.

```
Error: Failed to resolve secret `CI_TOKEN` from provider `exec`: the command has an unterminated `"` quote
```

That quoting is worth knowing because of what it does to an **empty
substitution**. An unquoted variable that expanded to nothing disappears
entirely; a quoted one becomes a real empty argument. Against a script that
prints `argc=$#`:

```json
{ "version": 1, "secrets": { "CI_TOKEN": "exec://./argc.sh ${localEnv:NO_SUCH_VAR}" } }
```

```
argc=0
```

```json
{ "version": 1, "secrets": { "CI_TOKEN": "exec://./argc.sh \"${localEnv:NO_SUCH_VAR}\"" } }
```

```
argc=1
```

Most CLIs read an absent argument and an empty one as different things. Pick
deliberately.

**Never put a credential in the command string.** The failing command is printed
back in the error:

```
Error: Failed to resolve secret `CI_TOKEN` from provider `exec`: `/bin/cat .secrets/nope` failed (exit 1): cat: .secrets/nope: No such file or directory
```

A credential belongs in the environment the command reads. The command inherits
`dev`'s environment, so `VAULT_ADDR`, `VAULT_TOKEN`, `HOME` and the rest all
reach it. The command's **stdout is never printed** — it goes straight into the
value and nowhere else. Only the exit status and at most one capped line of
stderr reach the error.

The command runs in the workspace folder, cannot read stdin (it is
`/dev/null`), and is bounded at 120 seconds. A tool that expects to prompt
interactively has to be given its credentials another way.

This looks alarming until you notice that `postCreateCommand` already runs
arbitrary shell from the same config tree that carries `secrets.json`, and
`initializeCommand` runs it on the host. `exec` adds no trust that was not
already there, and is weaker than either, because it never reaches a shell.

### External providers (`dev-secret-*`)

A provider name no built-in answers to resolves to an executable
`dev-secret-<name>` on `PATH`. That is how you add a vault `dev` has never heard
of without touching `dev`'s source.

See [Writing a `dev-secret-*` plugin](#writing-a-dev-secret--plugin) for the
wire format and a working example.

## Optional and create-time flags

### `optional`

Default `false`. `true` turns a resolution failure into an omitted key, and the
container still comes up.

```json
{
  "version": 1,
  "secrets": {
    "DB_PASSWORD": {
      "provider": "op",
      "ref": "Private/fsm-db/password",
      "optional": true
    }
  }
}
```

Reach for it when a secret is genuinely absent for some people — a reporting
password only two of the team hold, say — and the app degrades rather than
crashes without it.

The cost: a typo in an `optional` reference is silent. It is not a way to quiet
an error you have not read.

`optional` does not excuse an **unknown provider**. That fails the command even
when every reference naming it is optional, because it is a config error rather
than a missing value.

### `createTime`

Default `true`.

`true` means the value is in the container's environment from creation. Lifecycle
hooks see it, long-running container processes started at `postStart` see it, and
it is in `docker inspect`.

```json
{ "version": 1, "secrets": { "API_TOKEN": "env://MY_TOKEN" } }
```

```sh
dev up --rebuild
docker inspect <container> --format '{{json .Config.Env}}'
```

```
["REMOTE_CONTAINERS=true","API_TOKEN=hunter2","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
```

`false` means the value is injected only by `dev exec` and `dev shell`. It never
reaches `docker inspect`, and lifecycle hooks never see it.

```json
{
  "version": 1,
  "secrets": {
    "API_TOKEN": { "provider": "env", "ref": "MY_TOKEN", "createTime": false }
  }
}
```

```sh
dev up --rebuild
docker inspect <container> --format '{{json .Config.Env}}'
```

```
["REMOTE_CONTAINERS=true","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
```

```sh
dev exec -- printenv API_TOKEN
```

```
hunter2
```

Use `createTime: false` when the secret is only for interactive and scripted
work and nothing in the container needs it at boot. Keep the default when a
service in the container reads it at startup.

## When secrets are resolved

**Validation runs on every `dev up`**, before any side effect. It resolves
nothing.

**Resolution runs only on the create path.** A `dev up` that reuses a running
container resolves nothing and prompts for nothing. The direct consequence: a
rotated secret does not reach an already-running container's environment.

```sh
MY_TOKEN=old-value dev up --rebuild
MY_TOKEN=new-value dev up
docker inspect <container> --format '{{json .Config.Env}}'
```

```
Container 'vsc-demo-…' is already running.
["REMOTE_CONTAINERS=true","API_TOKEN=old-value","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
```

**`dev exec` and `dev shell` re-resolve on every invocation** and pass the values
through the exec's own environment. A rotated secret reaches the next command or
the next shell with no rebuild:

```sh
MY_TOKEN=new-value dev exec -- printenv API_TOKEN
```

```
new-value
```

Every secret is injected at exec time regardless of `createTime`. That flag
governs create only.

To pick up a rotation in the container's *own* environment, recreate it with
`dev up --rebuild`.

Two honest consequences:

- A process started at `postStart` keeps the value it was given until it
  restarts. Recreating the container is the only way to change it.
- Per-invocation resolution is only affordable because providers cache their own
  sessions. `dev` builds no cache of its own and holds values in memory for the
  length of one command.

## Precedence

Create-time environment is applied in this order, last value for a key winning:

1. the image's own environment (lowest);
2. `dev`'s effective `containerEnv`;
3. `dev`'s create-time `remoteEnv` layer;
4. `--secrets-file` literal values, which sit in the same tier as `remoteEnv`;
5. all `--env-file` entries from `runArgs`, in their relative order;
6. all explicit `--env`/`-e` entries from `runArgs`, in their relative order;
7. resolved `secrets.json` references (highest).

**Note the asymmetry, because it is real and non-obvious.** `--secrets-file`
carries literal values and lands at the `remoteEnv` tier, so a `runArgs --env`
entry still beats it. Resolved secret *references* are applied last and outrank
every other env source, including `runArgs`.

Secrets go last so a stale `--env-file` cannot silently shadow a live secret.

Demonstrated on one container where `SHARED` and `FROM_FILE` are each claimed by
several layers:

```json
{
  "name": "secrets-demo",
  "image": "alpine:3.20",
  "containerEnv": { "A_CONTAINERENV": "from-containerEnv", "SHARED": "from-containerEnv" },
  "remoteEnv": { "SHARED": "from-remoteEnv" },
  "runArgs": ["--env", "SHARED=from-runArgs", "--env", "FROM_FILE=from-runArgs"]
}
```

with `secrets.json` claiming `SHARED` and a `--secrets-file` claiming both:

```sh
MY_TOKEN=hunter2 dev up --rebuild --secrets-file literals.json
docker inspect <container> --format '{{json .Config.Env}}'
```

```
[
    "REMOTE_CONTAINERS=true",
    "A_CONTAINERENV=from-containerEnv",
    "FROM_FILE=from-runArgs",
    "SHARED=hunter2",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
]
```

`FROM_FILE` shows `runArgs` beating `--secrets-file`. `SHARED` shows the
resolved secret beating everything.

## Command-line flags

Both are `dev up` flags. **`dev exec` and `dev shell` take neither.** They
rediscover the sidecar beside the config on every invocation.

### `dev up --secrets <path>`

Read secret references from this file instead of the `secrets.json` beside the
config.

**It replaces the sidecar. It never merges with it.** There is exactly one
references file per invocation and no merge order to reason about. When the flag
is given, the sidecar is not read at all, even if it exists.

```sh
dev up --secrets ~/.config/dev/fsm-secrets.json
```

Unlike a missing sidecar, a path that does not exist is an error:

```
Error: Invalid devcontainer configuration: `--secrets /nope/secrets.json`: no such file
```

The motivating case is the public repo. Keep the references file outside the
tree, or gitignored, and point at it.

**One consequence to plan around.** Because `dev exec` and `dev shell` have no
such flag, a container created with `dev up --secrets <path>` in a repo with
**no** sidecar gets create-time secrets and no exec-time refresh:

```sh
dev up --rebuild --secrets outside-secrets.json     # MY_TOKEN=hunter2
MY_TOKEN=rotated-value dev exec -- printenv OUTSIDE_TOKEN
```

```
hunter2
```

The value the exec sees is the one baked in at create, because there is no
sidecar for `dev exec` to rediscover. In a repo that *does* have a sidecar, the
exec-time values come from that sidecar — a different file than the container
was created with. If you want exec-time refresh, use the sidecar.

### `dev up --secrets-file <path>`

A flat JSON map of environment variable name to **literal value**. Same flag and
same semantics `devcontainers/cli` implements.

```json
{
  "API_TOKEN": "hunter2",
  "OPENAI_API_KEY": "sk-example"
}
```

```sh
dev up --secrets-file ./ci-secrets.json
```

This file holds values, not references. No provider is consulted and no
reference parser is called on anything in it — a value that looks like a
reference is still a literal.

It is never merged with `--secrets`. Both flags may be given together and stay
independent, and a resolved `secrets.json` entry wins on a shared key (see
[Precedence](#precedence)).

They are separate flags because one carries values and one carries references.
Blurring them would mean sniffing a document to decide what it is. Hand a
references document to `--secrets-file` and it says so:

```
Error: Invalid devcontainer configuration: `--secrets-file` `/Users/you/wrong.json`: the value for `secrets` is not a string. This flag takes literal values; a `secrets.json` references document goes to `--secrets`
```

## What is visible, and where

**Create-time values are readable through `docker inspect`.**

```sh
docker inspect <container> --format '{{json .Config.Env}}'
```

```
["REMOTE_CONTAINERS=true","API_TOKEN=hunter2","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
```

This is inherent to environment variables and is not something `dev` can fix.
Anyone who can talk to the container daemon can read them. `createTime: false`
is the way out when it matters: the value is then injected only at exec time and
never reaches the container's create-time environment.

**No resolved value reaches a command line, on any runtime.** Docker and Apple
Containers pass environment through an API. Podman's HTTP API does not reliably
support interactive TTY exec, so `dev shell` shells out to the `podman` binary —
but it passes `-e NAME` with the name only and puts the value in the podman
client's own environment, which `podman` then reads back. That distinction is
worth stating plainly: `/proc/<pid>/cmdline` is world readable, so an assignment
in argv is legible to every user on the host, while `/proc/<pid>/environ` is
readable only by the process owner.

**`dev` never writes a resolved value to disk.** Not the lockfile, not the
`devcontainer.metadata` image label, no cache anywhere. Values live in memory
for the length of one command.

Inside `dev`, a resolved value lives in a `SecretValue` whose `Debug` and
`Display` both print `***`, and `expose()` is the only way out of it. So
`grep -rn "expose()" src/` enumerates every place in the codebase where a secret
becomes a plain string. They are confined to the secrets module, the two `dev up`
env applications, and the `dev exec` / `dev shell` paths.

**Error messages name the key, the provider, a path or a locator — never the
value.** For example:

```
Error: Failed to resolve secret `CI_TOKEN` from provider `file`: file `/Users/you/code/demo/.secrets/token` does not exist
```

**`secrets.json` holds references only.** What is committed is the vault path,
not the secret. See the [committed-file warning](#where-secretsjson-goes).

## Docker Compose

Compose supports exec-time secrets and refuses create-time ones. Every refusal
lands before any Compose side effect, the same way project-declared `runArgs`
are rejected.

`"createTime": false` works on Compose exactly as it does everywhere else. Such
an entry is never injected at container creation on any runtime — `dev exec` and
`dev shell` resolve it per invocation and pass it on the exec itself, and the
generated override file never sees it:

```json
{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": {
      "provider": "op",
      "ref": "Private/Linear CLI/credential",
      "createTime": false
    }
  }
}
```

A create-time entry beside a Compose config is refused, and the message names
the keys that are the problem:

```
Error: create-time secrets are not supported for Docker Compose devcontainers in `dev`; they are injected as container environment when `dev` creates the container, and the Compose path creates containers through `docker compose up` instead. In /Users/you/code/demo/.devcontainer/secrets.json, either add `"createTime": false` to LINEAR_API_KEY so the value is injected on `dev exec` and `dev shell` instead, or put the equivalent values on the configured Compose service definition (`environment:` or `env_file:`).
```

`--secrets-file` on a Compose project:

```
Error: `--secrets-file` is not supported for Docker Compose devcontainers in `dev`; Compose environment is written to a generated override file on disk, and `dev` never writes a secret value to disk. Remove `--secrets-file /Users/you/code/demo/literals.json` and put the equivalent values on the configured Compose service definition (`environment:` or `env_file:`).
```

`--secrets` on a Compose project:

```
Error: `--secrets` is not supported for Docker Compose devcontainers in `dev`; `dev up` injects create-time secrets when it creates the container, and the Compose path creates containers through `docker compose up` instead. Remove `--secrets /Users/you/code/demo/other-secrets.json`; exec-time secrets come from the `secrets.json` beside the config, which `dev exec` and `dev shell` read on every invocation.
```

The three reasons differ. Compose creates containers through `docker compose up`,
so nothing on that path injects a create-time value — a container would come up
green and misbehave later with the secret missing. Compose environment is written
to a generated override file on disk, which is the one thing `dev` promises never
to do with a secret value, so `--secrets-file` cannot be honoured at all. And
`--secrets` feeds create-time injection only; `dev exec` and `dev shell`
rediscover the sidecar per invocation and would never see the named file, so
accepting the flag would make it read as a working override when it is inert.

What to do instead for a value a Compose service needs at startup: put it on the
service (`environment:` or `env_file:`). Everything a command needs rather than
the service itself belongs in `"createTime": false`.

## Writing a `dev-secret-*` plugin

A plugin is a plain executable. It reads one JSON request on stdin, writes one
JSON response on stdout, and exits. Nothing more.

### Lookup

A provider name `dev` does not recognize — say `vault` — resolves to an
executable named `dev-secret-vault` on `PATH`. The name must be a single path
component and may contain only letters, digits, `_` and `-`.

If nothing on `PATH` matches, the unknown provider is reported at validation
time, before any side effect:

```
Error: Invalid secret reference for `CI_TOKEN`: uses unknown provider `demo`; known providers are env, exec, file, keychain, op; or put an executable `dev-secret-demo` on PATH
```

A file that is present but has no execute bit does not count as found, so it
produces this same message.

### Invocation

`dev` writes one JSON request to the plugin's stdin, followed by a newline, and
reads one JSON response from its stdout. **One invocation carries the whole batch
for that provider**, so a plugin that can do one round trip for many secrets
should.

The plugin runs with the workspace folder as its working directory and inherits
`dev`'s full environment, so `VAULT_ADDR`, `HOME`, and session tokens all reach
it.

### The request

```json
{
  "version": 1,
  "provider": "vault",
  "workspaceFolder": "/Users/you/code/fsm",
  "secrets": [
    {
      "key": "VAULT_DB_PASSWORD",
      "ref": "kv/data/prod/db#password"
    },
    {
      "key": "VAULT_API_TOKEN",
      "ref": "kv/data/prod/api#token",
      "options": {
        "namespace": "team-a"
      }
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `version` | number | Protocol version. Currently `1`. |
| `provider` | string | The bare provider name from the reference, not the executable name. One binary linked under several names can tell which it was invoked as. |
| `workspaceFolder` | string | The host workspace folder. |
| `secrets` | array | One entry per secret in this batch, in declaration order. |
| `secrets[].key` | string | The environment variable name. |
| `secrets[].ref` | string | The reference body, with the `foo://` scheme already stripped and variables already substituted. |
| `secrets[].options` | object | The object form's unrecognized keys, verbatim. **Absent when empty.** An option written as `""` stays on the wire as `""` and stays distinguishable from one that is not there. |

`dev` never sends `optional` or `createTime`. What to do about a failure is
`dev`'s policy, not the plugin's.

### The response

```json
{
  "version": 1,
  "secrets": [
    { "key": "VAULT_DB_PASSWORD", "value": "hunter2" },
    { "key": "VAULT_API_TOKEN", "error": "no such path" }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `version` | number | Required. Must be `1`. |
| `error` | string | Optional. A top-level error fails the whole batch. |
| `secrets` | array | Optional. One entry per key. |
| `secrets[].key` | string | The key from the request. |
| `secrets[].value` | string | The value, taken verbatim, newline and all. |
| `secrets[].error` | string | Why there is no value. |

Exactly one of `value` and `error` per entry. Both, or neither, fails the whole
batch.

A per-key `error` behaves exactly like any other resolution failure, so
`optional` applies to it. A key `dev` asked about that the plugin never
mentioned is also a per-key failure. Entries for keys `dev` did not ask for are
ignored.

Unknown fields are ignored, so a plugin can add one without breaking an older
`dev`.

### Rules for plugin authors

- **A plugin reporting a failure exits 0 and sets `error`.** This is the rule
  people get wrong. A non-zero exit means the plugin crashed, and `dev` reports
  the exit code rather than trusting whatever landed on stdout.
- Write nothing but the JSON response to stdout.
- Put diagnostics on stderr. stderr is inherited and `dev` never reads or
  reprints it — it is your own channel to the user's terminal, which is what
  lets a plugin prompt.
- Never echo a secret value into an `error` string. `dev` prints those and
  cannot inspect them.
- **A broken pipe on stdin is deliberately not an error.** You may answer without
  draining stdin; `dev` ignores the resulting `EPIPE` and reads your response.
- Own your own timeout. `dev` never kills a plugin, so it can wait on a
  fingerprint, a hardware key, or a 2FA push. After ten seconds `dev` prints one
  warning naming the plugin — a notice to the user, not a deadline. Anything that
  can hang with nobody present, network calls above all, needs a timeout of your
  own.
- A plugin on `PATH` runs with whatever ambient credentials the user has. So does
  `postCreateCommand`, out of the same config, so this adds no trust that was not
  there.

### Failure handling

Everything below the first row is a resolution failure and reaches the user
prefixed with ``Failed to resolve secret `KEY` from provider `demo`: ``.

| What happened | What `dev` says |
|---|---|
| Nothing on `PATH`, or present without the execute bit | ``Invalid secret reference for `KEY`: uses unknown provider `demo`; … or put an executable `dev-secret-demo` on PATH`` |
| Lost the execute bit between validation and spawn | ``plugin `dev-secret-demo` at /path is not executable; run `chmod +x /path` `` |
| Exited non-zero | ``plugin `dev-secret-demo` exited with code 3; a plugin reporting a failure should exit 0 and set `error` in its response`` |
| Wrote stdout `dev` cannot parse | ``plugin `dev-secret-demo` did not write a valid version 1 response on stdout`` |
| Replied with another protocol version | ``plugin `dev-secret-demo` replied with protocol version 2; this build of dev speaks version 1`` |
| Set a per-key `error`, or returned no entry for a requested key | your error string, verbatim |
| Set a top-level `error` | your error string, verbatim, applied to every key in the batch |

### A complete example

`dev-secret-demo` answers `demo://<name>` from a JSON file in the workspace.
Real, and short enough to read in one go.

```python
#!/usr/bin/env python3
"""dev-secret-demo: answers `demo://<name>` from a JSON file in the workspace."""
import json
import os
import sys

request = json.load(sys.stdin)
store_path = os.path.join(request["workspaceFolder"], ".secrets/store.json")
try:
    with open(store_path) as f:
        store = json.load(f)
except OSError as e:
    print(f"cannot read {store_path}: {e}", file=sys.stderr)
    json.dump({"version": 1, "error": "the demo store is unreadable"}, sys.stdout)
    sys.exit(0)

answers = []
for secret in request["secrets"]:
    name = secret["ref"]
    section = store.get(secret.get("options", {}).get("section", "default"), {})
    if name in section:
        answers.append({"key": secret["key"], "value": section[name]})
    else:
        answers.append({"key": secret["key"], "error": f"no entry named `{name}`"})

json.dump({"version": 1, "secrets": answers}, sys.stdout)
```

The whole loop:

```sh
chmod +x ~/bin/dev-secret-demo
export PATH="$HOME/bin:$PATH"
```

`.secrets/store.json` in the workspace:

```json
{
  "default": { "ci": "hunter2" },
  "staging": { "ci": "sk-example" }
}
```

`.devcontainer/secrets.json`:

```json
{
  "version": 1,
  "secrets": {
    "CI_TOKEN": "demo://ci",
    "STAGING_TOKEN": { "provider": "demo", "ref": "ci", "section": "staging" }
  }
}
```

Without the plugin on `PATH`:

```sh
dev exec -- printenv CI_TOKEN STAGING_TOKEN
```

```
Error: Invalid secret reference for `CI_TOKEN`: uses unknown provider `demo`; known providers are env, exec, file, keychain, op; or put an executable `dev-secret-demo` on PATH
```

With it:

```sh
dev exec -- printenv CI_TOKEN STAGING_TOKEN
```

```
hunter2
sk-example
```

Note that `section` was never declared anywhere in `dev`. It is an object-form
key `dev` does not recognize, so it arrived in `options` untouched.

## Troubleshooting

| Message | What to do |
|---|---|
| ``uses unknown provider `foo`; known providers are env, exec, file, keychain, op; or put an executable `dev-secret-foo` on PATH`` | Fix the scheme spelling, or put a `dev-secret-foo` executable on `PATH`. A file without the execute bit does not count. |
| ``reference has no `://` scheme`` | The shorthand needs a scheme: `env://NAME`, not `NAME`. Or use the object form. |
| ``field `provider` is missing`` / ``field `ref` is missing`` | The object form requires both. |
| ``the environment variable name contains `=` `` | The key is the env var name. `=` and whitespace are not allowed and it cannot be empty. |
| ``declared more than once`` | Two entries in `secrets` share a key. |
| ``declares secrets version 2, but only version 1 is supported`` | Set `"version": 1`. |
| ``the `env` provider takes no options, but `account` was given`` | `env`, `file` and `exec` take no options. `op` takes `account`; `keychain` takes `account`. |
| ``host environment variable `MY_TOKEN` is not set`` | Export it, or point the reference at a provider that has the value. |
| ``file `/path` does not exist`` | Check the slash count (`file:///abs` vs `file://relative`) and remember that relative paths resolve against the **workspace folder**. If the path contains `${`, a variable name is misspelled. |
| ``the 1Password CLI (`op`) is not installed or is not on PATH`` | `brew install 1password-cli`. |
| `` `op` is not authorized; run `op signin` `` | Run `op signin` in a terminal. If it mentions multiple accounts, add `"account"` to the object form. |
| ``1Password could not resolve `op://…` `` | The vault, item, or field name is wrong. Check with `op read`. |
| ``no generic password item for service `name` `` | Add one: `security add-generic-password -a "$USER" -s name -w`. |
| ``the keychain prompt for service `name` was declined or could not be shown`` | Approve the dialog. The rest of the batch was skipped, so re-run after approving. |
| ``the `keychain` provider requires macOS`` | Use `exec` or a `dev-secret-*` plugin instead. |
| `` `vault` is not installed or not on PATH `` | Install the tool the `exec` reference names. |
| ``the command has an unterminated `"` quote`` | Fix the quoting in the `exec` command string. |
| `` `cmd` succeeded but printed nothing `` | The command exited 0 with empty stdout. It probably needs credentials it did not get. |
| ``plugin `dev-secret-foo` exited with code 3`` | The plugin crashed. A plugin reporting a failure exits 0 and sets `error`. |
| ``plugin `dev-secret-foo` did not write a valid version 1 response on stdout`` | Something other than the JSON response reached stdout. Move diagnostics to stderr. |
| ``create-time secrets are not supported for Docker Compose devcontainers`` | Add `"createTime": false` to the named keys, or move them to the Compose service. See [Docker Compose](#docker-compose). |
| `` `--secrets /path`: no such file `` | Unlike a missing sidecar, an explicitly named references file must exist. |
| `` `--secrets-file` `/path`: the value for `secrets` is not a string `` | You handed a references document to the literals flag. Use `--secrets`. |

## Limits

- **No secrets for image builds.** Injection is container environment. A build
  that needs a credential needs BuildKit build secrets, which is a separate
  feature.
- **No caching by `dev`.** Every `dev exec` and `dev shell` pays one provider
  round trip. That is only affordable because providers cache their own sessions.
- **Already-running processes keep their old values.** A rotated secret needs
  `dev up --rebuild` to reach a process started at `postStart`.
- **No create-time secrets on Docker Compose.** Exec-time (`"createTime": false`)
  entries work there; create-time ones do not. See [above](#docker-compose).
- **`secrets.json` is fork-local.** It is not part of the Dev Containers
  specification, so `devcontainers/cli` and VS Code do not read it. Only
  `--secrets-file` is shared with the reference CLI.
