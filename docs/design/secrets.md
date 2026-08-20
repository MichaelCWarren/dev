# Secrets

Status: design, not implemented.

Dev resolves secret values itself, from pluggable providers, and injects them into
the container. Nothing has to be exported in the user's shell and no secret value
is ever written to disk by dev.

## The problem

Today the only way to get a secret into a dev container is `remoteEnv` (or
`containerEnv`, or a `--env-file` in `runArgs`). All of them have the same shape:
they copy a value that already exists somewhere dev can see.

`remoteEnv` in particular is worth stating plainly, because dev does not do what
the spec describes. The spec has the tooling apply `remoteEnv` each time it
attaches, so it reaches editor terminals but not the container's own processes.
Dev instead pours both `containerEnv` and `remoteEnv` into the same map that
becomes `ContainerConfig.env` on create (`up.rs:486-497`), with `remoteEnv`
inserted second so it wins on conflicts. Nothing re-applies it at exec time. So in
dev, `remoteEnv` is a static string map baked into the container at create.

Which means `${localEnv:LINEAR_API_KEY}` reads dev's *own* process environment, and
something must have put it there first: a shell rc export, or a wrapper such as
`op run --env-file=... -- dev up`. Both are bad. An rc export leaves a live secret
in every shell on the machine; a wrapper is a second command to remember and an
easy one to forget, and forgetting it produces a container that comes up fine and
misbehaves later.

`secrets` differs in exactly one way, and it is the whole point: **dev fetches the
value itself.** The config holds a reference, not a value.

## Non-goals

- Storing secret values in any file dev reads. References only.
- Caching secret values. Dev holds them in memory for one command and drops them.
  Providers may cache their own sessions; that is their business.
- Secrets for image *builds*. That needs BuildKit build secrets and is a separate
  feature.

## Where secrets are declared

A sidecar file named `secrets.json`, next to the config that governs the container:

| Scope | Path |
|---|---|
| Recipe (User) | `~/.dev/devcontainers/<name>/.devcontainer/secrets.json` |
| Recipe (Workspace) | `<workspace>/.devcontainer/secrets.json` |
| Plain devcontainer.json | `<workspace>/.devcontainer/secrets.json` |

One basename, one lookup rule, both scopes covered.

Not a property in `devcontainer.json`. The spec is explicit about this
(`devcontainers/spec`, `docs/specs/secrets-support.md`): "Secrets are not part of
dev containers specification and we do not expect users to store secrets inside
`devcontainer.json`." It asks the tool to supply the secure mechanism instead, and
names a secrets file, Windows Credential Manager, Mac keychain, and Azure Key Vault
as examples. That is a provider architecture described in prose. We are storing
references rather than values so we are inside the intent either way, but keeping
it out of the config file also means VS Code opening the same project never sees a
property it silently ignores.

Not a field on `Recipe` either. Anything under `recipe.customizations` is merged
into the composed `devcontainer.json` and would become a non-spec property there,
and `dev config set` rewrites `recipe.json` through `serde_json`, so anything
living in it is subject to reformatting. A sidecar is immune to both.

Sitting in the recipe directory is safe by construction, not by luck:
`prepare_recipe_directory_in` plans copies from the *global template's* source
tree, so a file with no template counterpart is never written and never removed,
and template-derived files that were edited locally are rejected rather than
clobbered (that is what the `generated` SHA map is for). The fsm recipe already
keeps `scripts/postcreate.sh` there.

### Format

```json
{
  "version": 1,
  "secrets": {
    "LINEAR_API_KEY": "op://Private/Linear CLI/credential",
    "OPENAI_API_KEY": {
      "provider": "op",
      "ref": "Work/OpenAI/api key",
      "account": "example.1password.com"
    },
    "DB_PASSWORD": { "provider": "keychain", "ref": "fsm-db", "optional": true }
  }
}
```

String shorthand is a URI whose scheme names the provider. The object form takes
provider options. `optional` (default false) turns a resolution failure into an
omitted key instead of an error.

At workspace scope this file is committed, which is mostly good: a teammate with
their own vault access inherits the wiring. It does publish vault and item names,
so a `secretsFile` path override is needed for the public-repo case.

## Providers

A trait with **batch** resolution:

```rust
trait SecretProvider {
    fn name(&self) -> &'static str;
    fn resolve(&self, refs: &[SecretRef]) -> Result<Vec<(String, SecretValue)>, DevError>;
}
```

Batch, not one call per secret. It is what lets the op provider collapse eight
lookups into a single `op inject` and therefore a single biometric prompt. A
per-secret API cannot grow that later without breaking every provider.

Three tiers, so no single provider is load-bearing:

**Built-in.** `op` (1Password CLI, with `--account` for multi-account hosts),
`keychain` (macOS `security find-generic-password`), `env` (host passthrough),
`file` (read a path).

**`exec`.** The universal escape hatch: `"exec://vault kv get -field=token secret/ci"`.
Covers Vault, AWS Secrets Manager, `pass`, `sops`, and anything else with a CLI.
This looks alarming until you notice `postCreateCommand` already runs arbitrary
shell from the same config, so it adds no new trust.

**External plugins.** An unrecognised provider `foo` resolves to a `dev-secret-foo`
executable on `PATH`, invoked with a JSON request on stdin and a JSON response on
stdout. Same pattern as git subcommands and docker CLI plugins. Someone can add a
provider without touching dev, which is the actual insurance against being stuck
with one vendor.

## Resolution timing

Split, and the split is the load-bearing decision.

**Validate early**, beside `resolve_run_args` at `up.rs:209`. Parse every reference,
reject unknown providers and malformed URIs before any side effect: before
`initializeCommand`, before container reuse, before the image build. That is the
discipline `run_args.rs` already documents, and it means a typo fails in a second
rather than after a five-minute build.

**Resolve late**, just before the env map is assembled around `up.rs:486`, and only
on the create path. Env only reaches a container at create, so resolving during a
`dev up` that reuses an existing container buys nothing and costs a biometric
prompt every single time. Get this wrong and the feature is annoying enough that
people turn it off.

**Apply last.** After the `runArgs` env loop at `up.rs:545`, so secrets are the
highest-precedence layer. Otherwise a stale `--env-file` silently shadows a live
secret, which is a miserable thing to debug.

### Exec-time injection

The spec asks that changing a secret not require rebuilding the container. Create-
time injection alone cannot do that. `docker exec` accepts `-e`, so `dev exec` and
`dev shell` can re-resolve and inject per invocation, and a rotated secret then
reaches the next shell without a recreate.

Both halves are wanted, for different reasons: create-time so lifecycle hooks and
long-running container processes have the values, exec-time so they stay fresh.
Two consequences to be honest about. Already-running processes (a dev server
started at postStart) keep the old value until restarted. And the create-time half
is what puts secrets in `docker inspect`; a `"createTime": false` per-secret option
covers the case where only exec-time injection is wanted.

Per-invocation resolution is only tolerable because providers cache their own
sessions. Dev must not build a cache of its own.

## Security rules

1. Resolved values are never persisted. Not to the lockfile (which carries only
   features), not to the `devcontainer.metadata` image label (written from feature
   metadata), not to any cache. Both are clean today and must stay that way.
2. `SecretValue` is a newtype whose `Debug` prints `***`, but it does not by itself
   close the leak. `ContainerConfig.env` is a `HashMap<String, String>`
   (`runtime/mod.rs:75`), so the newtype is gone by the time a resolved value lands
   there, and the struct's derived `Debug` would have dumped every secret on one
   `{:?}` in a future debug line. `ContainerConfig` therefore has a hand-written
   `Debug` that prints env keys and `***` for every value. The two together close
   the class of bug.
3. Error messages name the key, never the value. `run_args.rs` already sets this
   precedent ("Do not print the bytes, they may be secret-adjacent").
4. Values still land in `docker inspect` on the container via the create-time half.
   That is inherent to environment variables and should be documented, not papered
   over.

## Reference CLI compatibility

`devcontainers/cli` implements this as `devcontainer up --secrets-file <path>`,
taking a flat JSON map of key to **literal value**, applied as `remoteEnv`. Accept
the same flag with the same semantics. It is cheap, and it keeps dev usable by
anything that already knows how to drive the reference CLI. Keep it separate from
`secrets.json`: one carries values, the other carries references, and blurring them
would need format sniffing.

## Plan

**1. The seam.** New `src/devcontainer/secrets.rs`: the `SecretProvider` trait,
`SecretRef` parsing for both the URI and object forms, the provider registry, the
`SecretValue` newtype, and `secrets.json` loading and validation. Parsing only, no
I/O, no resolution. Fully unit-testable, and it is where the design either holds or
does not.

**2. Wiring.** Sidecar discovery for both scopes. Two call sites in `up.rs`:
validation at ~209, resolution and application after ~545. No provider does real
work yet; a fake provider carries the tests.

**3. Providers.** `env` and `file` first, since they need no external binary and
keep the suite hermetic. Then `op` (batched `op inject`, `--account`, and distinct
errors for not-installed and not-signed-in). Then `keychain`, then `exec`, then the
`dev-secret-*` plugin protocol.

**4. Tests.** Follow `run_args.rs`, the best-tested module in the tree.
Table-driven parsing tests; a fake provider for the up-path tests. Specifically:
resolution does *not* fire on the container-reuse path; `format!("{:?}")` of a
`SecretValue` and of a populated `ContainerConfig` contains no secret material;
`optional` omits rather than fails; secrets override a conflicting `runArgs`
env-file key.

**5. Exec-time injection.** `dev exec` and `dev shell` re-resolve and pass `-e`.
Design the trait for it in phase 1 so this is additive.

**6. `--secrets-file`.** Reference CLI compatibility.

**7. Docs and rollout.** `docs/secrets.md` in this repo. Then in chezmoi: bump
`DEV_REV` in `run_onchange_after_25-dev.sh.tmpl`, `chezmoi diff`, `chezmoi apply`,
and add a note to that repo's `CLAUDE.md` saying where per-project secrets are
declared, since recipes live outside chezmoi and nothing there would otherwise
reveal it.

Phases 1 and 2 are the real work. Every provider after that is small and
independent.

## Upstream

`secrets.json` is not in the devcontainer spec and the reference CLI solves the
same problem with a flag, so this is fork-local and gets carried across rebases
onto `squirrelsoft-dev/dev` alongside the runtime and feature-passthrough work.
Phase 6 is the part that could plausibly go upstream on its own.
