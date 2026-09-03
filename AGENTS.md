# Project Commands
- Install: `cargo build`
- Build: `cargo build --release`
- Test: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format check: `cargo fmt --all --check`
- Typecheck: `cargo check`

# Non-Negotiables
- Do not add new dependencies without a strong reason
- Always include verification steps after code changes
- Run tests before marking any task complete

# Common Mistakes
- (add rules here as you discover repeated issues)

# Learnings
- The `devcontainer` crate's tests are all in-file `#[cfg(test)] mod tests`; it has no `tests/`
  directory (the vendored `crates/buildkit-client-patch` is the exception).
- Anything that reads `~/.dev` has an `*_in` variant taking a `&DevHome` (defined in
  `src/util/paths.rs`); test against those with `DevHome::at(tmp)` rather than the
  `current()`-based wrappers.
- In `src/devcontainer/merge.rs`, array merge strategy is split: `forwardPorts`/`mounts`
  concatenate with dedup (`merge_array`), but `runArgs` concatenates **without** dedup
  (`merge_array_concat`) because repeated flags like `--env-file` are legitimate and
  order matters. Don't move `runArgs` back into the dedup path.
- `runArgs` is translated in `src/devcontainer/run_args.rs` (supported create-time subset:
  env file/env flags plus `--cap-add`, `--security-opt`, `--userns`, `--privileged`,
  `--init`) and applied in `src/commands/up.rs` before container creation. Every other
  flag is rejected before side effects. Docker/Podman use the shared bollard create body;
  Apple accepts only the env subset. Compose rejects project-declared `runArgs` but ignores
  inherited lower-layer `runArgs`. `extra_args` on `ContainerConfig` is now always empty
  (kept for struct compatibility).
- Feature contributions (mounts, entrypoints, capabilities, hooks) round-trip through the
  image's `devcontainer.metadata` label: written by `build_metadata_label`, recovered on the
  cache-hit path by `features_from_metadata` (both `src/devcontainer/features.rs`). The label's
  Dockerfile escaping must be `\$` — `$$` is Compose syntax and Docker's builder strips the
  dollar, corrupting `${devcontainerId}` mounts.
- `merge_layer_tracked`/`Provenance` in `src/devcontainer/merge.rs` IS the production merge
  (`dev config explain` records origins through it); the untracked `merge_layer(s)` wrappers are
  `#[cfg(test)]` reference implementations. Instrument new merge strategies there or explain drifts.
- `feature_image_tag` hashes a `TAG_FORMAT` constant (src/devcontainer/features.rs). Bump it
  whenever the generated Dockerfile or label encoding changes shape, so images cached under the
  old scheme stop being cache hits; prune then sweeps them as superseded. A pure reordering of
  content-equivalent output does not need a bump; a change to what install scripts receive does.
- The generated Dockerfile must be byte-identical between processes or Docker's layer cache
  misses and every feature reinstalls. Config's `features` map and `containerEnv` are `HashMap`s,
  so anything baked into the image goes through a sorted view: `order_features` sorts by feature
  id (the one choke point every build path calls), `ResolvedFeature.container_env` is a
  `BTreeMap`, and `build_metadata_label` routes config env maps through `sorted_env_value`.
  serde_json's `preserve_order` feature is on, so `to_value(&hashmap)` is NOT sorted any more.
- `resolve_depends_on` (src/devcontainer/features.rs) records `install_after` edges in a
  pass over the whole closure, after the discovery queue drains. Recording them during the
  drain loses any edge whose dependent is discovered after the dependency was popped, which
  can install a feature before the one it dependsOn. Keep edge recording out of that loop.
- Feature options exported into the RUN step are the project's values merged over the defaults
  in the feature's own `devcontainer-feature.json` (`ResolvedFeature.option_defaults`), per the
  spec. Exporting only what the project named leaves scripts that don't self-default with empty
  options.
- `BollardRuntime::build_image` buffers the build output tail when `-v` is off and dumps it on
  every error path, so a failing feature install.sh is not reported as a bare exit code. Keep new
  error returns in that loop going through `dump_build_tail`. The Apple runtime builds through the
  external `apple_container` crate and has no equivalent.
- Lifecycle hooks are split by moment in `src/devcontainer/lifecycle.rs`: `run_create_hooks`
  (onCreate/updateContent/postCreate/postStart) versus `run_start_hooks` (postStart only).
  Pick by whether the container already existed — never re-run create-time hooks on reuse.
  Compose has no reuse branch of its own, so `run_compose` probes `compose ps -q` before
  `compose up` and feeds `compose_hooks_owed` in `src/commands/up.rs`.
- `relay_terminal` (`src/runtime/terminal_relay.rs`) is the single place `dev shell` rewrites
  keystrokes on the way into a container, on every runtime, calling `terminal_input.rs` (splits
  bracketed pastes from keys, rewrites Shift+Enter) and `paste_bridge.rs` (copies a pasted host
  file into `/tmp/dev-paste` over the session's `SessionPeer`). Docker relays a bollard exec
  stream; Podman and Apple relay a dev-owned pty whose slave the runtime's own process gets.
  Only a file that exists on the host running `dev`, under home or a temp dir, is touched,
  which is what lets cmux's ssh upload chain into it. A new runtime's interactive path goes
  through `relay_terminal` and implements `SessionPeer`; nothing hands the host's tty
  descriptors to a runtime any more.
- cmux status is opt-in via the `cmux` config key (`cmux.status`, a `MAP_FIELDS` entry), also
  gated on `CMUX_SURFACE_ID`; without both, output is unchanged. `src/cmux.rs` is the
  module, `StatusGuard` clears the pill on drop. cmux's CLI is Mach-O, so no container-side
  agent is tracked; `cmux.agent` does nothing yet. cmux ships `cmuxd-remote-linux-<arch>` as
  a release asset, but it needs a relay token handshake `dev` doesn't own. See
  `.workflow/cmux-integration/blueprint/agent-relay-findings.md`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
