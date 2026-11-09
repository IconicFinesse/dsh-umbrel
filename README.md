# dsh-umbrel

DeepSeek Harness (`@deepseek-ai/dsh`, MIT) packaged to run on umbrelOS as
the app **iconicfinesse-dsh** in the IconicFinesse community store.

## Shape

One thin image (Node 26 + git), two roles, one shared data volume:

- **`dsh` service** — the harness. The image carries no dsh at all: an
  entrypoint installs it from npm into the volume and keeps it converged.
- **`web` service** — a small password gate (zero-dependency Node) in front
  of dsh web. dsh's own web sign-in is a one-time launch-token link; the
  gate exchanges that token server-side (it reads the current link from the
  shared volume) so no token ever appears in a browser URL. Sign-in is
  password-only with a first-run setup: until the owner creates a password
  on first open, the gate serves a one-time setup page; that password is
  the sign-in from then on (the gate stores only a salted scrypt hash).
  The gate presents dsh's own bound authority upstream, so it works at
  whatever address the app lands on.

All durable state is in the app data folder: the harness install, DSH_HOME
(`home/.dsh` — providers, keys, profiles, plugins, sessions), the default
workspace (the volume's home), the launch link, and the gate's record.

## Updates: always latest, never destructive

On every start the entrypoint resolves the version tracked in
`data/dsh-version.txt` — by default the npm `latest` dist-tag — and, if it
moved, installs the new version *beside* the old one, verifies the binary
runs, then swaps atomically. The previous install is kept as a
one-generation rollback, and if a fresh update fails to come up the
entrypoint rolls back on its own. A failed *download* just keeps the old
version serving. User data is never in the swap path, so updates cannot
delete it. To freeze on an exact version, write it into
`data/dsh-version.txt` and restart the app.

The image itself changes only when the entrypoint, the gate, or the base
image changes; CI (`.github/workflows/build-image.yml`) builds multi-arch
(amd64 + arm64) to GHCR. dsh releases never touch this pipeline.

## Scope

Inside the app, the agent's "full access" reaches the app's container and
data folder — not the Umbrel host. Host/admin control is a separate wiring:
dsh as an MCP client to the umbrelOS Agents MCP, the way Agent Zero /
Hermes containers reach it.

## Spike results (2026-11-08, all verified live)

Run in Arcane's nested Docker on the Umbrel host (kernel 6.12):

1. **dsh web runs in a container** — full browser flow: auth fence (401) →
   token exchange (303 + cookie) → UI (200). dsh refuses wildcard binds by
   design, so the entrypoint resolves the container's concrete IPv4.
2. **Landlock ABI 5 is available in-container** under Docker's default
   seccomp profile, so dsh's Read Only / Workspace Write presets work in
   app form. (`probe/landlock_probe.py`)
3. **Updates proven both directions** — pin bump 0.2.1-rc.5 → 0.2.2-rc.1
   swapped cleanly with a `~/.dsh` marker SHA-256-identical after; a bogus
   pin was rejected with the old version kept serving.

## Layout

- `Dockerfile`, `entrypoint.sh` — the image and the dsh role
- `gate/gate.js` — the password front door (the original VM install runs
  its own earlier copy of the gate, in username+password mode; this file
  defaults to that same mode and adds the app's password-only setup mode)
- `proof/` — a local compose proof of the production shape + test battery
- The Umbrel package itself (manifest + compose) lives in the
  **iconicfinesse-umbrel-app-store** repo under `iconicfinesse-dsh/`
