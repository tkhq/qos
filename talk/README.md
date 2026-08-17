# Hexagonal Architecture in the Age of Slop

A five-minute live talk built around one claim: coding agents amplify the dependency shape they find.

The slide deck is a standalone [Topcoat](https://github.com/tokio-rs/topcoat) 0.5 application. It uses Rust 1.95 without changing QoS's Rust 1.94 workspace MSRV.

## Run the slides

```sh
cd talk
cargo run
```

Open <http://127.0.0.1:3000>. Use the arrow keys, Page Up/Page Down, or Space to navigate. Press `N` for presenter notes and `F` for full screen. Each live prompt slide has a copy button.

## Prepare the live demo

```sh
talk/scripts/prepare-demo.sh
```

The script creates two detached worktrees beneath a fresh temporary directory:

- `slop` is the repository baseline.
- `hexagonal` has the validated transport-boundary patch applied.

It prints the two `codex -C <worktree>` commands to start genuinely new sessions. It never removes an existing worktree or directory.

Read [RUN_OF_SHOW.md](RUN_OF_SHOW.md) before presenting. The exact repeated feature prompt is [prompts/add-transcript.md](prompts/add-transcript.md); both slides embed that one file, so the wording cannot drift.

## Contents

- `src/`: Topcoat slide application and browser assets.
- `prompts/`: the repeated feature prompt, unslop prompt, and private Surreal primer.
- `patches/hexagonal-transport.patch`: compiled, test-checked terminal-B baseline.
- `patches/recording-adapter.patch`: compiled, tested fallback for the expected terminal-B feature result.
- `receipts/`: compact fallback excerpts rendered in the deck.
- `scripts/prepare-demo.sh`: non-destructive two-worktree setup.
- `CANDIDATES.md`: why protocol transcripts beat the other demo candidates.
- `RUN_OF_SHOW.md`: setup, timing, talk track, failure modes, and cleanup.

The fallback receipts are deliberately representative excerpts. During a successful live run, show the actual `git diff --stat` and diff from each worktree instead.
