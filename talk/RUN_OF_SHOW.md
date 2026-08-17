# Run of show

## The night before

1. Run `talk/scripts/prepare-demo.sh` and keep the printed paths.
2. In terminal A, run `codex -C <baseline-path>`. Do not resume an old conversation.
3. In terminal B, run `codex -C <hexagonal-path>`. Do not resume an old conversation.
4. In both sessions, ask `bootstrap with surreal` and wait for completion.
5. In terminal B only, paste `talk/prompts/secret-primer.md` and let Codex finish loading context. Do not paste the feature prompt yet.
6. Run `cargo check -p qos_client --tests` in terminal B. Keep the clean output visible above the prompt.
7. Start the slide server with `cd talk && cargo run`, open it, press `F`, and verify prompt copy buttons.
8. Put each terminal at 125–140 columns. Turn off shell notifications and anything that can steal focus.

Running `codex -C <path>` sets the agent's working directory before it starts. Starting the command twice without `resume` gives the demo two separate conversations, as required.

## Five-minute timing

| Time | Slide | Say / do |
|---:|---|---|
| 0:00 | Title | “This is not a talk about making agents smarter. It is a live test of whether architecture makes an imperfect agent safer.” |
| 0:20 | Claim | “Agents are pattern amplifiers. Mixed ownership produces wide plausible changes; an explicit boundary contains the same instinct.” |
| 0:45 | Pressure | Point out the twelve real protocol call sites and three wire policies. “The next requirement reveals the next boundary.” |
| 1:05 | Prompt one | Copy the prompt, switch to terminal A, paste it, and submit. Let the room see that this is a fresh session. |
| 1:20 | While it works | Say only: “It is reading the same code a teammate would read.” Do not narrate every tool call. |
| 1:45 | Receipt one | If complete, run `git diff --stat` and show several threaded signatures. If incomplete, return to the slide and use the fallback receipt. |
| 2:15 | Unslop | Show the hexagon. “We pay once to give the effect an owner: endpoint, policy, port, adapter.” The refactor is prepared, compiled, and disclosed; do not pretend it happened in ten seconds. |
| 3:15 | Prompt two | Copy the same prompt from the slide, switch to terminal B, paste it, and submit. Mention that the conversation has never seen attempt one. |
| 4:00 | Receipt two | Show the live diff if ready; otherwise use the adapter-composition fallback. Compare workflow knowledge, not just lines. |
| 4:40 | Close | “The goal is not to prevent slop. Make the slop easy to unslop.” Stop at five minutes. |

## Exact session rules

- Feature attempts A and B are new Codex conversations.
- Both use the exact text in `prompts/add-transcript.md`. The website embeds that file twice.
- Terminal A receives no talk-specific architectural coaching.
- Terminal B receives `prompts/secret-primer.md` before the feature. That is the intentionally unfair experimental variable: repository shape plus context.
- Never use `codex resume` for either feature attempt.
- Do not run agents with `--yolo`. The demo worktrees already provide isolation; normal approvals preserve the credibility of the experiment.

## If the agent is slow

Advance on schedule. The agent can keep running behind the slide deck. The fallback receipts make the argument without claiming they are the live output. Say: “This is the prepared shape; we will check whether the live run converges after the talk.”

If terminal A unexpectedly introduces a clean transport port, that is not a failed talk. Say: “Great—the requirement was strong enough to force the boundary immediately. The question is whether the code made that move obvious or whether the agent had to invent it.” Then compare its refactor size with terminal B's feature-only diff.

If terminal B threads parameters through workflows, show the prepared adapter receipt and say the experiment failed: context and structure were insufficient to constrain this run. A live demo is evidence only if surprising results are allowed.

The full prepared feature result is `talk/patches/recording-adapter.patch`. It applies only after `hexagonal-transport.patch` and is for rehearsal or fallback inspection—not something to apply behind the audience's back during the experiment.

## If either diff is noisy

Use these commands in its worktree:

```sh
git diff --stat
git diff -- src/qos_client/src/lib.rs src/qos_client/src/cli/mod.rs src/qos_client/src/cli/services.rs
```

Avoid generated files and dependency lockfile churn on screen. The comparison is dependency direction.

## Cleanup

The setup script intentionally does not delete anything. After preserving any useful agent output, remove each printed worktree explicitly from the original repository:

```sh
git worktree remove <baseline-path>
git worktree remove <hexagonal-path>
```

Then remove the now-empty temporary parent directory yourself. Do not make cleanup part of the live talk.
