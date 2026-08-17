# Demo candidate analysis

The demo needs more than code that could be improved. It needs a feature whose dependency surface is obvious on screen, reliably different after one architectural move, and small enough for two agents to attempt inside five minutes.

| Candidate | Baseline pressure | Hexagonal payoff | Live risk | Verdict |
|---|---|---|---|---|
| Protocol transcript for every enclave wire attempt | Twelve direct protocol calls across handlers and services; JSON, Borsh, and compatibility retry paths | A recording decorator observes one narrow `ProtocolTransport` port; workflows stay unchanged | Medium: serialization details may slow the agent | **Use this** |
| Selectable second `qos_client` transport | Concrete `ureq` behavior is reached directly from workflows | A second adapter is the textbook port demonstration | High: socket semantics create too much real implementation work | Keep as the motivating future requirement |
| `boot-genesis --dry-run` | Filesystem, request, attestation, persistence, and output are sequenced together | A plan/result split makes dry-run explicit | High: destructive semantics and artifact expectations distract from the architecture | Reject for five minutes |
| Recording `NsmProvider` | Existing `NsmProvider` is already a clean capability boundary | New provider is naturally local | Low | Use only as the positive proof that QoS already contains this architecture |
| JSON output for status/version | Transport, response interpretation, and rendering share handlers | Typed results isolate rendering | Low | Too small; the baseline diff is not viscerally bad |

## Why protocol transcripts work

The transcript requirement must see every physical attempt, not merely one logical request. That includes fallback from JSON to Borsh and the manifest-version encoding sequence. Recording therefore belongs around the wire-attempt capability.

On the current baseline, there is no object representing that capability. `request::post`, `post_json`, and `post_borsh` are called from twelve places, and endpoint/configuration data travels independently. A smallest-pattern-matching implementation naturally threads the transcript through handlers, argument structs, services, and helper functions.

The prepared refactor gives each decision one owner:

| Decision | Owner |
|---|---|
| Parse the endpoint and choose adapters | CLI composition root |
| JSON-first legacy fallback | `ProtocolClient` |
| One encoded protocol attempt | `ProtocolTransport` port |
| HTTP request/response mechanics | `HttpTransport` adapter |
| Whether attempts are recorded | Future recording adapter |

The architecture is intentionally a little more explicit than the minimum production change. That is honest for the format: the talk is testing whether a visible boundary constrains a fresh coding agent.

## What counts as a win

Do not compare raw line counts alone. Compare:

- number of existing workflow signatures changed;
- number of unrelated commands taught about recording;
- number of files the agent had to understand;
- whether tests can exercise the feature without HTTP;
- whether removing the feature deletes one adapter or unwinds a parameter through the application.
