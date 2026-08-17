use topcoat::{
	Result,
	router::{Body, Response, Router, page, route},
	view::view,
};

const FEATURE_PROMPT: &str = include_str!("../prompts/add-transcript.md");
const UNSLOP_PROMPT: &str = include_str!("../prompts/unslop.md");
const SECRET_PRIMER: &str = include_str!("../prompts/secret-primer.md");
const SLOP_RECEIPT: &str = include_str!("../receipts/slop.diff");
const HEXAGONAL_RECEIPT: &str = include_str!("../receipts/hexagonal.diff");
const SMALL_RECEIPT: &str = include_str!("../receipts/small.diff");
const SLIDES_CSS: &str = include_str!("./slides.css");
const SLIDES_JS: &str = include_str!("./slides.js");

#[tokio::main]
async fn main() {
	let router =
		Router::builder().page(home).route(slides_css).route(slides_js).build();

	println!("Slides: http://127.0.0.1:3000");

	topcoat::start(router).await.expect("talk server should start");
}

#[route(GET "/slides.css")]
async fn slides_css() -> Result<Response> {
	Ok(Response::builder()
		.header("Content-Type", "text/css; charset=utf-8")
		.body(Body::from(SLIDES_CSS))?)
}

#[route(GET "/slides.js")]
async fn slides_js() -> Result<Response> {
	Ok(Response::builder()
		.header("Content-Type", "text/javascript; charset=utf-8")
		.body(Body::from(SLIDES_JS))?)
}

#[page("/")]
#[allow(clippy::too_many_lines)]
async fn home() -> Result {
	view! {
		<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<meta name="theme-color" content="#090b10">
				<title>"Hexagonal Architecture in the Age of Slop"</title>
				<link rel="stylesheet" href="/slides.css">
				topcoat::dev::script()
			</head>
			<body>
				<main class="deck" data-deck="">
					<section class="slide title-slide is-active" data-slide="0" data-cue="0:00 — 0:20">
						<div class="eyebrow">"A five-minute live experiment"</div>
						<h1>"Hexagonal Architecture" <span>"in the Age of Slop"</span></h1>
						<p class="lede">"Same feature. Same agent. Different shape of code."</p>
						<div class="title-mark" aria-hidden="true">
							<span>"PROMPT"</span>
							<i></i>
							<span>"DIFF"</span>
						</div>
						<aside class="notes">
							"Open cold: this is not a talk about making agents smarter. It is a live test of whether architecture can make an imperfect agent safer."
						</aside>
					</section>

					<section class="slide" data-slide="1" data-cue="0:20 — 0:45">
						<div class="eyebrow">"The claim"</div>
						<h2>"Agents amplify the shape they find."</h2>
						<div class="amplifier-grid">
							<article class="signal-card signal-card--bad">
								<span class="signal-label">"Mixed ownership"</span>
								<strong>"One new concern"</strong>
								<div class="sprawl" aria-label="Change spreads across six modules">
									<i></i><i></i><i></i><i></i><i></i><i></i>
								</div>
								<p>"The agent repeats the nearest pattern everywhere."</p>
							</article>
							<article class="signal-card signal-card--good">
								<span class="signal-label">"Explicit boundary"</span>
								<strong>"One new concern"</strong>
								<div class="contained" aria-label="Change stays in one adapter"><i></i></div>
								<p>"The same instinct produces a local change."</p>
							</article>
						</div>
						<aside class="notes">
							"Do not call the current code bad. It shipped useful behavior. Say: the next requirement reveals the next boundary."
						</aside>
					</section>

					<section class="slide" data-slide="2" data-cue="0:45 — 1:05">
						<div class="eyebrow">"The pressure"</div>
						<h2>"Twelve calls. Three wire policies. No owner."</h2>
						<div class="code-map">
							<div class="code-map__callers">
								<span>"status"</span><span>"version"</span><span>"genesis"</span>
								<span>"boot"</span><span>"provision"</span><span>"key-fwd"</span>
								<span>"export"</span><span>"inject"</span><span>"attest"</span>
							</div>
							<div class="code-map__arrows" aria-hidden="true">"\\  |  /"</div>
							<pre class="code-window"><code><span class="kw">"request::"</span>"post(uri, &req)\n"
								<span class="kw">"request::"</span>"post_json(uri, &req)\n"
								<span class="kw">"request::"</span>"post_borsh(uri, &req)"</code></pre>
						</div>
						<p class="caption">"The feature: record every wire attempt — including compatibility retries."</p>
						<aside class="notes">
							"This is real qos_client code. The HTTP helper is centralized, but the capability and its configuration are not. Recording exposes that distinction."
						</aside>
					</section>

					<section class="slide prompt-slide" data-slide="3" data-cue="1:05 — 1:45">
						<div class="eyebrow">"Fresh Codex session · baseline"</div>
						<div class="slide-heading-row">
							<h2>"Prompt one: add the feature."</h2>
							<button class="copy-button" type="button" data-copy-target="feature-prompt">"Copy prompt"</button>
						</div>
						<pre class="prompt" id="feature-prompt"><code>(FEATURE_PROMPT)</code></pre>
						<div class="live-strip">
							<span class="live-dot"></span>
							<strong>"LIVE"</strong>
							<span>"Switch to terminal A. Let Codex follow the code it sees."</span>
						</div>
						<aside class="notes">
							"Use a genuinely new session. If it runs long, let it continue and advance: the fallback receipt is next. Do not editorialize while it works."
						</aside>
					</section>

					<section class="slide receipt-slide" data-slide="4" data-cue="1:45 — 2:15">
						<div class="eyebrow">"Receipt one"</div>
						<h2>"The concern follows every call."</h2>
						<div class="metric-row">
							<div><strong>"12"</strong><span>"call sites"</span></div>
							<div><strong>"9"</strong><span>"signatures"</span></div>
							<div><strong>"4"</strong><span>"layers touched"</span></div>
						</div>
						<pre class="diff" id="slop-receipt"><code>(SLOP_RECEIPT)</code></pre>
						<p class="caption">"Nothing here is absurd in isolation. The aggregate is the smell."</p>
						<aside class="notes">
							"Metrics are the representative fallback target, not a promise about the stochastic live diff. Replace them with the live git diff --stat if the run completes."
						</aside>
					</section>

					<section class="slide architecture-slide" data-slide="5" data-cue="2:15 — 3:15">
						<div class="eyebrow">"Unslop once"</div>
						<h2>"Give the effect an owner."</h2>
						<div class="architecture-layout">
							<div class="hexagon" aria-label="Hexagonal layers">
								<div class="hexagon__ring hexagon__ring--outer"><span>"ADAPTERS"</span></div>
								<div class="hexagon__ring hexagon__ring--middle"><span>"PORT"</span></div>
								<div class="hexagon__ring hexagon__ring--inner"><span>"WORKFLOW"</span></div>
							</div>
							<div class="boundary-list">
								<div><span>"CLI"</span><p>"chooses and composes adapters"</p></div>
								<div><span>"ProtocolClient"</span><p>"owns encoding and fallback policy"</p></div>
								<div><span>"ProtocolTransport"</span><p>"one typed wire attempt"</p></div>
								<div><span>"HttpTransport"</span><p>"owns ureq and HTTP errors"</p></div>
							</div>
						</div>
						<details class="prompt-details">
							<summary>"The unslop prompt"</summary>
							<pre class="prompt" id="unslop-prompt"><code>(UNSLOP_PROMPT)</code></pre>
						</details>
						<pre class="diff diff--short"><code>(HEXAGONAL_RECEIPT)</code></pre>
						<aside class="notes">
							"This refactor is prepared before the talk. The secret session primer is available in presenter mode. The point is not traits everywhere: one effect, used many times, earned one port."
							<pre id="secret-primer"><code>(SECRET_PRIMER)</code></pre>
						</aside>
					</section>

					<section class="slide prompt-slide" data-slide="6" data-cue="3:15 — 4:00">
						<div class="eyebrow">"Fresh Codex session · hexagonal baseline"</div>
						<div class="slide-heading-row">
							<h2>"Same prompt. Not one word changed."</h2>
							<button class="copy-button" type="button" data-copy-target="feature-prompt-repeat">"Copy prompt"</button>
						</div>
						<pre class="prompt prompt--repeat" id="feature-prompt-repeat"><code>(FEATURE_PROMPT)</code></pre>
						<div class="live-strip live-strip--good">
							<span class="live-dot"></span>
							<strong>"LIVE"</strong>
							<span>"Switch to terminal B. The session has never seen attempt one."</span>
						</div>
						<aside class="notes">
							"Terminal B starts from the prepared hexagonal patch in a separate worktree and a new Codex conversation. It was privately primed from Surreal before the room arrived."
						</aside>
					</section>

					<section class="slide comparison-slide" data-slide="7" data-cue="4:00 — 4:40">
						<div class="eyebrow">"Receipt two"</div>
						<h2>"The feature becomes an adapter."</h2>
						<div class="comparison">
							<article class="comparison__before">
								<header><span>"BEFORE"</span><strong>"Thread the concern"</strong></header>
								<div class="file-stack"><i></i><i></i><i></i><i></i><i></i><i></i></div>
								<p>"Every workflow learns about recording."</p>
							</article>
							<article class="comparison__after">
								<header><span>"AFTER"</span><strong>"Compose the concern"</strong></header>
								<pre class="diff diff--small"><code>(SMALL_RECEIPT)</code></pre>
								<p>"Workflows remain oblivious."</p>
							</article>
						</div>
						<aside class="notes">
							"Use the live diff if available. The important metric is not raw lines: it is how many unrelated workflows had to understand the new concern."
						</aside>
					</section>

					<section class="slide closing-slide" data-slide="8" data-cue="4:40 — 5:00">
						<div class="eyebrow">"The takeaway"</div>
						<h2>"Do not try to eliminate slop."</h2>
						<p class="closing-line">"Make the slop" <strong>"easy to unslop."</strong></p>
						<div class="closing-rules">
							<span>"Clear owners"</span>
							<span>"Narrow capabilities"</span>
							<span>"Local diffs"</span>
						</div>
						<p class="closing-footnote">"Architecture is a context window for humans and agents."</p>
						<aside class="notes">
							"Land the final line and stop. Do not recap the implementation."
						</aside>
					</section>
				</main>

				<footer class="controls">
					<div class="controls__left">
						<span class="wordmark">"HEX / SLOP"</span>
						<span class="cue" data-cue-label="">"0:00 — 0:20"</span>
					</div>
					<div class="progress" aria-label="Slide progress"><i data-progress=""></i></div>
					<div class="controls__right">
						<button type="button" data-action="notes" title="Toggle presenter notes">"N"</button>
						<button type="button" data-action="prev" aria-label="Previous slide">"←"</button>
						<span><b data-current="">"1"</b>" / 9"</span>
						<button type="button" data-action="next" aria-label="Next slide">"→"</button>
					</div>
				</footer>

				<div class="toast" role="status" aria-live="polite" data-toast="">"Copied"</div>
				<script src="/slides.js" defer=""></script>
			</body>
		</html>
	}
}
