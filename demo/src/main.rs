//! The vfaas lightning-talk deck: a server-rendered slideshow whose live
//! slides shell out to `cargo xtask` and forward the output on screen.
//!
//! The URL is the slide state (`/0` … `/7`, plus `/appendix`); arrow keys
//! navigate. Live slides run the same xtask commands anyone would run by
//! hand — the deck adds nothing to the trust story, it just projects the
//! CLI.
//!
//! Endpoint config (read per command): `VFAAS_URL` sends commands to a
//! pivot's HTTP front (e.g. the TVC app URL); otherwise `VFAAS_SOCKET`
//! (default `/tmp/pivot_vfaas.sock`) drives a local pivot — the stage
//! fallback is flipping one environment variable.

use tokio::process::Command;
use topcoat::{
	Result,
	asset::{Asset, AssetBundle, RouterBuilderAssetExt, asset},
	context::Cx,
	router::{Router, layout, page},
	runtime::{Event, procedure, shard},
	view::{component, view},
};

/// Repo root: `demo/` sits directly under it.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

const STYLE: Asset = asset!("./style.css");
const NAV_JS: Asset = asset!("./nav.js");

const POLICY_SOURCE: &str =
	include_str!("../../src/vfaas/examples/screening-rules/src/lib.rs");
const PROGRAM_SOURCE: &str =
	include_str!("../../src/vfaas/examples/sanctions-screening/src/lib.rs");

/// The address the list-v2 upgrade newly flags — clear under v1.
const WATCHED_ADDRESS: &str = "0x3333333333333333333333333333333333333333";

#[tokio::main]
async fn main() {
	topcoat::start(
		Router::builder()
			.assets(AssetBundle::load().unwrap())
			.layout(deck)
			.page(preflight)
			.page(title)
			.page(ceremony)
			.page(policy)
			.page(program)
			.page(live_register)
			.page(live_upgrade)
			.page(close)
			.page(appendix)
			.build(),
	)
	.await
	.unwrap();
}

// --- chrome ----------------------------------------------------------------

#[layout("/")]
async fn deck(slot: Result) -> Result {
	view! {
		<!DOCTYPE html>
		<html>
			<head>
				<meta charset="utf-8">
				<title>"vfaas"</title>
				<link rel="stylesheet" href=(STYLE)>
				topcoat::dev::script()
				topcoat::runtime::script()
			</head>
			<body>
				(slot?)
				<footer class="nav-hint">"← → navigate · a appendix"</footer>
				<script src=(NAV_JS)></script>
			</body>
		</html>
	}
}

// --- slides ----------------------------------------------------------------

/// Hidden preflight board: is the enclave reachable, what is registered.
/// Probes at page render — reload to re-check.
#[page("/0")]
async fn preflight() -> Result {
	let endpoint = endpoint_description();
	let listing = run_xtask("preflight", "").await;

	view! {
		<section class="slide">
			<h2>"preflight"</h2>
			<p class="dim">"endpoint: "(endpoint)</p>
			<pre class="out">(listing)</pre>
			<p class="dim">
				"expected before the talk: both policies, fee-calculator, \
				 reverse, and sanctions-screening v0.1.0 — v0.2.0 must NOT \
				 be registered yet."
			</p>
		</section>
	}
}

#[page("/1")]
async fn title() -> Result {
	view! {
		<section class="slide">
			<h1>"vfaas — verifiable functions"</h1>
			<p class="big">
				"shipping enclave logic: an approval, not a deployment"
			</p>
			<p class="dim">"one QOS enclave · quorum-approved WASM \
			 functions · quorum-approved WASM policies · every outcome \
			 signed"</p>
		</section>
	}
}

#[page("/2")]
async fn ceremony() -> Result {
	view! {
		<section class="slide">
			<h2>"the cost of a change"</h2>
			<div class="contrast">
				<div class="today">
					<h3>"today: every app change"</h3>
					<ol>
						<li>"rebuild the enclave image"</li>
						<li>"new manifest"</li>
						<li>"K-of-N re-sign"</li>
						<li>"cold boot new enclaves"</li>
						<li>"re-provision the quorum key"</li>
						<li>"shift traffic"</li>
					</ol>
				</div>
				<div class="vfaas">
					<h3>"vfaas: every function change"</h3>
					<ol>
						<li>"K-of-N sign the artifact"</li>
						<li>"one HTTP request to the running enclave"</li>
					</ol>
					<p class="dim">
						"the enclave, its manifest, its attestation, and \
						 its provisioned keys never change"
					</p>
				</div>
			</div>
		</section>
	}
}

#[page("/3")]
async fn policy() -> Result {
	view! {
		<section class="slide">
			<h2>"a policy is one plain Rust function"</h2>
			<pre class="source">(POLICY_SOURCE)</pre>
		</section>
	}
}

#[page("/4")]
async fn program() -> Result {
	view! {
		<section class="slide">
			<h2>"the function is just as boring"</h2>
			<p class="dim">
				"typed Borsh in, typed Borsh out; the SDK hides every byte \
				 of enclave and WASM plumbing — it tests with plain cargo \
				 test, no wasm toolchain"
			</p>
			<pre class="source">(PROGRAM_SOURCE)</pre>
		</section>
	}
}

#[page("/5")]
async fn live_register() -> Result {
	view! {
		<section class="slide">
			<h2>"live: content-addressed invocation"</h2>
			run_panel(
				id: "invoke-v1",
				description: xtask_help("invoke").await,
				address: Some("0x1111111111111111111111111111111111111111"),
			)
			<p class="dim">
				"the POST path IS the program's wasm hash — you invoke \
				 exactly the code the quorum approved, not \"an endpoint\". \
				 The attestation binds program, policy, input, and outcome; \
				 try a malformed address: the denial comes back signed too."
			</p>
		</section>
	}
}

#[page("/6")]
async fn live_upgrade() -> Result {
	view! {
		<section class="slide">
			<h2>"live: the upgrade is one request"</h2>
			run_panel(
				id: "invoke-v1",
				description: "Screen the watched address against list v1 — \
				              it is not on that list.".to_string(),
				address: Some(WATCHED_ADDRESS),
			)
			run_panel(
				id: "register-v2",
				description: xtask_help("register").await,
				address: None,
			)
			run_panel(
				id: "invoke-v2",
				description: "Screen the same address against list v2 — a \
				              different content address, a different \
				              verdict, and v1 is still registered and \
				              auditable under its own hash.".to_string(),
				address: Some(WATCHED_ADDRESS),
			)
		</section>
	}
}

#[page("/7")]
async fn close() -> Result {
	view! {
		<section class="slide">
			<h1>"an approval, not a deployment"</h1>
			<ul>
				<li>"policies and functions: single-threaded Rust anyone \
				     can review"</li>
				<li>"the enclave's own manifest set signs every artifact \
				     — no new trust machinery"</li>
				<li>"upgrades register against the running enclave; \
				     nothing reboots, nothing re-provisions"</li>
				<li>"content-addressed paths: the URL says what runs"</li>
			</ul>
			<p class="dim">
				"also runnable here: provable password generators, PII \
				 redaction, provable oracles — anything that is a \
				 function"
			</p>
			<p class="dim">"qos · rp/meta-pivot-fable · src/vfaas"</p>
		</section>
	}
}

#[page("/appendix")]
async fn appendix() -> Result {
	let helps = [
		xtask_help_full(None).await,
		xtask_help_full(Some("bootstrap")).await,
		xtask_help_full(Some("pubkeys")).await,
		xtask_help_full(Some("build")).await,
		xtask_help_full(Some("approve")).await,
		xtask_help_full(Some("register")).await,
		xtask_help_full(Some("invoke")).await,
		xtask_help_full(Some("ls")).await,
		xtask_help_full(Some("demo")).await,
	];

	view! {
		<section class="slide">
			<h2>"appendix: the entire client surface"</h2>
			<p class="dim">
				"rendered live from cargo xtask --help — the deck and the \
				 CLI cannot drift"
			</p>
			for help in helps {
				<pre>(help)</pre>
			}
		</section>
	}
}

// --- live panels -------------------------------------------------------------

/// One live command: its clap description, the literal command line, a Run
/// button, and the forwarded output.
#[component]
async fn run_panel(
	id: &'static str,
	description: String,
	address: Option<&'static str>,
) -> Result {
	let display = command_line(id, address.unwrap_or("<address>"));

	view! {
		signal cmd = id.to_string();
		signal address_value = address.unwrap_or_default().to_string();
		signal output = String::new();

		<div class="panel">
			<p class="help">(description)</p>
			<code class="cmdline">"$ "(display)</code>
			if address.is_some() {
				<input
					:value=$(address_value.get())
					@input=$(|e: Event| address_value.set(e.target.value))
				>
			}
			<button @click=$(async |_e| {
				let result = run_xtask_on_server(
					cmd.get(),
					address_value.get(),
				)
				.await;
				output.set(result);
			})>
				"Run"
			</button>
			xtask_output(output: $(output.get()))
		</div>
	}
}

/// Runs a deck command on the server and returns the shell output.
#[procedure]
pub async fn run_xtask_on_server(
	id: String,
	address: String,
) -> Result<String> {
	Ok(run_xtask(&id, &address).await)
}

/// The output panel re-renders whenever a run completes.
#[shard]
async fn xtask_output(cx: &Cx, output: String) -> Result {
	if output.is_empty() {
		return view! { <pre class="out dim">"— not run yet —"</pre> };
	}

	view! { <pre class="out">(output)</pre> }
}

// --- xtask plumbing ----------------------------------------------------------

/// The commands the deck may run. The id→argv table is server-side and
/// closed: the browser picks an id and an address, never an argv.
fn command_args(id: &str, address: &str) -> Option<Vec<String>> {
	let args: Vec<&str> = match id {
		"preflight" => vec!["ls"],
		"register-v2" => vec!["register", "sanctions-screening-v2"],
		"invoke-v1" => {
			vec!["invoke", "sanctions-screening", "--address", address]
		}
		"invoke-v2" => {
			vec!["invoke", "sanctions-screening-v2", "--address", address]
		}
		_ => return None,
	};

	Some(args.into_iter().map(String::from).collect())
}

fn command_line(id: &str, address: &str) -> String {
	let args = command_args(id, address)
		.map_or_else(|| format!("<unknown id {id}>"), |a| a.join(" "));
	format!("cargo xtask {args} {}", endpoint_flags().join(" "))
}

fn endpoint_flags() -> Vec<String> {
	match std::env::var("VFAAS_URL") {
		Ok(url) => vec!["--url".to_string(), url],
		Err(_) => vec![
			"--socket".to_string(),
			std::env::var("VFAAS_SOCKET")
				.unwrap_or_else(|_| "/tmp/pivot_vfaas.sock".to_string()),
		],
	}
}

fn endpoint_description() -> String {
	endpoint_flags().join(" ")
}

fn xtask_bin() -> String {
	format!("{REPO_ROOT}/target/debug/xtask")
}

async fn run_xtask(id: &str, address: &str) -> String {
	let Some(mut args) = command_args(id, address) else {
		return format!("unknown command id {id:?}");
	};
	args.extend(endpoint_flags());
	let display = format!("$ cargo xtask {}", args.join(" "));

	match Command::new(xtask_bin())
		.args(&args)
		.current_dir(REPO_ROOT)
		.output()
		.await
	{
		Ok(out) => format!(
			"{display}\n\n{}{}",
			String::from_utf8_lossy(&out.stdout),
			String::from_utf8_lossy(&out.stderr),
		),
		Err(e) => format!(
			"{display}\n\nfailed to spawn {}: {e}\nbuild it first: cargo \
			 build -p xtask",
			xtask_bin()
		),
	}
}

/// A subcommand's clap description: the `--help` text above its Usage
/// line, i.e. the `long_about`.
async fn xtask_help(subcommand: &str) -> String {
	let full = xtask_help_full(Some(subcommand)).await;
	full.split("Usage:").next().unwrap_or(&full).trim().to_string()
}

async fn xtask_help_full(subcommand: Option<&str>) -> String {
	let mut args: Vec<&str> = subcommand.into_iter().collect();
	args.push("--help");

	match Command::new(xtask_bin())
		.args(&args)
		.current_dir(REPO_ROOT)
		.output()
		.await
	{
		Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
		Err(e) => format!(
			"failed to run xtask --help: {e}\nbuild it first: cargo build \
			 -p xtask"
		),
	}
}
