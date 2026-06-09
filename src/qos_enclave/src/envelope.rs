//! JSON-envelope log emission for the qos-enclave container.
//!
//! Every line the container writes to stdout is wrapped in a `v:1` JSON
//! envelope so downstream consumers (tvc-observer) can discriminate customer
//! application output from system logs without trusting line contents:
//!
//! ```json
//! {"v":1,"log_type":"system","ts":"2026-05-28T20:26:40.000Z","level":"info","msg":"Booting Nitro Enclave:"}
//! {"v":1,"log_type":"app","stream":"stdout","ts":"2026-05-28T20:26:40.000Z","msg":"hello from the pivot"}
//! ```
//!
//! The envelope is the cross-repo contract consumed by tvc-observer (mono);
//! its shape is pinned by the fixtures in `fixtures/`. App output can never
//! spoof a system line: customer bytes only ever appear inside `msg`.
//!
//! `ts` is host-assigned ("when qos_enclave saw the line"), not in-enclave
//! emission time.

use std::{
	io::{self, Write},
	time::{SystemTime, UNIX_EPOCH},
};

/// Prefixes that `qos_core`'s reaper (`reprint_pivot_output`) prepends to
/// every line of pivot (customer app) output before it reaches the enclave
/// console.
///
/// LOAD-BEARING CONTRACT: classification of app vs system lines depends on
/// these exact strings. If `qos_core/src/reaper.rs` changes its prefixes,
/// these must change in lockstep (and vice versa).
pub const PIVOT_STDOUT_PREFIX: &str = "PIVOT[OUT]: ";
/// See [`PIVOT_STDOUT_PREFIX`].
pub const PIVOT_STDERR_PREFIX: &str = "PIVOT[ERR]: ";

/// Upper bound on a single buffered line. A line longer than this is emitted
/// in segments (each segment classified independently) so a pathological
/// pivot can't grow memory without bound by never writing a newline.
const MAX_LINE_BYTES: usize = 256 * 1024;

type Clock = fn() -> SystemTime;

/// An [`io::Write`] adapter that turns a raw console byte stream into
/// newline-delimited JSON envelope lines on the inner writer.
///
/// The nitro-cli console reader (`Console::read_to`) delivers arbitrary
/// chunk boundaries (raw epoll reads, not line-aligned), so this writer
/// carries partial lines across `write` calls. Call [`EnvelopeWriter::finish`]
/// after the console stream ends to emit a trailing unterminated line.
pub struct EnvelopeWriter<W: Write> {
	out: W,
	partial: Vec<u8>,
	clock: Clock,
}

impl<W: Write> EnvelopeWriter<W> {
	pub fn new(out: W) -> Self {
		Self::with_clock(out, SystemTime::now)
	}

	fn with_clock(out: W, clock: Clock) -> Self {
		Self { out, partial: Vec::new(), clock }
	}

	/// Emit any buffered unterminated line and flush the inner writer. Call
	/// once after the console stream disconnects.
	pub fn finish(&mut self) -> io::Result<()> {
		if !self.partial.is_empty() {
			let line = std::mem::take(&mut self.partial);
			self.emit_line(&line)?;
		}
		self.out.flush()
	}

	/// Classify one complete line (without its trailing `\n`) and write it as
	/// an envelope line.
	fn emit_line(&mut self, line: &[u8]) -> io::Result<()> {
		// Console output commonly uses CRLF line endings; strip the CR.
		let line = match line.last() {
			Some(b'\r') => &line[..line.len() - 1],
			_ => line,
		};

		let text = String::from_utf8_lossy(line);

		// Customer app output always carries the reaper prefix; anything
		// unprefixed (qos_core logs, kernel/init boot noise) is system.
		let (log_type, stream, msg) =
			if let Some(msg) = text.strip_prefix(PIVOT_STDOUT_PREFIX) {
				("app", Some("stdout"), msg)
			} else if let Some(msg) = text.strip_prefix(PIVOT_STDERR_PREFIX) {
				("app", Some("stderr"), msg)
			} else {
				("system", None, text.as_ref())
			};

		let envelope = format_envelope(
			log_type,
			stream,
			None,
			&rfc3339_millis((self.clock)()),
			msg,
		);

		self.out.write_all(envelope.as_bytes())
	}
}

impl<W: Write> Write for EnvelopeWriter<W> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		// Always consume the full buffer: the nitro-cli console loop calls
		// `write` (not `write_all`) and would silently drop a short count.
		let mut start = 0;

		for (i, b) in buf.iter().enumerate() {
			if *b == b'\n' {
				if self.partial.is_empty() {
					let segment = buf[start..i].to_vec();
					self.emit_line(&segment)?;
				} else {
					let mut line = std::mem::take(&mut self.partial);
					line.extend_from_slice(&buf[start..i]);
					self.emit_line(&line)?;
				}

				start = i + 1;
			}
		}

		self.partial.extend_from_slice(&buf[start..]);

		// Bound memory for never-terminated lines by emitting a segment.
		if self.partial.len() >= MAX_LINE_BYTES {
			let line = std::mem::take(&mut self.partial);
			self.emit_line(&line)?;
		}

		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		// Intentionally does NOT emit the partial line: a flush mid-stream
		// must not split a line. Use `finish` at end-of-stream.
		self.out.flush()
	}
}

/// Write one `log_type:"system"` envelope line for qos_enclave's own logging
/// to stdout (level `info`).
pub fn log_system(msg: &str) {
	log_system_level("info", msg);
}

/// Like [`log_system`] but with level `error`.
pub fn log_system_err(msg: &str) {
	log_system_level("error", msg);
}

fn log_system_level(level: &str, msg: &str) {
	let envelope = format_envelope(
		"system",
		None,
		Some(level),
		&rfc3339_millis(SystemTime::now()),
		msg,
	);
	// Rust's Stdout is line-buffered; the envelope ends in \n so each call
	// flushes. Logging must never crash the enclave runner: ignore errors.
	let _ = io::stdout().write_all(envelope.as_bytes());
}

/// Render one envelope line (including the trailing newline).
///
/// Only `msg` (and in theory `level`/`stream`, which we control) require JSON
/// escaping; field order is fixed: v, log_type, stream?, level?, ts, msg.
fn format_envelope(
	log_type: &str,
	stream: Option<&str>,
	level: Option<&str>,
	ts: &str,
	msg: &str,
) -> String {
	let mut s = String::with_capacity(msg.len() + 96);
	s.push_str("{\"v\":1,\"log_type\":\"");
	s.push_str(log_type);

	if let Some(stream) = stream {
		s.push_str("\",\"stream\":\"");
		s.push_str(stream);
	}

	if let Some(level) = level {
		s.push_str("\",\"level\":\"");
		s.push_str(level);
	}

	s.push_str("\",\"ts\":\"");
	s.push_str(ts);
	s.push_str("\",\"msg\":\"");
	push_json_escaped(&mut s, msg);
	s.push_str("\"}\n");

	s
}

/// Append `msg` to `out` with JSON string escaping, matching serde_json's
/// output byte-for-byte: `"` and `\` escaped, the C escapes for backspace,
/// form feed, newline, carriage return and tab, `\u00XX` for the remaining
/// control characters, and everything else (including non-ASCII) verbatim.
fn push_json_escaped(out: &mut String, msg: &str) {
	for c in msg.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\u{08}' => out.push_str("\\b"),
			'\u{0C}' => out.push_str("\\f"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			c if (c as u32) < 0x20 => {
				let b = c as u32;
				out.push_str("\\u00");
				out.push(char::from_digit(b >> 4, 16).expect("nibble"));
				out.push(char::from_digit(b & 0xF, 16).expect("nibble"));
			}
			c => out.push(c),
		}
	}
}

/// Format a [`SystemTime`] as RFC 3339 UTC with millisecond precision, e.g.
/// `2026-05-28T20:26:40.123Z`. Times before the epoch clamp to the epoch.
fn rfc3339_millis(t: SystemTime) -> String {
	let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
	let secs = d.as_secs();
	let millis = d.subsec_millis();

	let days = (secs / 86_400) as i64;
	let rem = secs % 86_400;
	let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
	let (year, month, day) = civil_from_days(days);

	format!(
		"{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z"
	)
}

/// Convert days since the Unix epoch to a (year, month, day) civil date.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = (z - era * 146_097) as u64;
	let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe as i64 + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;

	(if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Fixed clock so envelope output is deterministic: 1780000000s after
	/// the epoch = 2026-05-28T20:26:40Z.
	const FIXED_EPOCH_SECS: u64 = 1_780_000_000;
	const FIXED_TS: &str = "2026-05-28T20:26:40.000Z";

	fn fixed_clock() -> SystemTime {
		UNIX_EPOCH + std::time::Duration::from_secs(FIXED_EPOCH_SECS)
	}

	fn writer() -> EnvelopeWriter<Vec<u8>> {
		EnvelopeWriter::with_clock(Vec::new(), fixed_clock)
	}

	/// Run the full input through the writer in the given chunk sizes and
	/// return the emitted envelope text.
	fn run_chunked(input: &[u8], chunk_size: usize) -> String {
		let mut w = writer();

		for chunk in input.chunks(chunk_size) {
			let n = w.write(chunk).expect("write");
			assert_eq!(n, chunk.len(), "write must consume the full buffer");
		}

		w.finish().expect("finish");

		String::from_utf8(w.out).expect("envelope output is valid UTF-8")
	}

	#[test]
	fn classifies_pivot_and_system_lines() {
		let out = run_chunked(
			b"PIVOT[OUT]: hello world\n\
			  PIVOT[ERR]: oh no\n\
			  qos_core booted\n",
			1024,
		);

		let lines: Vec<&str> = out.lines().collect();
		assert_eq!(lines.len(), 3);
		assert_eq!(
			lines[0],
			format!(
				"{{\"v\":1,\"log_type\":\"app\",\"stream\":\"stdout\",\"ts\":\"{FIXED_TS}\",\"msg\":\"hello world\"}}"
			)
		);
		assert_eq!(
			lines[1],
			format!(
				"{{\"v\":1,\"log_type\":\"app\",\"stream\":\"stderr\",\"ts\":\"{FIXED_TS}\",\"msg\":\"oh no\"}}"
			)
		);
		assert_eq!(
			lines[2],
			format!(
				"{{\"v\":1,\"log_type\":\"system\",\"ts\":\"{FIXED_TS}\",\"msg\":\"qos_core booted\"}}"
			)
		);
	}

	#[test]
	fn prefix_mid_line_is_not_app() {
		let out = run_chunked(b"some text PIVOT[OUT]: not a prefix\n", 1024);
		assert!(out.contains("\"log_type\":\"system\""));
		assert!(out.contains("some text PIVOT[OUT]: not a prefix"));
	}

	#[test]
	fn prefix_only_line_has_empty_msg() {
		let out = run_chunked(b"PIVOT[OUT]: \n", 1024);
		assert!(out.contains("\"log_type\":\"app\""));
		assert!(out.contains("\"msg\":\"\""));
	}

	#[test]
	fn empty_line_is_system_with_empty_msg() {
		let out = run_chunked(b"\n", 1024);
		assert!(out.contains("\"log_type\":\"system\""));
		assert!(out.contains("\"msg\":\"\""));
	}

	#[test]
	fn strips_crlf() {
		let out = run_chunked(b"PIVOT[OUT]: windows line\r\n", 1024);
		assert!(out.contains("\"msg\":\"windows line\""));
		assert!(!out.contains("\\r"));
	}

	#[test]
	fn chunking_invariance() {
		let input: &[u8] = b"PIVOT[OUT]: line one\n\
			system noise\r\n\
			PIVOT[ERR]: line two with \xF0\x9F\xA6\x80 crab\n\
			PIVOT[OUT]: trailing without newline";

		let reference = run_chunked(input, input.len());

		// Pathological chunkings, including boundaries mid-prefix and
		// mid-UTF-8-codepoint (1-byte chunks split everything).
		for chunk_size in [1, 2, 3, 5, 7, 13] {
			assert_eq!(
				run_chunked(input, chunk_size),
				reference,
				"chunk_size={chunk_size} must not change output"
			);
		}
	}

	#[test]
	fn finish_emits_trailing_unterminated_line() {
		let mut w = writer();
		w.write_all(b"PIVOT[OUT]: no newline at end").expect("write");
		assert!(w.out.is_empty(), "no envelope before newline or finish");
		w.finish().expect("finish");

		let out = String::from_utf8(w.out).expect("utf8");
		assert!(out.contains("\"msg\":\"no newline at end\""));
		assert!(out.ends_with("\"}\n"));
	}

	#[test]
	fn flush_does_not_emit_partial_line() {
		let mut w = writer();
		w.write_all(b"partial").expect("write");
		w.flush().expect("flush");
		assert!(w.out.is_empty());
	}

	#[test]
	fn invalid_utf8_is_lossy_replaced() {
		let out = run_chunked(b"PIVOT[OUT]: bad \xFF byte\n", 1024);
		assert!(out.contains("bad \u{FFFD} byte"));
	}

	#[test]
	fn oversized_line_is_segmented_not_unbounded() {
		let mut w = writer();
		let big = vec![b'a'; MAX_LINE_BYTES + 10];
		w.write_all(&big).expect("write");

		assert!(
			!w.out.is_empty(),
			"oversized line must be emitted in segments"
		);
		assert!(w.partial.len() < MAX_LINE_BYTES);
	}

	#[test]
	fn escaper_matches_serde_json() {
		let corpus = [
			"plain",
			"with \"quotes\" and \\backslashes\\",
			"tab\there",
			"control\u{01}\u{1F}chars",
			"backspace\u{08}formfeed\u{0C}",
			"unicode: caf\u{E9} \u{1F980} \u{FFFD}",
			"",
			"PIVOT[OUT]: looks like a prefix",
			"{\"log_type\":\"system\",\"evil\":true}",
		];

		for msg in corpus {
			let mut ours = String::new();
			push_json_escaped(&mut ours, msg);

			let serde = serde_json::to_string(msg).expect("serde");
			// serde_json::to_string includes the surrounding quotes.
			assert_eq!(
				format!("\"{ours}\""),
				serde,
				"escaper diverges from serde_json for {msg:?}"
			);
		}
	}

	#[test]
	fn envelope_lines_round_trip_as_json() {
		let out =
			run_chunked(b"PIVOT[OUT]: msg with \"quotes\"\nsystem line\n", 4);

		for line in out.lines() {
			let v: serde_json::Value =
				serde_json::from_str(line).expect("every line parses as JSON");
			assert_eq!(v["v"], 1);
			assert!(v["log_type"] == "app" || v["log_type"] == "system");
			assert_eq!(v["ts"], FIXED_TS);
			assert!(v["msg"].is_string());
		}
	}

	#[test]
	fn rfc3339_known_vectors() {
		let vectors: [(u64, &str); 5] = [
			(0, "1970-01-01T00:00:00.000Z"),
			(951_782_400, "2000-02-29T00:00:00.000Z"),
			(1_780_000_000, "2026-05-28T20:26:40.000Z"),
			(4_102_444_799, "2099-12-31T23:59:59.000Z"),
			(1_735_689_600, "2025-01-01T00:00:00.000Z"),
		];

		for (secs, expected) in vectors {
			let t = UNIX_EPOCH + std::time::Duration::from_secs(secs);
			assert_eq!(rfc3339_millis(t), expected, "for {secs}");
		}
	}

	#[test]
	fn rfc3339_millis_precision() {
		let t = UNIX_EPOCH
			+ std::time::Duration::from_secs(FIXED_EPOCH_SECS)
			+ std::time::Duration::from_millis(123);
		assert_eq!(rfc3339_millis(t), "2026-05-28T20:26:40.123Z");
	}

	/// Golden fixtures: the cross-repo envelope contract. `fixtures/
	/// console_input.bin` is a raw console byte stream; `fixtures/
	/// expected_envelopes.jsonl` is the exact expected output (with the fixed
	/// test clock). tvc-observer (mono repo) consumes the same fixture file
	/// to test its parser — change both repos together if this changes.
	#[test]
	fn golden_fixtures() {
		let input = include_bytes!("../fixtures/console_input.bin");
		let expected = include_str!("../fixtures/expected_envelopes.jsonl");

		// Chunked at 7 bytes to exercise reassembly on the golden path too.
		assert_eq!(run_chunked(input, 7), expected);
		assert_eq!(run_chunked(input, input.len()), expected);
	}
}
