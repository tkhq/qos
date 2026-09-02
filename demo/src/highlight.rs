//! Minimal server-side Rust syntax highlighter for the source slides.
//!
//! Emits `<span class="hl-…">` tokens over HTML-escaped text; the classes
//! are styled in `style.css`. This is deliberately not a general
//! highlighter — it covers exactly the constructs that appear in the vfaas
//! example sources (line comments, strings, attributes, keywords, types,
//! macro calls, numbers, lifetimes) and passes everything else through as
//! escaped plain text.

const KEYWORDS: &[&str] = &[
	"as", "async", "await", "break", "const", "continue", "crate", "dyn",
	"else", "enum", "fn", "for", "if", "impl", "in", "let", "loop", "match",
	"mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static",
	"struct", "super", "trait", "type", "unsafe", "use", "where", "while",
];

/// Highlight Rust `source` into trusted HTML.
pub fn rust(source: &str) -> String {
	let chars: Vec<char> = source.chars().collect();
	let mut out = String::with_capacity(source.len() * 2);
	let mut i = 0;
	// The most recent identifier-like token, so `fn` can color the name
	// that follows it.
	let mut prev_word = String::new();

	while i < chars.len() {
		let c = chars[i];

		// Line comments: `//`, `///`, `//!`.
		if c == '/' && chars.get(i + 1) == Some(&'/') {
			let start = i;
			while i < chars.len() && chars[i] != '\n' {
				i += 1;
			}
			push_span(&mut out, "hl-com", &text(&chars[start..i]));
			continue;
		}

		// String literals, with `\` escapes.
		if c == '"' {
			let start = i;
			i = consume_string(&chars, i);
			push_span(&mut out, "hl-str", &text(&chars[start..i]));
			continue;
		}

		// Attributes: `#[…]` / `#![…]`, strings inside skipped whole.
		if c == '#'
			&& (chars.get(i + 1) == Some(&'[')
				|| (chars.get(i + 1) == Some(&'!')
					&& chars.get(i + 2) == Some(&'[')))
		{
			let start = i;
			while i < chars.len() && chars[i] != '[' {
				i += 1;
			}
			let mut depth = 0usize;
			while i < chars.len() {
				match chars[i] {
					'"' => i = consume_string(&chars, i),
					'[' => {
						depth += 1;
						i += 1;
					}
					']' => {
						depth -= 1;
						i += 1;
						if depth == 0 {
							break;
						}
					}
					_ => i += 1,
				}
			}
			push_span(&mut out, "hl-attr", &text(&chars[start..i]));
			continue;
		}

		// Lifetimes (`'a`) vs char literals (`'x'`, `'\n'`).
		if c == '\'' {
			let is_lifetime = chars
				.get(i + 1)
				.is_some_and(|c| c.is_alphabetic() || *c == '_')
				&& chars.get(i + 2) != Some(&'\'');
			let start = i;
			if is_lifetime {
				i += 1;
				while i < chars.len()
					&& (chars[i].is_alphanumeric() || chars[i] == '_')
				{
					i += 1;
				}
				push_span(&mut out, "hl-life", &text(&chars[start..i]));
			} else {
				i += 1;
				while i < chars.len() {
					match chars[i] {
						'\\' => i = (i + 2).min(chars.len()),
						'\'' => {
							i += 1;
							break;
						}
						_ => i += 1,
					}
				}
				push_span(&mut out, "hl-str", &text(&chars[start..i]));
			}
			continue;
		}

		// Identifiers: keywords, macro calls, types, function names.
		if c.is_alphabetic() || c == '_' {
			let start = i;
			while i < chars.len()
				&& (chars[i].is_alphanumeric() || chars[i] == '_')
			{
				i += 1;
			}
			let word = text(&chars[start..i]);
			if KEYWORDS.contains(&word.as_str()) {
				push_span(&mut out, "hl-kw", &word);
			} else if word == "true" || word == "false" {
				push_span(&mut out, "hl-num", &word);
			} else if chars.get(i) == Some(&'!') {
				i += 1;
				push_span(&mut out, "hl-mac", &format!("{word}!"));
			} else if prev_word == "fn" {
				push_span(&mut out, "hl-fn", &word);
			} else if word.chars().next().is_some_and(char::is_uppercase) {
				push_span(&mut out, "hl-ty", &word);
			} else {
				push_escaped(&mut out, &word);
			}
			prev_word = word;
			continue;
		}

		// Numeric literals, including suffixes and separators (`2_000u64`).
		if c.is_ascii_digit() {
			let start = i;
			while i < chars.len()
				&& (chars[i].is_alphanumeric() || chars[i] == '_')
			{
				i += 1;
			}
			push_span(&mut out, "hl-num", &text(&chars[start..i]));
			continue;
		}

		push_escaped(&mut out, &c.to_string());
		i += 1;
	}

	out
}

/// Advance past the string literal starting at `chars[start]` (a `"`).
fn consume_string(chars: &[char], start: usize) -> usize {
	let mut i = start + 1;
	while i < chars.len() {
		match chars[i] {
			'\\' => i = (i + 2).min(chars.len()),
			'"' => return i + 1,
			_ => i += 1,
		}
	}
	i
}

fn text(chars: &[char]) -> String {
	chars.iter().collect()
}

fn push_span(out: &mut String, class: &str, text: &str) {
	out.push_str("<span class=\"");
	out.push_str(class);
	out.push_str("\">");
	push_escaped(out, text);
	out.push_str("</span>");
}

fn push_escaped(out: &mut String, text: &str) {
	for c in text.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			_ => out.push(c),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::rust;

	#[test]
	fn comments_and_doc_comments() {
		let html = rust("/// doc\n// plain\nlet x = 1;");
		assert!(html.contains(r#"<span class="hl-com">/// doc</span>"#));
		assert!(html.contains(r#"<span class="hl-com">// plain</span>"#));
	}

	#[test]
	fn string_containing_slashes_stays_a_string() {
		let html = rust(r#"let url = "https://example.com";"#);
		assert!(
			html.contains(r#"<span class="hl-str">"https://example.com"</span>"#)
		);
		assert!(!html.contains("hl-com"));
	}

	#[test]
	fn keywords_types_functions_and_macros() {
		let html = rust("pub fn evaluate(req: PolicyRequest) { todo!() }");
		assert!(html.contains(r#"<span class="hl-kw">pub</span>"#));
		assert!(html.contains(r#"<span class="hl-kw">fn</span>"#));
		assert!(html.contains(r#"<span class="hl-fn">evaluate</span>"#));
		assert!(html.contains(r#"<span class="hl-ty">PolicyRequest</span>"#));
		assert!(html.contains(r#"<span class="hl-mac">todo!</span>"#));
	}

	#[test]
	fn attributes_swallow_inner_strings() {
		let html = rust("#[cfg(feature = \"list-v2\")]\nstruct S;");
		assert!(html.contains(
			r#"<span class="hl-attr">#[cfg(feature = "list-v2")]</span>"#
		));
	}

	#[test]
	fn html_is_escaped() {
		let html = rust("fn f() -> Vec<u8> {}");
		assert!(html.contains("-&gt;"));
		assert!(html.contains("Vec</span>&lt;"));
	}

	#[test]
	fn lifetimes_and_numbers() {
		let html = rust("fn f<'a>(x: &'a str) -> u64 { 2_000_000 }");
		assert!(html.contains(r#"<span class="hl-life">'a</span>"#));
		assert!(html.contains(r#"<span class="hl-num">2_000_000</span>"#));
	}
}
