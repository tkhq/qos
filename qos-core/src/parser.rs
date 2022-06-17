//! Command line token parser.
use std::{collections::HashMap, fmt};

const HELP_INPUT: &str = "--help";
const VERSION_INPUT: &str = "--version";
const INPUT_PREFIX: &str = "--";

/// Token parsing error.
#[derive(Debug, PartialEq)]
pub enum ParserError {
	/// The input was was not expected.
	UnexpectedInput(String),
	/// A value for the input was not provided.
	MissingInputValue(String),
	/// The input was provided more than once.
	DuplicateInput(String),
	/// Inputs are mutually exclusive.
	MutuallyExclusiveInput(String, String),
	/// The a value is required for the given token.
	MissingValue(String),
	/// An expected input is missing.
	MissingInput(String),
}

/// Simple parser for CLIs. Reads input and parses them into [`Token`]s.
/// See [`Token`] and [`TokenType`] for options on possible commands.
#[derive(Default, Clone)]
pub struct Parser {
	token_map: TokenMap,
}

impl Parser {
	/// Create a new instance of [`Self`].
	#[must_use]
	pub fn new() -> Self {
		Parser::default()
	}

	/// Add an expected Token to parse.
	#[must_use]
	pub fn token(mut self, token: Token) -> Self {
		self.token_map.insert(token);
		self
	}

	/// Parse the command line arguments.
	pub fn parse(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		self.token_map.parse(inputs)
	}

	/// Tokens stored in the parser.
	#[must_use]
	pub fn token_map(&self) -> &TokenMap {
		&self.token_map
	}

	/// Info message about tokens.
	#[must_use]
	pub fn info(&self) -> String {
		let mut info = vec![];

		let required = self.tokens_info(true);
		if !required.is_empty() {
			info.push("Required CLI inputs:".to_string());
			info.push(required);
		}

		// Newline
		info.push("".to_string());

		let optional = self.tokens_info(false);
		if !optional.is_empty() {
			info.push("Optional CLI inputs:".to_string());
			info.push(optional);
		}

		info.join("\n")
	}

	fn tokens_info(&self, is_required: bool) -> String {
		let tokens: Vec<_> = self
			.token_map
			.tokens
			.values()
			.filter(|arg| is_required == arg.required)
			.collect();

		let width =
			tokens.iter().map(|arg| arg.format_name().len()).max().unwrap_or(0);

		tokens
			.into_iter()
			.map(|arg| arg.format_info(width))
			.collect::<Vec<_>>()
			.join("\n")
	}
}

/// Token type.
#[derive(Clone, Debug, PartialEq)]
pub enum TokenType {
	/// A type that has no value and just has meaning by being present or not.
	Flag,
	/// A type that has a single value.
	Single(String),
	/// A type that has multiple values.
	Multiple(Vec<String>),
}

impl TokenType {
	fn as_single(&self) -> Option<&String> {
		match self {
			TokenType::Single(s) => Some(s),
			_ => None,
		}
	}

	fn as_multiple(&self) -> Option<&[String]> {
		match self {
			TokenType::Multiple(v) => Some(v),
			_ => None,
		}
	}

	fn as_flag(&self) -> bool {
		matches!(self, TokenType::Flag)
	}

	fn push_val(&mut self, val: &str) -> Result<(), ParserError> {
		match self {
			TokenType::Multiple(ref mut v) => {
				v.push(val.to_string());
				Ok(())
			}
			_ => Err(ParserError::DuplicateInput(val.to_string())),
		}
	}
}

impl fmt::Display for TokenType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			TokenType::Flag => write!(f, "true"),
			TokenType::Single(s) => write!(f, "{}", s),
			TokenType::Multiple(v) => write!(f, "{:?}", v),
		}
	}
}

/// Configuration for parsing a token.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Token {
	name: String,
	help: String,
	required: bool,
	requires: Option<String>,
	forbids: Vec<String>,
	takes_value: bool,
	default_value: Option<TokenType>,
	user_value: Option<TokenType>,
	allow_multiple: bool,
}

impl Token {
	/// Create `name` token with the given `help` message.
	#[must_use]
	pub fn new(name: &str, help: &str) -> Token {
		Token {
			name: name.to_string(),
			help: help.to_string(),
			..Default::default()
		}
	}

	/// Require that the user must provide this token.
	#[must_use]
	pub fn required(mut self, required: bool) -> Self {
		self.required = required;
		self
	}

	/// Specify another token that must be present when this one is.
	#[must_use]
	pub fn requires(mut self, other_arg: String) -> Self {
		self.requires = Some(other_arg);
		self
	}

	/// Specify other tokens that are mutually exclusive of self.
	#[must_use]
	pub fn forbids(mut self, args: Vec<String>) -> Self {
		self.forbids = args;
		self
	}

	/// Set the token as requiring an input. In other words, make it not a
	/// flag.
	#[must_use]
	pub fn takes_value(mut self, takes_value: bool) -> Self {
		self.takes_value = takes_value;
		self
	}

	/// Keep a default value which will be used if the user didn't provide a
	/// value for the token.
	#[must_use]
	pub fn default_value(mut self, default_value: String) -> Self {
		self.default_value = Some(TokenType::Single(default_value));
		self
	}

	fn format_name(&self) -> String {
		if self.takes_value {
			format!("	--{} <{}>", self.name, self.name)
		} else {
			format!("	--{}", self.name)
		}
	}

	fn format_info(&self, width: usize) -> String {
		let mut info = vec![
			format!("{:<width$}", self.format_name(), width = width),
			"	".to_string(),
			self.help.clone(),
		];

		if let Some(v) = &self.default_value {
			info.push(format!("[default: {}]", v));
		}

		info.join(" ")
	}
}

fn version() -> Token {
	let mut t = Token::new("version", "Display the version");
	t.user_value = Some(TokenType::Flag);
	t
}
fn help() -> Token {
	let mut t = Token::new("help", "Display a help message");
	t.user_value = Some(TokenType::Flag);
	t
}

/// Stores the tokens of the parser
#[derive(Default, Clone, Debug, PartialEq)]
pub struct TokenMap {
	/// Map of token name to `Token`.
	tokens: HashMap<String, Token>,
}
impl TokenMap {
	/// Parse tokens based on given input and expected tokens.
	///
	/// # Special Cases
	///
	/// * If `--help` is present, we ignore all the inputs.
	/// * If `--version` is present, we ignore all other inputs except help.
	pub fn parse(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		// Skip parsing rest of help parameter exists.
		if inputs.contains(&HELP_INPUT.to_string()) {
			self.insert(help());
			return Ok(());
		}

		// Skip parsing rest if version parameter exists.
		if inputs.contains(&VERSION_INPUT.to_string()) {
			self.insert(version());
			return Ok(());
		}

		self.parse_helper(inputs)
	}

	/// Get the value of `name` if the token exists and its of type Multiple.
	pub fn get_multiple(&self, name: &'static str) -> Option<&[String]> {
		self.type_of(name).and_then(TokenType::as_multiple)
	}

	/// Get the value of `name` if the token exists and its of type Single.
	pub fn get_single(&self, name: &str) -> Option<&String> {
		self.type_of(name).and_then(TokenType::as_single)
	}

	/// Get a bool indicating if the flags state. Always false if the token is a
	/// not a flag.
	#[must_use]
	pub fn get_flag(&self, name: &str) -> bool {
		match self.type_of(name) {
			Some(t) => t.as_flag(),
			None => false,
		}
	}

	/// Fill the tokens in the map with user provided inputs.
	fn parse_helper(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		let mut iter = inputs.iter();
		while let Some(input) = iter.next() {
			self.check_input(input)?;

			let name = &input[INPUT_PREFIX.len()..];

			// Get a mutable reference to the token so we can update it in
			// place.
			let token = self.tokens.get_mut(name).ok_or_else(|| {
				ParserError::UnexpectedInput(name.to_string())
			})?;

			let user_value = if token.takes_value {
				// Find the value
				let value = iter
					.next()
					.filter(|i| !i.starts_with(INPUT_PREFIX))
					.ok_or_else(|| ParserError::MissingValue(name.to_string()))?
					.clone();

				// Store the value
				if token.allow_multiple {
					match token.user_value.take() {
						Some(mut multiple) => {
							multiple.push_val(&value)?;
							multiple
						}
						None => TokenType::Multiple(vec![value]),
					}
				} else {
					TokenType::Single(value)
				}
			} else {
				// This token doesn't take a value
				TokenType::Flag
			};

			token.user_value = Some(user_value);
		}

		// Check constraints based on the found tokens.
		self.check_constraints(inputs)?;

		Ok(())
	}

	/// Check
	///
	/// - if a value is required for the token
	/// - if this token requires the presence of another token
	/// - if there already exists a token that is mutually exclusive of this
	///   token.
	fn check_constraints(&self, inputs: &[String]) -> Result<(), ParserError> {
		for token in self.tokens.values() {
			// Check if a value is required for the token.
			if token.required && token.user_value.is_none() {
				Err(ParserError::MissingValue(token.name.to_string()))?;
			}

			if token.user_value.is_some() {
				// Check if this token requires the presence of another token
				if let Some(ref other_name) = token.requires {
					if !inputs.contains(&(format!("--{}", other_name))) {
						return Err(ParserError::MissingInput(
							other_name.to_string(),
						));
					}
				}

				// Check if there already exists a token that is mutually
				// exclusive of this token.
				for other_name in &token.forbids {
					if inputs.contains(&(format!("--{}", other_name))) {
						Err(ParserError::MutuallyExclusiveInput(
							token.name.to_string(),
							other_name.to_string(),
						))?;
					}
				}
			}
		}
		Ok(())
	}

	fn check_input(&self, input: &str) -> Result<(), ParserError> {
		if input.starts_with(INPUT_PREFIX) {
			return Err(ParserError::UnexpectedInput(input.to_string()));
		}
		let name = &input[INPUT_PREFIX.len()..];

		let token = self
			.tokens
			.get(name)
			// If it doesn't exist in the map, then it was unexpected.
			.ok_or_else(|| ParserError::UnexpectedInput(input.to_string()))?;

		if !token.allow_multiple && token.user_value.is_some() {
			// We don't allow multiple of this token, but we already have a
			// value for it
			return Err(ParserError::DuplicateInput(input.to_string()));
		}

		Ok(())
	}

	/// Get the type of token with `name`.
	fn type_of(&self, name: &str) -> Option<&TokenType> {
		self.tokens.get(name).and_then(|token| {
			token.user_value.as_ref().or(token.default_value.as_ref())
		})
	}

	/// Insert a `Token`
	fn insert(&mut self, token: Token) {
		self.tokens.insert(token.name.clone(), token);
	}
}
