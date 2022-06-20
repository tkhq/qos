//! Command line token parser.
use core::marker::PhantomData;
use std::{collections::BTreeMap, convert::From, fmt};

const HELP: &str = "help";
const HELP_INPUT: &str = "--help";
const VERSION: &str = "version";
const VERSION_INPUT: &str = "--version";
const INPUT_PREFIX: &str = "--";

/// Token parsing error.
#[derive(Debug, PartialEq)]
pub enum ParserError {
	/// Input was was not expected.
	UnexpectedInput(String),
	/// Input was provided more than once.
	DuplicateInput(String),
	/// Inputs are mutually exclusive.
	MutuallyExclusiveInput(String, String),
	/// A value is required for the given token, but none was given
	MissingValue(String),
	/// An expected input is missing.
	MissingInput(String),
}

impl fmt::Display for ParserError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnexpectedInput(u) => write!(f, "found {u}, which was not an expected argument"),
			Self::DuplicateInput(i) => write!(f, "found argument {i} more then once, but only one instance was expected"),
			Self::MutuallyExclusiveInput(y, z) => write!(f, "arguments {y} and {z} are mutually exclusive and cannot be used at the same time"),
			Self::MissingValue(i) => write!(f, "found argument {i}, which requires a value, but no value was given"),
			Self::MissingInput(i) => write!(f, "argument {i} is required but was not found"),
		}
	}
}

/// Something that has method to get a parser. Meant to be used with
/// [`OptionsParser`].
pub trait GetParserForOptions {
	/// Get the parser
	fn parser() -> Parser;
}

/// Parse input that does not include a command, just options. If you need to
/// parse a command as well use [`CommandParser`].
///
/// Assumes the format `--token1 value1 --flag --token2 value2`.
pub struct OptionsParser<T: GetParserForOptions> {
	_phantom: PhantomData<T>,
}

impl<T: GetParserForOptions> OptionsParser<T> {
	/// Parse inputs for `C`.
	pub fn parse(inputs: &mut Vec<String>) -> Result<Parser, ParserError> {
		// Remove the binary name
		inputs.remove(0);
		let mut parser = T::parser();
		parser.parse(inputs)?;

		Ok(parser)
	}
}

/// Something that has method to get a parser. Meant to be used with
/// [`CommandParser`].
pub trait GetParserForCommand {
	/// Get the parser
	fn parser(&self) -> Parser;
}

/// Parse input for a command. If you do not need to parse a command but
/// instead just options, use [`OptionsParser`].
///
///  Note that subcommands are not supported.
///
/// Assumes the format `command-name --token1 value1 --flag --token2 value2`.
pub struct CommandParser<C: From<String> + GetParserForCommand> {
	_phantom: PhantomData<C>,
}

impl<C: From<String> + GetParserForCommand> CommandParser<C> {
	/// Parse inputs for the command `C`.
	pub fn parse(inputs: &mut Vec<String>) -> Result<(C, Parser), ParserError> {
		let command = Self::extract_command(inputs);
		let mut parser = command.parser();
		parser.parse(inputs)?;

		Ok((command, parser))
	}

	/// Helper function to extract the command from inputs.
	/// WARNING: this removes the first two items from `args`
	fn extract_command(inputs: &mut Vec<String>) -> C {
		// Remove the binary name
		inputs.remove(0);

		let command: C =
			inputs.get(0).expect("No command provided").clone().into();

		// Remove the command
		inputs.remove(0);

		command
	}
}

/// Parser, primarily designed for CLI inputs. This reads input and parses them
/// into [`Token`]s. See [`Token`] for options on possible commands.
///
/// After registering tokens with [`Self::token`], you can call [`Self::parse`]
/// to populate the parser with the provided input. To display a help / info
/// message based on all the registered tokens see [`Self::info`].
///
/// Both `--help` and `--version` are always registered as tokens.
///
/// To access the parsed input based on the expected type see:
///
/// * [`Self::help`]
/// * [`Self::version`]
/// * [`Self::flag`]
/// * [`Self::single`]
/// * [`Self::multiple`]
#[derive(Default, Clone)]
pub struct Parser {
	token_map: TokenMap,
}

impl Parser {
	/// Create a new instance of [`Self`] with the given `cmd`.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Register a Token with the parser.
	#[must_use]
	pub fn token(mut self, token: Token) -> Self {
		self.token_map.insert(token);
		self
	}

	/// Wether or not the user passed in `--help`. Should always be checked.
	#[must_use]
	pub fn help(&self) -> bool {
		self.token_map.get_flag(HELP).unwrap_or(false)
	}

	/// Wether or not the user passed in `--version`. Should always be checked.
	#[must_use]
	pub fn version(&self) -> bool {
		self.token_map.get_flag(VERSION).unwrap_or(false)
	}

	/// Returns a bool indicating if the flag with `name` was passed. None if
	/// `name` is not a token in registered in the parser.
	#[must_use]
	pub fn flag(&self, name: &str) -> Option<bool> {
		self.token_map.get_flag(name)
	}

	/// Returns the value of `name` if the token exists and it only can be in
	/// the input once.
	#[must_use]
	pub fn single(&self, name: &str) -> Option<&String> {
		self.token_map.get_single(name)
	}

	/// Returns the value of `name` if the token exists and it can be in the
	/// input multiple times.
	#[must_use]
	pub fn multiple(&self, name: &str) -> Option<&[String]> {
		self.token_map.get_multiple(name)
	}

	/// Parse the command line arguments. Instead of using this directly it is
	/// preferred to use [`OptionsParser`] or [`CommandParser`].
	///
	/// # Note
	///
	/// When getting env args, the first value will be the binary name. That
	/// needs to be removed before calling this.
	pub fn parse(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		self.token_map.parse(inputs)
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
			tokens.iter().map(|arg| arg.name().len()).max().unwrap_or(0);

		tokens
			.into_iter()
			.map(|arg| arg.info(width))
			.collect::<Vec<_>>()
			.join("\n")
	}
}

/// Configuration for a parsing token.
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

	/// Let their multiple of this token.
	#[must_use]
	pub fn allow_multiple(mut self, multiple: bool) -> Self {
		self.allow_multiple = multiple;
		self
	}

	/// Require that the user must provide this token.
	#[must_use]
	pub fn required(mut self, required: bool) -> Self {
		self.required = required;
		self
	}

	/// Specify another token that must be present when this one is.
	#[must_use]
	pub fn requires(mut self, required: &str) -> Self {
		self.requires = Some(required.to_string());
		self
	}

	/// Specify other tokens that are mutually exclusive of this token.
	#[must_use]
	pub fn forbids(mut self, forbidden: Vec<&str>) -> Self {
		self.forbids = forbidden.into_iter().map(String::from).collect();
		self
	}

	/// Set the token as requiring an input. In other words, make it not a
	/// flag.
	#[must_use]
	pub fn takes_value(mut self, takes_value: bool) -> Self {
		self.takes_value = takes_value;
		self
	}

	/// Specify a default value which will be used if the user didn't provide a
	/// value for the token.
	#[must_use]
	pub fn default_value(mut self, default: &str) -> Self {
		self.default_value = Some(TokenType::Single(default.to_string()));
		self
	}

	fn name(&self) -> String {
		if self.takes_value {
			format!("	--{} <{}>", self.name, self.name)
		} else {
			format!("	--{}", self.name)
		}
	}

	fn info(&self, width: usize) -> String {
		let mut info = vec![
			format!("{:<width$}", self.name(), width = width),
			self.help.clone(),
		];

		if let Some(v) = &self.default_value {
			info.push(format!("[default: {}]", v));
		}

		info.join(" ")
	}
}

/// Token type.
#[derive(Clone, Debug, PartialEq)]
enum TokenType {
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
			Self::Flag => write!(f, "true"),
			Self::Single(s) => write!(f, "{}", s),
			Self::Multiple(v) => write!(f, "{:?}", v),
		}
	}
}

/// Stores the tokens of the parser
#[derive(Clone, Debug, PartialEq)]
struct TokenMap {
	/// Map of token name to `Token`.
	tokens: BTreeMap<String, Token>,
}
impl TokenMap {
	/// Parse input based on expected tokens.
	///
	/// # Special Cases
	///
	/// * If `--help` is present, we ignore all the inputs.
	/// * If `--version` is present, we ignore all other inputs except help.
	fn parse(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		// Skip parsing rest of help parameter exists.
		if inputs.contains(&HELP_INPUT.to_string()) {
			let h = self
				.tokens
				.get_mut(HELP)
				.expect("CLI Parser internal error: help token does not exist");
			h.user_value = Some(TokenType::Flag);
			return Ok(());
		}

		// Skip parsing rest if version parameter exists.
		if inputs.contains(&VERSION_INPUT.to_string()) {
			let v = self.tokens.get_mut(VERSION).expect(
				"CLI Parser internal error: version token does not exist",
			);
			v.user_value = Some(TokenType::Flag);
			return Ok(());
		}

		self.do_parse(inputs)
	}

	/// Get the value of `name` if the token exists and its of type Multiple.
	fn get_multiple(&self, name: &str) -> Option<&[String]> {
		self.type_of(name).and_then(TokenType::as_multiple)
	}

	/// Get the value of `name` if the token exists and its of type Single.
	fn get_single(&self, name: &str) -> Option<&String> {
		self.type_of(name).and_then(TokenType::as_single)
	}

	/// Get a bool indicating if the flag was passed. None if the `name` is not
	/// a [`Token`] in the parser.
	fn get_flag(&self, name: &str) -> Option<bool> {
		self.type_of(name).map(TokenType::as_flag)
	}

	/// Fill the tokens in the map with user provided inputs.
	fn do_parse(&mut self, inputs: &[String]) -> Result<(), ParserError> {
		let mut iter = inputs.iter().peekable();
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
				let value = if iter
					.peek()
					.filter(|i| !i.starts_with(INPUT_PREFIX))
					.is_some()
				{
					// Advance the iterator since we only peaked above
					iter.next().unwrap().to_string()
				} else if let Some(ref d) = token.default_value {
					// Couldn't find a value, so take the default
					d.to_string()
				} else {
					// No value and no default??? go home, you're drunk!
					Err(ParserError::MissingValue(name.to_string()))?
				};

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
			// Check if a value is required for the token
			if token.required && token.user_value.is_none() {
				Err(ParserError::MissingInput(token.name.to_string()))?;
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

	/// Check if a single `input` is baseline valid and registered to a token.
	fn check_input(&self, input: &str) -> Result<(), ParserError> {
		if !input.starts_with(INPUT_PREFIX) {
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
			return Err(ParserError::DuplicateInput(name.to_string()));
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

impl Default for TokenMap {
	fn default() -> Self {
		let mut token_map =
			Self { tokens: BTreeMap::<String, Token>::default() };

		// Add the help and version token to ensure that the options are always
		// displayed in the help menu.
		token_map.insert(Token::new(HELP, "Display the help message."));
		token_map.insert(Token::new(VERSION, "Display the version"));

		token_map
	}
}

#[cfg(test)]
mod test {
	use super::*;
	fn setup() -> Parser {
		Parser::new()
			.token(
				Token::new("required-with-value", "info 1")
					.required(true)
					.takes_value(true),
			)
			.token(
				Token::new("requires-no-value", "info 2")
					.requires("optional-value")
					.takes_value(false),
			)
			.token(
				Token::new("multiple", "info 69")
					.allow_multiple(true)
					.takes_value(true),
			)
			.token(
				Token::new("optional-with-default", "info 3")
					.takes_value(true)
					.default_value("default1"),
			)
			.token(
				Token::new("forbid1-with-value", "info 5")
					.takes_value(true)
					.forbids(vec!["forbid2-no-value"]),
			)
			.token(
				Token::new("forbid2-no-value", "info 6")
					.forbids(vec!["forbid1-with-value"]),
			)
			.token(Token::new("optional-value", "info 7").takes_value(true))
	}

	#[test]
	fn parse_works() {
		let input: Vec<_> = vec![
			"--required-with-value",
			"val1",
			"--requires-no-value",
			"--multiple",
			"val2",
			"--multiple",
			"val3",
			"--optional-with-default",
			"--forbid1-with-value",
			"val4",
			"--optional-value",
			"val5",
		]
		.into_iter()
		.map(String::from)
		.collect::<Vec<String>>();
		let mut parser = setup();
		parser.parse(&input).unwrap();

		assert_eq!(
			parser.single("required-with-value"),
			Some(&"val1".to_string())
		);

		assert_eq!(parser.flag("requires-no-value"), Some(true));
		// Mistype name
		assert_eq!(parser.flag("requires-no-va"), None);

		assert_eq!(
			parser.multiple("multiple"),
			Some(&["val2".to_string(), "val3".to_string()][..])
		);

		assert_eq!(
			parser.single("optional-with-default"),
			Some(&"default1".to_string())
		);

		assert_eq!(
			parser.single("forbid1-with-value"),
			Some(&"val4".to_string())
		);

		assert_eq!(parser.single("optional-value"), Some(&"val5".to_string()));
	}

	#[test]
	fn parser_errors_correctly() {
		// Errors with missing value
		let input = [
			"--requires-no-value",
			"--required-with-value",
			"--forbid2-with-default",
			"a",
		]
		.into_iter()
		.map(String::from)
		.collect::<Vec<String>>();
		assert_eq!(
			setup().parse(&input),
			Err(ParserError::MissingValue("required-with-value".to_string()))
		);

		// Errors with duplicate inputs
		let input: Vec<_> = [
			"--forbid2-no-value",
			"--multiple",
			"beans",
			"--required-with-value",
			"a",
			"--forbid2-no-value",
			"--multiple",
			"based",
		]
		.into_iter()
		.map(String::from)
		.collect();
		assert_eq!(
			setup().parse(&input),
			Err(ParserError::DuplicateInput("forbid2-no-value".to_string()))
		);

		// Errors when a required input is missing
		let input: Vec<_> =
			vec!["--requires-no-value", "--optional-with-default", "420"]
				.into_iter()
				.map(String::from)
				.collect();
		assert_eq!(
			setup().parse(&input),
			Err(ParserError::MissingInput("required-with-value".to_string()))
		);

		// Errors with an unexpected input that is preceeded by `--`
		let input: Vec<_> = vec![
			"--requires-no-value",
			"--required-with-value",
			"brawndo",
			"--vape-nation",
		]
		.into_iter()
		.map(String::from)
		.collect();

		assert_eq!(
			setup().parse(&input),
			Err(ParserError::UnexpectedInput("--vape-nation".to_string()))
		);

		// Errors with an unexpected input
		let input: Vec<_> = vec![
			"--requires-no-value",
			"--required-with-value",
			"brawndo",
			"one-vape-world",
		]
		.into_iter()
		.map(String::from)
		.collect();
		assert_eq!(
			setup().parse(&input),
			Err(ParserError::UnexpectedInput("one-vape-world".to_string()))
		);

		let input =
			vec!["--forbid1-with-value", "eataly", "--forbid2-no-value"]
				.into_iter()
				.map(String::from)
				.collect::<Vec<String>>();
		assert_eq!(
			setup().parse(&input),
			Err(ParserError::MutuallyExclusiveInput(
				"forbid1-with-value".to_string(),
				"forbid2-no-value".to_string(),
			))
		);
	}

	#[test]
	fn version_works() {
		let input: Vec<_> = ["--version", "right to bear vapes"]
			.into_iter()
			.map(String::from)
			.collect();

		let mut parser = setup();
		parser.parse(&input).unwrap();

		assert!(parser.version());
	}

	#[test]
	fn help_works() {
		let input: Vec<_> = [
			"--help",
			"your body needs to vape",
			"--because",
			"vapes got what your body needs",
		]
		.into_iter()
		.map(String::from)
		.collect();

		let mut parser = setup();
		parser.parse(&input).unwrap();

		assert!(parser.help());
	}

	#[test]
	fn info_works() {
		let parser = Parser::new()
			.token(
				Token::new("token1", "info 1").required(true).takes_value(true),
			)
			.token(
				Token::new("token2-is-super-long", "info 2").takes_value(false),
			)
			.token(
				Token::new("token3", "info 3")
					.takes_value(false)
					.default_value("token3-default"),
			);
		let expected = "Required CLI inputs:
\t--token1 <token1> info 1

Optional CLI inputs:
\t--help                 Display the help message.
\t--token2-is-super-long info 2
\t--token3               info 3 [default: token3-default]
\t--version              Display the version";
		assert_eq!(parser.info(), expected);
	}
}
