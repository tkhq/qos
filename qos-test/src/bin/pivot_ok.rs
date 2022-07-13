use qos_core::parser::{GetParserForOptions, OptionsParser, Parser, Token};

// TODO get this to write a message
struct PivotParser;
impl GetParserForOptions for PivotParser {
	fn parser() -> Parser {
		Parser::new()
			.token(
				Token::new("msg", "A msg to write")
					.takes_value(true)
					.required(true)
			)
	}
}

fn main() {
	for i in 0..3 {
		std::thread::sleep(std::time::Duration::from_millis(i));
	}



	OptionsParser::<HostParser>::parse(args)

	std::fs::write(qos_test::PIVOT_OK_SUCCESS_FILE, b"contents").unwrap();
}
