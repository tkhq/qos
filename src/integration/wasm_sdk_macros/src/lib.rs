use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn qos_function(_attr: TokenStream, item: TokenStream) -> TokenStream {
	let function = parse_macro_input!(item as ItemFn);
	let name = &function.sig.ident;
	quote! {
		#function

		#[no_mangle]
		pub extern "C" fn execute(ptr: i32, len: i32) -> i64 {
			qos_wasm_sdk::abi::function_entry(ptr, len, #name)
		}
	}
	.into()
}

#[proc_macro_attribute]
pub fn qos_policy(_attr: TokenStream, item: TokenStream) -> TokenStream {
	let function = parse_macro_input!(item as ItemFn);
	let name = &function.sig.ident;
	quote! {
		#function

		#[no_mangle]
		pub extern "C" fn execute(ptr: i32, len: i32) -> i64 {
			qos_wasm_sdk::abi::policy_entry(ptr, len, #name)
		}
	}
	.into()
}
