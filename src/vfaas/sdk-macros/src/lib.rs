//! Attribute macros for the vfaas SDK.
//!
//! `#[program]` and `#[policy]` wrap a typed Rust function with the WASM ABI
//! the `pivot_vfaas` host expects. The wrapper is emitted only under
//! `cfg(target_arch = "wasm32")` — under any other target the user's function
//! is left as-is so `cargo test` runs it directly without a WASM runtime.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

/// Mark a function as a vfaas program entry point.
///
/// The function must have the shape
/// `fn name(_: &Context, input: T) -> R` where `T: BorshDeserialize` and
/// `R: BorshSerialize`. The macro generates an exported `__vfaas_execute`
/// extern "C" wrapper that handles the WASM ABI; the user's function is
/// otherwise untouched so it remains directly callable from tests.
#[proc_macro_attribute]
pub fn program(_attr: TokenStream, item: TokenStream) -> TokenStream {
	let item_fn = parse_macro_input!(item as ItemFn);
	expand_entry(&item_fn, "__vfaas_execute").into()
}

/// Mark a function as a vfaas policy entry point.
///
/// The function must have the shape
/// `fn name(_: &Context, request: PolicyRequest) -> Decision`. The macro
/// generates an exported `__vfaas_evaluate` extern "C" wrapper; the user's
/// function is otherwise untouched so it remains directly callable from
/// tests.
#[proc_macro_attribute]
pub fn policy(_attr: TokenStream, item: TokenStream) -> TokenStream {
	let item_fn = parse_macro_input!(item as ItemFn);
	expand_entry(&item_fn, "__vfaas_evaluate").into()
}

fn expand_entry(
	item_fn: &ItemFn,
	export_name: &str,
) -> proc_macro2::TokenStream {
	let user_ident = &item_fn.sig.ident;
	let export_ident =
		syn::Ident::new(export_name, proc_macro2::Span::call_site());

	quote! {
		#item_fn

		#[cfg(target_arch = "wasm32")]
		#[unsafe(no_mangle)]
		#[doc(hidden)]
		pub extern "C" fn #export_ident(ptr: u32, len: u32) -> u64 {
			::vfaas_sdk::rt::install_panic_hook();
			let input_bytes = ::vfaas_sdk::rt::take_input(ptr, len);
			let input = ::vfaas_sdk::rt::borsh_from_slice(&input_bytes)
				.expect("vfaas: input Borsh deserialization failed");
			let ctx = ::vfaas_sdk::Context::__new_internal();
			let output = #user_ident(&ctx, input);
			let out_bytes = ::vfaas_sdk::rt::borsh_to_vec(&output)
				.expect("vfaas: output Borsh serialization failed");
			::vfaas_sdk::rt::pack_result(out_bytes)
		}
	}
}
