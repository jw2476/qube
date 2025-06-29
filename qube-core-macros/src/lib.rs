#![allow(clippy::missing_panics_doc)]

use proc_macro::TokenStream;
use syn::{DeriveInput, ItemFn, parse_macro_input};

#[proc_macro_derive(Component)]
pub fn derive_component(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.to_string();
    format!(
        "qube_core::register_component!(register_{}, {ident});",
        ident.to_lowercase()
    )
    .parse()
    .unwrap()
}

#[proc_macro_attribute]
pub fn init(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let parsed = parse_macro_input!(input as ItemFn);
    let ident = parsed.sig.ident.to_string();

    format!("{input_str} qube_core::register_initialiser!(register_{ident}, {ident});",)
        .parse()
        .unwrap()
}

#[proc_macro_attribute]
pub fn system(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input_str = input.to_string();
    let parsed = parse_macro_input!(input as ItemFn);
    let ident = parsed.sig.ident.to_string();

    format!("{input_str} qube_core::register_system!(register_{ident}, {ident});",)
        .parse()
        .unwrap()
}
